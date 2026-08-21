// Package acme obtains certificates from an RFC 8555 authority using DNS-01.
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	protocol "github.com/mholt/acmez/v3/acme"
)

const (
	// LetsEncryptProduction is the default public ACME directory.
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	propagationTimeout    = 5 * time.Minute
	propagationInterval   = 2 * time.Second
	defaultHTTPTimeout    = 30 * time.Second
)

// TXTProvider publishes the value required by one DNS-01 challenge.
type TXTProvider interface {
	SetTXT(context.Context, string, string) error
}

// Request contains one certificate order.
type Request struct {
	Directory  string
	Email      string
	Domains    []string
	AccountKey *ecdsa.PrivateKey
	Provider   TXTProvider
	Resolver   *net.Resolver
	HTTPClient *http.Client
	Replaces   *x509.Certificate
}

// Result contains a new private key and certificate chain.
type Result struct {
	PrivateKeyPEM []byte
	ChainDER      [][]byte
}

// RenewalInfo is the scheduling information returned by ACME ARI.
type RenewalInfo struct {
	WindowStart time.Time
	WindowEnd   time.Time
	RetryAfter  time.Time
}

// Issuer obtains exact-and-wildcard certificates with DNS-01.
type Issuer struct{}

// GetRenewalInfo fetches the CA-recommended ARI window for leaf.
func (Issuer) GetRenewalInfo(ctx context.Context, directory string, leaf *x509.Certificate, httpClient *http.Client) (RenewalInfo, error) {
	if directory == "" || leaf == nil {
		return RenewalInfo{}, errors.New("incomplete ARI request")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	client := &protocol.Client{Directory: directory, HTTPClient: httpClient}
	info, err := client.GetRenewalInfo(ctx, leaf)
	if err != nil {
		return RenewalInfo{}, fmt.Errorf("fetch ACME renewal information: %w", err)
	}
	var retryAfter time.Time
	if info.RetryAfter != nil {
		retryAfter = info.RetryAfter.UTC()
	}
	return RenewalInfo{
		WindowStart: info.SuggestedWindow.Start.UTC(),
		WindowEnd:   info.SuggestedWindow.End.UTC(),
		RetryAfter:  retryAfter,
	}, nil
}

// Issue completes one ACME order.
func (Issuer) Issue(ctx context.Context, request Request) (Result, error) {
	if request.Directory == "" || len(request.Domains) == 0 || request.AccountKey == nil || request.Provider == nil {
		return Result{}, errors.New("incomplete ACME request")
	}
	httpClient := request.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	client := &protocol.Client{Directory: request.Directory, HTTPClient: httpClient}
	account := protocol.Account{PrivateKey: request.AccountKey, TermsOfServiceAgreed: true}
	if request.Email != "" {
		account.Contact = []string{"mailto:" + request.Email}
	}
	registered, err := client.NewAccount(ctx, account)
	if err != nil {
		return Result{}, fmt.Errorf("register or load ACME account: %w", err)
	}
	account = registered
	identifiers := make([]protocol.Identifier, 0, len(request.Domains))
	for _, domain := range request.Domains {
		identifiers = append(identifiers, protocol.Identifier{Type: "dns", Value: domain})
	}
	newOrder := protocol.Order{Identifiers: identifiers}
	if request.Replaces != nil {
		newOrder.Replaces, err = protocol.ARIUniqueIdentifier(request.Replaces)
		if err != nil {
			return Result{}, fmt.Errorf("derive predecessor certificate ID: %w", err)
		}
	}
	order, err := client.NewOrder(ctx, account, newOrder)
	if err != nil {
		return Result{}, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authorizationURL := range order.Authorizations {
		authorization, err := client.GetAuthorization(ctx, account, authorizationURL)
		if err != nil {
			return Result{}, fmt.Errorf("get ACME authorization: %w", err)
		}
		if authorization.Status == protocol.StatusValid {
			continue
		}
		challenge := dnsChallenge(authorization.Challenges)
		if challenge == nil {
			return Result{}, fmt.Errorf("ACME offered no DNS-01 challenge for %s", authorization.IdentifierValue())
		}
		name := challenge.DNS01TXTRecordName()
		value := challenge.DNS01KeyAuthorization()
		if err := request.Provider.SetTXT(ctx, name, value); err != nil {
			return Result{}, fmt.Errorf("publish %s: %w", name, err)
		}
		if err := waitForTXT(ctx, request.Resolver, name, value); err != nil {
			return Result{}, err
		}
		if _, err := client.InitiateChallenge(ctx, account, *challenge); err != nil {
			return Result{}, fmt.Errorf("start ACME challenge: %w", err)
		}
		if _, err := client.PollAuthorization(ctx, account, authorization); err != nil {
			return Result{}, fmt.Errorf("validate ACME authorization: %w", err)
		}
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: request.Domains[0]}, DNSNames: request.Domains}, certificateKey)
	if err != nil {
		return Result{}, fmt.Errorf("create certificate request: %w", err)
	}
	order, err = client.FinalizeOrder(ctx, account, order, csr)
	if err != nil {
		return Result{}, fmt.Errorf("finalize ACME order: %w", err)
	}
	chains, err := client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		return Result{}, fmt.Errorf("download certificate chain: %w", err)
	}
	if len(chains) == 0 {
		return Result{}, errors.New("ACME returned no certificate chain")
	}
	chainDER, err := parseChain(chains[0].ChainPEM)
	if err != nil {
		return Result{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(certificateKey)
	if err != nil {
		return Result{}, fmt.Errorf("marshal certificate key: %w", err)
	}
	return Result{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), ChainDER: chainDER}, nil
}

func dnsChallenge(challenges []protocol.Challenge) *protocol.Challenge {
	for i := range challenges {
		if challenges[i].Type == protocol.ChallengeTypeDNS01 {
			return &challenges[i]
		}
	}
	return nil
}

func waitForTXT(ctx context.Context, resolver *net.Resolver, name, expected string) error {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	name = strings.TrimSuffix(name, ".")
	deadline := time.NewTimer(propagationTimeout)
	defer deadline.Stop()
	for {
		values, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, value := range values {
				if value == expected {
					return nil
				}
			}
		}
		timer := time.NewTimer(propagationInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return fmt.Errorf("DNS challenge did not become visible at %s", name)
		case <-timer.C:
		}
	}
}

func parseChain(data []byte) ([][]byte, error) {
	var chain [][]byte
	for rest := data; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("parse ACME certificate chain: %w", err)
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("ACME certificate chain is empty")
	}
	return chain, nil
}
