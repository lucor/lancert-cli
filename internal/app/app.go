// Package app coordinates local state, Lancert DNS, and ACME issuance.
package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.lucor.dev/lancert-cli/internal/acme"
	"go.lucor.dev/lancert-cli/internal/certificate"
	"go.lucor.dev/lancert-cli/internal/lancertapi"
	"go.lucor.dev/lancert-cli/internal/state"
	"go.lucor.dev/lancert-cli/internal/target"
)

const (
	// ProductName is the user-facing CLI name.
	ProductName = "lancert"
	// DefaultAPIURL is the production Lancert API endpoint.
	DefaultAPIURL           = "https://lancert.dev"
	ariErrorRetry           = 6 * time.Hour
	minimumARICheckInterval = time.Hour
	minimumARIRetryLead     = time.Minute
	ariFallbackRenewalLead  = 30 * 24 * time.Hour
	defaultUserAgent        = "lancert-cli/dev"
)

// ErrTermsRequired means a new ACME account needs explicit terms acceptance.
var ErrTermsRequired = errors.New("accept the certificate authority terms with --accept-terms")

// Config controls one command invocation.
type Config struct {
	APIURL         string
	ACMEDirectory  string
	Email          string
	ConfigDir      string
	AcceptTerms    bool
	HTTPClient     *http.Client
	ACMEHTTPClient *http.Client
	UserAgent      string
	Resolver       *net.Resolver
	Now            func() time.Time
	Output         io.Writer
}

// Runner executes issuance and renewal commands.
type Runner struct {
	config Config
	store  *state.Store
	api    *lancertapi.Client
	issuer issuer
}

type issuer interface {
	Issue(context.Context, acme.Request) (acme.Result, error)
	GetRenewalInfo(context.Context, string, *x509.Certificate, *http.Client) (acme.RenewalInfo, error)
}

// New validates configuration and creates a runner.
func New(config Config) (*Runner, error) {
	if config.APIURL == "" {
		config.APIURL = DefaultAPIURL
	}
	if config.ACMEDirectory == "" {
		config.ACMEDirectory = acme.LetsEncryptProduction
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Output == nil {
		config.Output = io.Discard
	}
	if config.UserAgent == "" {
		config.UserAgent = defaultUserAgent
	}
	store, err := state.Open(config.ConfigDir)
	if err != nil {
		return nil, err
	}
	apiClient, err := lancertapi.New(config.APIURL, config.HTTPClient, config.UserAgent)
	if err != nil {
		return nil, err
	}
	return &Runner{config: config, store: store, api: apiClient, issuer: acme.Issuer{}}, nil
}

// Ensure obtains a certificate for targetIP or reuses the current usable one.
func (r *Runner) Ensure(ctx context.Context, targetIP string) error {
	if _, err := target.Parse(targetIP); err != nil {
		return err
	}
	registration, found, err := r.store.LoadRegistration(targetIP)
	if err != nil {
		return err
	}
	if !found {
		if err := r.ensureTerms(r.config.ACMEDirectory); err != nil {
			return err
		}
		credentials, err := r.api.Register(ctx, targetIP)
		if err != nil {
			return err
		}
		registration = state.Registration{
			TargetIP: targetIP, APIURL: r.config.APIURL, ACMEDirectory: r.config.ACMEDirectory,
			Email: r.config.Email, Credentials: credentials, CreatedAt: r.config.Now().UTC(),
		}
		if err := r.store.SaveRegistration(registration); err != nil {
			return fmt.Errorf("save one-time registration credentials: %w", err)
		}
	}
	return r.ensureRegistration(ctx, registration)
}

// Renew processes every locally managed registration and continues after failures.
func (r *Runner) Renew(ctx context.Context) error {
	registrations, err := r.store.Registrations()
	if err != nil {
		return err
	}
	if len(registrations) == 0 {
		fmt.Fprintln(r.config.Output, "No managed certificates.")
		return nil
	}
	var failures []string
	for _, registration := range registrations {
		if err := r.renewRegistration(ctx, registration); err != nil {
			failures = append(failures, registration.TargetIP+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("renewal failed for %d target(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

func (r *Runner) ensureRegistration(ctx context.Context, registration state.Registration) error {
	chainPath, keyPath := r.store.CertificatePaths(registration.Credentials.Hostname)
	usable, err := certificate.Usable(chainPath, keyPath, registration.Credentials.Hostname, r.config.Now())
	if err != nil {
		return err
	}
	if usable {
		r.printResult(registration, chainPath, keyPath, "Certificate is already valid.")
		return nil
	}
	leaf, _, err := certificate.LoadLeaf(chainPath)
	if err != nil {
		return err
	}
	return r.issueAndSave(ctx, registration, leaf, "Certificate issued.")
}

func (r *Runner) renewRegistration(ctx context.Context, registration state.Registration) error {
	chainPath, _ := r.store.CertificatePaths(registration.Credentials.Hostname)
	leaf, found, err := certificate.LoadLeaf(chainPath)
	if err != nil {
		return err
	}
	if !found {
		return r.issueAndSave(ctx, registration, nil, "Certificate issued.")
	}
	due, err := r.renewalDue(ctx, &registration, leaf)
	if err != nil || !due {
		return err
	}
	return r.issueAndSave(ctx, registration, leaf, "Certificate renewed.")
}

func (r *Runner) renewalDue(ctx context.Context, registration *state.Registration, leaf *x509.Certificate) (bool, error) {
	now := r.config.Now().UTC()
	certificateID := certificateID(leaf)
	if registration.Renewal.CertificateID != certificateID {
		registration.Renewal = state.RenewalState{CertificateID: certificateID}
	}
	if !registration.Renewal.RenewAt.IsZero() && !registration.Renewal.NextCheck.IsZero() && now.Before(registration.Renewal.NextCheck) {
		return !now.Before(registration.Renewal.RenewAt), nil
	}

	info, infoErr := r.issuer.GetRenewalInfo(ctx, registration.ACMEDirectory, leaf, r.config.ACMEHTTPClient)
	if infoErr == nil && validARIWindow(info.WindowStart, info.WindowEnd, leaf.NotAfter) {
		windowEnd := info.WindowEnd
		if windowEnd.After(leaf.NotAfter) {
			windowEnd = leaf.NotAfter
		}
		registration.Renewal.WindowStart = info.WindowStart.UTC()
		registration.Renewal.WindowEnd = windowEnd.UTC()
		registration.Renewal.RenewAt = chooseRenewAt(certificateID, info.WindowStart, windowEnd)
		registration.Renewal.NextCheck = info.RetryAfter.UTC()
		if registration.Renewal.NextCheck.IsZero() || registration.Renewal.NextCheck.Before(now.Add(minimumARIRetryLead)) {
			registration.Renewal.NextCheck = now.Add(minimumARICheckInterval)
		}
	} else {
		registration.Renewal.WindowStart = time.Time{}
		registration.Renewal.WindowEnd = time.Time{}
		registration.Renewal.RenewAt = leaf.NotAfter.Add(-ariFallbackRenewalLead).UTC()
		registration.Renewal.NextCheck = now.Add(ariErrorRetry)
	}
	if err := r.store.SaveRegistration(*registration); err != nil {
		return false, fmt.Errorf("save renewal schedule: %w", err)
	}
	return !now.Before(registration.Renewal.RenewAt), nil
}

func (r *Runner) issueAndSave(ctx context.Context, registration state.Registration, replaces *x509.Certificate, message string) error {
	accountKey, _, err := r.store.AccountKey(registration.ACMEDirectory)
	if err != nil {
		return err
	}
	if err := r.ensureTerms(registration.ACMEDirectory); err != nil {
		return err
	}
	apiClient := r.api
	if registration.APIURL != r.config.APIURL {
		apiClient, err = lancertapi.New(registration.APIURL, r.config.HTTPClient, r.config.UserAgent)
		if err != nil {
			return err
		}
	}
	result, err := r.issue(ctx, registration, accountKey, apiClient, replaces)
	if err != nil {
		return err
	}
	chainPEM, err := certificate.EncodeChain(result.ChainDER)
	if err != nil {
		return err
	}
	if err := r.store.SaveCertificate(registration.Credentials.Hostname, chainPEM, result.PrivateKeyPEM); err != nil {
		return err
	}
	registration.Renewal = state.RenewalState{}
	if err := r.store.SaveRegistration(registration); err != nil {
		return fmt.Errorf("reset renewal schedule: %w", err)
	}
	chainPath, keyPath := r.store.CertificatePaths(registration.Credentials.Hostname)
	r.printResult(registration, chainPath, keyPath, message)
	return nil
}

func (r *Runner) ensureTerms(directory string) error {
	accepted, err := r.store.TermsAccepted(directory)
	if err != nil {
		return err
	}
	if accepted {
		return nil
	}
	if !r.config.AcceptTerms {
		return ErrTermsRequired
	}
	return r.store.AcceptTerms(directory)
}

func (r *Runner) issue(ctx context.Context, registration state.Registration, accountKey *ecdsa.PrivateKey, apiClient *lancertapi.Client, replaces *x509.Certificate) (acme.Result, error) {
	provider := txtProvider{api: apiClient, registration: registration.Credentials}
	return r.issuer.Issue(ctx, acme.Request{
		Directory: registration.ACMEDirectory, Email: registration.Email,
		Domains:    []string{registration.Credentials.Hostname, "*." + registration.Credentials.Hostname},
		AccountKey: accountKey, Provider: provider, Resolver: r.config.Resolver, HTTPClient: r.config.ACMEHTTPClient,
		Replaces: replaces,
	})
}

func validARIWindow(start, end, notAfter time.Time) bool {
	return !start.IsZero() && !end.IsZero() && start.Before(end) && start.Before(notAfter)
}

func certificateID(leaf *x509.Certificate) string {
	digest := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(digest[:])
}

func chooseRenewAt(id string, start, end time.Time) time.Time {
	if !start.Before(end) {
		return end
	}
	hash := sha256.New()
	hash.Write([]byte(id))
	hash.Write([]byte{0})
	hash.Write([]byte(start.UTC().Format(time.RFC3339Nano)))
	hash.Write([]byte{0})
	hash.Write([]byte(end.UTC().Format(time.RFC3339Nano)))
	offset := binary.BigEndian.Uint64(hash.Sum(nil)[:8])
	return start.Add(time.Duration(offset % uint64(end.Sub(start))))
}

func (r *Runner) printResult(registration state.Registration, chainPath, keyPath, message string) {
	fmt.Fprintln(r.config.Output, message)
	fmt.Fprintf(r.config.Output, "Hostname: %s\n", registration.Credentials.Hostname)
	fmt.Fprintf(r.config.Output, "Certificate: %s\n", chainPath)
	fmt.Fprintf(r.config.Output, "Private key: %s\n", keyPath)
}

type txtProvider struct {
	api          *lancertapi.Client
	registration lancertapi.Registration
}

func (p txtProvider) SetTXT(ctx context.Context, name, value string) error {
	if strings.TrimSuffix(name, ".") != p.registration.FullDomain {
		return fmt.Errorf("ACME requested unexpected DNS name %q", name)
	}
	return p.api.Update(ctx, p.registration, value)
}
