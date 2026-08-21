// Package certificate validates and encodes locally managed certificates.
package certificate

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// EncodeChain converts DER certificates to a PEM chain.
func EncodeChain(chain [][]byte) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	var data []byte
	for _, der := range chain {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return data, nil
}

// LoadLeaf reads the first certificate from a PEM chain. found is false when
// no chain exists yet.
func LoadLeaf(chainPath string) (leaf *x509.Certificate, found bool, err error) {
	chainPEM, err := os.ReadFile(chainPath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(chainPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, false, errors.New("invalid certificate PEM")
	}
	leaf, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf, true, nil
}

// Usable reports whether the certificate and key exist, match, contain both
// requested names, and are currently valid.
func Usable(chainPath, keyPath, hostname string, now time.Time) (bool, error) {
	leaf, found, err := LoadLeaf(chainPath)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	keyPEM, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read certificate key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return false, errors.New("invalid certificate key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse certificate key: %w", err)
	}
	if !publicKeysEqual(leaf.PublicKey, &key.PublicKey) {
		return false, errors.New("certificate and private key do not match")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false, nil
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return false, nil
	}
	if err := leaf.VerifyHostname("test." + hostname); err != nil {
		return false, nil
	}
	return true, nil
}

func publicKeysEqual(left any, right *ecdsa.PublicKey) bool {
	key, ok := left.(*ecdsa.PublicKey)
	return ok && key.Equal(right)
}
