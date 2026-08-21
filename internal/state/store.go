// Package state owns Lancert's local credentials, ACME accounts, and certificates.
package state

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"go.lucor.dev/lancert-cli/internal/lancertapi"
)

const configDirName = "lancert"

// Registration is all local state needed to issue and renew one target certificate.
type Registration struct {
	TargetIP      string                  `json:"target_ip"`
	APIURL        string                  `json:"api_url"`
	ACMEDirectory string                  `json:"acme_directory"`
	Email         string                  `json:"email,omitempty"`
	Credentials   lancertapi.Registration `json:"credentials"`
	CreatedAt     time.Time               `json:"created_at"`
	Renewal       RenewalState            `json:"renewal,omitzero"`
}

// RenewalState caches the ARI schedule for the currently stored certificate.
type RenewalState struct {
	CertificateID string    `json:"certificate_id"`
	WindowStart   time.Time `json:"window_start,omitzero"`
	WindowEnd     time.Time `json:"window_end,omitzero"`
	RenewAt       time.Time `json:"renew_at"`
	NextCheck     time.Time `json:"next_check"`
}

// Store persists state beneath one private configuration directory.
type Store struct {
	root string
}

// DefaultDir returns the platform-native user configuration directory for Lancert.
func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("user configuration directory is not absolute")
	}
	return filepath.Join(dir, configDirName), nil
}

// Open creates and secures a local state directory.
func Open(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("config directory must be an absolute path")
	}
	if err := secureDir(root); err != nil {
		return nil, err
	}
	for _, child := range []string{"accounts", "registrations", "certs"} {
		if err := secureDir(filepath.Join(root, child)); err != nil {
			return nil, err
		}
	}
	return &Store{root: root}, nil
}

// LoadRegistration loads a previously persisted target registration.
func (s *Store) LoadRegistration(targetIP string) (Registration, bool, error) {
	path := s.registrationPath(targetIP)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Registration{}, false, nil
	}
	if err != nil {
		return Registration{}, false, fmt.Errorf("read registration: %w", err)
	}
	var registration Registration
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil {
		return Registration{}, false, fmt.Errorf("decode registration: %w", err)
	}
	if registration.TargetIP != targetIP || registration.APIURL == "" || registration.ACMEDirectory == "" {
		return Registration{}, false, errors.New("registration state is incomplete")
	}
	if err := registration.Credentials.Validate(); err != nil {
		return Registration{}, false, fmt.Errorf("registration credentials: %w", err)
	}
	return registration, true, nil
}

// SaveRegistration atomically persists credentials before certificate issuance.
func (s *Store) SaveRegistration(registration Registration) error {
	if err := registration.Credentials.Validate(); err != nil {
		return fmt.Errorf("registration credentials: %w", err)
	}
	data, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registration: %w", err)
	}
	data = append(data, '\n')
	return atomicWrite(s.registrationPath(registration.TargetIP), data, 0o600)
}

// Registrations loads every managed registration in stable target order.
func (s *Store) Registrations() ([]Registration, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "registrations"))
	if err != nil {
		return nil, fmt.Errorf("list registrations: %w", err)
	}
	var registrations []Registration
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		targetIP := entry.Name()[:len(entry.Name())-len(".json")]
		registration, found, err := s.LoadRegistration(targetIP)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.Name(), err)
		}
		if found {
			registrations = append(registrations, registration)
		}
	}
	sort.Slice(registrations, func(i, j int) bool { return registrations[i].TargetIP < registrations[j].TargetIP })
	return registrations, nil
}

// AccountKey loads or creates a P-256 account key scoped to one ACME directory.
func (s *Store) AccountKey(directory string) (*ecdsa.PrivateKey, bool, error) {
	path := s.accountPath(directory)
	data, err := os.ReadFile(path)
	if err == nil {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "EC PRIVATE KEY" || len(rest) != 0 {
			return nil, false, errors.New("invalid ACME account key file")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("parse ACME account key: %w", err)
		}
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("read ACME account key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate ACME account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, false, fmt.Errorf("marshal ACME account key: %w", err)
	}
	if err := atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// TermsAccepted reports whether this installation explicitly accepted the CA
// terms for the selected directory.
func (s *Store) TermsAccepted(directory string) (bool, error) {
	_, err := os.Stat(s.termsPath(directory))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("read ACME terms acceptance: %w", err)
}

// AcceptTerms durably records terms acceptance for one ACME directory.
func (s *Store) AcceptTerms(directory string) error {
	return atomicWrite(s.termsPath(directory), []byte("accepted\n"), 0o600)
}

// CertificatePaths returns the stable paths consumed by local web servers.
func (s *Store) CertificatePaths(hostname string) (fullchain, privateKey string) {
	dir := filepath.Join(s.root, "certs", hostname)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// SaveCertificate atomically replaces each certificate file and keeps the previous
// version beside it with a .bak suffix.
func (s *Store) SaveCertificate(hostname string, fullchain, privateKey []byte) error {
	dir := filepath.Join(s.root, "certs", hostname)
	if err := secureDir(dir); err != nil {
		return err
	}
	chainPath, keyPath := s.CertificatePaths(hostname)
	if err := backupFile(chainPath); err != nil {
		return fmt.Errorf("back up certificate chain: %w", err)
	}
	if err := backupFile(keyPath); err != nil {
		return fmt.Errorf("back up certificate key: %w", err)
	}
	if err := atomicWrite(keyPath, privateKey, 0o600); err != nil {
		return fmt.Errorf("save certificate key: %w", err)
	}
	if err := atomicWrite(chainPath, fullchain, 0o600); err != nil {
		return fmt.Errorf("save certificate chain: %w", err)
	}
	return nil
}

func backupFile(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current file: %w", err)
	}
	if err := atomicWrite(path+".bak", data, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	return nil
}

func (s *Store) registrationPath(targetIP string) string {
	return filepath.Join(s.root, "registrations", targetIP+".json")
}

func (s *Store) accountPath(directory string) string {
	digest := sha256.Sum256([]byte(directory))
	return filepath.Join(s.root, "accounts", hex.EncodeToString(digest[:])+".pem")
}

func (s *Store) termsPath(directory string) string {
	digest := sha256.Sum256([]byte(directory))
	return filepath.Join(s.root, "accounts", hex.EncodeToString(digest[:])+".terms")
}

func secureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode fs.FileMode) (returnErr error) {
	dir := filepath.Dir(path)
	if err := secureDir(dir); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".lancert-*")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		if returnErr != nil {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return fmt.Errorf("secure temporary state file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary state file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("commit state file: %w", err)
	}
	return nil
}
