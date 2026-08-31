package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.lucor.dev/lancert-cli/internal/app"
	"go.lucor.dev/lancert-cli/internal/lancertapi"
	"go.lucor.dev/lancert-cli/internal/state"
)

func TestVersionCommandDoesNotInitializeState(t *testing.T) {
	var output bytes.Buffer
	command := newCommand("/path/that/is/not/used", strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "version"}); err != nil {
		t.Fatal(err)
	}
	if output.String() != Version+"\n" {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestTermsPrompt(t *testing.T) {
	var output bytes.Buffer
	accepted, err := confirmTerms(strings.NewReader("yes\n"), &output)
	if err != nil || !accepted {
		t.Fatalf("confirmTerms(yes) = %v, %v", accepted, err)
	}
	accepted, err = confirmTerms(strings.NewReader("no\n"), &output)
	if err == nil || accepted {
		t.Fatalf("confirmTerms(no) = %v, %v", accepted, err)
	}
}

func TestListNoRegistrations(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "No managed certificates.\n" {
		t.Fatalf("list output = %q", output.String())
	}
}

func TestListMultipleRegistrationsSortedByHostname(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	registrations := []state.Registration{
		reg(now, "10.0.0.12", "blue-fox.lancert.dev", "12345678-1234-4234-9234-123456789abd"),
		reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc"),
	}
	for _, r := range registrations {
		if err := store.SaveRegistration(r); err != nil {
			t.Fatal(err)
		}
	}
	chain, key := testCert(t, now.Add(-time.Hour), now.Add(61*24*time.Hour), "quiet-otter.lancert.dev")
	if err := store.SaveCertificate("quiet-otter.lancert.dev", chain, key); err != nil {
		t.Fatal(err)
	}
	chain, key = testCert(t, now.Add(-time.Hour), now.Add(18*24*time.Hour), "blue-fox.lancert.dev")
	if err := store.SaveCertificate("blue-fox.lancert.dev", chain, key); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), output.String())
	}
	if !strings.Contains(lines[1], "blue-fox") || !strings.Contains(lines[1], "10.0.0.12") {
		t.Fatalf("expected blue-fox first, got %q", lines[1])
	}
	if !strings.Contains(lines[2], "quiet-otter") || !strings.Contains(lines[2], "192.168.1.50") {
		t.Fatalf("expected quiet-otter second, got %q", lines[2])
	}
}

func TestListExpiredCertificate(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	chain, key := testCert(t, now.Add(-2*24*time.Hour), now.Add(-2*time.Hour), "quiet-otter.lancert.dev")
	if err := store.SaveCertificate("quiet-otter.lancert.dev", chain, key); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "expired") {
		t.Fatalf("expected expired, got %q", output.String())
	}
}

func TestListMissingCertificate(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "not found") {
		t.Fatalf("expected 'not found', got %q", output.String())
	}
}

func TestListUnreadableCertificate(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	chainPath, _ := store.CertificatePaths("quiet-otter.lancert.dev")
	if err := os.MkdirAll(filepath.Dir(chainPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "unreadable") {
		t.Fatalf("expected 'unreadable', got %q", output.String())
	}
}

func TestListInvalidCertificatePEM(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	chainPath, _ := store.CertificatePaths("quiet-otter.lancert.dev")
	if err := os.MkdirAll(filepath.Dir(chainPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chainPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad-der")}), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "unreadable") {
		t.Fatalf("expected 'unreadable', got %q", output.String())
	}
}

func TestListPartialBrokenRegistration(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	good := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(good); err != nil {
		t.Fatal(err)
	}
	chain, key := testCert(t, now.Add(-time.Hour), now.Add(61*24*time.Hour), "quiet-otter.lancert.dev")
	if err := store.SaveCertificate("quiet-otter.lancert.dev", chain, key); err != nil {
		t.Fatal(err)
	}
	bad := reg(now, "10.0.0.12", "blue-fox.lancert.dev", "12345678-1234-4234-9234-123456789abd")
	if err := store.SaveRegistration(bad); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "quiet-otter") || !strings.Contains(output.String(), "blue-fox") {
		t.Fatalf("expected both registrations, got %q", output.String())
	}
	if !strings.Contains(output.String(), "not found") {
		t.Fatalf("expected 'not found', got %q", output.String())
	}
}

func TestListWithCustomConfigDir(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "custom")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "--config-dir", dir, "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "quiet-otter") {
		t.Fatalf("expected output, got %q", output.String())
	}
}

func TestListHeaderFormat(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "lancert")
	store := createStore(t, dir)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	r := reg(now, "192.168.1.50", "quiet-otter.lancert.dev", "12345678-1234-4234-9234-123456789abc")
	if err := store.SaveRegistration(r); err != nil {
		t.Fatal(err)
	}
	chain, key := testCert(t, now.Add(-time.Hour), now.Add(61*24*time.Hour), "quiet-otter.lancert.dev")
	if err := store.SaveCertificate("quiet-otter.lancert.dev", chain, key); err != nil {
		t.Fatal(err)
	}
	chainPath, _ := store.CertificatePaths("quiet-otter.lancert.dev")
	var output bytes.Buffer
	command := newCommand(dir, strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	header := lines[0]
	if !strings.Contains(header, "HOSTNAME") || !strings.Contains(header, "IP") || !strings.Contains(header, "EXPIRES") || !strings.Contains(header, "CERTIFICATE") {
		t.Fatalf("header = %q, missing columns", header)
	}
	if !strings.Contains(lines[1], chainPath) {
		t.Fatalf("certificate path is not absolute: %q", lines[1])
	}
}

func TestListHelpOutput(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	command := newCommand("/nonexistent", strings.NewReader(""), &output, &output)
	if err := command.Run(context.Background(), []string{app.ProductName, "list", "--help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "list locally managed certificates") {
		t.Fatalf("help output = %q", output.String())
	}
}

func createStore(t *testing.T, dir string) *state.Store {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func reg(now time.Time, targetIP, hostname, username string) state.Registration {
	return state.Registration{
		TargetIP: targetIP, APIURL: "https://lancert.dev",
		ACMEDirectory: "https://acme-v02.api.letsencrypt.org/directory", CreatedAt: now,
		Credentials: lancertapi.Registration{
			Hostname: hostname, Username: username,
			Password:   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
			Subdomain:  strings.Split(hostname, ".")[0],
			FullDomain: "_acme-challenge." + hostname,
		},
	}
}

func testCert(t *testing.T, notBefore, notAfter time.Time, hostname string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname},
		NotBefore: notBefore, NotAfter: notAfter,
		DNSNames: []string{hostname, "test." + hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
