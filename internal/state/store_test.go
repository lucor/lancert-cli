package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.lucor.dev/lancert-cli/internal/lancertapi"
)

func TestRegistrationAndAccountPersistence(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "lancert")
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	registration := Registration{
		TargetIP: "192.168.1.50", APIURL: "https://lancert.dev",
		ACMEDirectory: "https://acme.example/directory", CreatedAt: time.Now().UTC(),
		Credentials: lancertapi.Registration{Hostname: "quiet-otter.lancert.dev", Username: "12345678-1234-4234-9234-123456789abc", Password: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", Subdomain: "quiet-otter", FullDomain: "_acme-challenge.quiet-otter.lancert.dev"},
	}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadRegistration(registration.TargetIP)
	if err != nil || !found || loaded.Credentials.Password != "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN" {
		t.Fatalf("LoadRegistration() = %#v, %v, %v", loaded, found, err)
	}
	key, created, err := store.AccountKey(registration.ACMEDirectory)
	if err != nil || !created || key == nil {
		t.Fatalf("AccountKey() = %v, %v, %v", key, created, err)
	}
	keyAgain, created, err := store.AccountKey(registration.ACMEDirectory)
	if err != nil || created || !keyAgain.PublicKey.Equal(&key.PublicKey) {
		t.Fatalf("second AccountKey() did not reuse key")
	}
	accepted, err := store.TermsAccepted(registration.ACMEDirectory)
	if err != nil || accepted {
		t.Fatalf("TermsAccepted() = %v, %v", accepted, err)
	}
	if err := store.AcceptTerms(registration.ACMEDirectory); err != nil {
		t.Fatal(err)
	}
	accepted, err = store.TermsAccepted(registration.ACMEDirectory)
	if err != nil || !accepted {
		t.Fatalf("TermsAccepted() after acceptance = %v, %v", accepted, err)
	}
	for _, path := range []string{root, filepath.Join(root, "registrations"), filepath.Join(root, "accounts")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode = %v, err %v", path, info.Mode().Perm(), err)
		}
	}
	info, err := os.Stat(store.registrationPath(registration.TargetIP))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registration mode = %v, err %v", info.Mode().Perm(), err)
	}
}

func TestSaveCertificateReplacesFilesAndKeepsBackups(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "lancert"))
	if err != nil {
		t.Fatal(err)
	}
	const hostname = "quiet-otter.lancert.dev"
	if err := store.SaveCertificate(hostname, []byte("chain-one"), []byte("key-one")); err != nil {
		t.Fatal(err)
	}
	chainPath, keyPath := store.CertificatePaths(hostname)
	assertFileContents(t, chainPath, "chain-one")
	assertFileContents(t, keyPath, "key-one")
	assertNotExists(t, chainPath+".bak")
	assertNotExists(t, keyPath+".bak")
	if err := store.SaveCertificate(hostname, []byte("chain-two"), []byte("key-two")); err != nil {
		t.Fatal(err)
	}
	assertFileContents(t, chainPath, "chain-two")
	assertFileContents(t, keyPath, "key-two")
	assertFileContents(t, chainPath+".bak", "chain-one")
	assertFileContents(t, keyPath+".bak", "key-one")
	for _, path := range []string{chainPath, keyPath, chainPath + ".bak", keyPath + ".bak"} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s mode = %v", path, info.Mode())
		}
	}
}

func assertFileContents(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatalf("read %s = %q, %v; want %q", path, data, err, expected)
	}
}

func assertNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s not to exist, got %v", path, err)
	}
}
