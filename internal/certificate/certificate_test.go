package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUsableChecksValidityNamesAndKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	chain, key := testCertificate(t, now.Add(-time.Hour), now.Add(60*24*time.Hour), []string{"quiet-otter.lancert.dev", "*.quiet-otter.lancert.dev"})
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(chainPath, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	usable, err := Usable(chainPath, keyPath, "quiet-otter.lancert.dev", now)
	if err != nil || !usable {
		t.Fatalf("Usable() = %v, %v", usable, err)
	}
	usable, err = Usable(chainPath, keyPath, "quiet-otter.lancert.dev", now.Add(61*24*time.Hour))
	if err != nil || usable {
		t.Fatalf("Usable() after expiration = %v, %v", usable, err)
	}
}

func testCertificate(t *testing.T, notBefore, notAfter time.Time, names []string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: names,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
