package app

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.lucor.dev/lancert-cli/internal/acme"
	"go.lucor.dev/lancert-cli/internal/lancertapi"
	"go.lucor.dev/lancert-cli/internal/state"
)

type failingIssuer struct {
	calls       int
	ariCalls    int
	renewalInfo acme.RenewalInfo
	renewalErr  error
}

func (i *failingIssuer) Issue(context.Context, acme.Request) (acme.Result, error) {
	i.calls++
	return acme.Result{}, errors.New("test issuance failure")
}

func (i *failingIssuer) GetRenewalInfo(context.Context, string, *x509.Certificate, *http.Client) (acme.RenewalInfo, error) {
	i.ariCalls++
	return i.renewalInfo, i.renewalErr
}

func TestRenewalDueUsesAndCachesARIWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	runner, err := New(Config{APIURL: "https://api.test", ConfigDir: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	issuer := &failingIssuer{renewalInfo: acme.RenewalInfo{
		WindowStart: now.Add(time.Hour), WindowEnd: now.Add(25 * time.Hour), RetryAfter: now.Add(30 * time.Minute),
	}}
	runner.issuer = issuer
	registration := testRegistration(now)
	if err := runner.store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{Raw: []byte("certificate-one"), NotAfter: now.Add(60 * 24 * time.Hour)}
	due, err := runner.renewalDue(context.Background(), &registration, leaf)
	if err != nil || due {
		t.Fatalf("renewalDue() = %v, %v", due, err)
	}
	if issuer.ariCalls != 1 {
		t.Fatalf("ARI calls = %d, want 1", issuer.ariCalls)
	}
	if registration.Renewal.RenewAt.Before(issuer.renewalInfo.WindowStart) || !registration.Renewal.RenewAt.Before(issuer.renewalInfo.WindowEnd) {
		t.Fatalf("renew_at %s is outside ARI window", registration.Renewal.RenewAt)
	}
	if _, err := runner.renewalDue(context.Background(), &registration, leaf); err != nil {
		t.Fatal(err)
	}
	if issuer.ariCalls != 1 {
		t.Fatalf("cached ARI calls = %d, want 1", issuer.ariCalls)
	}
	loaded, found, err := runner.store.LoadRegistration(registration.TargetIP)
	if err != nil || !found || loaded.Renewal.CertificateID == "" {
		t.Fatalf("persisted renewal state = %#v, %v, %v", loaded.Renewal, found, err)
	}
}

func TestRenewalDueFallsBackWhenARIUnavailable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	runner, err := New(Config{APIURL: "https://api.test", ConfigDir: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	runner.issuer = &failingIssuer{renewalErr: errors.New("ARI unavailable")}
	registration := testRegistration(now)
	if err := runner.store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{Raw: []byte("certificate-two"), NotAfter: now.Add(60 * 24 * time.Hour)}
	due, err := runner.renewalDue(context.Background(), &registration, leaf)
	if err != nil || due {
		t.Fatalf("renewalDue() = %v, %v", due, err)
	}
	want := leaf.NotAfter.Add(-30 * 24 * time.Hour)
	if !registration.Renewal.RenewAt.Equal(want) {
		t.Fatalf("fallback renew_at = %s, want %s", registration.Renewal.RenewAt, want)
	}
}

func TestChooseRenewAtIsStableAndInsideWindow(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	first := chooseRenewAt("certificate", start, end)
	second := chooseRenewAt("certificate", start, end)
	if !first.Equal(second) || first.Before(start) || !first.Before(end) {
		t.Fatalf("chooseRenewAt() = %s, %s", first, second)
	}
}

func testRegistration(now time.Time) state.Registration {
	return state.Registration{
		TargetIP: "192.168.1.50", APIURL: "https://api.test", ACMEDirectory: "https://acme.test/directory", CreatedAt: now,
		Credentials: lancertapi.Registration{
			Hostname: "quiet-otter.lancert.dev", Username: "12345678-1234-4234-9234-123456789abc",
			Password: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", Subdomain: "quiet-otter",
			FullDomain: "_acme-challenge.quiet-otter.lancert.dev",
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func jsonResponse(status int, body string) *http.Response {
	response := &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	response.Header.Set("X-Lancert-API-Version", "2")
	return response
}

func TestEnsureRequestsTermsBeforeRegistration(t *testing.T) {
	t.Parallel()
	registrations := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		registrations++
		return jsonResponse(http.StatusInternalServerError, `{}`), nil
	})}
	runner, err := New(Config{APIURL: "https://api.test", ConfigDir: filepath.Join(t.TempDir(), "state"), HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	err = runner.Ensure(context.Background(), "192.168.1.50")
	if !errors.Is(err, ErrTermsRequired) {
		t.Fatalf("Ensure() error = %v", err)
	}
	if registrations != 0 {
		t.Fatalf("registration requests = %d, want 0", registrations)
	}
}

func TestEnsurePersistsRegistrationBeforeIssuance(t *testing.T) {
	t.Parallel()
	registrations := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/register/192.168.1.50" {
			return jsonResponse(http.StatusNotFound, `{"error":"not_found"}`), nil
		}
		registrations++
		return jsonResponse(http.StatusCreated, `{"hostname":"quiet-otter.lancert.dev","username":"12345678-1234-4234-9234-123456789abc","password":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN","subdomain":"quiet-otter","fulldomain":"_acme-challenge.quiet-otter.lancert.dev"}`), nil
	})}
	runner, err := New(Config{APIURL: "https://api.test", ConfigDir: filepath.Join(t.TempDir(), "state"), HTTPClient: httpClient, AcceptTerms: true})
	if err != nil {
		t.Fatal(err)
	}
	issuer := &failingIssuer{}
	runner.issuer = issuer
	for range 2 {
		if err := runner.Ensure(context.Background(), "192.168.1.50"); err == nil {
			t.Fatal("Ensure() unexpectedly succeeded")
		}
	}
	if registrations != 1 {
		t.Fatalf("registration requests = %d, want 1", registrations)
	}
	if issuer.calls != 2 {
		t.Fatalf("issuance attempts = %d, want 2", issuer.calls)
	}
}
