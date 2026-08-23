package lancertapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, body string) *http.Response {
	response := &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	response.Header.Set(compatibilityHeader, compatibilityVersion)
	return response
}

func TestRegisterAndUpdate(t *testing.T) {
	t.Parallel()
	const password = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	const username = "12345678-1234-4234-9234-123456789abc"
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("User-Agent") != "lancert-cli/test" {
			t.Fatalf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/register/192.168.1.50":
			return response(http.StatusCreated, `{"hostname":"quiet-otter.lancert.dev","username":"12345678-1234-4234-9234-123456789abc","password":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN","subdomain":"quiet-otter","fulldomain":"_acme-challenge.quiet-otter.lancert.dev"}`), nil
		case "/update":
			if r.Header.Get("X-Api-User") != username || r.Header.Get("X-Api-Key") != password {
				t.Fatal("missing credentials")
			}
			return response(http.StatusOK, `{"txt":"abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"}`), nil
		default:
			return response(http.StatusNotFound, `{"error":"not_found"}`), nil
		}
	})}

	client, err := New("https://api.test", httpClient, "lancert-cli/test")
	if err != nil {
		t.Fatal(err)
	}
	registration, err := client.Register(context.Background(), "192.168.1.50")
	if err != nil {
		t.Fatal(err)
	}
	const txt = "abcdefghijklmnopqrstuvwxyzABCDEFGH012345678"
	if err := client.Update(context.Background(), registration, txt); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusCreated, `{"hostname":"quiet-otter.lancert.dev","username":"12345678-1234-4234-9234-123456789abc","password":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN","subdomain":"quiet-otter","fulldomain":"_acme-challenge.quiet-otter.lancert.dev","extra":true}`), nil
	})}
	client, _ := New("https://api.test", httpClient, "lancert-cli/test")
	if _, err := client.Register(context.Background(), "192.168.1.50"); err == nil {
		t.Fatal("expected strict decoding error")
	}
}

func TestCredentialFieldValidationUsesProtocolParsers(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"AQ", "YWJjZA", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"} {
		if !base64URL(value) {
			t.Errorf("base64URL(%q) = false", value)
		}
	}
	for _, value := range []string{"", "abc=", "not base64"} {
		if base64URL(value) {
			t.Errorf("base64URL(%q) = true", value)
		}
	}
	if !validUUIDv4("12345678-1234-4234-9234-123456789abc") {
		t.Fatal("valid UUIDv4 rejected")
	}
	if validUUIDv4("12345678-1234-1234-9234-123456789abc") {
		t.Fatal("UUIDv1 accepted as UUIDv4")
	}
}

func TestRegistrationValidationAcceptsCustomZone(t *testing.T) {
	registration := Registration{
		Hostname: "quiet-otter.staging.example", Subdomain: "quiet-otter",
		FullDomain: "_acme-challenge.quiet-otter.staging.example",
		Username:   "12345678-1234-4234-9234-123456789abc",
		Password:   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
	}
	if err := registration.Validate(); err != nil {
		t.Fatal(err)
	}
}
