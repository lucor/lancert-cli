// Package lancertapi implements the small Lancert registration and DNS update API.
package lancertapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const (
	maxResponseBytes     = 4096
	maxErrorBodyBytes    = 512
	compatibilityHeader  = "X-Lancert-API-Version"
	compatibilityVersion = "2"
)

// Registration is the standard acme-dns credential response plus the assigned hostname.
type Registration struct {
	Hostname   string `json:"hostname"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

// Client talks to one Lancert service instance.
type Client struct {
	base *url.URL
	http *http.Client
}

// New creates a client for baseURL.
func New(baseURL string, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("invalid Lancert API URL %q", baseURL)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	base.Path = strings.TrimSuffix(base.Path, "/")
	return &Client{base: base, http: httpClient}, nil
}

// Register creates credentials for targetIP. The server returns the password only once.
func (c *Client) Register(ctx context.Context, targetIP string) (Registration, error) {
	u := *c.base
	u.Path += "/register/" + url.PathEscape(targetIP)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return Registration{}, fmt.Errorf("create registration request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Registration{}, fmt.Errorf("register target: %w", err)
	}
	defer resp.Body.Close()
	if err := checkCompatibility(resp); err != nil {
		return Registration{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return Registration{}, responseError("register target", resp)
	}
	var registration Registration
	if err := decodeStrict(resp.Body, &registration); err != nil {
		return Registration{}, fmt.Errorf("decode registration response: %w", err)
	}
	if err := registration.Validate(); err != nil {
		return Registration{}, fmt.Errorf("invalid registration response: %w", err)
	}
	return registration, nil
}

// Update publishes one DNS-01 value using registration credentials.
func (c *Client) Update(ctx context.Context, registration Registration, txt string) error {
	payload, err := json.Marshal(struct {
		Subdomain string `json:"subdomain"`
		TXT       string `json:"txt"`
	}{registration.Subdomain, txt})
	if err != nil {
		return fmt.Errorf("encode DNS update: %w", err)
	}
	u := *c.base
	u.Path += "/update"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create DNS update request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", registration.Username)
	req.Header.Set("X-Api-Key", registration.Password)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("publish DNS challenge: %w", err)
	}
	defer resp.Body.Close()
	if err := checkCompatibility(resp); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return responseError("publish DNS challenge", resp)
	}
	var result struct {
		TXT string `json:"txt"`
	}
	if err := decodeStrict(resp.Body, &result); err != nil {
		return fmt.Errorf("decode DNS update response: %w", err)
	}
	if result.TXT != txt {
		return errors.New("DNS update response did not confirm the submitted value")
	}
	return nil
}

func checkCompatibility(response *http.Response) error {
	version := response.Header.Get(compatibilityHeader)
	if version != compatibilityVersion {
		if version == "" {
			version = "missing"
		}
		return fmt.Errorf("unsupported Lancert API version %s (need %s)", version, compatibilityVersion)
	}
	return nil
}

// Validate checks every server-controlled field before it reaches local paths or headers.
func (r Registration) Validate() error {
	if !validLabel(r.Subdomain) {
		return errors.New("invalid DNS subdomain")
	}
	if !validHostname(r.Hostname) || !strings.HasPrefix(r.Hostname, r.Subdomain+".") || r.FullDomain != "_acme-challenge."+r.Hostname {
		return errors.New("inconsistent hostname fields")
	}
	if !validUUIDv4(r.Username) {
		return errors.New("invalid API username")
	}
	if !base64URL(r.Password) {
		return errors.New("invalid API password")
	}
	return nil
}

func validHostname(value string) bool {
	if len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for i := range len(value) {
		character := value[i]
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	return true
}

func validUUIDv4(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed.Version() == uuid.Version(4) && parsed.Variant() == uuid.RFC4122
}

func base64URL(value string) bool {
	if value == "" {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func decodeStrict(reader io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("response is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("response contains trailing data")
	}
	return nil
}

func responseError(operation string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
	var result struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &result)
	if result.Error == "" {
		result.Error = http.StatusText(response.StatusCode)
	}
	if retryAfter := response.Header.Get("Retry-After"); retryAfter != "" {
		return fmt.Errorf("%s: %s (retry after %s)", operation, result.Error, retryAfter)
	}
	return fmt.Errorf("%s: %s", operation, result.Error)
}
