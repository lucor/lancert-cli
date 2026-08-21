// Package cli implements the Lancert command-line interface.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	urfavecli "github.com/urfave/cli/v3"

	"go.lucor.dev/lancert-cli/internal/acme"
	"go.lucor.dev/lancert-cli/internal/app"
	"go.lucor.dev/lancert-cli/internal/state"
)

// Version is set at build time via -ldflags. It falls back to "dev" locally.
var Version = "dev"

const (
	commandTimeout     = 10 * time.Minute
	defaultHTTPTimeout = 30 * time.Second
	dnsDialTimeout     = 5 * time.Second
)

// Run executes the CLI with the supplied process arguments and streams.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	configDir, err := state.DefaultDir()
	if err != nil {
		// Help and version must work even when the platform config directory is
		// not writable; the action reports the configuration error when needed.
		configDir = ""
	}
	return newCommand(configDir, stdin, stdout, stderr).Run(context.Background(), args)
}

func newCommand(configDir string, stdin io.Reader, stdout, stderr io.Writer) *urfavecli.Command {
	flags := []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "api-url", Value: app.DefaultAPIURL, Usage: "Lancert API base URL"},
		&urfavecli.StringFlag{Name: "acme-directory", Value: acme.LetsEncryptProduction, Usage: "ACME directory URL"},
		&urfavecli.StringFlag{Name: "email", Usage: "ACME account contact email"},
		&urfavecli.BoolFlag{Name: "accept-terms", Usage: "accept the selected CA terms of service"},
		&urfavecli.StringFlag{Name: "ca-cert", Usage: "additional CA certificate for a custom ACME directory"},
		&urfavecli.StringFlag{Name: "dns-server", Usage: "DNS server used to verify challenge propagation"},
		&urfavecli.StringFlag{Name: "config-dir", Value: configDir, Usage: "local state directory"},
	}
	return &urfavecli.Command{
		Name:      app.ProductName,
		Usage:     "obtain a browser-trusted TLS certificate from Lancert for a private IPv4 development target",
		Version:   Version,
		Writer:    stdout,
		ErrWriter: stderr,
		Flags:     flags,
		Commands: []*urfavecli.Command{
			{Name: "version", Usage: "print the CLI version", Action: func(context.Context, *urfavecli.Command) error {
				fmt.Fprintln(stdout, Version)
				return nil
			}},
			{Name: "renew", Usage: "renew locally managed certificates", Action: func(ctx context.Context, cmd *urfavecli.Command) error {
				return executeRenew(ctx, cmd, stdout)
			}},
		},
		Action: func(ctx context.Context, cmd *urfavecli.Command) error {
			if cmd.NArg() != 1 {
				return urfavecli.Exit("expected one private IPv4 address", 2)
			}
			return executeEnsure(ctx, cmd, cmd.Args().First(), stdin, stdout)
		},
	}
}

func executeEnsure(ctx context.Context, cmd *urfavecli.Command, targetIP string, stdin io.Reader, stdout io.Writer) error {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	runner, err := newRunner(cmd, stdout)
	if err != nil {
		return err
	}
	err = runner.Ensure(commandCtx, targetIP)
	if !errors.Is(err, app.ErrTermsRequired) || cmd.Bool("accept-terms") {
		return err
	}
	accepted, promptErr := confirmTerms(stdin, stdout)
	if promptErr != nil {
		return promptErr
	}
	if !accepted {
		return errors.New("certificate authority terms were not accepted")
	}
	runner, err = newRunnerWithTerms(cmd, stdout)
	if err != nil {
		return err
	}
	return runner.Ensure(commandCtx, targetIP)
}

func executeRenew(ctx context.Context, cmd *urfavecli.Command, stdout io.Writer) error {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	runner, err := newRunner(cmd, stdout)
	if err != nil {
		return err
	}
	return runner.Renew(commandCtx)
}

func newRunner(cmd *urfavecli.Command, stdout io.Writer) (*app.Runner, error) {
	return newRunnerConfig(cmd, stdout, cmd.Bool("accept-terms"))
}

func newRunnerWithTerms(cmd *urfavecli.Command, stdout io.Writer) (*app.Runner, error) {
	return newRunnerConfig(cmd, stdout, true)
}

func newRunnerConfig(cmd *urfavecli.Command, stdout io.Writer, acceptTerms bool) (*app.Runner, error) {
	acmeHTTPClient, err := acmeClient(cmd.String("ca-cert"))
	if err != nil {
		return nil, err
	}
	resolver, err := dnsResolver(cmd.String("dns-server"))
	if err != nil {
		return nil, err
	}
	configDir := cmd.String("config-dir")
	if configDir == "" {
		configDir, err = state.DefaultDir()
		if err != nil {
			return nil, err
		}
	}
	return app.New(app.Config{
		APIURL: cmd.String("api-url"), ACMEDirectory: cmd.String("acme-directory"), Email: cmd.String("email"),
		ConfigDir: configDir, AcceptTerms: acceptTerms,
		HTTPClient: &http.Client{Timeout: defaultHTTPTimeout}, ACMEHTTPClient: acmeHTTPClient,
		Resolver: resolver, Output: stdout,
	})
}

func acmeClient(certificatePath string) (*http.Client, error) {
	if certificatePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("CA certificate contains no valid certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: defaultHTTPTimeout}, nil
}

func dnsResolver(address string) (*net.Resolver, error) {
	if address == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("invalid DNS server: %w", err)
	}
	dialer := &net.Dialer{Timeout: dnsDialTimeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", address)
		},
	}, nil
}

func confirmTerms(input io.Reader, output io.Writer) (bool, error) {
	fmt.Fprint(output, "Accept the selected certificate authority terms of service? [y/N] ")
	var answer string
	if _, err := fmt.Fscanln(input, &answer); err != nil {
		return false, errors.New("terms were not accepted; rerun with --accept-terms for non-interactive use")
	}
	if answer != "y" && answer != "Y" && answer != "yes" && answer != "YES" {
		return false, errors.New("certificate authority terms were not accepted")
	}
	return true, nil
}
