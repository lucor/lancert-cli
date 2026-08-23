# Lancert CLI

Lancert gets a trusted HTTPS certificate for an app on your private network.
You do not need to own a domain, set up DNS, or install a local certificate authority.

Lancert uses the standard ACME DNS-01 challenge. The CLI keeps the ACME
account, registration credentials, certificate, and private key on your
machine. The Lancert service assigns the public hostname and publishes the
short-lived DNS challenge records needed by the certificate authority.

## Install

With Homebrew:

```console
brew install lucor/tap/lancert
```

Or install from source with Go:

```console
go install go.lucor.dev/lancert-cli/cmd/lancert@latest
```

## Get a certificate

```console
lancert 192.168.1.50
```

On the first request, the CLI asks you to accept the selected certificate
authority's terms. It then prints output similar to:

```text
Certificate issued.
Hostname: quiet-otter.lancert.dev
Certificate: /home/alice/.config/lancert/certs/quiet-otter.lancert.dev/fullchain.pem
Private key: /home/alice/.config/lancert/certs/quiet-otter.lancert.dev/privkey.pem
```

The certificate covers both `quiet-otter.lancert.dev` and
`*.quiet-otter.lancert.dev`. Repeating the same command reuses every valid
certificate; renewal is handled by `lancert renew`.

By default, the CLI uses Let's Encrypt. Its terms, policies, and rate limits
apply. Use `--acme-directory` to select another ACME-compatible certificate
authority.

The CLI accepts only private IPv4 addresses in `10.0.0.0/8`, `172.16.0.0/12`,
and `192.168.0.0/16`.

## Renew certificates

```console
lancert renew
```

When the certificate authority provides ACME Renewal Information (ARI), the
command chooses a stable time inside its suggested renewal window. If ARI is
unavailable, it renews certificates within 30 days of expiry. It is safe to
invoke regularly from cron, systemd, or launchd.

## Where Lancert stores data

Lancert stores its data in your standard configuration directory:

- Linux: `${XDG_CONFIG_HOME:-~/.config}/lancert`
- macOS: `~/Library/Application Support/lancert`
- Windows: `%AppData%\\lancert`

For example, on Linux:

```text
~/.config/lancert/
├── accounts/
│   ├── <acme-directory-hash>.pem
│   └── <acme-directory-hash>.terms
├── registrations/
│   └── 192.168.1.50.json
└── certs/
    └── quiet-otter.lancert.dev/
        ├── fullchain.pem
        ├── fullchain.pem.bak
        ├── privkey.pem
        └── privkey.pem.bak
```

`accounts` stores one ACME account key and terms record for each certificate
authority. `registrations` stores the Lancert credentials and renewal settings
for each target IP. The `.bak` files hold the certificate and key replaced by
the latest renewal.

## Advanced options

```console
lancert --email alice@example.com 192.168.1.50
lancert --accept-terms 192.168.1.50
lancert --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory 192.168.1.50
lancert --api-url https://lancert.dev 192.168.1.50
lancert --config-dir /absolute/path 192.168.1.50
```

Use `--accept-terms` for an explicitly configured non-interactive first run. A
registration remembers its Lancert API, ACME directory, and contact email so
renewal keeps using the same authority.

`--ca-cert` and `--dns-server` are available for local ACME interoperability
testing with an authority such as Pebble.

## Development

To work on the CLI, use [mise](https://mise.jdx.dev/):

```console
mise run check
mise run race
mise run build
mise run release-snapshot
```

## License

MIT. See [LICENSE](LICENSE).
