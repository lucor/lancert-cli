# Repository Agent Guide

This public repository owns the `lancert` local certificate client. The
`github.com/lucor/lancert` repository separately owns the public DNS/API
service and website.

Keep all public output in plain, idiomatic English. Never commit credentials,
private keys, certificates, private planning material, or persistent backlog
markers.

Run `mise run check` for routine validation and `mise run race` when changing
state, concurrency, HTTP, DNS, or ACME behavior. Run `mise run
release-snapshot` when changing build or release configuration.

The server must never receive certificate private keys or ACME account keys.
Persist a new registration response before starting ACME issuance because its
password cannot be recovered from the service.
