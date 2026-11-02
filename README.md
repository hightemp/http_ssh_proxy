# http_ssh_proxy

[![Go Version](https://img.shields.io/github/go-mod/go-version/hightemp/http_ssh_proxy?logo=go)](https://github.com/hightemp/http_ssh_proxy/blob/main/go.mod)
[![CI](https://github.com/hightemp/http_ssh_proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/hightemp/http_ssh_proxy/actions/workflows/ci.yml)
[![golangci-lint](https://github.com/hightemp/http_ssh_proxy/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/hightemp/http_ssh_proxy/actions/workflows/golangci-lint.yml)
[![GitHub Downloads](https://img.shields.io/github/downloads/hightemp/http_ssh_proxy/total?logo=github&label=downloads)](https://github.com/hightemp/http_ssh_proxy/releases)
[![](https://asdertasd.site/counter/http_ssh_proxy)](https://asdertasd.site/counter/http_ssh_proxy)

`http_ssh_proxy` is an HTTP forward proxy whose outbound connections travel
through SSH. It forwards ordinary HTTP requests and HTTPS `CONNECT` tunnels
while preserving request semantics, cancellation, TCP half-close, and bounded
graceful shutdown.

## Features

- HTTP forwarding and HTTPS `CONNECT` tunneling over one managed SSH transport.
- Optional HTTP, HTTPS, or SOCKS5 upstream proxies reached through the SSH tunnel.
- Random or round-robin upstream selection for HTTP requests and CONNECT tunnels.
- OpenSSH `known_hosts` verification or an explicitly pinned SHA256 host-key fingerprint.
- Optional TLS and Basic proxy authentication for clients.
- Connection limits, CONNECT idle timeouts, bounded reconnects, and graceful shutdown.
- Strict YAML validation with safe loopback defaults.
- Race-tested critical paths with a 90% repository coverage gate.
- Cross-platform release archives, embedded version metadata, checksums, SPDX SBOM, and GitHub artifact attestations.

## Requirements

- Go 1.27.3 or later when building from source (or [mise](https://mise.jdx.dev/): `mise install`).
- An SSH server that permits TCP forwarding.
- A trusted SSH host key verifier and at least one SSH authentication method.
- A TLS certificate when exposing the proxy beyond the loopback interface.

## Configuration

Copy the example and edit it:

```bash
cp config.example.yaml config.yaml
```

```yaml
# Safe defaults: loopback-only HTTP listener and SSH port 22.
listen_addr: "127.0.0.1:8888"
username: ""                         # Set both fields or neither
password: ""
proto: "http"                        # http or https

max_connections: 128
tunnel_idle_timeout_seconds: 300
shutdown_timeout_seconds: 15

# Disabled by default. Set to true to route through one of the proxies below.
upstreams_enabled: false
upstream_strategy: "roundrobin"      # roundrobin or random
upstreams:
  - "http://user:password@proxy-a.example.com:3128"
  - "https://user:password@proxy-b.example.com:443"
  - "socks5://user:password@proxy-c.example.com:1080"

ssh_host: "ssh.example.com"
ssh_port: 22
ssh_user: "proxy"
ssh_pass: ""                         # Password, private key, or both
ssh_key_file: "~/.ssh/id_ed25519"    # With neither, default keys are searched
ssh_reconnect_attempts: 3

ssh_known_hosts_file: "~/.ssh/known_hosts" # Exactly one verifier
# ssh_host_key_fingerprint: "SHA256:..."             # Alternative verifier

# Required for proto: https
# pem_path: "./server.pem"
# key_path: "./server.key"
```

The loader rejects unknown fields, multiple YAML documents, invalid addresses
and ports, missing SSH authentication, unreadable key files, invalid TLS
certificate/key pairs, and ambiguous host-key verification. A non-loopback
listener is accepted only with HTTPS and both proxy credentials configured.

When `upstreams_enabled: true`, the connection chain is:

```text
client -> http_ssh_proxy -> SSH tunnel -> selected upstream proxy -> destination
```

Supported schemes are `http`, `https`, `socks`, `socks5`, and `socks5h`;
`socks` is an alias for SOCKS5. Default ports are 80, 443, and 1080
respectively. Credentials use URL userinfo and must be percent-encoded when
they contain URL-reserved characters. `roundrobin` rotates complete HTTP
requests and CONNECT tunnels; `random` chooses one upstream independently for
each. Per-upstream HTTP transports retain connection reuse without mixing
connections between proxies.

With `upstreams_enabled: false` (the default), the `upstreams` list is retained
in configuration but ignored, and destinations are reached directly through
the SSH connection. Enabling upstream routing requires at least one list entry.

HTTP requests use native forward-proxy absolute-form. CONNECT tunnels use an
HTTP CONNECT or SOCKS5 CONNECT handshake as appropriate. Hostnames sent through
SOCKS are resolved by the SOCKS proxy. HTTPS upstream certificates are verified
against the operating system trust store with TLS 1.2 or newer.

If neither `ssh_key_file` nor `ssh_pass` is set, the proxy searches for
`id_ed25519`, `id_ecdsa` and `id_rsa` in `~/.ssh` once at startup and offers every
usable key in that order. Passphrase-protected or unreadable keys are skipped with
a warning, and startup fails if none remains. A problem with an explicit
`ssh_key_file` is always fatal and never falls back to these keys. A leading `~/`
is expanded in `ssh_key_file` and `ssh_known_hosts_file`.

Obtain the SSH host key or fingerprint through a trusted channel. Do not accept
an unknown key from the same untrusted connection that the proxy will use.

The proxy requests the host key types recorded for `[host]:port` in
`known_hosts`, so one entry of any type is enough. As in OpenSSH, an entry
without a port applies only to port 22. With a fingerprint, the key type is
unknown, so the proxy tries ED25519, ECDSA and RSA in turn: a server may see up
to three short connections before authentication. A rejected host key is not
retried within `ssh_reconnect_attempts`.

### TLS certificate helper

Generate a development certificate without overwriting existing files:

```bash
./generate_keys.sh server.key server.pem localhost
```

`TLS_DAYS` changes its lifetime and `TLS_SAN` changes the SAN extension. To
deliberately replace both output files, set `FORCE=1`. Production deployments
should use a certificate issued for the actual proxy hostname.

## Build and run

```bash
make build
./http_ssh_proxy -config config.yaml
```

The Makefile embeds the version from `VERSION`, the current commit, and the UTC
build time. Inspect a binary or validate configuration without starting the
proxy:

```bash
./http_ssh_proxy -version
./http_ssh_proxy -config config.yaml -check-config
```

The canonical module path also supports installation of a tagged source version:

```bash
go install github.com/hightemp/http_ssh_proxy/cmd/http_ssh_proxy@latest
```

## Test and inspect a running proxy

Run the automated checks:

```bash
make test
make coverage
make check
make fuzz
```

`make check` verifies the module graph, runs `go vet`, enforces at least 90%
statement coverage, and runs `govulncheck`. CI performs the same module, test,
coverage, fuzz-smoke, and vulnerability checks for every pull request.

Test a running proxy against a target you control. The script reads the
listener, TLS CA, and credentials from the config; credentials are placed in a
temporary mode-0600 curl config instead of the process arguments:

```bash
./test.sh https://example.internal/health config.yaml
```

The script intentionally has no public default target and never disables TLS
verification.

## Systemd installation

After creating `config.yaml` next to the installer, run:

```bash
./install_service.sh
```

The installer builds a metadata-bearing binary, preserves an existing config,
enforces mode `0600`, validates the config as the service account, installs a
hardened unit, and verifies that the service becomes active. The previous
binary is saved as `/usr/local/bin/http_ssh_proxy.previous` and is restored
automatically if the upgraded service fails to start.

The unit has no Linux capabilities, restricts namespaces, writable filesystem
access, devices, kernel interfaces, address families, task count, and file
descriptors. It intentionally permits read-only home access so a configured SSH
key or `known_hosts` file can remain in the service user's home directory.

## Releases and verification

Tagged releases contain these native archives:

| System | Architectures |
| --- | --- |
| Linux | amd64, arm64, armv7 |
| macOS | amd64, arm64 |
| Windows | amd64, arm64 |

Before publication, GitHub-hosted Linux, macOS, and Windows runners build and
execute `-version` natively. The release also includes `checksums.txt` and an
SPDX JSON SBOM. After downloading an archive and the checksum file, verify it:

```bash
sha256sum --check checksums.txt --ignore-missing
gh attestation verify http_ssh_proxy_v0.2.0_linux_amd64.tar.gz \
  --repo hightemp/http_ssh_proxy
```

Both build provenance and the SBOM association are attested. Digest validation
still matters: attestations establish where an artifact came from, not whether
you intended to trust every dependency in it.

### Creating a release

Change only `VERSION` after committing the release contents, then run:

```bash
make release
```

The target validates and commits `VERSION`, refuses an existing local or remote
tag, creates an annotated tag, and atomically pushes the branch and tag without
force. Published tags are therefore immutable in the normal workflow.

If a release went wrong and preserving the same version is essential, first
commit the repair on `main`, make sure the worktree is clean and `VERSION` still
matches the affected tag, then use the explicit recovery path:

```bash
make rewrite-release-tag CONFIRM_REWRITE_TAG=v0.2.0
```

This command force-updates only that tag, protected by the exact remote tag
object observed immediately before the push (`--force-with-lease`). It never
force-pushes `main`. Rewriting a published tag invalidates previous checksums,
cached archives, and users' assumptions; prefer a new patch version whenever
possible.

## Security model and limitations

- This is an HTTP/HTTPS forward proxy, not a SOCKS proxy or a reverse proxy.
- Basic proxy credentials are protected in transit only when the client connects over TLS; plaintext HTTP is restricted to loopback by validation.
- With upstreams disabled, destination traffic exits from the SSH server. When enabled, the SSH server connects to the selected proxy and destination traffic exits there; both environments' routing and audit policies apply.
- Credentials sent to an `http` or SOCKS upstream are protected by SSH only up to the SSH server; use an HTTPS upstream or a trusted network between the SSH server and upstream proxy when credential confidentiality matters.
- All requests share one managed SSH client; limits prevent unbounded resource use, but one SSH endpoint remains a dependency and bottleneck.
- The project does not currently provide per-user authorization, rate limiting, metrics, or a dedicated health endpoint.
- Protect access to `config.yaml`, upstream credentials, SSH private keys, TLS private keys, logs, and the service account.

## License

This project is available under the [MIT License](LICENSE).
