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
- OpenSSH `known_hosts` verification or an explicitly pinned SHA256 host-key fingerprint, with an interactive `-trust-host-key` command and optional accept-new recording of unknown hosts.
- Optional TLS and Basic proxy authentication for clients.
- Connection limits, CONNECT idle timeouts, bounded reconnects, and graceful shutdown.
- Strict YAML validation with safe loopback defaults.
- Race-tested critical paths with a 90% repository coverage gate.
- Cross-platform release archives, embedded version metadata, checksums, SPDX SBOM, and GitHub artifact attestations.

## Requirements

- Go 1.26.11 or later when building from source.
- An SSH server that permits TCP forwarding.
- A trusted SSH host key verifier and at least one SSH authentication method.
- A TLS certificate when using `proto: https`.

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
# stealth_enabled: false             # Look like a web server to strangers
# stealth_server_header: "nginx"
# stealth_auth_host: "login.example" # Secret host that still returns 407

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
ssh_key_file: "/home/user/.ssh/id_ed25519"
ssh_reconnect_attempts: 3

ssh_known_hosts_file: "/home/user/.ssh/known_hosts" # Exactly one verifier
# ssh_host_key_fingerprint: "SHA256:..."             # Alternative verifier
# ssh_known_hosts_accept_new: false                  # Record unknown hosts automatically

# Required for proto: https
# pem_path: "./server.pem"
# key_path: "./server.key"
```

The loader rejects unknown fields, multiple YAML documents, invalid addresses
and ports, missing SSH authentication, unreadable key files, invalid TLS
certificate/key pairs, and ambiguous host-key verification. Proxy credentials
are optional on any listener; when `listen_addr` is reachable from other hosts,
set `username` and `password` (preferably with `proto: https`) or restrict
access with a firewall, otherwise anyone who can reach the port can use the
proxy.

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

Obtain the SSH host key or fingerprint through a trusted channel. Do not accept
an unknown key from the same untrusted connection that the proxy will use.

A host key verification failure is permanent: the proxy reports the host, the
`known_hosts` file, and the SHA256 fingerprints involved, then stops without
retrying. Entries are matched against `ssh_host` exactly (`[host]:port` for
non-default ports), so after changing `ssh_host` the new server must be added.

To review and add the key of the configured server, run:

```bash
http_ssh_proxy -config /etc/http_ssh_proxy/config.yaml -trust-host-key
```

The command connects, stops the handshake before authentication, prints the
presented key type and SHA256 fingerprint, and appends the key to
`ssh_known_hosts_file` after you confirm (`-yes` skips the prompt). The file is
created with mode `0600` if it does not exist. A key that conflicts with an
existing entry is refused; remove the old entry with `ssh-keygen -R` first when
the change is expected.

Alternatively, `ssh_known_hosts_accept_new: true` records the key of a host
that has no entry yet on the first connection and logs a warning, like OpenSSH
`StrictHostKeyChecking=accept-new`. A changed or revoked key is still rejected.
This trusts whatever server answers the first connection, so use it only on a
network you trust for that moment. The systemd unit mounts home directories
read-only; to let the service record keys there, add a drop-in such as
`ReadWritePaths=/home/user/.ssh/http_ssh_proxy_known_hosts` (the file must
exist), or run `-trust-host-key` manually instead.

With `ssh_known_hosts_file`, only the key types listed for the host are offered
during key exchange, so listing just one of the server's key types is enough. A
pinned `ssh_host_key_fingerprint` must belong to the key type the server
negotiates; the mismatch error names that type.

### Stealth mode

`stealth_enabled: true` makes the listener look like an ordinary web server to
anyone who does not use it as an authenticated proxy:

- Direct requests (`GET /`), proxy requests without credentials or with wrong
  ones, and such CONNECT requests receive a `404 Not Found` HTML page with the
  `stealth_server_header` (`nginx` by default; empty omits it) instead of
  `407` or `400`.
- Error responses (400, 500, 502, 503) use the same page style and never
  mention the proxy, and a successful CONNECT answers `200 OK`.
- Credentials are always evaluated, so response timing does not reveal whether
  a password was missing or wrong.

Without the `407` challenge, clients must send `Proxy-Authorization`
preemptively. curl (`-x http://user:pass@host:port`) and most HTTP libraries do
so. Browsers only send proxy credentials after a challenge, so set
`stealth_auth_host` to a secret hostname (for example `login.example`; it
requires `username` and `password`) and open `http://login.example/` once
through the proxy: only requests to that host receive `407`, the browser asks
for credentials, and afterwards sends them with every request for the session.

Without proxy credentials, stealth mode only hides direct requests and error
details; proxy requests are still served to anyone who can reach the port.
Malformed HTTP that `net/http` rejects before reaching the handler still gets
the Go server's plain `400 Bad Request`.

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
- Stealth mode hides the proxy from casual scanners, not from an observer of the client traffic or from someone who knows the credentials or `stealth_auth_host`.
- Basic proxy credentials are protected in transit only when the client connects over TLS; a listener without credentials is an open proxy for everyone who can reach it.
- With upstreams disabled, destination traffic exits from the SSH server. When enabled, the SSH server connects to the selected proxy and destination traffic exits there; both environments' routing and audit policies apply.
- Credentials sent to an `http` or SOCKS upstream are protected by SSH only up to the SSH server; use an HTTPS upstream or a trusted network between the SSH server and upstream proxy when credential confidentiality matters.
- All requests share one managed SSH client; limits prevent unbounded resource use, but one SSH endpoint remains a dependency and bottleneck.
- The project does not currently provide per-user authorization, rate limiting, metrics, or a dedicated health endpoint.
- Protect access to `config.yaml`, upstream credentials, SSH private keys, TLS private keys, logs, and the service account.

## License

This project is available under the [MIT License](LICENSE).
