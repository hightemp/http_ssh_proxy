# http_ssh_proxy

[![Go Version](https://img.shields.io/github/go-mod/go-version/hightemp/http_ssh_proxy?logo=go)](https://github.com/hightemp/http_ssh_proxy/blob/main/go.mod)
[![CI](https://github.com/hightemp/http_ssh_proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/hightemp/http_ssh_proxy/actions/workflows/ci.yml)
[![golangci-lint](https://github.com/hightemp/http_ssh_proxy/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/hightemp/http_ssh_proxy/actions/workflows/golangci-lint.yml)
[![GitHub Downloads](https://img.shields.io/github/downloads/hightemp/http_ssh_proxy/total?logo=github&label=downloads)](https://github.com/hightemp/http_ssh_proxy/releases)
[![](https://asdertasd.site/counter/http_ssh_proxy)](https://asdertasd.site/counter/http_ssh_proxy)

This project is a simple HTTP proxy with SSH tunneling support. HTTP requests and HTTPS `CONNECT` tunnels are forwarded through an SSH connection.

## Features

- **HTTP and HTTPS Support**: Handles regular HTTP requests and tunnels HTTPS requests using the CONNECT method.
- **SSH Tunneling**: All requests are securely tunneled through an SSH connection.
- **TLS Configuration**: Supports serving over HTTPS with configurable PEM and key paths.
- **Graceful Shutdown**: Tracks HTTP requests and hijacked CONNECT tunnels, with bounded shutdown.
- **Resource Limits**: Bounds SSH-forwarded connections and expires idle CONNECT tunnels.

## Prerequisites

- Go 1.26.5 or later
- SSH server access
- TLS certificates (if you plan to serve over HTTPS)

## Setup

### Configuration

1. **Copy the example configuration file**:
    ```bash
    cp config.example.yaml config.yaml
    ```
   
2. **Edit `config.yaml`**: Update the SSH endpoint, authentication, and host-key verifier:

```yaml
# Safe defaults: 127.0.0.1:8888, HTTP, SSH port 22.
listen_addr: "127.0.0.1:8888"
username: ""                        # Set both username and password, or neither
password: ""
proto: "http"                       # http or https

max_connections: 128                # Total concurrent SSH-forwarded connections
tunnel_idle_timeout_seconds: 300     # Close inactive CONNECT tunnels
shutdown_timeout_seconds: 15         # Graceful shutdown deadline

ssh_host: "ssh.example.com"
ssh_port: 22
ssh_user: "proxy"
ssh_pass: ""                        # Set ssh_pass, ssh_key_file, or both
ssh_key_file: "/home/user/.ssh/id_ed25519"
ssh_reconnect_attempts: 3            # Context-aware reconnect attempts
ssh_known_hosts_file: "/home/user/.ssh/known_hosts" # Choose exactly one verifier
# ssh_host_key_fingerprint: "SHA256:..."             # Alternative verifier

# Required when proto is https:
# pem_path: "./server.pem"
# key_path: "./server.key"
```

Configure exactly one SSH host key verifier. `ssh_known_hosts_file` uses the
standard OpenSSH `known_hosts` format. Alternatively, pin the server public
key with `ssh_host_key_fingerprint`; obtain it through a trusted channel and
use the complete `SHA256:...` value.

The loader rejects unknown fields, extra YAML documents, invalid ports, missing
SSH authentication, unreadable key files, and invalid TLS certificate/key
pairs. A non-loopback `listen_addr` is accepted only with HTTPS and both proxy
credentials configured. This prevents accidentally exposing a plaintext open
proxy; firewall restrictions are still recommended.

Regular HTTP requests reuse one context-aware transport. Redirect responses are
returned to the client unchanged, hop-by-hop headers are removed in both
directions, and request cancellation interrupts SSH dialing. CONNECT tunnels
support TCP half-close, have an idle timeout, and are tracked until graceful
shutdown. `max_connections` limits the combined number of HTTP upstream
connections and CONNECT tunnels carried by SSH.

### Keys Generation

If you need to generate your own TLS keys, you can use the provided script:
```bash
./generate_keys.sh
```

### Running the Proxy

1. **Build the project**:
    ```bash
    go build -o http_ssh_proxy ./cmd/http_ssh_proxy
    ```

    Alternatively, install the latest tagged version:
    ```bash
    go install github.com/hightemp/http_ssh_proxy/cmd/http_ssh_proxy@latest
    ```

2. **Run the proxy**:
    ```bash
    ./http_ssh_proxy -config config.yaml
    ```

The proxy server should now be running and listening on the address specified in the `config.yaml` file.

To serve remote clients, set `proto: https`, configure a certificate and key,
set both `username` and `password`, and restrict access with a firewall.
Proxy Basic credentials are only encrypted between a remote client and this
proxy when `proto: https` is enabled; plaintext HTTP is intentionally restricted
to loopback addresses by configuration validation.

### Tests and checks

Run race-enabled tests locally with:

```bash
make test
```

`make coverage` enforces at least 90% statement coverage, `make fuzz` exercises
the authentication and header parsers, and `make check` additionally verifies
the module graph and runs `govulncheck`. The same tests, coverage gate,
vulnerability scan, and module checks run for every pull request.

### Systemd installation

The installer builds the current source, installs the binary and unit, then restarts the service:

```bash
./install_service.sh
```

An existing `/etc/http_ssh_proxy/config.yaml` is preserved during upgrades.
The previous executable is retained as `/usr/local/bin/http_ssh_proxy.previous` for rollback.

## License

This project is open-source and available under the [MIT License](LICENSE).
