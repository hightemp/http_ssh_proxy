# http_ssh_proxy

[![GitHub Downloads](https://img.shields.io/github/downloads/hightemp/http_ssh_proxy/total?logo=github&label=downloads)](https://github.com/hightemp/http_ssh_proxy/releases)
[![GitHub Repo Size](https://img.shields.io/github/repo-size/hightemp/http_ssh_proxy?logo=github)](https://github.com/hightemp/http_ssh_proxy)

[![](https://asdertasd.site/counter/http_ssh_proxy)](https://asdertasd.site/counter/http_ssh_proxy)

This project is a simple HTTP proxy with SSH tunneling support. HTTP requests and HTTPS `CONNECT` tunnels are forwarded through an SSH connection.

## Features

- **HTTP and HTTPS Support**: Handles regular HTTP requests and tunnels HTTPS requests using the CONNECT method.
- **SSH Tunneling**: All requests are securely tunneled through an SSH connection.
- **TLS Configuration**: Supports serving over HTTPS with configurable PEM and key paths.

## Prerequisites

- Go 1.22 or later
- SSH server access
- TLS certificates (if you plan to serve over HTTPS)

## Setup

### Configuration

1. **Copy the example configuration file**:
    ```bash
    cp config.example.yaml config.yaml
    ```
   
2. **Edit `config.yaml`**: Update the configuration file with your specific settings. Below are the required fields:

```yaml
listen_addr: "127.0.0.1:8888" # Keep the unauthenticated proxy local
ssh_host: "your_ssh_host"  # SSH host
ssh_port: 22               # SSH port
ssh_user: "username"       # SSH user
ssh_pass: "password"       # SSH password
ssh_key_file: "path/to/key" # SSH key file (optional if using password)
proto: "http"              # Protocol (http or https)
pem_path: "path/to/pem"    # Path to PEM file (only if proto is https)
key_path: "path/to/key"    # Path to Key file (only if proto is https)
```

### Keys Generation

If you need to generate your own TLS keys, you can use the provided script:
```bash
./generate_keys.sh
```

### Running the Proxy

1. **Build the project**:
    ```bash
    go build -o http_ssh_proxy
    ```

2. **Run the proxy**:
    ```bash
    ./http_ssh_proxy -config config.yaml
    ```

The proxy server should now be running and listening on the address specified in the `config.yaml` file.

Do not bind an unauthenticated proxy to `0.0.0.0`. If remote clients must use it, configure `username` and `password` and restrict access with a firewall.

### Systemd installation

The installer builds the current source, installs the binary and unit, then restarts the service:

```bash
./install_service.sh
```

An existing `/etc/http_ssh_proxy/config.yaml` is preserved during upgrades.
The previous executable is retained as `/usr/local/bin/http_ssh_proxy.previous` for rollback.

## License

This project is open-source and available under the MIT License.
