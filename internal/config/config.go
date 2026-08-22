// Package config defines, loads, and validates the application configuration.
package config

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultProxyAddr                = "127.0.0.1:8888"
	defaultSSHPort                  = 22
	defaultProto                    = "http"
	defaultUpstreamStrategy         = UpstreamStrategyRoundRobin
	defaultMaxConnections           = 128
	defaultTunnelIdleTimeoutSeconds = 300
	defaultShutdownTimeoutSeconds   = 15
	defaultSSHReconnectAttempts     = 3
	maxUpstreamProxies              = 100
)

const (
	// UpstreamStrategyRandom chooses a random upstream proxy for each request.
	UpstreamStrategyRandom = "random"
	// UpstreamStrategyRoundRobin rotates requests across upstream proxies.
	UpstreamStrategyRoundRobin = "roundrobin"
)

// Config contains the proxy, TLS, and SSH settings.
type Config struct {
	ProxyAddr string `yaml:"listen_addr"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	Proto     string `yaml:"proto"`
	CertPath  string `yaml:"pem_path"`
	KeyPath   string `yaml:"key_path"`

	MaxConnections           int      `yaml:"max_connections"`
	TunnelIdleTimeoutSeconds int      `yaml:"tunnel_idle_timeout_seconds"`
	ShutdownTimeoutSeconds   int      `yaml:"shutdown_timeout_seconds"`
	UpstreamsEnabled         bool     `yaml:"upstreams_enabled"`
	UpstreamStrategy         string   `yaml:"upstream_strategy"`
	Upstreams                []string `yaml:"upstreams"`

	SSHHost     string `yaml:"ssh_host"`
	SSHPort     int    `yaml:"ssh_port"`
	SSHUser     string `yaml:"ssh_user"`
	SSHPassword string `yaml:"ssh_pass"`
	SSHKeyFile  string `yaml:"ssh_key_file"`

	SSHKnownHostsFile     string `yaml:"ssh_known_hosts_file"`
	SSHHostKeyFingerprint string `yaml:"ssh_host_key_fingerprint"`
	SSHReconnectAttempts  int    `yaml:"ssh_reconnect_attempts"`
}

// Default returns a configuration with conservative local-only defaults.
func Default() Config {
	return Config{
		ProxyAddr:                defaultProxyAddr,
		Proto:                    defaultProto,
		UpstreamsEnabled:         false,
		UpstreamStrategy:         defaultUpstreamStrategy,
		MaxConnections:           defaultMaxConnections,
		TunnelIdleTimeoutSeconds: defaultTunnelIdleTimeoutSeconds,
		ShutdownTimeoutSeconds:   defaultShutdownTimeoutSeconds,
		SSHPort:                  defaultSSHPort,
		SSHReconnectAttempts:     defaultSSHReconnectAttempts,
	}
}

// Load reads one strict YAML document, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	cfg := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config file %q: %w", path, err)
	}

	var extraDocument any
	if err := decoder.Decode(&extraDocument); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode config file %q: multiple YAML documents are not allowed", path)
		}
		return nil, fmt.Errorf("decode trailing data in config file %q: %w", path, err)
	}

	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config file %q: %w", path, err)
	}

	return &cfg, nil
}

// Validate checks required fields, combinations, addresses, ports, and files.
func (cfg Config) Validate() error {
	var validationErrors []error

	listenHost, listenErr := validateListenAddress(cfg.ProxyAddr)
	if listenErr != nil {
		validationErrors = append(validationErrors, listenErr)
	}

	if cfg.Proto != "http" && cfg.Proto != "https" {
		validationErrors = append(validationErrors, fmt.Errorf("proto must be \"http\" or \"https\", got %q", cfg.Proto))
	}

	proxyUserSet := cfg.Username != ""
	proxyPasswordSet := cfg.Password != ""
	if proxyUserSet != proxyPasswordSet {
		validationErrors = append(validationErrors, errors.New("username and password must either both be set or both be empty"))
	}

	if listenErr == nil && !isLoopbackHost(listenHost) {
		if cfg.Proto != "https" {
			validationErrors = append(validationErrors, errors.New("a non-loopback listen_addr requires proto: https"))
		}
		if !proxyUserSet || !proxyPasswordSet {
			validationErrors = append(validationErrors, errors.New("a non-loopback listen_addr requires username and password"))
		}
	}

	if cfg.Proto == "https" {
		switch {
		case cfg.CertPath == "" && cfg.KeyPath == "":
			validationErrors = append(validationErrors, errors.New("pem_path and key_path are required when proto is https"))
		case cfg.CertPath == "" || cfg.KeyPath == "":
			validationErrors = append(validationErrors, errors.New("pem_path and key_path must both be set when proto is https"))
		default:
			if _, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath); err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("load TLS certificate and key: %w", err))
			}
		}
	}

	if cfg.MaxConnections < 1 || cfg.MaxConnections > 10000 {
		validationErrors = append(validationErrors, fmt.Errorf("max_connections must be between 1 and 10000, got %d", cfg.MaxConnections))
	}
	if cfg.TunnelIdleTimeoutSeconds < 1 || cfg.TunnelIdleTimeoutSeconds > 86400 {
		validationErrors = append(validationErrors, fmt.Errorf("tunnel_idle_timeout_seconds must be between 1 and 86400, got %d", cfg.TunnelIdleTimeoutSeconds))
	}
	if cfg.ShutdownTimeoutSeconds < 1 || cfg.ShutdownTimeoutSeconds > 300 {
		validationErrors = append(validationErrors, fmt.Errorf("shutdown_timeout_seconds must be between 1 and 300, got %d", cfg.ShutdownTimeoutSeconds))
	}
	if cfg.UpstreamStrategy != UpstreamStrategyRandom && cfg.UpstreamStrategy != UpstreamStrategyRoundRobin {
		validationErrors = append(validationErrors, fmt.Errorf(
			"upstream_strategy must be %q or %q, got %q",
			UpstreamStrategyRandom,
			UpstreamStrategyRoundRobin,
			cfg.UpstreamStrategy,
		))
	}
	if cfg.UpstreamsEnabled && len(cfg.Upstreams) == 0 {
		validationErrors = append(validationErrors, errors.New("upstreams must contain at least one entry when upstreams_enabled is true"))
	}
	if len(cfg.Upstreams) > maxUpstreamProxies {
		validationErrors = append(validationErrors, fmt.Errorf("upstreams must contain at most %d entries, got %d", maxUpstreamProxies, len(cfg.Upstreams)))
	} else {
		for index, upstream := range cfg.Upstreams {
			if err := validateUpstreamProxy(upstream, index); err != nil {
				validationErrors = append(validationErrors, err)
			}
		}
	}

	if cfg.SSHHost == "" {
		validationErrors = append(validationErrors, errors.New("ssh_host is required"))
	} else if strings.ContainsAny(cfg.SSHHost, " \t\r\n/") {
		validationErrors = append(validationErrors, errors.New("ssh_host must be a hostname or IP address without whitespace or a path"))
	}
	if cfg.SSHPort < 1 || cfg.SSHPort > 65535 {
		validationErrors = append(validationErrors, fmt.Errorf("ssh_port must be between 1 and 65535, got %d", cfg.SSHPort))
	}
	if cfg.SSHReconnectAttempts < 1 || cfg.SSHReconnectAttempts > 10 {
		validationErrors = append(validationErrors, fmt.Errorf("ssh_reconnect_attempts must be between 1 and 10, got %d", cfg.SSHReconnectAttempts))
	}
	if cfg.SSHUser == "" {
		validationErrors = append(validationErrors, errors.New("ssh_user is required"))
	}

	if cfg.SSHPassword == "" && cfg.SSHKeyFile == "" {
		validationErrors = append(validationErrors, errors.New("set ssh_pass or ssh_key_file for SSH authentication"))
	}
	if cfg.SSHKeyFile != "" {
		if err := validateRegularFile("ssh_key_file", cfg.SSHKeyFile); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}

	switch {
	case cfg.SSHKnownHostsFile == "" && cfg.SSHHostKeyFingerprint == "":
		validationErrors = append(validationErrors, errors.New("set ssh_known_hosts_file or ssh_host_key_fingerprint for SSH host key verification"))
	case cfg.SSHKnownHostsFile != "" && cfg.SSHHostKeyFingerprint != "":
		validationErrors = append(validationErrors, errors.New("ssh_known_hosts_file and ssh_host_key_fingerprint are mutually exclusive"))
	case cfg.SSHKnownHostsFile != "":
		if err := validateRegularFile("ssh_known_hosts_file", cfg.SSHKnownHostsFile); err != nil {
			validationErrors = append(validationErrors, err)
		}
	default:
		if err := ValidateSSHHostKeyFingerprint(cfg.SSHHostKeyFingerprint); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}

	return errors.Join(validationErrors...)
}

// ValidateSSHHostKeyFingerprint validates the SHA256 fingerprint format used by OpenSSH.
func ValidateSSHHostKeyFingerprint(fingerprint string) error {
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return fmt.Errorf("invalid ssh_host_key_fingerprint %q: expected SHA256:<base64>", fingerprint)
	}

	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, prefix))
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("invalid ssh_host_key_fingerprint %q: expected a 32-byte SHA-256 digest", fingerprint)
	}

	return nil
}

func (cfg *Config) normalize() {
	cfg.ProxyAddr = strings.TrimSpace(cfg.ProxyAddr)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Proto = strings.ToLower(strings.TrimSpace(cfg.Proto))
	cfg.CertPath = strings.TrimSpace(cfg.CertPath)
	cfg.KeyPath = strings.TrimSpace(cfg.KeyPath)
	cfg.UpstreamStrategy = strings.ToLower(strings.TrimSpace(cfg.UpstreamStrategy))
	for index := range cfg.Upstreams {
		cfg.Upstreams[index] = strings.TrimSpace(cfg.Upstreams[index])
	}
	cfg.SSHHost = strings.TrimSpace(cfg.SSHHost)
	cfg.SSHUser = strings.TrimSpace(cfg.SSHUser)
	cfg.SSHKeyFile = strings.TrimSpace(cfg.SSHKeyFile)
	cfg.SSHKnownHostsFile = strings.TrimSpace(cfg.SSHKnownHostsFile)
	cfg.SSHHostKeyFingerprint = strings.TrimSpace(cfg.SSHHostKeyFingerprint)
}

func validateUpstreamProxy(rawURL string, index int) error {
	field := fmt.Sprintf("upstreams[%d]", index)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s must be a valid proxy URL", field)
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "socks", "socks5", "socks5h":
	default:
		return fmt.Errorf("%s scheme must be http, https, socks, socks5, or socks5h", field)
	}
	if parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), " \t\r\n/") {
		return fmt.Errorf("%s must contain a valid proxy hostname", field)
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%s port must be between 1 and 65535", field)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("%s must not contain a path", field)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain a query or fragment", field)
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s port must be between 1 and 65535", field)
		}
	}
	if parsed.User != nil && parsed.User.Username() == "" {
		return fmt.Errorf("%s proxy username must not be empty", field)
	}
	if parsed.User != nil && (scheme == "socks" || scheme == "socks5" || scheme == "socks5h") {
		password, _ := parsed.User.Password()
		if len(parsed.User.Username()) > 255 || len(password) > 255 {
			return fmt.Errorf("%s SOCKS username and password must be at most 255 bytes", field)
		}
	}

	return nil
}

func validateListenAddress(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("listen_addr %q must be in host:port form: %w", address, err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("listen_addr port must be between 1 and 65535, got %q", portText)
	}
	return host, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateRegularFile(field, path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, path, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("%s %q must be a regular file", field, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s %q: %w", field, path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s %q: %w", field, path, err)
	}
	return nil
}
