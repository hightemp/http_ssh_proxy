// Package config defines, loads, and validates the application configuration.
package config

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultProxyAddr = "127.0.0.1:8888"
	defaultSSHPort   = 22
	defaultProto     = "http"
)

// Config contains the proxy, TLS, and SSH settings.
type Config struct {
	ProxyAddr   string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Proto       string `yaml:"proto"`
	CertPath    string `yaml:"pem_path"`
	KeyPath     string `yaml:"key_path"`
	SSHHost     string `yaml:"ssh_host"`
	SSHPort     int    `yaml:"ssh_port"`
	SSHUser     string `yaml:"ssh_user"`
	SSHPassword string `yaml:"ssh_pass"`
	SSHKeyFile  string `yaml:"ssh_key_file"`

	SSHKnownHostsFile     string `yaml:"ssh_known_hosts_file"`
	SSHHostKeyFingerprint string `yaml:"ssh_host_key_fingerprint"`
}

// Default returns a configuration with conservative local-only defaults.
func Default() Config {
	return Config{
		ProxyAddr: defaultProxyAddr,
		Proto:     defaultProto,
		SSHPort:   defaultSSHPort,
	}
}

// Load reads one strict YAML document, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	cfg := Default()
	decoder := yaml.NewDecoder(file)
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

	if cfg.SSHHost == "" {
		validationErrors = append(validationErrors, errors.New("ssh_host is required"))
	} else if strings.ContainsAny(cfg.SSHHost, " \t\r\n/") {
		validationErrors = append(validationErrors, errors.New("ssh_host must be a hostname or IP address without whitespace or a path"))
	}
	if cfg.SSHPort < 1 || cfg.SSHPort > 65535 {
		validationErrors = append(validationErrors, fmt.Errorf("ssh_port must be between 1 and 65535, got %d", cfg.SSHPort))
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
	cfg.SSHHost = strings.TrimSpace(cfg.SSHHost)
	cfg.SSHUser = strings.TrimSpace(cfg.SSHUser)
	cfg.SSHKeyFile = strings.TrimSpace(cfg.SSHKeyFile)
	cfg.SSHKnownHostsFile = strings.TrimSpace(cfg.SSHKnownHostsFile)
	cfg.SSHHostKeyFingerprint = strings.TrimSpace(cfg.SSHHostKeyFingerprint)
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
