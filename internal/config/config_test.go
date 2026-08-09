package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestLoadAppliesSafeDefaults(t *testing.T) {
	path := writeTestConfig(t, `
ssh_host: ssh.example.com
ssh_user: proxy
ssh_pass: secret
ssh_host_key_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ProxyAddr != "127.0.0.1:8888" {
		t.Errorf("ProxyAddr = %q, want local-only default", cfg.ProxyAddr)
	}
	if cfg.Proto != "http" {
		t.Errorf("Proto = %q, want http", cfg.Proto)
	}
	if cfg.SSHPort != 22 {
		t.Errorf("SSHPort = %d, want 22", cfg.SSHPort)
	}
	if cfg.MaxConnections != 128 {
		t.Errorf("MaxConnections = %d, want 128", cfg.MaxConnections)
	}
	if cfg.TunnelIdleTimeoutSeconds != 300 {
		t.Errorf("TunnelIdleTimeoutSeconds = %d, want 300", cfg.TunnelIdleTimeoutSeconds)
	}
	if cfg.ShutdownTimeoutSeconds != 15 {
		t.Errorf("ShutdownTimeoutSeconds = %d, want 15", cfg.ShutdownTimeoutSeconds)
	}
	if cfg.SSHReconnectAttempts != 3 {
		t.Errorf("SSHReconnectAttempts = %d, want 3", cfg.SSHReconnectAttempts)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeTestConfig(t, `
ssh_host: ssh.example.com
ssh_user: proxy
ssh_pass: secret
ssh_host_key_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
unknown_field: true
`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("Load() error = %v, want unknown field error", err)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	path := writeTestConfig(t, `
ssh_host: ssh.example.com
ssh_user: proxy
ssh_pass: secret
ssh_host_key_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
---
ssh_host: other.example.com
`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("Load() error = %v, want multiple document error", err)
	}
}

func TestLoadReportsFileTrailingAndValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		path    func(*testing.T) string
		wantErr string
	}{
		{
			name: "missing file",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.yaml")
			},
			wantErr: "read config file",
		},
		{
			name: "malformed trailing document",
			path: func(t *testing.T) string {
				return writeTestConfig(t, `
ssh_host: ssh.example.com
ssh_user: proxy
ssh_pass: secret
ssh_host_key_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
---
[
`)
			},
			wantErr: "decode trailing data",
		},
		{
			name: "validation failure",
			path: func(t *testing.T) string {
				return writeTestConfig(t, "ssh_host: ssh.example.com\n")
			},
			wantErr: "validate config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.path(t))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAcceptsSafeLoopbackConfiguration(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsUnsafeOrIncompleteConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*Config)
		wantErr string
	}{
		{
			name:    "invalid listen address",
			change:  func(cfg *Config) { cfg.ProxyAddr = "127.0.0.1" },
			wantErr: "host:port form",
		},
		{
			name:    "invalid listen port",
			change:  func(cfg *Config) { cfg.ProxyAddr = "127.0.0.1:0" },
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "unsupported protocol",
			change:  func(cfg *Config) { cfg.Proto = "socks5" },
			wantErr: "proto must be",
		},
		{
			name:    "invalid connection limit",
			change:  func(cfg *Config) { cfg.MaxConnections = 0 },
			wantErr: "max_connections must be between 1 and 10000",
		},
		{
			name:    "invalid tunnel idle timeout",
			change:  func(cfg *Config) { cfg.TunnelIdleTimeoutSeconds = 0 },
			wantErr: "tunnel_idle_timeout_seconds must be between 1 and 86400",
		},
		{
			name:    "invalid shutdown timeout",
			change:  func(cfg *Config) { cfg.ShutdownTimeoutSeconds = 301 },
			wantErr: "shutdown_timeout_seconds must be between 1 and 300",
		},
		{
			name: "incomplete proxy credentials",
			change: func(cfg *Config) {
				cfg.Username = "proxy"
				cfg.Password = ""
			},
			wantErr: "username and password must either both be set",
		},
		{
			name:    "public plaintext listener",
			change:  func(cfg *Config) { cfg.ProxyAddr = "0.0.0.0:8888" },
			wantErr: "non-loopback listen_addr requires proto: https",
		},
		{
			name: "public listener without authentication",
			change: func(cfg *Config) {
				cfg.ProxyAddr = "0.0.0.0:8888"
				cfg.Proto = "https"
			},
			wantErr: "non-loopback listen_addr requires username and password",
		},
		{
			name:    "HTTPS without certificate",
			change:  func(cfg *Config) { cfg.Proto = "https" },
			wantErr: "pem_path and key_path are required",
		},
		{
			name: "incomplete TLS pair",
			change: func(cfg *Config) {
				cfg.Proto = "https"
				cfg.CertPath = "certificate.pem"
			},
			wantErr: "pem_path and key_path must both be set",
		},
		{
			name: "invalid TLS pair",
			change: func(cfg *Config) {
				dir := t.TempDir()
				cfg.Proto = "https"
				cfg.CertPath = filepath.Join(dir, "certificate.pem")
				cfg.KeyPath = filepath.Join(dir, "key.pem")
				if err := os.WriteFile(cfg.CertPath, []byte("invalid"), 0o600); err != nil {
					t.Fatalf("write certificate: %v", err)
				}
				if err := os.WriteFile(cfg.KeyPath, []byte("invalid"), 0o600); err != nil {
					t.Fatalf("write key: %v", err)
				}
			},
			wantErr: "load TLS certificate and key",
		},
		{
			name:    "missing SSH host",
			change:  func(cfg *Config) { cfg.SSHHost = "" },
			wantErr: "ssh_host is required",
		},
		{
			name:    "SSH host contains a path",
			change:  func(cfg *Config) { cfg.SSHHost = "ssh.example.com/path" },
			wantErr: "ssh_host must be a hostname or IP address",
		},
		{
			name:    "invalid SSH port",
			change:  func(cfg *Config) { cfg.SSHPort = 65536 },
			wantErr: "ssh_port must be between 1 and 65535",
		},
		{
			name:    "invalid reconnect attempts",
			change:  func(cfg *Config) { cfg.SSHReconnectAttempts = 0 },
			wantErr: "ssh_reconnect_attempts must be between 1 and 10",
		},
		{
			name:    "missing SSH user",
			change:  func(cfg *Config) { cfg.SSHUser = "" },
			wantErr: "ssh_user is required",
		},
		{
			name:    "missing SSH authentication",
			change:  func(cfg *Config) { cfg.SSHPassword = "" },
			wantErr: "set ssh_pass or ssh_key_file",
		},
		{
			name: "missing SSH key file",
			change: func(cfg *Config) {
				cfg.SSHPassword = ""
				cfg.SSHKeyFile = "/missing/id_ed25519"
			},
			wantErr: "ssh_key_file",
		},
		{
			name:    "missing host key verifier",
			change:  func(cfg *Config) { cfg.SSHHostKeyFingerprint = "" },
			wantErr: "set ssh_known_hosts_file or ssh_host_key_fingerprint",
		},
		{
			name: "multiple host key verifiers",
			change: func(cfg *Config) {
				cfg.SSHKnownHostsFile = "known_hosts"
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "invalid host key fingerprint",
			change:  func(cfg *Config) { cfg.SSHHostKeyFingerprint = "SHA256:invalid" },
			wantErr: "expected a 32-byte SHA-256 digest",
		},
		{
			name:    "unsupported host key fingerprint format",
			change:  func(cfg *Config) { cfg.SSHHostKeyFingerprint = "MD5:00:11" },
			wantErr: "expected SHA256:<base64>",
		},
		{
			name: "missing known_hosts file",
			change: func(cfg *Config) {
				cfg.SSHHostKeyFingerprint = ""
				cfg.SSHKnownHostsFile = "/missing/known_hosts"
			},
			wantErr: "ssh_known_hosts_file",
		},
		{
			name: "known_hosts is a directory",
			change: func(cfg *Config) {
				cfg.SSHHostKeyFingerprint = ""
				cfg.SSHKnownHostsFile = t.TempDir()
			},
			wantErr: "must be a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			tt.change(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAcceptsKnownHostsFile(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg := validTestConfig()
	cfg.SSHHostKeyFingerprint = ""
	cfg.SSHKnownHostsFile = knownHostsPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsLoopbackAddressForms(t *testing.T) {
	for _, address := range []string{"LOCALHOST:8888", "[::1]:8888"} {
		t.Run(address, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.ProxyAddr = address
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func validTestConfig() Config {
	cfg := Default()
	cfg.SSHHost = "ssh.example.com"
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	cfg.SSHHostKeyFingerprint = testFingerprint
	return cfg
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
