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
			name:    "missing SSH host",
			change:  func(cfg *Config) { cfg.SSHHost = "" },
			wantErr: "ssh_host is required",
		},
		{
			name:    "invalid SSH port",
			change:  func(cfg *Config) { cfg.SSHPort = 65536 },
			wantErr: "ssh_port must be between 1 and 65535",
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
			name: "missing known_hosts file",
			change: func(cfg *Config) {
				cfg.SSHHostKeyFingerprint = ""
				cfg.SSHKnownHostsFile = "/missing/known_hosts"
			},
			wantErr: "ssh_known_hosts_file",
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

func validTestConfig() Config {
	return Config{
		ProxyAddr:             "127.0.0.1:8888",
		Proto:                 "http",
		SSHHost:               "ssh.example.com",
		SSHPort:               22,
		SSHUser:               "proxy",
		SSHPassword:           "secret",
		SSHHostKeyFingerprint: testFingerprint,
		SSHKnownHostsFile:     "",
		SSHKeyFile:            "",
		CertPath:              "",
		KeyPath:               "",
		Username:              "",
		Password:              "",
	}
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
