package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const clientKeyTestVerifier = "ssh_host: ssh.example.com\nssh_user: proxy\nssh_host_key_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"

func TestLoadFindsDefaultClientKeys(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestClientKey(t, filepath.Join(sshDir, "id_rsa"))
	writeTestClientKey(t, filepath.Join(sshDir, "id_ed25519"))
	writeTestClientKey(t, filepath.Join(sshDir, "id_dsa"))

	cfg, err := Load(writeTestConfig(t, clientKeyTestVerifier))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := []string{filepath.Join(sshDir, "id_ed25519"), filepath.Join(sshDir, "id_rsa")}
	if !slices.Equal(cfg.SSHDefaultKeyFiles, want) {
		t.Errorf("SSHDefaultKeyFiles = %v, want %v", cfg.SSHDefaultKeyFiles, want)
	}
}

func TestLoadSkipsUnusableDefaultClientKeys(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestEncryptedClientKey(t, filepath.Join(sshDir, "id_ed25519"))
	if err := os.Mkdir(filepath.Join(sshDir, "id_ecdsa"), 0o700); err != nil {
		t.Fatalf("create unreadable key path: %v", err)
	}
	writeTestClientKey(t, filepath.Join(sshDir, "id_rsa"))

	cfg, err := Load(writeTestConfig(t, clientKeyTestVerifier))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := []string{filepath.Join(sshDir, "id_rsa")}
	if !slices.Equal(cfg.SSHDefaultKeyFiles, want) {
		t.Errorf("SSHDefaultKeyFiles = %v, want %v", cfg.SSHDefaultKeyFiles, want)
	}
}

func TestLoadReportsCheckedPathsWithoutUsableClientKey(t *testing.T) {
	sshDir := setTestHome(t)
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}

	_, err := Load(writeTestConfig(t, clientKeyTestVerifier))
	if err == nil || !strings.Contains(err.Error(), "set ssh_pass or ssh_key_file") {
		t.Fatalf("Load() error = %v, want a missing authentication error", err)
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		if want := filepath.Join(sshDir, name); !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %v, want it to list %s", err, want)
		}
	}
}

func TestLoadRejectsMissingCredentialsWithoutHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	_, err := Load(writeTestConfig(t, clientKeyTestVerifier))
	if err == nil || !strings.Contains(err.Error(), "set ssh_pass or ssh_key_file") {
		t.Fatalf("Load() error = %v, want a missing authentication error", err)
	}
}

func TestLoadUsesDefaultClientKeysOnlyWithoutCredentials(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestClientKey(t, filepath.Join(sshDir, "id_ed25519"))
	explicitKey := filepath.Join(t.TempDir(), "explicit_key")
	writeTestClientKey(t, explicitKey)

	tests := []struct {
		name  string
		extra string
	}{
		{name: "password", extra: "ssh_pass: secret\n"},
		{name: "explicit key", extra: "ssh_key_file: " + filepath.ToSlash(explicitKey) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeTestConfig(t, clientKeyTestVerifier+tt.extra))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if len(cfg.SSHDefaultKeyFiles) != 0 {
				t.Errorf("SSHDefaultKeyFiles = %v, want none", cfg.SSHDefaultKeyFiles)
			}
		})
	}
}

func TestLoadDoesNotFallBackFromExplicitClientKey(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestClientKey(t, filepath.Join(sshDir, "id_ed25519"))
	missing := filepath.ToSlash(filepath.Join(t.TempDir(), "missing_key"))

	_, err := Load(writeTestConfig(t, clientKeyTestVerifier+"ssh_key_file: "+missing+"\n"))
	if err == nil || !strings.Contains(err.Error(), "ssh_key_file") {
		t.Fatalf("Load() error = %v, want an ssh_key_file error", err)
	}
}

func TestLoadRejectsDefaultClientKeysInFile(t *testing.T) {
	setTestHome(t)
	_, err := Load(writeTestConfig(t, clientKeyTestVerifier+"ssh_pass: secret\nsshdefaultkeyfiles: [/tmp/key]\n"))
	if err == nil || !strings.Contains(err.Error(), "decode config file") {
		t.Fatalf("Load() error = %v, want a decode error", err)
	}
}

func TestLoadExpandsHomeInSSHPaths(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestClientKey(t, filepath.Join(sshDir, "work_key"))
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg, err := Load(writeTestConfig(t, "ssh_host: ssh.example.com\nssh_user: proxy\nssh_key_file: ~/.ssh/work_key\nssh_known_hosts_file: ~/.ssh/known_hosts\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := filepath.Join(sshDir, "work_key"); cfg.SSHKeyFile != want {
		t.Errorf("SSHKeyFile = %q, want %q", cfg.SSHKeyFile, want)
	}
	if want := filepath.Join(sshDir, "known_hosts"); cfg.SSHKnownHostsFile != want {
		t.Errorf("SSHKnownHostsFile = %q, want %q", cfg.SSHKnownHostsFile, want)
	}
}

func TestLoadExpandsOnlyLeadingHomePrefix(t *testing.T) {
	setTestHome(t)
	_, err := Load(writeTestConfig(t, clientKeyTestVerifier+"ssh_key_file: ~other/key\n"))
	if err == nil || !strings.Contains(err.Error(), `"~other/key"`) {
		t.Fatalf("Load() error = %v, want the path left unexpanded", err)
	}
}

func setTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatalf("create SSH directory: %v", err)
	}
	return sshDir
}

func writeTestClientKey(t *testing.T, path string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
}

func writeTestEncryptedClientKey(t *testing.T, path string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte("passphrase"))
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
}
