package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const knownHostsTestBase = "ssh_host: ssh.example.com\nssh_user: proxy\nssh_pass: secret\n"

func TestLoadFindsDefaultKnownHostsFile(t *testing.T) {
	sshDir := setTestHome(t)
	want := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(want, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	cfg, err := Load(writeTestConfig(t, knownHostsTestBase))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SSHKnownHostsFile != want {
		t.Errorf("SSHKnownHostsFile = %q, want %q", cfg.SSHKnownHostsFile, want)
	}
	if !strings.Contains(logs.String(), "Using default known_hosts file: "+want) {
		t.Errorf("logs = %q, want them to name %s", logs.String(), want)
	}
}

func TestLoadFindsDefaultKnownHostsFileWithoutCredentials(t *testing.T) {
	sshDir := setTestHome(t)
	writeTestClientKey(t, filepath.Join(sshDir, "id_ed25519"))
	want := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(want, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg, err := Load(writeTestConfig(t, "ssh_host: ssh.example.com\nssh_user: proxy\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SSHKnownHostsFile != want {
		t.Errorf("SSHKnownHostsFile = %q, want %q", cfg.SSHKnownHostsFile, want)
	}
	if len(cfg.SSHDefaultKeyFiles) != 1 {
		t.Errorf("SSHDefaultKeyFiles = %v, want one key", cfg.SSHDefaultKeyFiles)
	}
}

func TestLoadReportsCheckedPathWithoutDefaultKnownHostsFile(t *testing.T) {
	sshDir := setTestHome(t)
	for _, name := range []string{"known_hosts2", "known_hosts.old"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	_, err := Load(writeTestConfig(t, knownHostsTestBase))
	if err == nil || !strings.Contains(err.Error(), "set ssh_known_hosts_file or ssh_host_key_fingerprint") {
		t.Fatalf("Load() error = %v, want a missing verifier error", err)
	}
	if want := filepath.Join(sshDir, "known_hosts"); !strings.Contains(err.Error(), want) {
		t.Errorf("Load() error = %v, want it to name %s", err, want)
	}
}

func TestLoadRejectsMissingVerifierWithoutHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	_, err := Load(writeTestConfig(t, knownHostsTestBase))
	if err == nil || !strings.Contains(err.Error(), "set ssh_known_hosts_file or ssh_host_key_fingerprint") {
		t.Fatalf("Load() error = %v, want a missing verifier error", err)
	}
}

func TestLoadRejectsDefaultKnownHostsPathThatIsNotAFile(t *testing.T) {
	sshDir := setTestHome(t)
	if err := os.Mkdir(filepath.Join(sshDir, "known_hosts"), 0o700); err != nil {
		t.Fatalf("create directory: %v", err)
	}

	_, err := Load(writeTestConfig(t, knownHostsTestBase))
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("Load() error = %v, want a regular file error", err)
	}
}

func TestLoadSkipsDefaultKnownHostsFileWithFingerprint(t *testing.T) {
	sshDir := setTestHome(t)
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cfg, err := Load(writeTestConfig(t, clientKeyTestVerifier+"ssh_pass: secret\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SSHKnownHostsFile != "" {
		t.Errorf("SSHKnownHostsFile = %q, want none", cfg.SSHKnownHostsFile)
	}
}

func TestLoadDoesNotFallBackFromExplicitKnownHostsFile(t *testing.T) {
	sshDir := setTestHome(t)
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	missing := filepath.ToSlash(filepath.Join(t.TempDir(), "missing"))

	_, err := Load(writeTestConfig(t, knownHostsTestBase+"ssh_known_hosts_file: "+missing+"\n"))
	if err == nil || !strings.Contains(err.Error(), "ssh_known_hosts_file") {
		t.Fatalf("Load() error = %v, want an ssh_known_hosts_file error", err)
	}
}
