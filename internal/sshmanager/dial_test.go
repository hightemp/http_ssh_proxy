package sshmanager

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestIsDestinationDialError(t *testing.T) {
	channelErr := &ssh.OpenChannelError{
		Reason:  ssh.ConnectionFailed,
		Message: "connection refused",
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "SSH channel rejection", err: channelErr, want: true},
		{name: "wrapped SSH channel rejection", err: fmt.Errorf("dial: %w", channelErr), want: true},
		{name: "SSH transport error", err: io.EOF, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDestinationDialError(tt.err); got != tt.want {
				t.Errorf("isDestinationDialError(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

func TestHostKeyCallbackFingerprint(t *testing.T) {
	hostKey := newTestHostKey(t)
	fingerprint := ssh.FingerprintSHA256(hostKey)

	callback, err := hostKeyCallback(&config.Config{SSHHostKeyFingerprint: fingerprint})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	if err := callback("ssh.example.com:22", nil, hostKey); err != nil {
		t.Errorf("callback() rejected matching key: %v", err)
	}

	otherKey := newTestHostKey(t)
	if err := callback("ssh.example.com:22", nil, otherKey); err == nil {
		t.Error("callback() accepted a key with a different fingerprint")
	}
}

func TestHostKeyCallbackKnownHosts(t *testing.T) {
	hostKey := newTestHostKey(t)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	contents := knownhosts.Line([]string{"ssh.example.com"}, hostKey) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	callback, err := hostKeyCallback(&config.Config{SSHKnownHostsFile: knownHostsPath})
	if err != nil {
		t.Fatalf("hostKeyCallback() error = %v", err)
	}

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback("ssh.example.com:22", remote, hostKey); err != nil {
		t.Errorf("callback() rejected known host key: %v", err)
	}

	if err := callback("ssh.example.com:22", remote, newTestHostKey(t)); err == nil {
		t.Error("callback() accepted an unknown host key")
	}
}

func TestHostKeyCallbackRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantErr string
	}{
		{
			name:    "no verifier",
			wantErr: "set ssh_known_hosts_file or ssh_host_key_fingerprint",
		},
		{
			name: "both verifiers",
			cfg: config.Config{
				SSHKnownHostsFile:     "known_hosts",
				SSHHostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "unsupported fingerprint",
			cfg:     config.Config{SSHHostKeyFingerprint: "MD5:00:11"},
			wantErr: "expected SHA256:<base64>",
		},
		{
			name:    "invalid SHA256 digest",
			cfg:     config.Config{SSHHostKeyFingerprint: "SHA256:not-base64!"},
			wantErr: "expected a 32-byte SHA-256 digest",
		},
		{
			name:    "missing known_hosts file",
			cfg:     config.Config{SSHKnownHostsFile: filepath.Join(t.TempDir(), "missing")},
			wantErr: "load known_hosts file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hostKeyCallback(&tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("hostKeyCallback() error = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	hostKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("convert host key: %v", err)
	}
	return hostKey
}
