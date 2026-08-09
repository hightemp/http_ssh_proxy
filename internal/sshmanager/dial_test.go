package sshmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestDialSSHHandshakeHonorsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	})

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	cfg := config.Default()
	cfg.SSHHost = host
	cfg.SSHPort = port
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	cfg.SSHHostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = dialSSH(ctx, &cfg)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialSSH() error = %v, want context deadline exceeded", err)
	}

	select {
	case conn := <-accepted:
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close accepted connection: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH transport was not accepted")
	}
}

func TestDialSSHRejectsConfigurationKeyAndTransportFailures(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(*testing.T) config.Config
		wantErr string
	}{
		{
			name: "invalid host key verifier",
			cfg: func(*testing.T) config.Config {
				cfg := config.Default()
				return cfg
			},
			wantErr: "configure SSH host key verification",
		},
		{
			name: "missing private key",
			cfg: func(t *testing.T) config.Config {
				cfg := validDialConfig()
				cfg.SSHKeyFile = filepath.Join(t.TempDir(), "missing-key")
				return cfg
			},
			wantErr: "read SSH key file",
		},
		{
			name: "invalid private key",
			cfg: func(t *testing.T) config.Config {
				cfg := validDialConfig()
				cfg.SSHKeyFile = filepath.Join(t.TempDir(), "invalid-key")
				if err := os.WriteFile(cfg.SSHKeyFile, []byte("not a private key"), 0o600); err != nil {
					t.Fatalf("write invalid key: %v", err)
				}
				return cfg
			},
			wantErr: "parse SSH private key",
		},
		{
			name: "transport unavailable",
			cfg: func(*testing.T) config.Config {
				cfg := validDialConfig()
				cfg.SSHHost = "127.0.0.1"
				cfg.SSHPort = 0
				return cfg
			},
			wantErr: "dial SSH transport",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg(t)
			client, err := dialSSH(context.Background(), &cfg)
			if client != nil {
				_ = client.Close()
				t.Fatal("dialSSH() returned a client, want failure")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("dialSSH() error = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCloseAfterErrorJoinsCloseFailure(t *testing.T) {
	operationErr := errors.New("operation failed")
	closeErr := errors.New("close failed")
	err := closeAfterError(errorCloser{err: closeErr}, operationErr)
	if !errors.Is(err, operationErr) || !errors.Is(err, closeErr) {
		t.Fatalf("closeAfterError() = %v, want both errors", err)
	}
}

type errorCloser struct {
	err error
}

func (c errorCloser) Close() error {
	return c.err
}

func validDialConfig() config.Config {
	cfg := config.Default()
	cfg.SSHHost = "ssh.example.com"
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	cfg.SSHHostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return cfg
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
