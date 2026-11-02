package sshmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestDialSSHKnownHostsRequestsRecordedKeyType(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, accepted := newHostKeyTestServer(t, signers.ed25519, signers.ecdsa, signers.rsa)

	tests := []struct {
		name string
		key  ssh.Signer
	}{
		{name: "ed25519", key: signers.ed25519},
		{name: "ecdsa", key: signers.ecdsa},
		{name: "rsa", key: signers.rsa},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepted.Store(0)
			cfg := dialConfigFor(t, sshServer)
			cfg.SSHKnownHostsFile = writeKnownHosts(t, knownhosts.Line([]string{sshServer.listener.Addr().String()}, tt.key.PublicKey()))

			client, err := dialSSH(context.Background(), &cfg)
			if err != nil {
				t.Fatalf("dialSSH() error = %v", err)
			}
			if err := client.Close(); err != nil {
				t.Errorf("close client: %v", err)
			}
			if got := accepted.Load(); got != 1 {
				t.Errorf("handshakes = %d, want 1", got)
			}
		})
	}
}

func TestDialSSHKnownHostsMatchesHashedEntry(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519, signers.ecdsa, signers.rsa)
	cfg := dialConfigFor(t, sshServer)
	hashed := knownhosts.HashHostname(knownhosts.Normalize(sshServer.listener.Addr().String()))
	cfg.SSHKnownHostsFile = writeKnownHosts(t, knownhosts.Line([]string{hashed}, signers.ed25519.PublicKey()))

	client, err := dialSSH(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("dialSSH() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("close client: %v", err)
	}
}

// Host certificates must stay preferred, otherwise a host that has both a
// certificate and a plain key could no longer be verified through its CA.
func TestDialSSHKnownHostsAcceptsCertificateAuthority(t *testing.T) {
	signers := newHostKeySigners(t)
	authority := newHostKeySigners(t).ed25519
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519, newHostCertSigner(t, signers.ed25519, authority, "127.0.0.1"))
	cfg := dialConfigFor(t, sshServer)
	entry := knownhosts.Line([]string{sshServer.listener.Addr().String()}, authority.PublicKey())
	cfg.SSHKnownHostsFile = writeKnownHosts(t, "@cert-authority "+entry)

	client, err := dialSSH(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("dialSSH() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("close client: %v", err)
	}
}

func TestDialSSHKnownHostsRejections(t *testing.T) {
	signers := newHostKeySigners(t)
	other := newHostKeySigners(t)
	sshServer, accepted := newHostKeyTestServer(t, signers.ed25519, signers.ecdsa)
	address := sshServer.listener.Addr().String()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split SSH address: %v", err)
	}

	tests := []struct {
		name    string
		entry   string
		wantErr string
	}{
		{
			name:    "changed key of the same type",
			entry:   knownhosts.Line([]string{address}, other.ed25519.PublicKey()),
			wantErr: "key mismatch",
		},
		{
			name:    "entry without a port does not apply",
			entry:   knownhosts.Line([]string{host}, signers.ed25519.PublicKey()),
			wantErr: "key is unknown",
		},
		{
			name:    "host missing from the file",
			entry:   knownhosts.Line([]string{"ssh.example.com"}, signers.ed25519.PublicKey()),
			wantErr: "key is unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepted.Store(0)
			cfg := dialConfigFor(t, sshServer)
			cfg.SSHKnownHostsFile = writeKnownHosts(t, tt.entry)

			client, err := dialSSH(context.Background(), &cfg)
			if client != nil {
				_ = client.Close()
				t.Fatal("dialSSH() returned a client, want a host key rejection")
			}
			assertHostKeyRejection(t, err, tt.wantErr)
			if want := knownhosts.Normalize(address); !strings.Contains(err.Error(), want) {
				t.Errorf("dialSSH() error = %v, want it to name %s", err, want)
			}
			if got := accepted.Load(); got != 1 {
				t.Errorf("handshakes = %d, want 1", got)
			}
		})
	}
}

func TestDialSSHFingerprintProbesKeyTypes(t *testing.T) {
	signers := newHostKeySigners(t)
	all := []ssh.Signer{signers.ed25519, signers.ecdsa, signers.rsa}

	tests := []struct {
		name           string
		serverKeys     []ssh.Signer
		pinned         ssh.Signer
		wantHandshakes int32
	}{
		{name: "ed25519 needs no probing", serverKeys: all, pinned: signers.ed25519, wantHandshakes: 1},
		{name: "ecdsa is second", serverKeys: all, pinned: signers.ecdsa, wantHandshakes: 2},
		{name: "rsa is last", serverKeys: all, pinned: signers.rsa, wantHandshakes: 3},
		{name: "server without ed25519", serverKeys: []ssh.Signer{signers.ecdsa}, pinned: signers.ecdsa, wantHandshakes: 2},
		{name: "server with rsa only", serverKeys: []ssh.Signer{signers.rsa}, pinned: signers.rsa, wantHandshakes: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshServer, accepted := newHostKeyTestServer(t, tt.serverKeys...)
			cfg := dialConfigFor(t, sshServer)
			cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(tt.pinned.PublicKey())

			client, err := dialSSH(context.Background(), &cfg)
			if err != nil {
				t.Fatalf("dialSSH() error = %v", err)
			}
			if err := client.Close(); err != nil {
				t.Errorf("close client: %v", err)
			}
			if got := accepted.Load(); got != tt.wantHandshakes {
				t.Errorf("handshakes = %d, want %d", got, tt.wantHandshakes)
			}
		})
	}
}

func TestDialSSHFingerprintReportsEveryPresentedKey(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, accepted := newHostKeyTestServer(t, signers.ed25519, signers.ecdsa, signers.rsa)
	cfg := dialConfigFor(t, sshServer)
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(newHostKeySigners(t).ed25519.PublicKey())

	client, err := dialSSH(context.Background(), &cfg)
	if client != nil {
		_ = client.Close()
		t.Fatal("dialSSH() returned a client, want a host key rejection")
	}
	assertHostKeyRejection(t, err, cfg.SSHHostKeyFingerprint)
	for _, key := range []ssh.Signer{signers.ed25519, signers.ecdsa, signers.rsa} {
		if want := ssh.FingerprintSHA256(key.PublicKey()); !strings.Contains(err.Error(), want) {
			t.Errorf("dialSSH() error = %v, want it to report %s", err, want)
		}
	}
	if got := accepted.Load(); got != 3 {
		t.Errorf("handshakes = %d, want 3", got)
	}
}

func TestDialSSHFingerprintRejectsServerWithoutSupportedKeyType(t *testing.T) {
	signers := newHostKeySigners(t)
	certOnly := newHostCertSigner(t, signers.ed25519, newHostKeySigners(t).ed25519, "127.0.0.1")
	sshServer, accepted := newHostKeyTestServer(t, certOnly)
	cfg := dialConfigFor(t, sshServer)
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(signers.ed25519.PublicKey())

	client, err := dialSSH(context.Background(), &cfg)
	if client != nil {
		_ = client.Close()
		t.Fatal("dialSSH() returned a client, want a host key rejection")
	}
	assertHostKeyRejection(t, err, "no supported host key type")
	if got := accepted.Load(); got != 3 {
		t.Errorf("handshakes = %d, want 3", got)
	}
}

func TestDialSSHFingerprintStopsProbingOnTransportFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})

	cfg := validDialConfig()
	setDialAddress(t, &cfg, listener.Addr())

	client, err := dialSSH(context.Background(), &cfg)
	if client != nil {
		_ = client.Close()
		t.Fatal("dialSSH() returned a client, want a transport failure")
	}
	if err == nil || errors.Is(err, errHostKeyVerification) {
		t.Fatalf("dialSSH() error = %v, want a transport failure", err)
	}
	if got := accepted.Load(); got != 1 {
		t.Errorf("handshakes = %d, want 1", got)
	}
}

func TestConnectDoesNotRetryHostKeyRejection(t *testing.T) {
	var calls atomic.Int32
	cfg := testManagerConfig(1)
	cfg.SSHReconnectAttempts = 3
	manager := newManager(cfg, func(context.Context) (sshClient, error) {
		calls.Add(1)
		return nil, fmt.Errorf("SSH handshake: %w", errHostKeyVerification)
	})
	manager.backoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})

	err := manager.Connect(context.Background())
	if !errors.Is(err, errHostKeyVerification) {
		t.Fatalf("Connect() error = %v, want a host key rejection", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("connect attempts = %d, want 1", got)
	}
}

func assertHostKeyRejection(t *testing.T, err error, wantErr string) {
	t.Helper()
	if !errors.Is(err, errHostKeyVerification) {
		t.Fatalf("dialSSH() error = %v, want a host key rejection", err)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("dialSSH() error = %v, want it to contain %q", err, wantErr)
	}
	if strings.Contains(err.Error(), "close after failure") {
		t.Errorf("dialSSH() error = %v, want no teardown noise", err)
	}
}

type hostKeySigners struct {
	ed25519 ssh.Signer
	ecdsa   ssh.Signer
	rsa     ssh.Signer
}

func newHostKeySigners(t *testing.T) hostKeySigners {
	t.Helper()
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	var signers hostKeySigners
	for target, key := range map[*ssh.Signer]any{
		&signers.ed25519: ed25519Key,
		&signers.ecdsa:   ecdsaKey,
		&signers.rsa:     rsaKey,
	} {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatalf("create host signer: %v", err)
		}
		*target = signer
	}
	return signers
}

func newHostCertSigner(t *testing.T, hostKey, authority ssh.Signer, principal string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             hostKey.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatalf("sign host certificate: %v", err)
	}
	signer, err := ssh.NewCertSigner(cert, hostKey)
	if err != nil {
		t.Fatalf("create certificate signer: %v", err)
	}
	return signer
}

// newHostKeyTestServer starts an SSH server offering the given host keys and
// counts the connections it accepts.
func newHostKeyTestServer(t *testing.T, hostKeys ...ssh.Signer) (*testSSHServer, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH: %v", err)
	}
	accepted := &atomic.Int32{}
	server := &testSSHServer{
		listener: countingListener{Listener: listener, accepted: accepted},
		hostKey:  hostKeys[0],
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	for _, hostKey := range hostKeys {
		serverConfig.AddHostKey(hostKey)
	}
	go server.serve(serverConfig)
	t.Cleanup(server.close)
	return server, accepted
}

type countingListener struct {
	net.Listener
	accepted *atomic.Int32
}

func (l countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

func dialConfigFor(t *testing.T, server *testSSHServer) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	setDialAddress(t, &cfg, server.listener.Addr())
	return cfg
}

func setDialAddress(t *testing.T, cfg *config.Config, addr net.Addr) {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split SSH address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse SSH port: %v", err)
	}
	cfg.SSHHost = host
	cfg.SSHPort = port
}

func writeKnownHosts(t *testing.T, entry string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(entry+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}
