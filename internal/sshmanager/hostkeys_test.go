package sshmanager

import (
	"context"
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

func TestAcceptNewVerifierRecordsUnknownHosts(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	firstKey := newTestHostKey(t)
	cfg := &config.Config{SSHKnownHostsFile: knownHostsPath, SSHKnownHostsAcceptNew: true}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2222}

	verifier, err := newHostKeyVerifier(cfg)
	if err != nil {
		t.Fatalf("newHostKeyVerifier() error = %v", err)
	}
	if err := verifier.callback("ssh.example.com:2222", remote, firstKey); err != nil {
		t.Fatalf("callback() rejected a new host with accept-new: %v", err)
	}
	// The same verifier snapshot must not append a duplicate line.
	if err := verifier.callback("ssh.example.com:2222", remote, firstKey); err != nil {
		t.Fatalf("callback() rejected the recorded host key: %v", err)
	}

	info, err := os.Stat(knownHostsPath)
	if err != nil {
		t.Fatalf("stat known_hosts: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("known_hosts permissions = %o, want 600", perm)
	}
	contents := readFile(t, knownHostsPath)
	wantLine := knownhosts.Line([]string{"[ssh.example.com]:2222"}, firstKey) + "\n"
	if contents != wantLine {
		t.Errorf("known_hosts = %q, want exactly %q", contents, wantLine)
	}

	reloaded, err := newHostKeyVerifier(cfg)
	if err != nil {
		t.Fatalf("newHostKeyVerifier() after recording error = %v", err)
	}
	if got := reloaded.algorithms("ssh.example.com:2222", remote); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("algorithms() = %v, want only the recorded key type", got)
	}
	err = reloaded.callback("ssh.example.com:2222", remote, newTestHostKey(t))
	if !isHostKeyError(err) || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("callback() error = %v, want a mismatch despite accept-new", err)
	}
	if got := readFile(t, knownHostsPath); got != wantLine {
		t.Errorf("known_hosts changed after a mismatch: %q", got)
	}
}

func TestAddKnownHostKeepsExistingEntries(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	existing := knownhosts.Line([]string{"other.example.com"}, newTestHostKey(t))
	if err := os.WriteFile(knownHostsPath, []byte(existing), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	key := newTestHostKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}

	added, err := addKnownHost(knownHostsPath, "ssh.example.com:22", remote, key)
	if err != nil || !added {
		t.Fatalf("addKnownHost() = %t, %v, want true, nil", added, err)
	}
	want := existing + "\n" + knownhosts.Line([]string{"ssh.example.com"}, key) + "\n"
	if got := readFile(t, knownHostsPath); got != want {
		t.Errorf("known_hosts = %q, want %q", got, want)
	}

	added, err = addKnownHost(knownHostsPath, "ssh.example.com:22", remote, key)
	if err != nil || added {
		t.Fatalf("second addKnownHost() = %t, %v, want false, nil", added, err)
	}
	_, err = addKnownHost(knownHostsPath, "ssh.example.com:22", remote, newTestHostKey(t))
	if !isHostKeyError(err) {
		t.Fatalf("addKnownHost() with a conflicting key error = %v, want a host key error", err)
	}
}

func TestAcceptNewVerifierReportsWriteFailure(t *testing.T) {
	knownHostsPath := filepath.Join(t.TempDir(), "missing-dir", "known_hosts")
	verifier, err := newHostKeyVerifier(&config.Config{SSHKnownHostsFile: knownHostsPath, SSHKnownHostsAcceptNew: true})
	if err != nil {
		t.Fatalf("newHostKeyVerifier() error = %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	err = verifier.callback("ssh.example.com:22", remote, newTestHostKey(t))
	if !isHostKeyError(err) || !strings.Contains(err.Error(), "cannot record new SSH host key") ||
		!strings.Contains(err.Error(), knownHostsPath) {
		t.Fatalf("callback() error = %v, want a descriptive write failure", err)
	}
}

func TestAcceptNewRejectsInvalidSetup(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantErr string
	}{
		{
			name: "fingerprint verifier",
			cfg: config.Config{
				SSHHostKeyFingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				SSHKnownHostsAcceptNew: true,
			},
			wantErr: "ssh_known_hosts_accept_new requires ssh_known_hosts_file",
		},
		{
			name:    "unreadable known_hosts path",
			cfg:     config.Config{SSHKnownHostsFile: t.TempDir(), SSHKnownHostsAcceptNew: true},
			wantErr: "load known_hosts file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newHostKeyVerifier(&tt.cfg); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("newHostKeyVerifier() error = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDialSSHAcceptNewIntegration(t *testing.T) {
	sshServer := newTestSSHServer(t, "proxy", "secret")
	t.Cleanup(sshServer.close)
	cfg := testServerConfig(t, sshServer)
	cfg.SSHKnownHostsFile = filepath.Join(t.TempDir(), "known_hosts")
	cfg.SSHKnownHostsAcceptNew = true

	for attempt := 1; attempt <= 2; attempt++ {
		client, err := dialSSH(context.Background(), &cfg)
		if err != nil {
			t.Fatalf("dialSSH() attempt %d error = %v", attempt, err)
		}
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}

	address := knownhosts.Normalize(sshServer.listener.Addr().String())
	want := knownhosts.Line([]string{address}, sshServer.hostKey.PublicKey()) + "\n"
	if got := readFile(t, cfg.SSHKnownHostsFile); got != want {
		t.Errorf("known_hosts = %q, want %q", got, want)
	}
}

func TestInspectAndTrustHostKeyIntegration(t *testing.T) {
	sshServer := newTestSSHServer(t, "proxy", "secret")
	t.Cleanup(sshServer.close)
	cfg := testServerConfig(t, sshServer)
	// Inspection stops before authentication, so credentials are irrelevant.
	cfg.SSHPassword = "wrong-password"
	cfg.SSHKnownHostsFile = filepath.Join(t.TempDir(), "known_hosts")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	inspection, err := InspectHostKey(ctx, &cfg)
	if err != nil {
		t.Fatalf("InspectHostKey() error = %v", err)
	}
	if inspection.Status != HostKeyUnknown {
		t.Fatalf("InspectHostKey() status = %v, want unknown", inspection.Status)
	}
	if got, want := inspection.Fingerprint(), ssh.FingerprintSHA256(sshServer.hostKey.PublicKey()); got != want {
		t.Errorf("Fingerprint() = %s, want %s", got, want)
	}
	if added, err := TrustHostKey(inspection); err != nil || !added {
		t.Fatalf("TrustHostKey() = %t, %v, want true, nil", added, err)
	}

	inspection, err = InspectHostKey(ctx, &cfg)
	if err != nil {
		t.Fatalf("second InspectHostKey() error = %v", err)
	}
	if inspection.Status != HostKeyKnown {
		t.Fatalf("second InspectHostKey() status = %v, want known", inspection.Status)
	}

	address := knownhosts.Normalize(sshServer.listener.Addr().String())
	conflicting := knownhosts.Line([]string{address}, newTestHostKey(t)) + "\n"
	if err := os.WriteFile(cfg.SSHKnownHostsFile, []byte(conflicting), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	inspection, err = InspectHostKey(ctx, &cfg)
	if err != nil {
		t.Fatalf("third InspectHostKey() error = %v", err)
	}
	if inspection.Status != HostKeyRejected || !isHostKeyError(inspection.Err) {
		t.Fatalf("third InspectHostKey() = %v, %v, want a rejected key", inspection.Status, inspection.Err)
	}
	if _, err := TrustHostKey(inspection); !isHostKeyError(err) {
		t.Fatalf("TrustHostKey() for a conflicting key error = %v, want a host key error", err)
	}
	if got := readFile(t, cfg.SSHKnownHostsFile); got != conflicting {
		t.Errorf("known_hosts changed after a refused trust: %q", got)
	}
}

func TestInspectHostKeyFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	host, portText, err := net.SplitHostPort(closedAddress)
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	notSSH := newEchoServer(t)
	t.Cleanup(notSSH.close)
	notSSHHost, notSSHPortText, err := net.SplitHostPort(notSSH.listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	notSSHPort, err := strconv.Atoi(notSSHPortText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	tests := []struct {
		name    string
		cfg     config.Config
		timeout time.Duration
		wantErr string
	}{
		{name: "no known_hosts file", cfg: config.Config{SSHHost: host, SSHPort: port}, wantErr: "requires ssh_known_hosts_file"},
		{
			name:    "unreadable known_hosts path",
			cfg:     config.Config{SSHHost: host, SSHPort: port, SSHKnownHostsFile: t.TempDir()},
			wantErr: "load known_hosts file",
		},
		{
			name:    "transport unavailable",
			cfg:     config.Config{SSHHost: host, SSHPort: port, SSHKnownHostsFile: knownHostsPath},
			wantErr: "dial SSH transport",
		},
		{
			name:    "server does not speak SSH",
			cfg:     config.Config{SSHHost: notSSHHost, SSHPort: notSSHPort, SSHKnownHostsFile: knownHostsPath},
			timeout: 200 * time.Millisecond,
			wantErr: "SSH handshake",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}
			inspection, err := InspectHostKey(ctx, &tt.cfg)
			if inspection != nil || err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("InspectHostKey() = %v, %v, want an error containing %q", inspection, err, tt.wantErr)
			}
		})
	}
}

func TestTrustHostKeyRequiresInspection(t *testing.T) {
	if _, err := TrustHostKey(nil); err == nil {
		t.Fatal("TrustHostKey(nil) succeeded")
	}
	if _, err := TrustHostKey(&HostKeyInspection{}); err == nil {
		t.Fatal("TrustHostKey() without a key succeeded")
	}
}

func testServerConfig(t *testing.T, server *testSSHServer) config.Config {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatalf("split SSH address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse SSH port: %v", err)
	}
	cfg := config.Default()
	cfg.SSHHost = host
	cfg.SSHPort = port
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	return cfg
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}
