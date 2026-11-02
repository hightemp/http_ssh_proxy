package sshmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestDialSSHLogsHostKeyVerifiedByKnownHosts(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519, signers.ecdsa)
	cfg := dialConfigFor(t, sshServer)
	address := sshServer.listener.Addr().String()
	cfg.SSHKnownHostsFile = writeKnownHosts(t, knownhosts.Line([]string{address}, signers.ecdsa.PublicKey()))
	logs := captureLogs(t)

	dialAndClose(t, &cfg)

	for _, want := range []string{
		"Host key verified for " + knownhosts.Normalize(address),
		ssh.KeyAlgoECDSA256,
		ssh.FingerprintSHA256(signers.ecdsa.PublicKey()),
		cfg.SSHKnownHostsFile,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs = %q, want them to contain %q", logs.String(), want)
		}
	}
}

func TestDialSSHLogsOnlyTheHostKeyMatchingFingerprint(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519, signers.rsa)
	cfg := dialConfigFor(t, sshServer)
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(signers.rsa.PublicKey())
	logs := captureLogs(t)

	dialAndClose(t, &cfg)

	output := logs.String()
	if got := strings.Count(output, "Host key verified"); got != 1 {
		t.Errorf("verified host keys logged = %d, want 1 in %q", got, output)
	}
	if !strings.Contains(output, cfg.SSHHostKeyFingerprint) || !strings.Contains(output, "pinned fingerprint") {
		t.Errorf("logs = %q, want the pinned fingerprint", output)
	}
}

func TestDialSSHLogsOnlyTheAcceptedDefaultClientKey(t *testing.T) {
	rejected, _ := newTestClientKeyFile(t)
	accepted, acceptedKey := newTestClientKeyFile(t)
	cfg := publicKeyDialConfig(t, acceptedKey)
	cfg.SSHDefaultKeyFiles = []string{rejected, accepted}
	logs := captureLogs(t)

	dialAndClose(t, &cfg)

	output := logs.String()
	if !strings.Contains(output, "Authenticated with client key "+accepted) {
		t.Errorf("logs = %q, want the accepted key %s", output, accepted)
	}
	if !strings.Contains(output, ssh.FingerprintSHA256(acceptedKey)) {
		t.Errorf("logs = %q, want the accepted key's fingerprint", output)
	}
	if strings.Contains(output, rejected) {
		t.Errorf("logs = %q, want no mention of the rejected key %s", output, rejected)
	}
}

// The tracking wrapper must keep RSA SHA-2 signatures working: a signer limited
// to the legacy ssh-rsa algorithm would be refused by the server.
func TestDialSSHLogsExplicitClientKeyOfEachType(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tests := []struct {
		name string
		key  any
	}{
		{name: "ecdsa", key: ecdsaKey},
		{name: "rsa", key: rsaKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKey(tt.key, "")
			if err != nil {
				t.Fatalf("marshal client key: %v", err)
			}
			path := filepath.Join(t.TempDir(), "client_key")
			if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
				t.Fatalf("write client key: %v", err)
			}
			signer, err := ssh.NewSignerFromKey(tt.key)
			if err != nil {
				t.Fatalf("create client signer: %v", err)
			}
			cfg := publicKeyDialConfig(t, signer.PublicKey())
			cfg.SSHKeyFile = path
			logs := captureLogs(t)

			dialAndClose(t, &cfg)

			if want := "Authenticated with client key " + path; !strings.Contains(logs.String(), want) {
				t.Errorf("logs = %q, want them to contain %q", logs.String(), want)
			}
		})
	}
}

func TestDialSSHLogsPasswordAuthenticationWithoutClientKey(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519)
	cfg := dialConfigFor(t, sshServer)
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(signers.ed25519.PublicKey())
	logs := captureLogs(t)

	dialAndClose(t, &cfg)

	if !strings.Contains(logs.String(), "Authenticated without a client key") {
		t.Errorf("logs = %q, want authentication without a client key", logs.String())
	}
}

func TestDialSSHDoesNotLogAuthenticationOfRejectedHost(t *testing.T) {
	signers := newHostKeySigners(t)
	sshServer, _ := newHostKeyTestServer(t, signers.ed25519)
	cfg := dialConfigFor(t, sshServer)
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(newHostKeySigners(t).ed25519.PublicKey())
	logs := captureLogs(t)

	client, err := dialSSH(context.Background(), &cfg)
	if client != nil {
		_ = client.Close()
		t.Fatal("dialSSH() returned a client, want a host key rejection")
	}
	if err == nil {
		t.Fatal("dialSSH() error = nil, want a host key rejection")
	}
	output := logs.String()
	if strings.Contains(output, "Host key verified") || strings.Contains(output, "Authenticated") {
		t.Errorf("logs = %q, want no success messages", output)
	}
}

func dialAndClose(t *testing.T, cfg *config.Config) {
	t.Helper()
	client, err := dialSSH(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dialSSH() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("close client: %v", err)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	logs := &lockedBuffer{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return logs
}
