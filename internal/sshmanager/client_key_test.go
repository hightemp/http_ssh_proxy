package sshmanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
)

func TestDialSSHOffersEveryDefaultClientKey(t *testing.T) {
	rejected, _ := newTestClientKeyFile(t)
	accepted, acceptedKey := newTestClientKeyFile(t)
	cfg := publicKeyDialConfig(t, acceptedKey)
	cfg.SSHDefaultKeyFiles = []string{rejected, accepted}

	client, err := dialSSH(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("dialSSH() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("close client: %v", err)
	}
}

func TestDialSSHSkipsDefaultClientKeyThatBecameUnusable(t *testing.T) {
	accepted, acceptedKey := newTestClientKeyFile(t)
	cfg := publicKeyDialConfig(t, acceptedKey)
	invalid := filepath.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(invalid, []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	cfg.SSHDefaultKeyFiles = []string{filepath.Join(t.TempDir(), "removed"), invalid, accepted}

	client, err := dialSSH(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("dialSSH() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("close client: %v", err)
	}
}

func TestDialSSHRejectsWhenNoDefaultClientKeyRemains(t *testing.T) {
	cfg := validDialConfig()
	cfg.SSHPassword = ""
	cfg.SSHDefaultKeyFiles = []string{filepath.Join(t.TempDir(), "removed")}

	client, err := dialSSH(context.Background(), &cfg)
	if client != nil {
		_ = client.Close()
		t.Fatal("dialSSH() returned a client, want failure")
	}
	if err == nil || !strings.Contains(err.Error(), "no usable default SSH client key") {
		t.Fatalf("dialSSH() error = %v, want a missing default key error", err)
	}
}

func publicKeyDialConfig(t *testing.T, acceptedKey ssh.PublicKey) config.Config {
	t.Helper()
	return authDialConfig(t, &ssh.ServerConfig{PublicKeyCallback: acceptPublicKey(acceptedKey)})
}

func acceptPublicKey(acceptedKey ssh.PublicKey) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), acceptedKey.Marshal()) {
			return nil, errors.New("unknown client key")
		}
		return nil, nil
	}
}

func authDialConfig(t *testing.T, serverConfig *ssh.ServerConfig) config.Config {
	t.Helper()
	hostKey := newHostKeySigners(t).ed25519
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH: %v", err)
	}
	server := &testSSHServer{
		listener: listener,
		hostKey:  hostKey,
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	serverConfig.AddHostKey(hostKey)
	go server.serve(serverConfig)
	t.Cleanup(server.close)

	cfg := config.Default()
	cfg.SSHUser = "proxy"
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(hostKey.PublicKey())
	setDialAddress(t, &cfg, listener.Addr())
	return cfg
}

func newTestClientKeyFile(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("convert client key: %v", err)
	}
	return path, sshPublicKey
}
