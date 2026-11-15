package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/sshmanager"

	"golang.org/x/crypto/ssh"
)

func TestTrustHostKeyFlow(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("convert key: %v", err)
	}
	rejection := errors.New("SSH host key mismatch")
	trustErr := errors.New("disk full")

	tests := []struct {
		name       string
		status     sshmanager.HostKeyStatus
		inspectErr error
		input      string
		assumeYes  bool
		trustAdded bool
		trustErr   error
		wantTrust  bool
		wantErr    error
		wantErrMsg string
		wantOut    []string
	}{
		{
			name:    "already known",
			status:  sshmanager.HostKeyKnown,
			wantOut: []string{ssh.FingerprintSHA256(key), "already trusted"},
		},
		{
			name:       "conflicting key",
			status:     sshmanager.HostKeyRejected,
			wantErr:    rejection,
			wantErrMsg: "ssh-keygen -R [127.0.0.1]:2222 -f /tmp/known_hosts",
		},
		{
			name:       "confirmed",
			status:     sshmanager.HostKeyUnknown,
			input:      "yes\n",
			trustAdded: true,
			wantTrust:  true,
			wantOut:    []string{"[y/N]", "Added ssh-ed25519 key for [127.0.0.1]:2222"},
		},
		{
			name:       "confirmed without newline",
			status:     sshmanager.HostKeyUnknown,
			input:      "Y",
			trustAdded: true,
			wantTrust:  true,
		},
		{
			name:    "declined",
			status:  sshmanager.HostKeyUnknown,
			input:   "n\n",
			wantErr: errHostKeyNotTrusted,
		},
		{
			name:    "no answer",
			status:  sshmanager.HostKeyUnknown,
			wantErr: errHostKeyNotTrusted,
		},
		{
			name:       "assume yes",
			status:     sshmanager.HostKeyUnknown,
			assumeYes:  true,
			trustAdded: true,
			wantTrust:  true,
		},
		{
			name:      "recorded concurrently",
			status:    sshmanager.HostKeyUnknown,
			assumeYes: true,
			wantTrust: true,
			wantOut:   []string{"already trusted"},
		},
		{
			name:      "trust failure",
			status:    sshmanager.HostKeyUnknown,
			assumeYes: true,
			trustErr:  trustErr,
			wantTrust: true,
			wantErr:   trustErr,
		},
		{
			name:       "inspect failure",
			inspectErr: errors.New("connection refused"),
			wantErrMsg: "inspect SSH host key: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted := false
			truster := hostKeyTruster{
				inspect: func(ctx context.Context, _ *config.Config) (*sshmanager.HostKeyInspection, error) {
					if _, ok := ctx.Deadline(); !ok {
						t.Error("inspect context has no deadline")
					}
					if tt.inspectErr != nil {
						return nil, tt.inspectErr
					}
					inspection := &sshmanager.HostKeyInspection{
						Address:        "127.0.0.1:2222",
						KnownHostsFile: "/tmp/known_hosts",
						Key:            key,
						Status:         tt.status,
					}
					if tt.status == sshmanager.HostKeyRejected {
						inspection.Err = rejection
					}
					return inspection, nil
				},
				trust: func(*sshmanager.HostKeyInspection) (bool, error) {
					trusted = true
					return tt.trustAdded, tt.trustErr
				},
			}

			var out bytes.Buffer
			cfg := &config.Config{SSHKnownHostsFile: "/tmp/known_hosts"}
			err := truster.run(context.Background(), cfg, strings.NewReader(tt.input), &out, tt.assumeYes)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("run() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrMsg)) {
				t.Fatalf("run() error = %v, want it to contain %q", err, tt.wantErrMsg)
			}
			if tt.wantErr == nil && tt.wantErrMsg == "" && err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if trusted != tt.wantTrust {
				t.Errorf("trust called = %t, want %t", trusted, tt.wantTrust)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output = %q, want it to contain %q", out.String(), want)
				}
			}
		})
	}
}

func TestTrustHostKeyRequiresKnownHostsFile(t *testing.T) {
	cfg := &config.Config{SSHHostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	err := TrustHostKey(context.Background(), cfg, strings.NewReader(""), &bytes.Buffer{}, true)
	if err == nil || !strings.Contains(err.Error(), "requires ssh_known_hosts_file") {
		t.Fatalf("TrustHostKey() error = %v, want a configuration error", err)
	}
}
