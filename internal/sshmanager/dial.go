package sshmanager

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func isDestinationDialError(err error) bool {
	var openChannelErr *ssh.OpenChannelError
	return errors.As(err, &openChannelErr)
}

func hostKeyCallback(cfg *config.Config) (ssh.HostKeyCallback, error) {
	knownHostsFile := strings.TrimSpace(cfg.SSHKnownHostsFile)
	fingerprint := strings.TrimSpace(cfg.SSHHostKeyFingerprint)

	switch {
	case knownHostsFile == "" && fingerprint == "":
		return nil, errors.New("set ssh_known_hosts_file or ssh_host_key_fingerprint")
	case knownHostsFile != "" && fingerprint != "":
		return nil, errors.New("ssh_known_hosts_file and ssh_host_key_fingerprint are mutually exclusive")
	case knownHostsFile != "":
		callback, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts file %q: %w", knownHostsFile, err)
		}
		return callback, nil
	default:
		if err := validateSHA256Fingerprint(fingerprint); err != nil {
			return nil, err
		}

		return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(actual), []byte(fingerprint)) != 1 {
				return fmt.Errorf("SSH host key mismatch for %s: expected %s, got %s", hostname, fingerprint, actual)
			}
			return nil
		}, nil
	}
}

func validateSHA256Fingerprint(fingerprint string) error {
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return fmt.Errorf("invalid SSH host key fingerprint %q: expected SHA256:<base64>", fingerprint)
	}

	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, prefix))
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("invalid SSH host key fingerprint %q: expected a 32-byte SHA-256 digest", fingerprint)
	}

	return nil
}

func dialSSH(cfg *config.Config) (*ssh.Client, error) {
	verifyHostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure SSH host key verification: %w", err)
	}

	var auth []ssh.AuthMethod
	if cfg.SSHPassword != "" {
		auth = append(auth, ssh.Password(cfg.SSHPassword))
	}
	if cfg.SSHKeyFile != "" {
		key, err := os.ReadFile(cfg.SSHKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read SSH key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            auth,
		HostKeyCallback: verifyHostKey,
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.SSHHost, cfg.SSHPort), sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}
