package sshmanager

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"

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
		if err := config.ValidateSSHHostKeyFingerprint(fingerprint); err != nil {
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

func dialSSH(ctx context.Context, cfg *config.Config) (*ssh.Client, error) {
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

	address := net.JoinHostPort(cfg.SSHHost, fmt.Sprintf("%d", cfg.SSHPort))
	netDialer := &net.Dialer{Timeout: sshConfig.Timeout}
	conn, err := netDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH transport: %w", err)
	}
	closeOnCancel := context.AfterFunc(ctx, func() {
		logutil.Close("canceled SSH transport", conn)
	})
	defer closeOnCancel()

	deadline := time.Now().Add(sshConfig.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, closeAfterError(conn, fmt.Errorf("set SSH handshake deadline: %w", err))
	}

	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		handshakeErr := fmt.Errorf("SSH handshake: %w", err)
		if ctx.Err() != nil {
			handshakeErr = fmt.Errorf("SSH handshake canceled: %w", ctx.Err())
		}
		return nil, closeAfterError(conn, handshakeErr)
	}
	if !closeOnCancel() && ctx.Err() != nil {
		return nil, closeAfterError(clientConn, fmt.Errorf("SSH handshake canceled: %w", ctx.Err()))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, closeAfterError(clientConn, fmt.Errorf("clear SSH handshake deadline: %w", err))
	}

	return ssh.NewClient(clientConn, channels, requests), nil
}

func closeAfterError(closer io.Closer, operationErr error) error {
	if closeErr := closer.Close(); closeErr != nil {
		return errors.Join(operationErr, fmt.Errorf("close after failure: %w", closeErr))
	}
	return operationErr
}
