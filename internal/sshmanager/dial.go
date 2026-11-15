package sshmanager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"

	"golang.org/x/crypto/ssh"
)

func isDestinationDialError(err error) bool {
	var openChannelErr *ssh.OpenChannelError
	return errors.As(err, &openChannelErr)
}

func dialSSH(ctx context.Context, cfg *config.Config) (*ssh.Client, error) {
	verifier, err := newHostKeyVerifier(cfg)
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
		HostKeyCallback: verifier.callback,
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

	if verifier.algorithms != nil {
		sshConfig.HostKeyAlgorithms = verifier.algorithms(address, conn.RemoteAddr())
	}

	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		handshakeErr := fmt.Errorf("SSH handshake: %w", err)
		if ctx.Err() != nil {
			handshakeErr = fmt.Errorf("SSH handshake canceled: %w", ctx.Err())
		} else if ctxDeadline, ok := ctx.Deadline(); ok && !time.Now().Before(ctxDeadline) {
			// A socket deadline can wake NewClientConn just before the context
			// timer publishes its error. Preserve the context-aware contract in
			// that narrow race instead of leaking an incidental net timeout.
			handshakeErr = fmt.Errorf("SSH handshake canceled: %w", context.DeadlineExceeded)
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

// closeAfterError closes closer after operationErr and reports close failures.
// An already closed connection is not a failure: ssh.NewClientConn and the
// cancellation hook both close the transport themselves.
func closeAfterError(closer io.Closer, operationErr error) error {
	if closeErr := closer.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return errors.Join(operationErr, fmt.Errorf("close after failure: %w", closeErr))
	}
	return operationErr
}
