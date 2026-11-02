package sshmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// errHostKeyVerification marks a connection refused because the server's host
// key could not be verified. Retrying cannot change the outcome.
var errHostKeyVerification = errors.New("SSH host key verification failed")

// hostKeyAlgorithmGroups lists plain host key algorithms in order of
// preference. Algorithms of one group share a key type, or differ only in a
// parameter of it, so a server holds at most one key per group in practice.
var hostKeyAlgorithmGroups = [][]string{
	{ssh.KeyAlgoED25519},
	{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
	{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
}

var hostCertAlgorithms = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01,
	ssh.CertAlgoRSASHA256v01,
}

func isDestinationDialError(err error) bool {
	var openChannelErr *ssh.OpenChannelError
	return errors.As(err, &openChannelErr)
}

func hostKeyCallback(cfg *config.Config) (ssh.HostKeyCallback, error) {
	verify, err := hostKeyVerifier(cfg)
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := verify(hostname, remote, key); err != nil {
			return fmt.Errorf("%w for %s: %w", errHostKeyVerification, knownhosts.Normalize(hostname), err)
		}
		return nil
	}, nil
}

func hostKeyVerifier(cfg *config.Config) (ssh.HostKeyCallback, error) {
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

		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(actual), []byte(fingerprint)) != 1 {
				return fmt.Errorf("expected %s, got %s", fingerprint, actual)
			}
			return nil
		}, nil
	}
}

// knownHostKeyAlgorithms returns the host key algorithms to request for a host
// recorded in known_hosts, or nil when the host has no entries. A server may
// hold several host keys and presents only the type the client prefers, so
// requesting a type that is not recorded fails verification with a genuine key.
func knownHostKeyAlgorithms(verify ssh.HostKeyCallback, address string) ([]string, error) {
	// No known_hosts entry matches this key, so the verifier reports all
	// entries recorded for the host. The verifier prefers address over remote.
	placeholder, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		return nil, fmt.Errorf("create placeholder host key: %w", err)
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(verify(address, &net.TCPAddr{IP: net.IPv4zero}, placeholder), &keyErr) || len(keyErr.Want) == 0 {
		return nil, nil
	}

	recorded := make([]string, 0, len(keyErr.Want))
	for _, known := range keyErr.Want {
		recorded = append(recorded, known.Key.Type())
	}

	// Host certificates come first, as in the library defaults: a certificate
	// authority entry says nothing about the type of the certified host key.
	algorithms := slices.Clone(hostCertAlgorithms)
	for _, group := range hostKeyAlgorithmGroups {
		for _, algorithm := range group {
			keyType := algorithm
			if algorithm == ssh.KeyAlgoRSASHA256 || algorithm == ssh.KeyAlgoRSASHA512 {
				keyType = ssh.KeyAlgoRSA
			}
			if slices.Contains(recorded, keyType) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	for _, keyType := range recorded {
		if keyType != ssh.KeyAlgoRSA && !slices.Contains(algorithms, keyType) {
			algorithms = append(algorithms, keyType)
		}
	}
	return algorithms, nil
}

// hostKeyAlgorithmAttempts returns the host key algorithm lists to try in
// order. A fingerprint does not reveal the key type, so every group is probed
// until the presented key matches. A nil list selects the library defaults.
func hostKeyAlgorithmAttempts(cfg *config.Config, verify ssh.HostKeyCallback, address string) ([][]string, error) {
	if strings.TrimSpace(cfg.SSHKnownHostsFile) == "" {
		return hostKeyAlgorithmGroups, nil
	}
	algorithms, err := knownHostKeyAlgorithms(verify, address)
	if err != nil {
		return nil, err
	}
	return [][]string{algorithms}, nil
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
	if len(cfg.SSHDefaultKeyFiles) > 0 {
		signers, err := defaultClientKeySigners(cfg.SSHDefaultKeyFiles)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signers...))
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            auth,
		HostKeyCallback: verifyHostKey,
		Timeout:         10 * time.Second,
	}

	address := net.JoinHostPort(cfg.SSHHost, fmt.Sprintf("%d", cfg.SSHPort))
	attempts, err := hostKeyAlgorithmAttempts(cfg, verifyHostKey, address)
	if err != nil {
		return nil, fmt.Errorf("configure SSH host key verification: %w", err)
	}

	// All attempts share one deadline.
	deadline := time.Now().Add(sshConfig.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	var rejected []error
	var unsupported error
	for _, algorithms := range attempts {
		sshConfig.HostKeyAlgorithms = algorithms
		client, err := handshakeSSH(ctx, address, sshConfig, deadline)
		switch {
		case err == nil:
			return client, nil
		case len(attempts) == 1:
			return nil, err
		case errors.Is(err, errHostKeyVerification):
			rejected = append(rejected, err)
		case isHostKeyNegotiationError(err):
			unsupported = err
		default:
			return nil, err
		}
	}
	if len(rejected) > 0 {
		return nil, errors.Join(rejected...)
	}
	return nil, fmt.Errorf("%w for %s: no supported host key type: %w", errHostKeyVerification, knownhosts.Normalize(address), unsupported)
}

// defaultClientKeySigners rereads the default client keys for each connection.
// A key that stopped being usable since startup is skipped.
func defaultClientKeySigners(paths []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, path := range paths {
		key, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[SSH] Skipping default client key %s: %v", path, err)
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Printf("[SSH] Skipping default client key %s: %v", path, err)
			continue
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no usable default SSH client key in %s", strings.Join(paths, ", "))
	}
	return signers, nil
}

func isHostKeyNegotiationError(err error) bool {
	var negotiationErr *ssh.AlgorithmNegotiationError
	return errors.As(err, &negotiationErr) && negotiationErr.What == "host key"
}

func handshakeSSH(ctx context.Context, address string, sshConfig *ssh.ClientConfig, deadline time.Time) (*ssh.Client, error) {
	netDialer := &net.Dialer{Deadline: deadline}
	conn, err := netDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH transport: %w", err)
	}
	closeOnCancel := context.AfterFunc(ctx, func() {
		logutil.Close("canceled SSH transport", conn)
	})
	defer closeOnCancel()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, closeAfterError(conn, fmt.Errorf("set SSH handshake deadline: %w", err))
	}

	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		// NewClientConn has already closed conn.
		handshakeErr := fmt.Errorf("SSH handshake: %w", err)
		if ctx.Err() != nil {
			handshakeErr = fmt.Errorf("SSH handshake canceled: %w", ctx.Err())
		} else if ctxDeadline, ok := ctx.Deadline(); ok && !time.Now().Before(ctxDeadline) {
			// A socket deadline can wake NewClientConn just before the context
			// timer publishes its error. Preserve the context-aware contract in
			// that narrow race instead of leaking an incidental net timeout.
			handshakeErr = fmt.Errorf("SSH handshake canceled: %w", context.DeadlineExceeded)
		}
		return nil, handshakeErr
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
