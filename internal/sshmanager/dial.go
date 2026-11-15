package sshmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
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

func isDestinationDialError(err error) bool {
	var openChannelErr *ssh.OpenChannelError
	return errors.As(err, &openChannelErr)
}

// errHostKeyRejected marks failures to verify the SSH server identity. They
// are permanent for a given configuration, so reconnect loops must not retry
// them.
var errHostKeyRejected = errors.New("SSH host key verification failed")

// hostKeyError describes a rejected SSH server identity while keeping both the
// errHostKeyRejected marker and the verifier's original error inspectable.
type hostKeyError struct {
	msg   string
	cause error
}

func (e *hostKeyError) Error() string { return e.msg }

func (e *hostKeyError) Unwrap() []error { return []error{errHostKeyRejected, e.cause} }

func isHostKeyError(err error) bool {
	return errors.Is(err, errHostKeyRejected)
}

// hostKeyVerifier verifies the SSH server identity and optionally restricts
// the host key algorithms offered during key exchange.
type hostKeyVerifier struct {
	callback ssh.HostKeyCallback
	// algorithms returns the host key algorithms to offer for address, or nil
	// to keep the library defaults.
	algorithms func(address string, remote net.Addr) []string
}

func newHostKeyVerifier(cfg *config.Config) (*hostKeyVerifier, error) {
	knownHostsFile := strings.TrimSpace(cfg.SSHKnownHostsFile)
	fingerprint := strings.TrimSpace(cfg.SSHHostKeyFingerprint)

	switch {
	case knownHostsFile == "" && fingerprint == "":
		return nil, errors.New("set ssh_known_hosts_file or ssh_host_key_fingerprint")
	case knownHostsFile != "" && fingerprint != "":
		return nil, errors.New("ssh_known_hosts_file and ssh_host_key_fingerprint are mutually exclusive")
	case knownHostsFile != "":
		db, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts file %q: %w", knownHostsFile, err)
		}
		certAuthorityLines, err := knownHostsCertAuthorityLines(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts file %q: %w", knownHostsFile, err)
		}
		return &hostKeyVerifier{
			callback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				if err := db(hostname, remote, key); err != nil {
					return describeKnownHostsError(knownHostsFile, hostname, key, err)
				}
				return nil
			},
			algorithms: func(address string, remote net.Addr) []string {
				return knownHostAlgorithms(db, certAuthorityLines, address, remote)
			},
		}, nil
	default:
		if err := config.ValidateSSHHostKeyFingerprint(fingerprint); err != nil {
			return nil, err
		}

		return &hostKeyVerifier{
			callback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
				actual := ssh.FingerprintSHA256(key)
				if subtle.ConstantTimeCompare([]byte(actual), []byte(fingerprint)) != 1 {
					return &hostKeyError{
						msg: fmt.Sprintf("SSH host key mismatch for %s: expected %s, server presented %s %s; "+
							"the pinned fingerprint must belong to the key type the server presents",
							hostname, fingerprint, key.Type(), actual),
						cause: errors.New("fingerprint mismatch"),
					}
				}
				return nil
			},
		}, nil
	}
}

// describeKnownHostsError turns knownhosts errors into actionable messages that
// name the host, the file, and the fingerprints involved.
func describeKnownHostsError(file, hostname string, key ssh.PublicKey, err error) error {
	presented := key.Type() + " " + ssh.FingerprintSHA256(key)

	var keyErr *knownhosts.KeyError
	var revokedErr *knownhosts.RevokedError
	var msg string
	switch {
	case errors.As(err, &revokedErr):
		msg = fmt.Sprintf("SSH host key %s presented by %s is revoked in %s:%d",
			presented, hostname, revokedErr.Revoked.Filename, revokedErr.Revoked.Line)
	case errors.As(err, &keyErr) && len(keyErr.Want) == 0:
		msg = fmt.Sprintf("SSH host %s is not listed in known_hosts file %q (server presented %s); "+
			"verify this key through a trusted channel and add the host to the file",
			hostname, file, presented)
	case errors.As(err, &keyErr):
		known := make([]string, 0, len(keyErr.Want))
		for _, want := range keyErr.Want {
			known = append(known, fmt.Sprintf("%s %s (%s:%d)",
				want.Key.Type(), ssh.FingerprintSHA256(want.Key), want.Filename, want.Line))
		}
		msg = fmt.Sprintf("SSH host key mismatch for %s: server presented %s, known_hosts lists %s; "+
			"the server key changed or the connection is being intercepted",
			hostname, presented, strings.Join(known, ", "))
	default:
		msg = fmt.Sprintf("SSH host key verification for %s failed: %v", hostname, err)
	}
	return &hostKeyError{msg: msg, cause: err}
}

// knownHostAlgorithms returns the host key algorithms matching the key types
// that known_hosts lists for address, in file order. Restricting negotiation to
// those algorithms prevents false mismatches when the server prefers a key type
// that is not recorded. It returns nil, keeping the library defaults, when the
// host has no entries or matches a certificate authority, because a CA key type
// says nothing about which host certificate algorithms the server uses.
func knownHostAlgorithms(db ssh.HostKeyCallback, certAuthorityLines map[int]bool, address string, remote net.Addr) []string {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(db(address, remote, probe), &keyErr) {
		return nil
	}

	supported := ssh.SupportedAlgorithms().HostKeys
	var algorithms []string
	for _, want := range keyErr.Want {
		if certAuthorityLines[want.Line] {
			return nil
		}
		for _, algorithm := range algorithmsForKeyType(want.Key.Type()) {
			if !slices.Contains(algorithms, algorithm) && (slices.Contains(supported, algorithm) || algorithm == ssh.KeyAlgoRSA) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	return algorithms
}

// knownHostsCertAuthorityLines returns the 1-based line numbers of
// @cert-authority entries, numbered the same way as knownhosts.KnownKey.Line.
func knownHostsCertAuthorityLines(file string) (map[int]bool, error) {
	contents, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	lines := make(map[int]bool)
	for number, line := range strings.Split(string(contents), "\n") {
		marker, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		marker, _, _ = strings.Cut(marker, "\t")
		if marker == "@cert-authority" {
			lines[number+1] = true
		}
	}
	return lines, nil
}

func algorithmsForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
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
