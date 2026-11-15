package sshmanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// errHostKeyRejected marks failures to verify the SSH server identity. They
// are permanent for a given configuration, so reconnect loops must not retry
// them.
var errHostKeyRejected = errors.New("SSH host key verification failed")

// errHostKeyCaptured aborts an inspection handshake right after the server
// presented its host key, before any client authentication is attempted.
var errHostKeyCaptured = errors.New("SSH host key captured")

// knownHostsWriteMu serializes in-process known_hosts updates so concurrent
// additions cannot interleave or record the same host twice.
var knownHostsWriteMu sync.Mutex

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

// knownHostsDB is one snapshot of a known_hosts file.
type knownHostsDB struct {
	path               string
	check              ssh.HostKeyCallback
	certAuthorityLines map[int]bool
	contents           []byte
}

// loadKnownHosts reads path. A missing file is an empty database when
// allowMissing is set, so the first accepted key can create it.
func loadKnownHosts(path string, allowMissing bool) (*knownHostsDB, error) {
	files := []string{path}
	contents, err := os.ReadFile(path)
	switch {
	case err == nil:
	case allowMissing && errors.Is(err, fs.ErrNotExist):
		files = nil
	default:
		return nil, fmt.Errorf("load known_hosts file %q: %w", path, err)
	}

	check, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts file %q: %w", path, err)
	}
	return &knownHostsDB{
		path:               path,
		check:              check,
		certAuthorityLines: knownHostsCertAuthorityLines(contents),
		contents:           contents,
	}, nil
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
		return newKnownHostsVerifier(knownHostsFile, cfg.SSHKnownHostsAcceptNew)
	default:
		if cfg.SSHKnownHostsAcceptNew {
			return nil, errors.New("ssh_known_hosts_accept_new requires ssh_known_hosts_file")
		}
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

func newKnownHostsVerifier(path string, acceptNew bool) (*hostKeyVerifier, error) {
	db, err := loadKnownHosts(path, acceptNew)
	if err != nil {
		return nil, err
	}

	return &hostKeyVerifier{
		callback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := db.check(hostname, remote, key)
			if err == nil {
				return nil
			}
			if !acceptNew || !isUnknownHost(err) {
				return describeKnownHostsError(path, hostname, key, err)
			}

			added, err := addKnownHost(path, hostname, remote, key)
			if err != nil {
				if isHostKeyError(err) {
					return err
				}
				return &hostKeyError{
					msg: fmt.Sprintf("cannot record new SSH host key %s %s for %s in %q: %v",
						key.Type(), ssh.FingerprintSHA256(key), hostname, path, err),
					cause: err,
				}
			}
			if added {
				log.Printf("[SSH] WARNING: permanently added %s key %s for %s to %s (ssh_known_hosts_accept_new)",
					key.Type(), ssh.FingerprintSHA256(key), knownhosts.Normalize(hostname), path)
			}
			return nil
		},
		algorithms: func(address string, remote net.Addr) []string {
			return knownHostAlgorithms(db, address, remote)
		},
	}, nil
}

func isUnknownHost(err error) bool {
	var keyErr *knownhosts.KeyError
	return errors.As(err, &keyErr) && len(keyErr.Want) == 0
}

// addKnownHost appends key for hostname to path unless the file, reread under
// knownHostsWriteMu, already accepts it. It returns a host key error when the
// file meanwhile lists a different key for the host, and reports whether a
// line was written.
func addKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	knownHostsWriteMu.Lock()
	defer knownHostsWriteMu.Unlock()

	db, err := loadKnownHosts(path, true)
	if err != nil {
		return false, err
	}
	if err := db.check(hostname, remote, key); err == nil {
		return false, nil
	} else if !isUnknownHost(err) {
		return false, describeKnownHostsError(path, hostname, key, err)
	}

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
	if len(db.contents) > 0 && !bytes.HasSuffix(db.contents, []byte("\n")) {
		line = "\n" + line
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := file.WriteString(line); err != nil {
		return false, closeAfterError(file, err)
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	return true, nil
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
			"verify this key through a trusted channel and add it with -trust-host-key, "+
			"or enable ssh_known_hosts_accept_new",
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
func knownHostAlgorithms(db *knownHostsDB, address string, remote net.Addr) []string {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(db.check(address, remote, probe), &keyErr) {
		return nil
	}

	supported := ssh.SupportedAlgorithms().HostKeys
	var algorithms []string
	for _, want := range keyErr.Want {
		if db.certAuthorityLines[want.Line] {
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
func knownHostsCertAuthorityLines(contents []byte) map[int]bool {
	lines := make(map[int]bool)
	for number, line := range strings.Split(string(contents), "\n") {
		marker, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		marker, _, _ = strings.Cut(marker, "\t")
		if marker == "@cert-authority" {
			lines[number+1] = true
		}
	}
	return lines
}

func algorithmsForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// HostKeyStatus is the relation between a presented host key and known_hosts.
type HostKeyStatus int

const (
	// HostKeyUnknown means known_hosts has no entry for the host.
	HostKeyUnknown HostKeyStatus = iota
	// HostKeyKnown means known_hosts already accepts the presented key.
	HostKeyKnown
	// HostKeyRejected means known_hosts lists a different or revoked key.
	HostKeyRejected
)

// HostKeyInspection describes the host key an SSH server presented.
type HostKeyInspection struct {
	// Address is the host:port used for the handshake and known_hosts lookup.
	Address string
	// KnownHostsFile is the configured known_hosts file.
	KnownHostsFile string
	// Key is the presented host public key.
	Key ssh.PublicKey
	// Status relates Key to the known_hosts file.
	Status HostKeyStatus
	// Err explains a HostKeyRejected status.
	Err error

	remote net.Addr
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of the presented key.
func (i *HostKeyInspection) Fingerprint() string {
	return ssh.FingerprintSHA256(i.Key)
}

// InspectHostKey connects to the configured SSH server, captures the host key
// it presents, and compares it with ssh_known_hosts_file. The handshake stops
// before authentication, so no credentials are sent.
func InspectHostKey(ctx context.Context, cfg *config.Config) (*HostKeyInspection, error) {
	path := strings.TrimSpace(cfg.SSHKnownHostsFile)
	if path == "" {
		return nil, errors.New("host key trust requires ssh_known_hosts_file")
	}
	db, err := loadKnownHosts(path, true)
	if err != nil {
		return nil, err
	}

	address := net.JoinHostPort(cfg.SSHHost, strconv.Itoa(cfg.SSHPort))
	inspection := &HostKeyInspection{Address: address, KnownHostsFile: path}
	clientConfig := &ssh.ClientConfig{
		User: cfg.SSHUser,
		HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
			inspection.Key = key
			inspection.remote = remote
			return errHostKeyCaptured
		},
		Timeout: 10 * time.Second,
	}

	netDialer := &net.Dialer{Timeout: clientConfig.Timeout}
	conn, err := netDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH transport: %w", err)
	}
	stopCloseOnCancel := context.AfterFunc(ctx, func() {
		logutil.Close("canceled SSH inspection transport", conn)
	})
	defer stopCloseOnCancel()

	deadline := time.Now().Add(clientConfig.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, closeAfterError(conn, fmt.Errorf("set SSH handshake deadline: %w", err))
	}
	clientConfig.HostKeyAlgorithms = knownHostAlgorithms(db, address, conn.RemoteAddr())

	clientConn, _, _, err := ssh.NewClientConn(conn, address, clientConfig)
	if err == nil {
		// Unreachable with a callback that always fails; close defensively.
		logutil.Close("unexpected SSH inspection client", clientConn)
		return nil, errors.New("SSH handshake completed without capturing the host key")
	}
	if !errors.Is(err, errHostKeyCaptured) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("SSH handshake canceled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}

	switch checkErr := db.check(address, inspection.remote, inspection.Key); {
	case checkErr == nil:
		inspection.Status = HostKeyKnown
	case isUnknownHost(checkErr):
		inspection.Status = HostKeyUnknown
	default:
		inspection.Status = HostKeyRejected
		inspection.Err = describeKnownHostsError(path, address, inspection.Key, checkErr)
	}
	return inspection, nil
}

// TrustHostKey records an inspected unknown host key in its known_hosts file.
// It reports whether a line was written and refuses keys that conflict with
// existing entries.
func TrustHostKey(inspection *HostKeyInspection) (bool, error) {
	if inspection == nil || inspection.Key == nil {
		return false, errors.New("no inspected SSH host key")
	}
	if inspection.Status == HostKeyRejected {
		return false, inspection.Err
	}
	return addKnownHost(inspection.KnownHostsFile, inspection.Address, inspection.remote, inspection.Key)
}
