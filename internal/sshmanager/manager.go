// Package sshmanager manages the shared SSH connection used by the proxy.
package sshmanager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
)

const (
	defaultMaxConnections     = 128
	defaultReconnectAttempts  = 3
	defaultKeepAliveInterval  = 30 * time.Second
	defaultKeepAliveFailLimit = 3
)

var (
	errManagerClosed   = errors.New("SSH manager is closed")
	errConnectionLimit = &connectionLimitError{}
)

type connectionLimitError struct{}

func (*connectionLimitError) Error() string {
	return "SSH connection limit reached"
}

func (*connectionLimitError) ResourceLimit() bool {
	return true
}

type sshClient interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Close() error
}

type connector func(ctx context.Context) (sshClient, error)

type clientState struct {
	client sshClient
}

// Manager manages the SSH connection with context-aware single-flight
// reconnection and a bounded number of forwarded connections.
type Manager struct {
	config    *config.Config
	connector connector

	mu    sync.RWMutex
	state *clientState

	reconnectGate chan struct{}
	connectionSem chan struct{}
	backoff       func(attempt int) time.Duration
	attempts      int
	keepAliveTick time.Duration
	keepAliveFail int

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	startOnce       sync.Once
	closeOnce       sync.Once
	workerMu        sync.Mutex
	keepAliveDone   chan struct{}
	closeErr        error
}

// New creates an SSH connection manager.
func New(cfg *config.Config) *Manager {
	return newManager(cfg, func(ctx context.Context) (sshClient, error) {
		return dialSSH(ctx, cfg)
	})
}

func newManager(cfg *config.Config, connect connector) *Manager {
	maxConnections := cfg.MaxConnections
	if maxConnections <= 0 {
		maxConnections = defaultMaxConnections
	}
	reconnectAttempts := cfg.SSHReconnectAttempts
	if reconnectAttempts <= 0 {
		reconnectAttempts = defaultReconnectAttempts
	}

	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Manager{
		config:          cfg,
		connector:       connect,
		reconnectGate:   make(chan struct{}, 1),
		connectionSem:   make(chan struct{}, maxConnections),
		backoff:         reconnectBackoff,
		attempts:        reconnectAttempts,
		keepAliveTick:   defaultKeepAliveInterval,
		keepAliveFail:   defaultKeepAliveFailLimit,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}
}

// Connect establishes the initial SSH connection and honors ctx cancellation.
func (m *Manager) Connect(ctx context.Context) error {
	if err := m.reconnect(ctx, nil); err != nil {
		return fmt.Errorf("establish initial SSH connection: %w", err)
	}
	return nil
}

// DialContext establishes a bounded connection through the SSH tunnel. If the
// SSH transport has failed, one goroutine reconnects while other callers wait.
func (m *Manager) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := m.linkContext(ctx)
	defer cancel()

	if err := m.acquireConnection(ctx); err != nil {
		return nil, err
	}
	release := func() { <-m.connectionSem }

	state, err := m.getClient(ctx)
	if err != nil {
		release()
		return nil, fmt.Errorf("SSH client unavailable: %w", err)
	}

	conn, dialErr := state.client.DialContext(ctx, network, addr)
	if dialErr == nil {
		return newLimitedConn(conn, release), nil
	}
	if isDestinationDialError(dialErr) {
		release()
		return nil, fmt.Errorf("SSH destination dial to %s failed: %w", addr, dialErr)
	}

	log.Printf("[SSH] Dial to %s failed (%v), attempting reconnect", addr, dialErr)
	if reconnectErr := m.reconnect(ctx, state); reconnectErr != nil {
		release()
		return nil, errors.Join(
			fmt.Errorf("SSH dial to %s failed: %w", addr, dialErr),
			fmt.Errorf("SSH reconnect failed: %w", reconnectErr),
		)
	}

	state, err = m.getClient(ctx)
	if err != nil {
		release()
		return nil, fmt.Errorf("get reconnected SSH client: %w", err)
	}
	conn, err = state.client.DialContext(ctx, network, addr)
	if err != nil {
		release()
		return nil, fmt.Errorf("SSH dial to %s failed after reconnect: %w", addr, err)
	}
	return newLimitedConn(conn, release), nil
}

// StartKeepAlive starts one monitored keepalive worker tied to ctx and Close.
func (m *Manager) StartKeepAlive(ctx context.Context) {
	m.startOnce.Do(func() {
		m.workerMu.Lock()
		defer m.workerMu.Unlock()
		if m.lifecycleCtx.Err() != nil {
			return
		}
		done := make(chan struct{})
		m.keepAliveDone = done
		go func() {
			defer close(done)
			m.keepAlive(ctx)
		}()
	})
}

func (m *Manager) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(m.keepAliveTick)
	defer ticker.Stop()

	failCount := 0
	for {
		select {
		case <-ticker.C:
			state := m.currentState()
			if state == nil {
				if err := m.reconnect(ctx, nil); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, errManagerClosed) {
					log.Printf("[SSH] Keepalive reconnect failed: %v", err)
				}
				continue
			}

			_, _, err := state.client.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				if failCount > 0 {
					log.Printf("[SSH] Keepalive recovered after %d failures", failCount)
				}
				failCount = 0
				continue
			}

			failCount++
			log.Printf("[SSH] Keepalive failed (count=%d): %v", failCount, err)
			if failCount >= m.keepAliveFail {
				if reconnectErr := m.reconnect(ctx, state); reconnectErr != nil {
					log.Printf("[SSH] Keepalive reconnect failed: %v", reconnectErr)
				} else {
					failCount = 0
				}
			}
		case <-ctx.Done():
			return
		case <-m.lifecycleCtx.Done():
			return
		}
	}
}

func (m *Manager) getClient(ctx context.Context) (*clientState, error) {
	if state := m.currentState(); state != nil {
		return state, nil
	}
	if err := m.reconnect(ctx, nil); err != nil {
		return nil, err
	}
	state := m.currentState()
	if state == nil {
		return nil, errors.New("SSH reconnect completed without a client")
	}
	return state, nil
}

func (m *Manager) reconnect(parent context.Context, failed *clientState) error {
	ctx, cancel := m.linkContext(parent)
	defer cancel()

	select {
	case m.reconnectGate <- struct{}{}:
		defer func() { <-m.reconnectGate }()
	case <-ctx.Done():
		return ctx.Err()
	}

	current := m.currentState()
	if failed == nil && current != nil {
		return nil
	}
	if failed != nil && current != failed {
		return nil
	}

	if current != nil {
		m.clearState(current)
		if err := current.client.Close(); err != nil {
			log.Printf("[SSH] Close failed client: %v", err)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= m.attempts; attempt++ {
		log.Printf("[SSH] Connect attempt %d/%d", attempt, m.attempts)
		client, err := m.connector(ctx)
		if err == nil {
			if installErr := m.installClient(client); installErr != nil {
				return installErr
			}
			log.Printf("[SSH] Connected to %s:%d as %s", m.config.SSHHost, m.config.SSHPort, m.config.SSHUser)
			return nil
		}

		lastErr = err
		log.Printf("[SSH] Connect attempt %d failed: %v", attempt, err)
		if errors.Is(err, errHostKeyVerification) {
			return fmt.Errorf("SSH connect aborted: %w", err)
		}
		if attempt == m.attempts {
			break
		}
		if err := waitContext(ctx, m.backoff(attempt)); err != nil {
			return err
		}
	}
	return fmt.Errorf("SSH reconnect failed after %d attempts: %w", m.attempts, lastErr)
}

func (m *Manager) installClient(client sshClient) error {
	m.mu.Lock()
	if err := m.lifecycleCtx.Err(); err != nil {
		m.mu.Unlock()
		if closeErr := client.Close(); closeErr != nil {
			return errors.Join(errManagerClosed, fmt.Errorf("close late SSH client: %w", closeErr))
		}
		return errManagerClosed
	}

	state := &clientState{client: client}
	previous := m.state
	m.state = state
	m.mu.Unlock()
	if previous != nil {
		if err := previous.client.Close(); err != nil {
			log.Printf("[SSH] Close replaced client: %v", err)
		}
	}
	return nil
}

func (m *Manager) clearState(expected *clientState) {
	m.mu.Lock()
	if m.state == expected {
		m.state = nil
	}
	m.mu.Unlock()
}

func (m *Manager) currentState() *clientState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Manager) acquireConnection(ctx context.Context) error {
	if err := m.lifecycleCtx.Err(); err != nil {
		return errManagerClosed
	}
	select {
	case m.connectionSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errConnectionLimit
	}
}

func (m *Manager) linkContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(m.lifecycleCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Close cancels reconnect/keepalive work and closes the active SSH client.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.lifecycleCancel()
		state := m.currentState()
		if state != nil {
			m.clearState(state)
			if err := state.client.Close(); err != nil {
				m.closeErr = fmt.Errorf("close SSH client: %w", err)
			}
		}
		m.workerMu.Lock()
		keepAliveDone := m.keepAliveDone
		m.workerMu.Unlock()
		if keepAliveDone != nil {
			<-keepAliveDone
		}
		log.Println("[SSH] Manager closed")
	})
	return m.closeErr
}

func reconnectBackoff(attempt int) time.Duration {
	delay := time.Duration(attempt*attempt) * time.Second
	return min(delay, 10*time.Second)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type limitedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func newLimitedConn(conn net.Conn, release func()) *limitedConn {
	return &limitedConn{Conn: conn, release: release}
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

func (c *limitedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}

var _ sshClient = (*ssh.Client)(nil)
