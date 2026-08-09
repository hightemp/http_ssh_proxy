// Package sshmanager manages the shared SSH connection used by the proxy.
package sshmanager

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/logutil"

	"golang.org/x/crypto/ssh"
)

// Manager manages the SSH connection with automatic reconnection and keepalive.
type Manager struct {
	config    *config.Config
	client    *ssh.Client
	mu        sync.RWMutex
	closed    chan struct{}
	closeOnce sync.Once
}

// New creates an SSH connection manager.
func New(cfg *config.Config) *Manager {
	return &Manager{
		config: cfg,
		closed: make(chan struct{}),
	}
}

// Connect establishes the initial SSH connection.
func (m *Manager) Connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectLocked()
}

func (m *Manager) connectLocked() error {
	if m.client != nil {
		logutil.Close("previous SSH client", m.client)
		m.client = nil
	}

	client, err := dialSSH(m.config)
	if err != nil {
		return fmt.Errorf("SSH dial failed: %w", err)
	}
	m.client = client
	log.Printf("[SSH] Connected to %s:%d as %s", m.config.SSHHost, m.config.SSHPort, m.config.SSHUser)
	return nil
}

func (m *Manager) reconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if the current client is still alive.
	if m.client != nil {
		_, _, err := m.client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return nil
		}
		log.Printf("[SSH] Connection check failed: %v, reconnecting...", err)
	}

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		log.Printf("[SSH] Reconnect attempt %d/5...", attempt)
		if err := m.connectLocked(); err != nil {
			lastErr = err
			log.Printf("[SSH] Reconnect attempt %d failed: %v", attempt, err)
			backoff := time.Duration(attempt*attempt) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-time.After(backoff):
			case <-m.closed:
				return fmt.Errorf("SSH manager closed during reconnect")
			}
			continue
		}
		log.Printf("[SSH] Reconnected successfully on attempt %d", attempt)
		return nil
	}
	return fmt.Errorf("SSH reconnect failed after 5 attempts: %w", lastErr)
}

func (m *Manager) getClient() (*ssh.Client, error) {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()

	if client != nil {
		return client, nil
	}

	if err := m.reconnect(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client, nil
}

// Dial establishes a connection through the SSH tunnel, reconnecting once if
// the SSH transport appears to be unavailable.
func (m *Manager) Dial(network, addr string) (net.Conn, error) {
	client, err := m.getClient()
	if err != nil {
		return nil, fmt.Errorf("SSH client unavailable: %w", err)
	}

	conn, err := client.Dial(network, addr)
	if err != nil {
		// OpenChannelError means that the SSH server is alive but could not reach
		// this destination. Reconnecting the healthy SSH transport cannot help.
		if isDestinationDialError(err) {
			return nil, fmt.Errorf("SSH destination dial to %s failed: %w", addr, err)
		}

		// The SSH connection may have died — try to reconnect once.
		log.Printf("[SSH] Dial to %s failed (%v), attempting reconnect...", addr, err)
		if reconnectErr := m.reconnect(); reconnectErr != nil {
			return nil, fmt.Errorf("SSH dial failed and reconnect failed: dial=%v reconnect=%v", err, reconnectErr)
		}
		client, err = m.getClient()
		if err != nil {
			return nil, err
		}
		conn, err = client.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("SSH dial failed after reconnect: %w", err)
		}
	}
	return conn, nil
}

// KeepAlive monitors the active SSH connection until the manager is closed.
func (m *Manager) KeepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	failCount := 0
	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			client := m.client
			m.mu.RUnlock()

			if client == nil {
				log.Printf("[SSH] No active client, triggering reconnect...")
				if err := m.reconnect(); err != nil {
					log.Printf("[SSH] Keepalive reconnect failed: %v", err)
				}
				continue
			}

			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				failCount++
				log.Printf("[SSH] Keepalive failed (count=%d): %v", failCount, err)
				if failCount >= 3 {
					log.Printf("[SSH] Keepalive failed %d times, forcing reconnect...", failCount)
					if err := m.reconnect(); err != nil {
						log.Printf("[SSH] Keepalive reconnect failed: %v", err)
					} else {
						failCount = 0
					}
				}
			} else {
				if failCount > 0 {
					log.Printf("[SSH] Keepalive recovered after %d failures", failCount)
				}
				failCount = 0
			}

		case <-m.closed:
			log.Println("[SSH] Keepalive loop stopped")
			return
		}
	}
}

// Close stops keepalive processing and closes the SSH connection.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.client != nil {
			logutil.Close("SSH client", m.client)
			m.client = nil
		}
		log.Println("[SSH] Manager closed")
	})
}
