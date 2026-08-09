package sshmanager

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewManagerAppliesFallbackLimits(t *testing.T) {
	cfg := testManagerConfig(0)
	cfg.SSHReconnectAttempts = 0
	manager := newManager(cfg, func(context.Context) (sshClient, error) {
		return nil, errors.New("not used")
	})
	t.Cleanup(func() { closeTestManager(t, manager) })

	if got := cap(manager.connectionSem); got != defaultMaxConnections {
		t.Errorf("connection limit = %d, want %d", got, defaultMaxConnections)
	}
	if manager.attempts != defaultReconnectAttempts {
		t.Errorf("reconnect attempts = %d, want %d", manager.attempts, defaultReconnectAttempts)
	}
}

func TestDialContextFailureStages(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) *Manager
	}{
		{
			name: "initial client unavailable",
			setup: func(t *testing.T) *Manager {
				return newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
					return nil, errors.New("SSH unavailable")
				})
			},
		},
		{
			name: "reconnect fails after transport failure",
			setup: func(t *testing.T) *Manager {
				manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
					return nil, errors.New("reconnect unavailable")
				})
				installTestClient(t, manager, &fakeSSHClient{dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("transport failed")
				}})
				return manager
			},
		},
		{
			name: "dial fails after successful reconnect",
			setup: func(t *testing.T) *Manager {
				newClient := &fakeSSHClient{dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("second dial failed")
				}}
				manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
					return newClient, nil
				})
				installTestClient(t, manager, &fakeSSHClient{dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("transport failed")
				}})
				return manager
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := tt.setup(t)
			t.Cleanup(func() { closeTestManager(t, manager) })
			if _, err := manager.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
				t.Fatal("DialContext() succeeded, want failure")
			}
			if len(manager.connectionSem) != 0 {
				t.Errorf("connection slots in use = %d, want 0", len(manager.connectionSem))
			}
		})
	}
}

func TestDialContextReconnectsWhenNoClientExists(t *testing.T) {
	manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
		return &fakeSSHClient{dial: successfulPipeDial}, nil
	})
	t.Cleanup(func() { closeTestManager(t, manager) })

	conn, err := manager.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close connection: %v", err)
	}
}

func TestManagerCancellationAndClosedPaths(t *testing.T) {
	t.Run("reconnect gate cancellation", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		manager.reconnectGate <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := manager.reconnect(ctx, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("reconnect() error = %v, want context canceled", err)
		}
		<-manager.reconnectGate
		closeTestManager(t, manager)
	})

	t.Run("dial after close", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		closeTestManager(t, manager)
		if _, err := manager.DialContext(context.Background(), "tcp", "example.com:80"); !errors.Is(err, errManagerClosed) {
			t.Fatalf("DialContext() error = %v, want manager closed", err)
		}
		manager.StartKeepAlive(context.Background())
	})

	t.Run("caller canceled while capacity is exhausted", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		t.Cleanup(func() { closeTestManager(t, manager) })
		manager.connectionSem <- struct{}{}
		defer func() { <-manager.connectionSem }()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := manager.DialContext(ctx, "tcp", "example.com:80"); !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext() error = %v, want context canceled", err)
		}
	})
}

func TestReconnectSkipsUnnecessaryWork(t *testing.T) {
	manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
		return nil, errors.New("not used")
	})
	client := &fakeSSHClient{dial: successfulPipeDial}
	installTestClient(t, manager, client)
	t.Cleanup(func() { closeTestManager(t, manager) })

	if err := manager.reconnect(context.Background(), nil); err != nil {
		t.Fatalf("reconnect current client error = %v", err)
	}
	stale := &clientState{client: &fakeSSHClient{dial: successfulPipeDial}}
	if err := manager.reconnect(context.Background(), stale); err != nil {
		t.Fatalf("reconnect stale client error = %v", err)
	}
}

func TestInstallClientHandlesLateAndReplacedClients(t *testing.T) {
	t.Run("late client", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		closeTestManager(t, manager)
		client := &fakeSSHClient{dial: successfulPipeDial}
		if err := manager.installClient(client); !errors.Is(err, errManagerClosed) {
			t.Fatalf("installClient() error = %v, want manager closed", err)
		}
		if client.closeCalls.Load() != 1 {
			t.Errorf("late client close calls = %d, want 1", client.closeCalls.Load())
		}
	})

	t.Run("late client close failure", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		closeTestManager(t, manager)
		closeErr := errors.New("close failed")
		client := &fakeSSHClient{dial: successfulPipeDial, close: func() error { return closeErr }}
		if err := manager.installClient(client); !errors.Is(err, closeErr) {
			t.Fatalf("installClient() error = %v, want close failure", err)
		}
	})

	t.Run("replaced client close failure", func(t *testing.T) {
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		oldClient := &fakeSSHClient{dial: successfulPipeDial, close: func() error { return errors.New("close failed") }}
		installTestClient(t, manager, oldClient)
		installTestClient(t, manager, &fakeSSHClient{dial: successfulPipeDial})
		if oldClient.closeCalls.Load() != 1 {
			t.Errorf("replaced client close calls = %d, want 1", oldClient.closeCalls.Load())
		}
		closeTestManager(t, manager)
	})
}

func TestKeepAliveRecoveryAndFailurePaths(t *testing.T) {
	t.Run("recovers after one failure", func(t *testing.T) {
		var calls atomic.Int64
		requests := make(chan int64, 4)
		client := &fakeSSHClient{
			dial: successfulPipeDial,
			sendRequest: func() error {
				call := calls.Add(1)
				requests <- call
				if call == 1 {
					return errors.New("temporary failure")
				}
				return nil
			},
		}
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		manager.keepAliveTick = time.Millisecond
		manager.keepAliveFail = 3
		installTestClient(t, manager, client)
		ctx, cancel := context.WithCancel(context.Background())
		manager.StartKeepAlive(ctx)
		for range 2 {
			select {
			case <-requests:
			case <-time.After(time.Second):
				t.Fatal("keepalive request was not sent")
			}
		}
		cancel()
		closeTestManager(t, manager)
	})

	t.Run("missing client reconnect failure", func(t *testing.T) {
		connectorCalled := make(chan struct{}, 1)
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			connectorCalled <- struct{}{}
			return nil, errors.New("SSH unavailable")
		})
		manager.keepAliveTick = time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		manager.StartKeepAlive(ctx)
		select {
		case <-connectorCalled:
		case <-time.After(time.Second):
			t.Fatal("keepalive reconnect was not attempted")
		}
		cancel()
		closeTestManager(t, manager)
	})

	t.Run("failed client reconnect failure", func(t *testing.T) {
		connectorCalled := make(chan struct{}, 1)
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			connectorCalled <- struct{}{}
			return nil, errors.New("SSH unavailable")
		})
		manager.keepAliveTick = time.Millisecond
		manager.keepAliveFail = 1
		installTestClient(t, manager, &fakeSSHClient{
			dial:        successfulPipeDial,
			sendRequest: func() error { return errors.New("keepalive failed") },
		})
		ctx, cancel := context.WithCancel(context.Background())
		manager.StartKeepAlive(ctx)
		select {
		case <-connectorCalled:
		case <-time.After(time.Second):
			t.Fatal("keepalive reconnect was not attempted")
		}
		cancel()
		closeTestManager(t, manager)
	})
}

func TestCloseWaitAndLimitedConnectionEdges(t *testing.T) {
	t.Run("client close failure", func(t *testing.T) {
		wantErr := errors.New("close failed")
		manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
			return nil, errors.New("not used")
		})
		installTestClient(t, manager, &fakeSSHClient{
			dial:  successfulPipeDial,
			close: func() error { return wantErr },
		})
		if err := manager.Close(); !errors.Is(err, wantErr) {
			t.Fatalf("Close() error = %v, want close failure", err)
		}
	})

	if err := waitContext(context.Background(), time.Nanosecond); err != nil {
		t.Fatalf("waitContext() error = %v", err)
	}

	t.Run("CloseWrite supported", func(t *testing.T) {
		wantErr := errors.New("close write failed")
		conn := &limitedConn{Conn: closeWriteConn{err: wantErr}, release: func() {}}
		if err := conn.CloseWrite(); !errors.Is(err, wantErr) {
			t.Fatalf("CloseWrite() error = %v, want close-write failure", err)
		}
	})

	t.Run("CloseWrite unsupported", func(t *testing.T) {
		conn, peer := net.Pipe()
		defer func() { _ = conn.Close() }()
		defer func() { _ = peer.Close() }()
		limited := &limitedConn{Conn: conn, release: func() {}}
		if err := limited.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite() error = %v", err)
		}
	})
}

type closeWriteConn struct {
	net.Conn
	err error
}

func (c closeWriteConn) CloseWrite() error {
	return c.err
}

func installTestClient(t *testing.T, manager *Manager, client sshClient) {
	t.Helper()
	if err := manager.installClient(client); err != nil {
		t.Fatalf("install client: %v", err)
	}
}

func closeTestManager(t *testing.T, manager *Manager) {
	t.Helper()
	if err := manager.Close(); err != nil {
		t.Errorf("close manager: %v", err)
	}
}
