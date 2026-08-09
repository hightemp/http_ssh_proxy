package sshmanager

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
)

type fakeSSHClient struct {
	dial        func(ctx context.Context, network, address string) (net.Conn, error)
	sendRequest func() error
	close       func() error
	closeCalls  atomic.Int64
}

func (c *fakeSSHClient) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return c.dial(ctx, network, address)
}

func (c *fakeSSHClient) SendRequest(_ string, _ bool, _ []byte) (bool, []byte, error) {
	if c.sendRequest == nil {
		return true, nil, nil
	}
	return true, nil, c.sendRequest()
}

func (c *fakeSSHClient) Close() error {
	c.closeCalls.Add(1)
	if c.close == nil {
		return nil
	}
	return c.close()
}

func TestDialContextReconnectsOnceForConcurrentFailures(t *testing.T) {
	const callers = 8
	started := make(chan struct{}, callers)
	releaseFailures := make(chan struct{})
	oldClient := &fakeSSHClient{dial: func(_ context.Context, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-releaseFailures
		return nil, io.EOF
	}}
	newClient := &fakeSSHClient{dial: successfulPipeDial}
	var connectCalls atomic.Int64
	manager := newManager(testManagerConfig(callers), func(context.Context) (sshClient, error) {
		connectCalls.Add(1)
		return newClient, nil
	})
	if err := manager.installClient(oldClient); err != nil {
		t.Fatalf("install initial client: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})

	errorsCh := make(chan error, callers)
	for range callers {
		go func() {
			conn, err := manager.DialContext(context.Background(), "tcp", "example.com:80")
			if err == nil {
				err = conn.Close()
			}
			errorsCh <- err
		}()
	}
	for range callers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("not all callers reached the failed client")
		}
	}
	close(releaseFailures)

	for range callers {
		if err := <-errorsCh; err != nil {
			t.Errorf("DialContext() error = %v", err)
		}
	}
	if got := connectCalls.Load(); got != 1 {
		t.Errorf("connector calls = %d, want 1", got)
	}
	if got := oldClient.closeCalls.Load(); got != 1 {
		t.Errorf("failed client close calls = %d, want 1", got)
	}
}

func TestDialContextDoesNotReconnectDestinationFailure(t *testing.T) {
	destinationErr := &ssh.OpenChannelError{Reason: ssh.ConnectionFailed, Message: "connection refused"}
	client := &fakeSSHClient{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, destinationErr
	}}
	var connectCalls atomic.Int64
	manager := newManager(testManagerConfig(2), func(context.Context) (sshClient, error) {
		connectCalls.Add(1)
		return nil, errors.New("unexpected reconnect")
	})
	if err := manager.installClient(client); err != nil {
		t.Fatalf("install client: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})

	_, err := manager.DialContext(context.Background(), "tcp", "unavailable.example:80")
	if !errors.Is(err, destinationErr) {
		t.Fatalf("DialContext() error = %v, want destination error", err)
	}
	if got := connectCalls.Load(); got != 0 {
		t.Errorf("connector calls = %d, want 0", got)
	}
}

func TestDialContextEnforcesConnectionLimit(t *testing.T) {
	var peersMu sync.Mutex
	var peers []net.Conn
	client := &fakeSSHClient{dial: func(context.Context, string, string) (net.Conn, error) {
		proxySide, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return proxySide, nil
	}}
	manager := newManager(testManagerConfig(1), func(context.Context) (sshClient, error) {
		return nil, errors.New("unexpected reconnect")
	})
	if err := manager.installClient(client); err != nil {
		t.Fatalf("install client: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("close pipe peer: %v", err)
			}
		}
	})

	first, err := manager.DialContext(context.Background(), "tcp", "first.example:80")
	if err != nil {
		t.Fatalf("first DialContext() error = %v", err)
	}
	if _, err := manager.DialContext(context.Background(), "tcp", "second.example:80"); !errors.Is(err, errConnectionLimit) {
		t.Fatalf("second DialContext() error = %v, want connection limit", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	third, err := manager.DialContext(context.Background(), "tcp", "third.example:80")
	if err != nil {
		t.Fatalf("third DialContext() error = %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("close third connection: %v", err)
	}
}

func TestReconnectBackoffHonorsContext(t *testing.T) {
	connectorCalled := make(chan struct{}, 1)
	cfg := testManagerConfig(2)
	cfg.SSHReconnectAttempts = 2
	manager := newManager(cfg, func(context.Context) (sshClient, error) {
		connectorCalled <- struct{}{}
		return nil, errors.New("SSH unavailable")
	})
	manager.backoff = func(int) time.Duration { return time.Hour }
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- manager.Connect(ctx) }()
	select {
	case <-connectorCalled:
	case <-time.After(time.Second):
		t.Fatal("connector was not called")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect backoff ignored context cancellation")
	}
}

func TestReconnectDoesNotSleepAfterFinalAttempt(t *testing.T) {
	cfg := testManagerConfig(1)
	cfg.SSHReconnectAttempts = 1
	manager := newManager(cfg, func(context.Context) (sshClient, error) {
		return nil, errors.New("SSH unavailable")
	})
	manager.backoff = func(int) time.Duration {
		panic("backoff called after final attempt")
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})

	if err := manager.Connect(context.Background()); err == nil {
		t.Fatal("Connect() succeeded, want failure")
	}
}

func TestCloseCancelsActiveConnect(t *testing.T) {
	connectorStarted := make(chan struct{})
	manager := newManager(testManagerConfig(1), func(ctx context.Context) (sshClient, error) {
		close(connectorStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	connectDone := make(chan error, 1)
	go func() { connectDone <- manager.Connect(context.Background()) }()
	select {
	case <-connectorStarted:
	case <-time.After(time.Second):
		t.Fatal("connector did not start")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-connectDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel connector")
	}
}

func successfulPipeDial(context.Context, string, string) (net.Conn, error) {
	proxySide, peer := net.Pipe()
	if err := peer.Close(); err != nil {
		return nil, err
	}
	return proxySide, nil
}

func testManagerConfig(maxConnections int) *config.Config {
	cfg := config.Default()
	cfg.MaxConnections = maxConnections
	cfg.SSHReconnectAttempts = 1
	cfg.SSHHost = "ssh.example.com"
	cfg.SSHPort = 22
	cfg.SSHUser = "proxy"
	return &cfg
}
