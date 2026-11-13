package sshmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/proxy"
	"golang.org/x/crypto/ssh"
)

func TestHTTPSProxyCONNECTThroughRealSSH(t *testing.T) {
	manager, _ := newDeadlineTestManager(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, "HTTPS through a real SSH channel"); err != nil {
			t.Errorf("write origin response: %v", err)
		}
	}))
	t.Cleanup(origin.Close)
	handler := proxy.NewHandler(proxy.Config{Username: "test-user", Password: "test-password", TunnelIdleTimeout: 2 * time.Second}, manager)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := handler.Shutdown(ctx); err != nil {
			t.Errorf("shut down proxy handler: %v", err)
		}
	})
	frontend := httptest.NewTLSServer(handler)
	t.Cleanup(frontend.Close)
	proxyURL, err := url.Parse(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("test-user", "test-password")
	roots := x509.NewCertPool()
	roots.AddCert(frontend.Certificate())
	roots.AddCert(origin.Certificate())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTPS CONNECT through SSH: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatalf("read origin response: %v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "HTTPS through a real SSH channel" {
		t.Fatalf("origin response = %d %q", response.StatusCode, body)
	}
}

func TestSSHForwardedConnectionDeadlineRegression(t *testing.T) {
	manager, address := newDeadlineTestManager(t)
	conn := dialDeadlineTestConn(t, manager, address)
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline on a real SSH channel: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set SSH read deadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set SSH write deadline: %v", err)
	}
	assertDeadlineEcho(t, conn)
	writer, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("forwarded connection lost CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatalf("half-close SSH channel: %v", err)
	}
	if extra, err := io.ReadAll(conn); err != nil || len(extra) != 0 {
		t.Fatalf("read after half-close = %q, %v; want clean EOF", extra, err)
	}
}

func TestSSHForwardedReadDeadlineClosesOnlyChannel(t *testing.T) {
	manager, address := newDeadlineTestManager(t)
	conn := dialDeadlineTestConn(t, manager, address)
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle SSH read error = %v, want deadline exceeded", err)
	}
	if err := conn.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("close expired channel: %v", err)
	}
	// A timed-out channel must not close the shared SSH transport or keep the
	// only connection-budget slot occupied.
	next := dialDeadlineTestConn(t, manager, address)
	if err := next.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set next channel deadline: %v", err)
	}
	assertDeadlineEcho(t, next)
}

func TestSSHForwardedDeadlineCanBeCleared(t *testing.T) {
	manager, address := newDeadlineTestManager(t)
	conn := dialDeadlineTestConn(t, manager, address)
	if err := conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set initial deadline: %v", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	// Cross the canceled deadline before using the channel again.
	<-time.After(200 * time.Millisecond)
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set replacement deadline: %v", err)
	}
	assertDeadlineEcho(t, conn)
}

func newDeadlineTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	server := newTestSSHServer(t, "deadline-proxy", "test-password")
	t.Cleanup(server.close)
	target := newEchoServer(t)
	t.Cleanup(target.close)
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.SSHHost, cfg.SSHPort = host, port
	cfg.SSHUser, cfg.SSHPassword = "deadline-proxy", "test-password"
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(server.hostKey.PublicKey())
	cfg.MaxConnections = 1
	manager := New(&cfg)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close SSH manager: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatalf("connect SSH manager: %v", err)
	}
	return manager, target.listener.Addr().String()
}

func dialDeadlineTestConn(t *testing.T, manager *Manager, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := manager.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("dial forwarded connection: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("close forwarded connection: %v", err)
		}
	})
	return conn
}

func assertDeadlineEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	message := []byte("real SSH channel with a deadline")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(message) {
		t.Fatalf("echo = %q, want %q", got, message)
	}
}
