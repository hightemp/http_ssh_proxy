package app

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"
	"github.com/hightemp/http_ssh_proxy/internal/proxy"
)

type fixedConnDialer struct {
	conn net.Conn
}

func (d fixedConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

type fakeManager struct {
	connectErr error
	closeErr   error
	connected  atomic.Bool
	keepAlive  atomic.Bool
	closed     atomic.Bool
}

func (m *fakeManager) Connect(context.Context) error {
	m.connected.Store(true)
	return m.connectErr
}

func (m *fakeManager) StartKeepAlive(context.Context) {
	m.keepAlive.Store(true)
}

func (m *fakeManager) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected proxy dial")
}

func (m *fakeManager) Close() error {
	m.closed.Store(true)
	return m.closeErr
}

func TestRunStopsAllComponentsWhenContextIsCanceled(t *testing.T) {
	cfg := config.Default()
	cfg.ProxyAddr = "127.0.0.1:0"
	manager := &fakeManager{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := run(ctx, &cfg, manager); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !manager.connected.Load() {
		t.Error("SSH manager was not connected")
	}
	if !manager.keepAlive.Load() {
		t.Error("SSH keepalive was not started")
	}
	if !manager.closed.Load() {
		t.Error("SSH manager was not closed")
	}
}

func TestRunReturnsConnectError(t *testing.T) {
	wantErr := errors.New("authentication failed")
	manager := &fakeManager{connectErr: wantErr}
	if err := run(context.Background(), ptr(config.Default()), manager); !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want connect error", err)
	}
	if manager.keepAlive.Load() {
		t.Error("keepalive started after a failed connect")
	}
	if !manager.closed.Load() {
		t.Error("SSH manager was not closed after a failed connect")
	}
}

func TestRunReturnsUpstreamSetupError(t *testing.T) {
	cfg := config.Default()
	cfg.UpstreamsEnabled = true
	cfg.UpstreamStrategy = "least-connections"
	cfg.Upstreams = []string{"http://proxy.example"}
	manager := &fakeManager{}
	err := run(context.Background(), &cfg, manager)
	if err == nil || !strings.Contains(err.Error(), "set up upstream proxy routing") {
		t.Fatalf("run() error = %v, want upstream setup error", err)
	}
	if !manager.connected.Load() || !manager.keepAlive.Load() || !manager.closed.Load() {
		t.Errorf(
			"manager lifecycle = connected %v keepalive %v closed %v; want all true",
			manager.connected.Load(),
			manager.keepAlive.Load(),
			manager.closed.Load(),
		)
	}
}

func TestRunClosesManagerAfterListenError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { closeTestConn(t, listener, "listener") })

	cfg := config.Default()
	cfg.ProxyAddr = listener.Addr().String()
	closeErr := errors.New("close failed")
	manager := &fakeManager{closeErr: closeErr}
	err = run(context.Background(), &cfg, manager)
	if err == nil || !strings.Contains(err.Error(), "listen on") || !errors.Is(err, closeErr) {
		t.Fatalf("run() error = %v, want listen and manager close errors", err)
	}
	if !manager.closed.Load() {
		t.Error("SSH manager was not closed")
	}
}

func TestProxyListener(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		cfg := config.Default()
		cfg.ProxyAddr = "127.0.0.1:0"
		listener, err := proxyListener(&cfg)
		if err != nil {
			t.Fatalf("proxyListener() error = %v", err)
		}
		closeTestConn(t, listener, "HTTP listener")
	})

	t.Run("invalid TLS key pair", func(t *testing.T) {
		cfg := config.Default()
		cfg.ProxyAddr = "127.0.0.1:0"
		cfg.Proto = "https"
		cfg.CertPath = "missing-cert.pem"
		cfg.KeyPath = "missing-key.pem"
		listener, err := proxyListener(&cfg)
		if err == nil || !strings.Contains(err.Error(), "load TLS certificate") {
			t.Fatalf("proxyListener() error = %v, want TLS certificate error", err)
		}
		if listener != nil {
			t.Fatal("proxyListener() returned a listener after TLS failure")
		}
	})

	t.Run("HTTPS", func(t *testing.T) {
		certificatePath, keyPath := writeTestCertificate(t)
		cfg := config.Default()
		cfg.ProxyAddr = "127.0.0.1:0"
		cfg.Proto = "https"
		cfg.CertPath = certificatePath
		cfg.KeyPath = keyPath
		listener, err := proxyListener(&cfg)
		if err != nil {
			t.Fatalf("proxyListener() error = %v", err)
		}
		if listener.Addr() == nil {
			t.Error("HTTPS listener has no address")
		}
		closeTestConn(t, listener, "HTTPS listener")
	})
}

func TestShutdownWaitsThenClosesHijackedConnections(t *testing.T) {
	proxySide, remoteSide := net.Pipe()
	t.Cleanup(func() { closeTestConn(t, remoteSide, "destination") })
	handler := proxy.NewHandler(proxy.Config{TunnelIdleTimeout: time.Minute}, fixedConnDialer{conn: proxySide})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { closeTestConn(t, client, "client") })
	if _, err := io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(client)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	err = shutdown(server, handler, 30*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown() error = %v, want context deadline exceeded", err)
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("Serve() error = %v, want http.ErrServerClosed", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP server did not stop")
	}
}

func TestNormalizeServeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "server closed", err: http.ErrServerClosed, want: false},
		{name: "unexpected", err: errors.New("listener failed"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeServeError(tt.err); (got != nil) != tt.want {
				t.Errorf("normalizeServeError(%v) = %v", tt.err, got)
			}
		})
	}
}

func ptr[T any](value T) *T {
	return &value
}

func closeTestConn(t *testing.T, closer io.Closer, name string) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close %s: %v", name, err)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "certificate.pem")
	keyPath := filepath.Join(directory, "key.pem")
	certificatePEM := pemEncode("CERTIFICATE", certificateDER)
	keyPEM := pemEncode("PRIVATE KEY", privateKeyDER)
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certificatePath, keyPath
}

func pemEncode(blockType string, contents []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents})
}
