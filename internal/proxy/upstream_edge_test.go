package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewUpstreamPoolConfigurationPaths(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("not used")}
	pool, err := newUpstreamPool(dialer, UpstreamConfig{}, nil, nil)
	if err != nil {
		t.Fatalf("newUpstreamPool() direct error = %v", err)
	}
	if len(pool.routes) != 1 {
		t.Fatalf("direct routes = %d, want 1", len(pool.routes))
	}
	pool.CloseIdleConnections()

	disabled, err := newUpstreamPool(dialer, UpstreamConfig{
		Proxies: []string{"not a proxy URL"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("newUpstreamPool() disabled configured error = %v", err)
	}
	if len(disabled.routes) != 1 {
		t.Fatalf("disabled configured routes = %d, want direct route", len(disabled.routes))
	}

	if _, err := newUpstreamPool(dialer, UpstreamConfig{Enabled: true}, nil, nil); err == nil {
		t.Fatal("newUpstreamPool() accepted enabled routing without proxies")
	}
	if _, err := newUpstreamPool(dialer, UpstreamConfig{Enabled: true, Strategy: "least-connections", Proxies: []string{"http://proxy.example"}}, nil, nil); err == nil {
		t.Fatal("newUpstreamPool() accepted unsupported strategy")
	}
	if _, err := newUpstreamPool(dialer, UpstreamConfig{
		Enabled:  true,
		Strategy: upstreamStrategyRoundRobin,
		Proxies:  []string{"http://user:supersecret@proxy.example/%zz"},
	}, nil, nil); err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("newUpstreamPool() error = %v, want sanitized invalid URL error", err)
	}
}

func TestValidateConnectTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "hostname", target: "example.com:443"},
		{name: "IPv6", target: "[::1]:443"},
		{name: "missing port", target: "example.com", wantErr: true},
		{name: "empty hostname", target: ":443", wantErr: true},
		{name: "control character", target: "example.com\r\n:443", wantErr: true},
		{name: "zero port", target: "example.com:0", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConnectTarget(tt.target); (err != nil) != tt.wantErr {
				t.Errorf("validateConnectTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestProxyEndpointRejectsInvalidDialInputs(t *testing.T) {
	wantErr := errors.New("SSH dial failed")
	endpoint, err := newProxyEndpoint(&fakeDialer{err: wantErr}, "http://proxy.example:3128", nil)
	if err != nil {
		t.Fatalf("newProxyEndpoint() error = %v", err)
	}
	if _, err := endpoint.DialContext(context.Background(), "udp", "target.example:443"); err == nil {
		t.Fatal("DialContext() accepted UDP")
	}
	if _, err := endpoint.DialContext(context.Background(), "tcp", "target.example:443"); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext() error = %v, want base dial error", err)
	}
}

func TestProxyEndpointReportsDeadlineSetupFailure(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closePipe(t, server) })
	wantErr := errors.New("deadline failed")
	endpoint, err := newProxyEndpoint(&fakeDialer{conn: &faultConn{Conn: client, deadlineErrors: []error{wantErr}}}, "http://proxy.example:3128", nil)
	if err != nil {
		t.Fatalf("newProxyEndpoint() error = %v", err)
	}
	if _, err := endpoint.DialContext(context.Background(), "tcp", "target.example:443"); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext() error = %v, want deadline error", err)
	}
}

func TestUpstreamHandshakeContextDeadlineRace(t *testing.T) {
	wantFailure := errors.New("handshake failed")
	tests := []struct {
		name     string
		deadline time.Time
		writeErr error
		wantErr  error
	}{
		{name: "elapsed deadline", deadline: time.Now().Add(-time.Second), writeErr: os.ErrDeadlineExceeded, wantErr: context.DeadlineExceeded},
		{name: "future deadline", deadline: time.Now().Add(time.Hour), writeErr: os.ErrDeadlineExceeded, wantErr: os.ErrDeadlineExceeded},
		{name: "no deadline", writeErr: os.ErrDeadlineExceeded, wantErr: os.ErrDeadlineExceeded},
		{name: "unrelated failure", deadline: time.Now().Add(-time.Second), writeErr: wantFailure, wantErr: wantFailure},
	}
	for _, scheme := range []string{"http", "https", "socks5"} {
		for _, tt := range tests {
			t.Run(scheme+"/"+tt.name, func(t *testing.T) {
				conn := &faultConn{Conn: newMemoryConn(nil), write: func([]byte) (int, error) { return 0, tt.writeErr }}
				endpoint, err := newProxyEndpoint(&fakeDialer{conn: conn}, scheme+"://proxy.example:1080", nil)
				if err != nil {
					t.Fatalf("newProxyEndpoint() error = %v", err)
				}
				// Model the interval after the socket deadline fires but before
				// the context timer publishes its cancellation.
				ctx := pendingDeadlineContext{Context: context.Background(), deadline: tt.deadline}
				if _, err := endpoint.DialContext(ctx, "tcp", "target.example:443"); !errors.Is(err, tt.wantErr) {
					t.Fatalf("DialContext() error = %v, want %v", err, tt.wantErr)
				}
			})
		}
	}
}

type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) {
	return c.deadline, !c.deadline.IsZero()
}

func TestSOCKS5ConnectRequestAddressTypes(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantType byte
		wantErr  bool
	}{
		{name: "domain", target: "example.com:443", wantType: 0x03},
		{name: "IPv4", target: "192.0.2.1:80", wantType: 0x01},
		{name: "IPv6", target: "[2001:db8::1]:8443", wantType: 0x04},
		{name: "missing port", target: "example.com", wantErr: true},
		{name: "zero port", target: "example.com:0", wantErr: true},
		{name: "long hostname", target: strings.Repeat("a", 256) + ":443", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := socks5ConnectRequest(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("socks5ConnectRequest() = %v, want error", request)
				}
				return
			}
			if err != nil {
				t.Fatalf("socks5ConnectRequest() error = %v", err)
			}
			if len(request) < 4 || request[3] != tt.wantType {
				t.Errorf("request = %v, want address type %d", request, tt.wantType)
			}
		})
	}
}

func TestReadSOCKS5ConnectResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantErr  bool
	}{
		{name: "IPv4", response: []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80}},
		{name: "IPv6", response: append([]byte{0x05, 0x00, 0x00, 0x04}, make([]byte, 18)...)},
		{name: "domain", response: []byte{0x05, 0x00, 0x00, 0x03, 0x03, 'f', 'o', 'o', 0, 80}},
		{name: "wrong version", response: []byte{0x04, 0x00, 0x00, 0x01}, wantErr: true},
		{name: "failure reply", response: []byte{0x05, 0x05, 0x00, 0x01}, wantErr: true},
		{name: "unknown address type", response: []byte{0x05, 0x00, 0x00, 0x09}, wantErr: true},
		{name: "truncated header", response: []byte{0x05}, wantErr: true},
		{name: "truncated domain length", response: []byte{0x05, 0x00, 0x00, 0x03}, wantErr: true},
		{name: "truncated address", response: []byte{0x05, 0x00, 0x00, 0x01, 127}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMemoryConn(tt.response)
			if err := readSOCKS5ConnectResponse(conn); (err != nil) != tt.wantErr {
				t.Errorf("readSOCKS5ConnectResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSOCKS5NegotiationFailures(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		user     *url.Userinfo
	}{
		{name: "wrong version", response: []byte{0x04, 0x00}},
		{name: "no methods", response: []byte{0x05, 0xff}},
		{name: "unsupported method", response: []byte{0x05, 0x03}},
		{name: "credentials not configured", response: []byte{0x05, 0x02}},
		{name: "authentication rejected", response: []byte{0x05, 0x02, 0x01, 0x01}, user: url.UserPassword("user", "secret")},
		{
			name:     "CONNECT rejected",
			response: []byte{0x05, 0x00, 0x05, 0x01, 0x00, 0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMemoryConn(tt.response)
			if err := connectSOCKS5Proxy(conn, tt.user, "target.example:443"); err == nil {
				t.Fatal("connectSOCKS5Proxy() succeeded, want failure")
			}
		})
	}
}

func TestUpstreamConnectionHelpers(t *testing.T) {
	t.Run("buffered and raw reads", func(t *testing.T) {
		conn := newMemoryConn([]byte("raw"))
		reader := bufio.NewReader(strings.NewReader("buffered"))
		if _, err := reader.Peek(len("buffered")); err != nil {
			t.Fatalf("buffer test data: %v", err)
		}
		buffered := &bufferedProxyConn{Conn: conn, reader: reader}
		data, err := io.ReadAll(buffered)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if string(data) != "bufferedraw" {
			t.Errorf("ReadAll() = %q, want bufferedraw", data)
		}
	})

	t.Run("CloseWrite", func(t *testing.T) {
		wantErr := errors.New("close write failed")
		conn := &closeWriteMemoryConn{memoryConn: *newMemoryConn(nil), err: wantErr}
		buffered := &bufferedProxyConn{Conn: conn, reader: bufio.NewReader(strings.NewReader(""))}
		if err := buffered.CloseWrite(); !errors.Is(err, wantErr) {
			t.Fatalf("CloseWrite() error = %v, want injected error", err)
		}
		unsupported := &bufferedProxyConn{Conn: newMemoryConn(nil), reader: bufio.NewReader(strings.NewReader(""))}
		if err := unsupported.CloseWrite(); err != nil {
			t.Fatalf("unsupported CloseWrite() error = %v", err)
		}
	})

	t.Run("writeAll detects no progress", func(t *testing.T) {
		if err := writeAll(zeroWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writeAll() error = %v, want io.ErrShortWrite", err)
		}
	})

	t.Run("close error is joined", func(t *testing.T) {
		operationErr := errors.New("operation failed")
		closeErr := errors.New("close failed")
		conn := &closeErrorMemoryConn{memoryConn: *newMemoryConn(nil), err: closeErr}
		err := closeProxyAfterError(conn, operationErr)
		if !errors.Is(err, operationErr) || !errors.Is(err, closeErr) {
			t.Fatalf("closeProxyAfterError() = %v, want joined errors", err)
		}
	})

	t.Run("TLS config clone", func(t *testing.T) {
		source := &tls.Config{MinVersion: tls.VersionTLS13}
		cloned := cloneTLSConfig(source)
		if cloned == source || cloned.MinVersion != tls.VersionTLS13 {
			t.Fatalf("cloneTLSConfig() = %#v", cloned)
		}
	})
}

type memoryConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
	closed bool
}

func newMemoryConn(data []byte) *memoryConn {
	return &memoryConn{reader: bytes.NewReader(data)}
}

func (c *memoryConn) Read(data []byte) (int, error)    { return c.reader.Read(data) }
func (c *memoryConn) Write(data []byte) (int, error)   { return c.writes.Write(data) }
func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return memoryAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return memoryAddr("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type closeWriteMemoryConn struct {
	memoryConn
	err error
}

func (c *closeWriteMemoryConn) CloseWrite() error { return c.err }

type closeErrorMemoryConn struct {
	memoryConn
	err error
}

func (c *closeErrorMemoryConn) Close() error { return c.err }

type memoryAddr string

func (a memoryAddr) Network() string { return string(a) }
func (a memoryAddr) String() string  { return string(a) }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

var _ net.Conn = (*memoryConn)(nil)

func TestNewHandlerWithUpstreamsRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewHandlerWithUpstreams(Config{}, &fakeDialer{}, UpstreamConfig{
		Enabled:  true,
		Strategy: upstreamStrategyRoundRobin,
		Proxies:  []string{"invalid"},
	}); err == nil {
		t.Fatal("NewHandlerWithUpstreams() accepted invalid proxy URL")
	}

	handler, err := NewHandlerWithUpstreams(Config{}, &fakeDialer{err: errors.New("not used")}, UpstreamConfig{})
	if err != nil {
		t.Fatalf("NewHandlerWithUpstreams() direct error = %v", err)
	}
	shutdownTestHandler(t, handler)
}
