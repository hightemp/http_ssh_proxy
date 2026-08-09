package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHandlerRejectsWorkDuringShutdownAndRequiresAuthentication(t *testing.T) {
	t.Run("shutdown", func(t *testing.T) {
		handler := NewHandler(Config{}, &fakeDialer{})
		if err := handler.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com", nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", recorder.Code)
		}
	})

	t.Run("authentication", func(t *testing.T) {
		handler := NewHandler(Config{Username: "proxy", Password: "secret"}, &fakeDialer{})
		t.Cleanup(func() { shutdownTestHandler(t, handler) })
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com", nil))
		if recorder.Code != http.StatusProxyAuthRequired {
			t.Errorf("status = %d, want 407", recorder.Code)
		}
	})
}

func TestHandleConnectRejectsInvalidTargetAndUnsupportedHijacking(t *testing.T) {
	handler := NewHandler(Config{}, &fakeDialer{})
	t.Cleanup(func() { shutdownTestHandler(t, handler) })

	tests := []struct {
		name       string
		host       string
		wantStatus int
	}{
		{name: "invalid target", host: "missing-port", wantStatus: http.StatusBadRequest},
		{name: "no hijacker", host: "example.com:443", wantStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
			request.Host = tt.host
			recorder := httptest.NewRecorder()
			handler.handleConnect(recorder, request, 1)
			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandleConnectFailureStages(t *testing.T) {
	wantErr := errors.New("injected failure")
	tests := []struct {
		name       string
		clientConn func(net.Conn) net.Conn
		targetConn func(net.Conn) net.Conn
		writer     func() *bufio.Writer
		hijackErr  error
		closing    bool
	}{
		{
			name:      "hijack failure",
			hijackErr: wantErr,
		},
		{
			name: "client deadline failure",
			clientConn: func(conn net.Conn) net.Conn {
				return &faultConn{Conn: conn, deadlineErrors: []error{wantErr}}
			},
		},
		{
			name: "target deadline failure",
			targetConn: func(conn net.Conn) net.Conn {
				return &faultConn{Conn: conn, deadlineErrors: []error{wantErr}}
			},
		},
		{
			name: "CONNECT response write failure",
			writer: func() *bufio.Writer {
				return bufio.NewWriterSize(errorWriter{err: wantErr}, 1)
			},
		},
		{
			name: "CONNECT response flush failure",
			writer: func() *bufio.Writer {
				return bufio.NewWriter(errorWriter{err: wantErr})
			},
		},
		{
			name:    "handler starts closing before registration",
			closing: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, targetPeer := net.Pipe()
			client, clientPeer := net.Pipe()
			defer closePipe(t, targetPeer)
			defer closePipe(t, clientPeer)

			if tt.targetConn != nil {
				target = tt.targetConn(target)
			}
			if tt.clientConn != nil {
				client = tt.clientConn(client)
			}
			writer := bufio.NewWriter(client)
			if tt.writer != nil {
				writer = tt.writer()
			}
			response := &hijackResponseWriter{
				header: http.Header{},
				conn:   client,
				buffer: bufio.NewReadWriter(bufio.NewReader(client), writer),
				err:    tt.hijackErr,
			}
			handler := NewHandler(Config{TunnelIdleTimeout: time.Second}, &fakeDialer{conn: target})
			if tt.closing {
				handler.tunnelsMu.Lock()
				handler.closing = true
				handler.tunnelsMu.Unlock()
			}
			request := httptest.NewRequest(http.MethodConnect, "http://proxy.invalid", nil)
			request.Host = "example.com:443"
			handler.handleConnect(response, request, 1)
			if len(handler.tunnels) != 0 {
				t.Errorf("active tunnels = %d, want 0", len(handler.tunnels))
			}
			if !handler.closing {
				shutdownTestHandler(t, handler)
			}
		})
	}
}

func TestHTTPErrorAndNormalizationPaths(t *testing.T) {
	t.Run("missing request host", func(t *testing.T) {
		handler := NewHandler(Config{}, &fakeDialer{})
		t.Cleanup(func() { shutdownTestHandler(t, handler) })
		request := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: "/resource"},
			Header: http.Header{},
		}
		recorder := httptest.NewRecorder()
		handler.handleHTTP(recorder, request, 1)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", recorder.Code)
		}
	})

	t.Run("relative URL is normalized", func(t *testing.T) {
		request := &http.Request{
			Method: http.MethodGet,
			Host:   "example.com",
			URL:    &url.URL{Path: "/resource"},
			Header: http.Header{"User-Agent": {"test-agent"}},
		}
		out, err := outboundRequest(request)
		if err != nil {
			t.Fatalf("outboundRequest() error = %v", err)
		}
		if out.URL.Scheme != "http" || out.URL.Host != "example.com" {
			t.Errorf("normalized URL = %s, want http://example.com/resource", out.URL)
		}
		if out.Header.Get("User-Agent") != "test-agent" {
			t.Error("existing User-Agent was not preserved")
		}
	})

	t.Run("response body read failure", func(t *testing.T) {
		handler := NewHandler(Config{}, &fakeDialer{})
		handler.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(errorReader{err: errors.New("body read failed")}),
			}, nil
		})}
		t.Cleanup(func() { shutdownTestHandler(t, handler) })
		recorder := httptest.NewRecorder()
		handler.handleHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com", nil), 1)
		if recorder.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", recorder.Code)
		}
	})

	t.Run("hop-by-hop trailer is ignored", func(t *testing.T) {
		header := http.Header{}
		if keys := announceTrailers(header, http.Header{"Connection": {"secret"}}); len(keys) != 0 {
			t.Errorf("announced trailers = %v, want none", keys)
		}
		if isHopByHopHeader("X-End-To-End") {
			t.Error("end-to-end header classified as hop-by-hop")
		}
	})
}

func TestIdleConnectionFailurePaths(t *testing.T) {
	wantErr := errors.New("deadline failed")

	if _, err := newIdleConn(&faultConn{deadlineErrors: []error{wantErr}}, time.Second); !errors.Is(err, wantErr) {
		t.Fatalf("newIdleConn() error = %v, want deadline failure", err)
	}
	if err := (&idleConn{Conn: &faultConn{}, timeout: 0}).touch(); err != nil {
		t.Fatalf("touch() with disabled timeout error = %v", err)
	}

	t.Run("read refresh", func(t *testing.T) {
		conn := &faultConn{
			deadlineErrors: []error{nil, wantErr},
			read: func(data []byte) (int, error) {
				return copy(data, "x"), nil
			},
		}
		got := &idleConn{Conn: conn, timeout: time.Second}
		if n, err := got.Read(make([]byte, 1)); n != 1 || !errors.Is(err, wantErr) {
			t.Fatalf("Read() = %d, %v; want 1 and deadline failure", n, err)
		}
	})

	t.Run("write refresh", func(t *testing.T) {
		conn := &faultConn{
			deadlineErrors: []error{nil, wantErr},
			write: func(data []byte) (int, error) {
				return len(data), nil
			},
		}
		got := &idleConn{Conn: conn, timeout: time.Second}
		if n, err := got.Write([]byte("x")); n != 1 || !errors.Is(err, wantErr) {
			t.Fatalf("Write() = %d, %v; want 1 and deadline failure", n, err)
		}
	})

	t.Run("activity reader refresh", func(t *testing.T) {
		conn := &faultConn{deadlineErrors: []error{nil, wantErr}}
		reader := activityReader{
			reader: strings.NewReader("x"),
			conn:   &idleConn{Conn: conn, timeout: time.Second},
		}
		if n, err := reader.Read(make([]byte, 1)); n != 1 || !errors.Is(err, wantErr) {
			t.Fatalf("Read() = %d, %v; want 1 and deadline failure", n, err)
		}
	})

	logTransferResult(1, transferResult{direction: "test", err: errors.New("unexpected transfer failure")})
}

type hijackResponseWriter struct {
	header http.Header
	conn   net.Conn
	buffer *bufio.ReadWriter
	err    error
	body   bytes.Buffer
	status int
}

func (w *hijackResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackResponseWriter) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func (w *hijackResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.buffer, w.err
}

type faultConn struct {
	net.Conn
	deadlineErrors []error
	deadlineCall   int
	read           func([]byte) (int, error)
	write          func([]byte) (int, error)
}

func (c *faultConn) SetDeadline(time.Time) error {
	if c.deadlineCall >= len(c.deadlineErrors) {
		return nil
	}
	err := c.deadlineErrors[c.deadlineCall]
	c.deadlineCall++
	return err
}

func (c *faultConn) Read(data []byte) (int, error) {
	if c.read != nil {
		return c.read(data)
	}
	return c.Conn.Read(data)
}

func (c *faultConn) Write(data []byte) (int, error) {
	if c.write != nil {
		return c.write(data)
	}
	return c.Conn.Write(data)
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func closePipe(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close pipe: %v", err)
	}
}
