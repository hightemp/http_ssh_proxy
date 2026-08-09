package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type dialCall struct {
	network string
	addr    string
}

type fakeDialer struct {
	conn  net.Conn
	err   error
	calls chan dialCall
}

func (d *fakeDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	if d.calls != nil {
		d.calls <- dialCall{network: network, addr: addr}
	}
	return d.conn, d.err
}

func TestHandleConnect(t *testing.T) {
	tests := []struct {
		name       string
		earlyData  string
		remoteData string
	}{
		{
			name:       "bidirectional tunnel",
			remoteData: "response through tunnel",
		},
		{
			name:       "preserves bytes buffered with CONNECT request",
			earlyData:  "early TLS client bytes",
			remoteData: "TLS server bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxySide, remoteSide := net.Pipe()
			t.Cleanup(func() {
				_ = remoteSide.Close()
			})

			dialer := &fakeDialer{
				conn:  proxySide,
				calls: make(chan dialCall, 1),
			}
			handler := NewHandler(Config{TunnelIdleTimeout: 5 * time.Second}, dialer)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.handleConnect(w, r, 1)
			}))
			t.Cleanup(server.Close)

			clientConn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatalf("dial test proxy: %v", err)
			}
			t.Cleanup(func() {
				_ = clientConn.Close()
			})
			if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + tt.earlyData
			if _, err := io.WriteString(clientConn, request); err != nil {
				t.Fatalf("write CONNECT request: %v", err)
			}

			reader := bufio.NewReader(clientConn)
			statusLine, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read CONNECT status: %v", err)
			}
			if want := "HTTP/1.1 200 Connection Established\r\n"; statusLine != want {
				t.Fatalf("CONNECT status = %q, want %q", statusLine, want)
			}

			var headers []string
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("read CONNECT headers: %v", err)
				}
				if line == "\r\n" {
					break
				}
				headers = append(headers, line)
			}
			if len(headers) != 0 {
				t.Errorf("successful CONNECT returned unexpected headers: %q", headers)
			}

			select {
			case call := <-dialer.calls:
				if call.network != "tcp" || call.addr != "example.com:443" {
					t.Errorf("Dial() call = %q %q, want tcp example.com:443", call.network, call.addr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for proxy dial")
			}

			if tt.earlyData != "" {
				if err := remoteSide.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("set remote deadline: %v", err)
				}
				got := make([]byte, len(tt.earlyData))
				if _, err := io.ReadFull(remoteSide, got); err != nil {
					t.Fatalf("read early tunneled bytes: %v", err)
				}
				if string(got) != tt.earlyData {
					t.Errorf("early tunneled bytes = %q, want %q", got, tt.earlyData)
				}
			}

			writeErr := make(chan error, 1)
			go func() {
				_, err := io.WriteString(remoteSide, tt.remoteData)
				writeErr <- err
			}()

			got := make([]byte, len(tt.remoteData))
			if _, err := io.ReadFull(reader, got); err != nil {
				t.Fatalf("read remote tunneled bytes: %v", err)
			}
			if string(got) != tt.remoteData {
				t.Errorf("remote tunneled bytes = %q, want %q", got, tt.remoteData)
			}
			if err := <-writeErr; err != nil {
				t.Fatalf("write remote tunneled bytes: %v", err)
			}
			if err := clientConn.Close(); err != nil {
				t.Errorf("close test client: %v", err)
			}
			if err := remoteSide.Close(); err != nil {
				t.Errorf("close test destination: %v", err)
			}
			shutdownTestHandler(t, handler)
		})
	}
}

func TestHandleConnectDialFailure(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("destination unavailable")}
	handler := NewHandler(Config{TunnelIdleTimeout: 5 * time.Second}, dialer)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.handleConnect(w, r, 2)
	}))
	t.Cleanup(server.Close)

	clientConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test proxy: %v", err)
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
	})
	if _, err := fmt.Fprint(clientConn, "CONNECT unavailable.example:443 HTTP/1.1\r\nHost: unavailable.example:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	statusLine, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT failure status: %v", err)
	}
	if !strings.Contains(statusLine, " 502 ") {
		t.Fatalf("CONNECT failure status = %q, want HTTP 502", statusLine)
	}
}

func TestConnectPreservesTCPHalfClose(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for target: %v", err)
	}
	t.Cleanup(func() {
		if err := targetListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close target listener: %v", err)
		}
	})

	targetDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		payload, readErr := io.ReadAll(conn)
		if readErr != nil {
			targetDone <- errors.Join(readErr, conn.Close())
			return
		}
		if string(payload) != "request after CONNECT" {
			targetDone <- errors.Join(fmt.Errorf("target payload = %q", payload), conn.Close())
			return
		}
		_, writeErr := io.WriteString(conn, "response after client EOF")
		targetDone <- errors.Join(writeErr, conn.Close())
	}()

	handler := NewHandler(Config{TunnelIdleTimeout: 5 * time.Second}, fixedAddressDialer{address: targetListener.Addr().String()})
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	clientRaw, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test proxy: %v", err)
	}
	client, ok := clientRaw.(*net.TCPConn)
	if !ok {
		t.Fatalf("client connection type = %T, want *net.TCPConn", clientRaw)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close proxy client: %v", err)
		}
	})
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if _, err := io.WriteString(client, "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	reader := bufio.NewReader(client)
	readConnectResponse(t, reader)
	if _, err := io.WriteString(client, "request after CONNECT"); err != nil {
		t.Fatalf("write tunneled request: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("half-close proxy client: %v", err)
	}

	response, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read response after half-close: %v", err)
	}
	if string(response) != "response after client EOF" {
		t.Errorf("tunneled response = %q", response)
	}
	if err := <-targetDone; err != nil {
		t.Fatalf("target server: %v", err)
	}
	shutdownTestHandler(t, handler)
}

func TestHandlerShutdownForceClosesActiveTunnel(t *testing.T) {
	proxySide, remoteSide := net.Pipe()
	t.Cleanup(func() {
		if err := remoteSide.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close destination: %v", err)
		}
	})
	handler := NewHandler(Config{TunnelIdleTimeout: time.Minute}, &fakeDialer{conn: proxySide})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	clientConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test proxy: %v", err)
	}
	defer func() {
		if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close client: %v", err)
		}
	}()
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	readConnectResponse(t, bufio.NewReader(clientConn))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = handler.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v, want context deadline exceeded", err)
	}
}

func TestConnectIdleTimeoutClosesTunnel(t *testing.T) {
	proxySide, remoteSide := net.Pipe()
	t.Cleanup(func() {
		if err := remoteSide.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close destination: %v", err)
		}
	})
	handler := NewHandler(Config{TunnelIdleTimeout: 30 * time.Millisecond}, &fakeDialer{conn: proxySide})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	clientConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test proxy: %v", err)
	}
	defer func() {
		if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close client: %v", err)
		}
	}()
	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	reader := bufio.NewReader(clientConn)
	readConnectResponse(t, reader)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("idle tunnel remained open")
	}
	shutdownTestHandler(t, handler)
}

type fixedAddressDialer struct {
	address string
}

func (d fixedAddressDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func readConnectResponse(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT header: %v", err)
		}
		if line == "\r\n" {
			return
		}
	}
}
