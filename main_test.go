package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

func (d *fakeDialer) Dial(network, addr string) (net.Conn, error) {
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handleConnect(w, r, dialer, 1)
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
		})
	}
}

func TestHandleConnectDialFailure(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("destination unavailable")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, dialer, 2)
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
	if !strings.Contains(statusLine, " 503 ") {
		t.Fatalf("CONNECT failure status = %q, want HTTP 503", statusLine)
	}
}

func TestIsDestinationDialError(t *testing.T) {
	channelErr := &ssh.OpenChannelError{
		Reason:  ssh.ConnectionFailed,
		Message: "connection refused",
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "SSH channel rejection", err: channelErr, want: true},
		{name: "wrapped SSH channel rejection", err: fmt.Errorf("dial: %w", channelErr), want: true},
		{name: "SSH transport error", err: io.EOF, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDestinationDialError(tt.err); got != tt.want {
				t.Errorf("isDestinationDialError(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}
