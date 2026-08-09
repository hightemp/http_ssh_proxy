package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/proxy"
)

type fixedConnDialer struct {
	conn net.Conn
}

func (d fixedConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func TestShutdownWaitsThenClosesHijackedConnections(t *testing.T) {
	proxySide, remoteSide := net.Pipe()
	t.Cleanup(func() {
		if err := remoteSide.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close destination: %v", err)
		}
	})
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
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close client: %v", err)
		}
	})
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
