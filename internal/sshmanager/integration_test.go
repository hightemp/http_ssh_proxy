package sshmanager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
)

func TestManagerConnectAndForwardIntegration(t *testing.T) {
	sshServer := newTestSSHServer(t, "proxy", "secret")
	t.Cleanup(sshServer.close)
	target := newEchoServer(t)
	t.Cleanup(target.close)

	host, portText, err := net.SplitHostPort(sshServer.listener.Addr().String())
	if err != nil {
		t.Fatalf("split SSH address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse SSH port: %v", err)
	}
	cfg := config.Default()
	cfg.SSHHost = host
	cfg.SSHPort = port
	cfg.SSHUser = "proxy"
	cfg.SSHPassword = "secret"
	cfg.SSHHostKeyFingerprint = ssh.FingerprintSHA256(sshServer.hostKey.PublicKey())

	manager := New(&cfg)
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close manager: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	conn, err := manager.DialContext(ctx, "tcp", target.listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	message := []byte("forwarded through SSH")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	received := make([]byte, len(message))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(received) != string(message) {
		t.Errorf("received %q, want %q", received, message)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close forwarded connection: %v", err)
	}
}

type directTCPIPRequest struct {
	DestinationAddress string
	DestinationPort    uint32
	OriginAddress      string
	OriginPort         uint32
}

type testSSHServer struct {
	listener net.Listener
	hostKey  ssh.Signer
	done     chan struct{}
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

func newTestSSHServer(t *testing.T, username, password string) *testSSHServer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create SSH host signer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH: %v", err)
	}
	server := &testSSHServer{
		listener: listener,
		hostKey:  hostKey,
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, candidate []byte) (*ssh.Permissions, error) {
			if metadata.User() != username || string(candidate) != password {
				return nil, errors.New("invalid credentials")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostKey)
	go server.serve(serverConfig)
	return server
}

func (s *testSSHServer) serve(cfg *ssh.ServerConfig) {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.serveConn(conn, cfg)
	}
}

func (s *testSSHServer) serveConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "direct-tcpip" {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		var request directTCPIPRequest
		if err := ssh.Unmarshal(channel.ExtraData(), &request); err != nil {
			_ = channel.Reject(ssh.Prohibited, "invalid direct-tcpip request")
			continue
		}
		destination := net.JoinHostPort(request.DestinationAddress, strconv.Itoa(int(request.DestinationPort)))
		target, err := net.DialTimeout("tcp", destination, time.Second)
		if err != nil {
			_ = channel.Reject(ssh.ConnectionFailed, "destination unavailable")
			continue
		}
		accepted, channelRequests, err := channel.Accept()
		if err != nil {
			_ = target.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)
		go bridgeSSHChannel(accepted, target)
	}
}

func bridgeSSHChannel(channel ssh.Channel, target net.Conn) {
	defer func() { _ = channel.Close() }()
	defer func() { _ = target.Close() }()
	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(channel, target)
		_ = channel.CloseWrite()
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(target, channel)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		copyDone <- struct{}{}
	}()
	<-copyDone
	<-copyDone
}

func (s *testSSHServer) close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	<-s.done
}

type echoServer struct {
	listener net.Listener
	done     chan struct{}
}

func newEchoServer(t *testing.T) *echoServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for echo server: %v", err)
	}
	server := &echoServer{listener: listener, done: make(chan struct{})}
	go func() {
		defer close(server.done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return server
}

func (s *echoServer) close() {
	_ = s.listener.Close()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		panic(fmt.Sprintf("echo server %s did not stop", s.listener.Addr()))
	}
}
