package proxy

import (
	"errors"
	"net"
	"testing"
	"time"
)

// noDeadlineConn mimics SSH channels, which reject every deadline call.
type noDeadlineConn struct{ net.Conn }

var errNoDeadline = errors.New("ssh: tcpChan: deadline not supported")

func (noDeadlineConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errNoDeadline }

func TestIsDeadlineUnsupported(t *testing.T) {
	if isDeadlineUnsupported(nil) {
		t.Error("nil error reported as unsupported")
	}
	if isDeadlineUnsupported(errors.New("boom")) {
		t.Error("unrelated error reported as unsupported")
	}
	if !isDeadlineUnsupported(errNoDeadline) {
		t.Error("SSH channel error not recognized")
	}
}

func TestIdleConnFallsBackToTimerWithoutDeadlineSupport(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closePipe(t, server) })

	idle, err := newIdleConn(noDeadlineConn{client}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("newIdleConn() error = %v, want nil", err)
	}
	// The idle timer must close the connection, unblocking the read.
	done := make(chan error, 1)
	go func() {
		_, err := idle.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read() returned nil error after idle timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle timer did not close the connection")
	}
}

func TestIdleConnTimerIsResetByActivity(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closePipe(t, server) })

	idle, err := newIdleConn(noDeadlineConn{client}, 150*time.Millisecond)
	if err != nil {
		t.Fatalf("newIdleConn() error = %v", err)
	}
	// Total time (5 x 60ms) exceeds the idle timeout, but every step is
	// activity, so the connection must stay open throughout.
	buf := make([]byte, 1)
	for i := 0; i < 5; i++ {
		go func() {
			time.Sleep(60 * time.Millisecond)
			_, _ = server.Write([]byte{'x'})
		}()
		if _, err := idle.Read(buf); err != nil {
			t.Fatalf("Read() #%d error = %v, want connection kept open", i, err)
		}
	}
	if err := idle.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
