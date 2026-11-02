package logutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

type testCloser struct {
	err error
}

func (c testCloser) Close() error {
	return c.err
}

func TestCloseHandlesSuccessAndFailure(t *testing.T) {
	Close("successful resource", testCloser{})
	Close("failed resource", testCloser{err: errors.New("close failed")})
}

func TestCloseIgnoresAlreadyClosedErrors(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	Close("eof resource", testCloser{err: io.EOF})
	Close("closed resource", testCloser{err: fmt.Errorf("wrapped: %w", net.ErrClosed)})
	if buf.Len() != 0 {
		t.Fatalf("logged %q for already-closed errors, want nothing", buf.String())
	}
	Close("failed resource", testCloser{err: errors.New("close failed")})
	if !strings.Contains(buf.String(), "close failed") {
		t.Fatalf("log = %q, want the real close error", buf.String())
	}
}
