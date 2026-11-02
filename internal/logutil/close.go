// Package logutil contains shared logging helpers.
package logutil

import (
	"errors"
	"io"
	"log"
	"net"
)

// Close closes a resource and logs any resulting error. Errors that only mean
// the resource was already closed (io.EOF from an SSH channel the peer closed,
// net.ErrClosed) are expected during teardown and are not logged.
func Close(name string, closer io.Closer) {
	err := closer.Close()
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	log.Printf("[CLOSE] Error closing %s: %v", name, err)
}
