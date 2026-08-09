// Package logutil contains shared logging helpers.
package logutil

import (
	"io"
	"log"
)

// Close closes a resource and logs any resulting error.
func Close(name string, closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Printf("[CLOSE] Error closing %s: %v", name, err)
	}
}
