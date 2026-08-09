package sshmanager

import (
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
