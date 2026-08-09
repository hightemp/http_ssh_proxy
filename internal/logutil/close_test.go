package logutil

import (
	"errors"
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
