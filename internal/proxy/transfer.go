package proxy

import (
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type transferResult struct {
	direction string
	bytes     int64
	err       error
}

type halfCloseWriter interface {
	io.Writer
	CloseWrite() error
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func newIdleConn(conn net.Conn, timeout time.Duration) (*idleConn, error) {
	wrapped := &idleConn{Conn: conn, timeout: timeout}
	if err := wrapped.touch(); err != nil {
		return nil, err
	}
	return wrapped, nil
}

func (c *idleConn) Read(data []byte) (int, error) {
	if err := c.touch(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(data)
	if n > 0 {
		if deadlineErr := c.touch(); err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

func (c *idleConn) Write(data []byte) (int, error) {
	if err := c.touch(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(data)
	if n > 0 {
		if deadlineErr := c.touch(); err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

func (c *idleConn) CloseWrite() error {
	writer, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}
	return writer.CloseWrite()
}

func (c *idleConn) touch() error {
	if c.timeout <= 0 {
		return nil
	}
	return c.SetDeadline(time.Now().Add(c.timeout))
}

type activityReader struct {
	reader io.Reader
	conn   *idleConn
}

func (r activityReader) Read(data []byte) (int, error) {
	if err := r.conn.touch(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(data)
	if n > 0 {
		if deadlineErr := r.conn.touch(); err == nil {
			err = deadlineErr
		}
	}
	return n, err
}

func transferHalf(destination halfCloseWriter, source io.Reader, direction string, results chan<- transferResult) {
	n, copyErr := io.Copy(destination, source)
	closeErr := destination.CloseWrite()
	results <- transferResult{
		direction: direction,
		bytes:     n,
		err:       errors.Join(copyErr, closeErr),
	}
}

func logTransferResult(reqID uint64, result transferResult) {
	if result.err == nil {
		log.Printf("[REQ-%d] %s done (%d bytes)", reqID, result.direction, result.bytes)
		return
	}

	errText := result.err.Error()
	if strings.Contains(errText, "use of closed network connection") ||
		strings.Contains(errText, "connection reset by peer") ||
		strings.Contains(errText, "broken pipe") ||
		strings.Contains(errText, "i/o timeout") {
		log.Printf("[REQ-%d] %s closed (%d bytes): %v", reqID, result.direction, result.bytes, result.err)
		return
	}
	log.Printf("[REQ-%d] %s transfer error after %d bytes: %v", reqID, result.direction, result.bytes, result.err)
}
