package sshmanager

import (
	"net"
	"os"
	"sync"
	"time"
)

// SSH channels do not implement native deadlines. Expiration closes only the
// forwarded channel, not the shared SSH transport. Closing the channel also
// interrupts blocked operations and releases its connection-budget slot.
type channelDeadlines struct {
	mu         sync.Mutex
	read       time.Time
	write      time.Time
	timer      *time.Timer
	generation uint64
	closed     bool
	expired    bool
	onExpire   func()
}

func (d *channelDeadlines) set(read, write *time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if read != nil {
		d.read = *read
	}
	if write != nil {
		d.write = *write
	}
	d.generation++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	next := d.read
	if next.IsZero() || (!d.write.IsZero() && d.write.Before(next)) {
		next = d.write
	}
	if !next.IsZero() {
		generation := d.generation
		d.timer = time.AfterFunc(time.Until(next), func() { d.expire(generation) })
	}
	return nil
}

func (d *channelDeadlines) expire(generation uint64) {
	d.mu.Lock()
	if d.closed || d.generation != generation {
		d.mu.Unlock()
		return
	}
	d.closed, d.expired = true, true
	d.timer = nil
	d.mu.Unlock()
	d.onExpire()
}

func (d *channelDeadlines) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.generation++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func (d *channelDeadlines) timedOut() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expired
}

// Read reports timeout when an emulated SSH deadline closed the channel.
func (c *limitedConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil && c.deadlines != nil && c.deadlines.timedOut() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

// Write reports timeout when an emulated SSH deadline closed the channel.
func (c *limitedConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if err != nil && c.deadlines != nil && c.deadlines.timedOut() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

// SetDeadline bounds an SSH channel's lifetime or delegates to a native socket.
func (c *limitedConn) SetDeadline(deadline time.Time) error {
	if c.deadlines != nil {
		return c.deadlines.set(&deadline, &deadline)
	}
	return c.Conn.SetDeadline(deadline)
}

// SetReadDeadline closes an SSH channel on expiry because reads cannot be
// interrupted independently by the SSH channel API.
func (c *limitedConn) SetReadDeadline(deadline time.Time) error {
	if c.deadlines != nil {
		return c.deadlines.set(&deadline, nil)
	}
	return c.Conn.SetReadDeadline(deadline)
}

// SetWriteDeadline closes an SSH channel on expiry because writes cannot be
// interrupted independently by the SSH channel API.
func (c *limitedConn) SetWriteDeadline(deadline time.Time) error {
	if c.deadlines != nil {
		return c.deadlines.set(nil, &deadline)
	}
	return c.Conn.SetWriteDeadline(deadline)
}
