// Package proxy implements the HTTP forward proxy and CONNECT tunneling.
package proxy

import (
	"log"
	"net"
	"net/http"
	"sync/atomic"
)

// Dialer establishes outbound connections for proxy requests.
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
}

// Config contains client authentication settings for the proxy.
type Config struct {
	Username string
	Password string
}

type handler struct {
	config         Config
	dialer         Dialer
	requestCounter uint64
}

// NewHandler creates an HTTP handler that forwards traffic through dialer.
func NewHandler(cfg Config, dialer Dialer) http.Handler {
	h := &handler{
		config: cfg,
		dialer: dialer,
	}
	return panicRecoveryMiddleware(h)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := atomic.AddUint64(&h.requestCounter, 1)
	log.Printf("[REQ-%d] %s %s %s from %s", reqID, r.Method, r.Host, r.URL, r.RemoteAddr)
	if h.config.Username != "" && !basicAuth(w, r, h.config, reqID) {
		return
	}

	if r.Method == http.MethodConnect {
		handleConnect(w, r, h.dialer, reqID)
		return
	}
	handleHTTP(w, r, h.dialer, reqID)
}
