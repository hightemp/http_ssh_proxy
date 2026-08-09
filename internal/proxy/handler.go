// Package proxy implements the HTTP forward proxy and CONNECT tunneling.
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const defaultMaxIdleConnections = 32

type requestDialContextKey struct{}

// Dialer establishes context-aware outbound connections for proxy requests.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Config contains runtime settings for the proxy handler.
type Config struct {
	Username          string
	Password          string
	TunnelIdleTimeout time.Duration
}

// Handler forwards regular HTTP requests and manages CONNECT tunnels.
type Handler struct {
	config         Config
	dialer         Dialer
	requestCounter atomic.Uint64
	transport      *http.Transport
	client         *http.Client
	serveHandler   http.Handler

	tunnelsMu sync.Mutex
	closing   bool
	tunnels   map[*tunnel]struct{}
	tunnelsWG sync.WaitGroup
}

// NewHandler creates an HTTP handler that forwards traffic through dialer.
func NewHandler(cfg Config, dialer Dialer) *Handler {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if requestCtx, ok := ctx.Value(requestDialContextKey{}).(context.Context); ok {
				ctx = requestCtx
			}
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          defaultMaxIdleConnections,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	h := &Handler{
		config:    cfg,
		dialer:    dialer,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tunnels: make(map[*tunnel]struct{}),
	}
	h.serveHandler = panicRecoveryMiddleware(http.HandlerFunc(h.serveHTTP))
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serveHandler.ServeHTTP(w, r)
}

func (h *Handler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if h.isClosing() {
		http.Error(w, "Proxy is shutting down", http.StatusServiceUnavailable)
		return
	}

	reqID := h.requestCounter.Add(1)
	log.Printf("[REQ-%d] %s %s %s from %s", reqID, r.Method, r.Host, r.URL, r.RemoteAddr)
	if h.config.Username != "" && !basicAuth(w, r, h.config, reqID) {
		return
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r, reqID)
		return
	}
	h.handleHTTP(w, r, reqID)
}

// Shutdown stops new work, closes idle HTTP connections, waits for active
// CONNECT tunnels, and force-closes them if ctx expires.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.tunnelsMu.Lock()
	h.closing = true
	h.tunnelsMu.Unlock()
	h.transport.CloseIdleConnections()

	done := make(chan struct{})
	go func() {
		h.tunnelsWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		h.closeActiveTunnels()
		<-done
		return fmt.Errorf("wait for CONNECT tunnels: %w", ctx.Err())
	}
}

func (h *Handler) isClosing() bool {
	h.tunnelsMu.Lock()
	defer h.tunnelsMu.Unlock()
	return h.closing
}

func (h *Handler) registerTunnel(active *tunnel) bool {
	h.tunnelsMu.Lock()
	defer h.tunnelsMu.Unlock()
	if h.closing {
		return false
	}
	h.tunnels[active] = struct{}{}
	h.tunnelsWG.Add(1)
	return true
}

func (h *Handler) unregisterTunnel(active *tunnel) {
	h.tunnelsMu.Lock()
	delete(h.tunnels, active)
	h.tunnelsMu.Unlock()
	h.tunnelsWG.Done()
}

func (h *Handler) closeActiveTunnels() {
	h.tunnelsMu.Lock()
	active := make([]*tunnel, 0, len(h.tunnels))
	for current := range h.tunnels {
		active = append(active, current)
	}
	h.tunnelsMu.Unlock()

	for _, current := range active {
		current.close()
	}
}
