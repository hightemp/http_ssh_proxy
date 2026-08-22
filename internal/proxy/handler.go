// Package proxy implements the HTTP forward proxy and CONNECT tunneling.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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

type outbound interface {
	Dialer
	http.RoundTripper
	CloseIdleConnections()
}

// Config contains runtime settings for the proxy handler.
type Config struct {
	Username          string
	Password          string
	TunnelIdleTimeout time.Duration
}

// UpstreamConfig controls proxy routing after the SSH tunnel. When Enabled is
// false, Proxies and Strategy are ignored and forwarding remains direct.
type UpstreamConfig struct {
	Enabled  bool
	Proxies  []string
	Strategy string
}

// Handler forwards regular HTTP requests and manages CONNECT tunnels.
type Handler struct {
	config         Config
	outbound       outbound
	requestCounter atomic.Uint64
	client         *http.Client
	serveHandler   http.Handler

	tunnelsMu sync.Mutex
	closing   bool
	tunnels   map[*tunnel]struct{}
	tunnelsWG sync.WaitGroup
}

// NewHandler creates an HTTP handler that forwards traffic through dialer.
func NewHandler(cfg Config, dialer Dialer) *Handler {
	return newHandler(cfg, newDirectOutbound(dialer))
}

// NewHandlerWithUpstreams creates an HTTP handler that forwards traffic through
// the selected upstream proxy after first reaching it through dialer.
func NewHandlerWithUpstreams(cfg Config, dialer Dialer, upstreamCfg UpstreamConfig) (*Handler, error) {
	pool, err := newUpstreamPool(dialer, upstreamCfg, nil, nil)
	if err != nil {
		return nil, err
	}
	return newHandler(cfg, pool), nil
}

func newHandler(cfg Config, route outbound) *Handler {
	h := &Handler{
		config:   cfg,
		outbound: route,
		client: &http.Client{
			Transport: route,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tunnels: make(map[*tunnel]struct{}),
	}
	h.serveHandler = panicRecoveryMiddleware(http.HandlerFunc(h.serveHTTP))
	return h
}

func newHTTPTransport(dialer Dialer, proxyFunc func(*http.Request) (*url.URL, error), tlsConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: proxyFunc,
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
		TLSClientConfig:       tlsConfig,
	}
}

type directOutbound struct {
	dialer    Dialer
	transport *http.Transport
}

func newDirectOutbound(dialer Dialer) *directOutbound {
	return &directOutbound{dialer: dialer, transport: newHTTPTransport(dialer, nil, nil)}
}

func (o *directOutbound) RoundTrip(request *http.Request) (*http.Response, error) {
	return o.transport.RoundTrip(request)
}

func (o *directOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return o.dialer.DialContext(ctx, network, address)
}

func (o *directOutbound) CloseIdleConnections() {
	o.transport.CloseIdleConnections()
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
	h.outbound.CloseIdleConnections()

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
