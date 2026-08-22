package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/hightemp/http_ssh_proxy/internal/logutil"
)

type tunnel struct {
	client *idleConn
	target *idleConn
	once   sync.Once
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request, reqID uint64) {
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		log.Printf("[REQ-%d] Invalid CONNECT target %q: %v", reqID, r.Host, err)
		http.Error(w, "Invalid CONNECT target", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[REQ-%d] Hijacking not supported", reqID)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Do not let reusable idle HTTP connections monopolize the global SSH
	// connection budget when a long-lived CONNECT tunnel is requested.
	h.outbound.CloseIdleConnections()
	targetConn, err := h.outbound.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		log.Printf("[REQ-%d] CONNECT dial to %s failed: %v", reqID, r.Host, err)
		writeDialError(w, err)
		return
	}

	clientConn, bufferedClient, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[REQ-%d] Hijack error: %v", reqID, err)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), targetConn)
		return
	}

	idleClient, err := newIdleConn(clientConn, h.config.TunnelIdleTimeout)
	if err != nil {
		log.Printf("[REQ-%d] Set client tunnel deadline: %v", reqID, err)
		logutil.Close(fmt.Sprintf("client connection for request %d", reqID), clientConn)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), targetConn)
		return
	}
	idleTarget, err := newIdleConn(targetConn, h.config.TunnelIdleTimeout)
	if err != nil {
		log.Printf("[REQ-%d] Set destination tunnel deadline: %v", reqID, err)
		logutil.Close(fmt.Sprintf("client connection for request %d", reqID), clientConn)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), targetConn)
		return
	}

	active := &tunnel{
		client: idleClient,
		target: idleTarget,
	}
	if !h.registerTunnel(active) {
		active.close()
		return
	}

	// Write the CONNECT response directly after hijacking. Calling WriteHeader
	// before Hijack makes net/http add chunked encoding to a successful CONNECT.
	if _, err := bufferedClient.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[REQ-%d] CONNECT response write failed: %v", reqID, err)
		active.close()
		h.unregisterTunnel(active)
		return
	}
	if err := bufferedClient.Flush(); err != nil {
		log.Printf("[REQ-%d] CONNECT response flush failed: %v", reqID, err)
		active.close()
		h.unregisterTunnel(active)
		return
	}

	go h.runTunnel(active, bufferedClient.Reader, reqID)
}

func (h *Handler) runTunnel(active *tunnel, bufferedClient *bufio.Reader, reqID uint64) {
	defer h.unregisterTunnel(active)
	defer active.close()

	results := make(chan transferResult, 2)
	go transferHalf(active.target, activityReader{reader: bufferedClient, conn: active.client}, "client->dest", results)
	go transferHalf(active.client, active.target, "dest->client", results)

	first := <-results
	second := <-results
	logTransferResult(reqID, first)
	logTransferResult(reqID, second)
}

func (t *tunnel) close() {
	t.once.Do(func() {
		logutil.Close("CONNECT client connection", t.client)
		logutil.Close("CONNECT destination connection", t.target)
	})
}
