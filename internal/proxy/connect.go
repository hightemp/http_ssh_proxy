package proxy

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/hightemp/http_ssh_proxy/internal/logutil"
)

func handleConnect(w http.ResponseWriter, r *http.Request, dialer Dialer, reqID uint64) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[REQ-%d] Hijacking not supported", reqID)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("[REQ-%d] CONNECT dial to %s failed: %v", reqID, r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientConn, bufferedClient, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[REQ-%d] Hijack error: %v", reqID, err)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), destConn)
		return
	}

	// Write the CONNECT response directly after hijacking. Calling WriteHeader
	// before Hijack makes net/http add "Transfer-Encoding: chunked", which is
	// invalid for a successful CONNECT response and rejected by strict clients.
	if _, err := bufferedClient.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[REQ-%d] CONNECT response write failed: %v", reqID, err)
		logutil.Close(fmt.Sprintf("client connection for request %d", reqID), clientConn)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), destConn)
		return
	}
	if err := bufferedClient.Flush(); err != nil {
		log.Printf("[REQ-%d] CONNECT response flush failed: %v", reqID, err)
		logutil.Close(fmt.Sprintf("client connection for request %d", reqID), clientConn)
		logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), destConn)
		return
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			logutil.Close(fmt.Sprintf("client connection for request %d", reqID), clientConn)
			logutil.Close(fmt.Sprintf("destination connection for request %d", reqID), destConn)
		})
	}

	go func() {
		defer closeBoth()
		// Read through net/http's buffered reader so TLS bytes sent in the same
		// packet as the CONNECT request are not discarded.
		transfer(destConn, bufferedClient.Reader, reqID, "client->dest")
	}()
	go func() {
		defer closeBoth()
		transfer(clientConn, destConn, reqID, "dest->client")
	}()
}
