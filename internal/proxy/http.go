package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/logutil"
)

func handleHTTP(w http.ResponseWriter, r *http.Request, dialer Dialer, reqID uint64) {
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		log.Printf("[REQ-%d] Error creating request: %v", reqID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if key != "Proxy-Authorization" && key != "Proxy-Connection" {
			outReq.Header[key] = values
		}
	}

	resp, err := httpClient.Do(outReq)
	if err != nil {
		log.Printf("[REQ-%d] Error forwarding request to %s: %v", reqID, r.URL.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer logutil.Close(fmt.Sprintf("response body for request %d", reqID), resp.Body)

	for key, values := range resp.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(resp.StatusCode)

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("[REQ-%d] Error copying response (%d bytes written): %v", reqID, n, err)
	} else {
		log.Printf("[REQ-%d] Completed %s %d (%d bytes)", reqID, r.URL.Host, resp.StatusCode, n)
	}
}
