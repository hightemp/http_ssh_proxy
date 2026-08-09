package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"

	"github.com/hightemp/http_ssh_proxy/internal/logutil"
)

func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request, reqID uint64) {
	outReq, err := outboundRequest(r)
	if err != nil {
		log.Printf("[REQ-%d] Invalid forward request: %v", reqID, err)
		http.Error(w, "Invalid proxy request", http.StatusBadRequest)
		return
	}

	resp, err := h.client.Do(outReq)
	if err != nil {
		log.Printf("[REQ-%d] Forward request to %s failed: %v", reqID, outReq.URL.Host, err)
		writeDialError(w, err)
		return
	}
	defer logutil.Close(fmt.Sprintf("response body for request %d", reqID), resp.Body)

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	trailerKeys := announceTrailers(w.Header(), resp.Trailer)
	w.WriteHeader(resp.StatusCode)

	destination := io.Writer(w)
	if flusher, ok := w.(http.Flusher); ok {
		destination = flushingWriter{writer: w, flusher: flusher}
	}

	n, copyErr := io.Copy(destination, resp.Body)
	copyTrailers(w.Header(), resp.Trailer, trailerKeys)
	if copyErr != nil {
		log.Printf("[REQ-%d] Error copying response from %s (%d bytes written): %v", reqID, outReq.URL.Host, n, copyErr)
		return
	}
	log.Printf("[REQ-%d] Completed %s %d (%d bytes)", reqID, outReq.URL.Host, resp.StatusCode, n)
}

func writeDialError(w http.ResponseWriter, err error) {
	var limit interface{ ResourceLimit() bool }
	if errors.As(err, &limit) && limit.ResourceLimit() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func outboundRequest(in *http.Request) (*http.Request, error) {
	out := in.Clone(in.Context())
	requestCtx := out.Context()
	out = out.WithContext(context.WithValue(requestCtx, requestDialContextKey{}, requestCtx))
	out.RequestURI = ""
	out.Header = in.Header.Clone()
	out.Host = in.Host
	out.Close = false

	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = in.Host
	}
	if out.URL.Host == "" {
		return nil, fmt.Errorf("request target has no host")
	}

	removeHopByHopHeaders(out.Header)
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	if _, present := in.Header["User-Agent"]; !present {
		out.Header.Set("User-Agent", "")
	}
	return out, nil
}

func copyHeader(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func announceTrailers(header http.Header, trailers http.Header) []string {
	keys := make([]string, 0, len(trailers))
	for key := range trailers {
		if isHopByHopHeader(key) {
			continue
		}
		keys = append(keys, http.CanonicalHeaderKey(key))
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		header.Set("Trailer", joinHeaderTokens(keys))
	}
	return keys
}

func copyTrailers(header http.Header, trailers http.Header, keys []string) {
	for _, key := range keys {
		header[key] = trailers.Values(key)
	}
}

type flushingWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w flushingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.flusher.Flush()
	return n, err
}
