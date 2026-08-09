package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type countingDialer struct {
	dialer net.Dialer
	calls  atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	return d.dialer.DialContext(ctx, network, address)
}

func TestHTTPForwardingPreservesRequestAndFiltersHopHeaders(t *testing.T) {
	requestObserved := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { requestObserved <- struct{}{} }()

		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Host != "virtual.example" {
			t.Errorf("Host = %q, want virtual.example", r.Host)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request body: %v", err)
		}
		if string(body) != "request body" {
			t.Errorf("body = %q, want request body", body)
		}
		if r.ContentLength != int64(len("request body")) {
			t.Errorf("ContentLength = %d, want %d", r.ContentLength, len("request body"))
		}
		if got := r.Header.Get("X-End-To-End"); got != "preserved" {
			t.Errorf("X-End-To-End = %q, want preserved", got)
		}
		for _, header := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "X-Remove"} {
			if value := r.Header.Get(header); value != "" {
				t.Errorf("hop-by-hop request header %s leaked with value %q", header, value)
			}
		}
		if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
			t.Errorf("proxy injected User-Agent %q", userAgent)
		}

		w.Header().Set("X-Upstream", "preserved")
		w.Header().Set("Connection", "X-Response-Remove")
		w.Header().Set("X-Response-Remove", "secret")
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, "response body"); err != nil {
			t.Errorf("write upstream response: %v", err)
		}
		w.Header().Set("X-Checksum", "sha256:test")
	}))
	t.Cleanup(upstream.Close)

	dialer := &countingDialer{}
	handler := NewHandler(Config{}, dialer)
	t.Cleanup(func() { shutdownTestHandler(t, handler) })

	request := httptest.NewRequest(http.MethodPost, upstream.URL+"/resource", strings.NewReader("request body"))
	request.Host = "virtual.example"
	request.Header.Set("X-End-To-End", "preserved")
	request.Header.Set("Connection", "X-Remove")
	request.Header.Set("X-Remove", "secret")
	request.Header.Set("Keep-Alive", "timeout=5")
	request.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	request.Header.Set("Proxy-Connection", "keep-alive")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", response.StatusCode)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	if string(responseBody) != "response body" {
		t.Errorf("response body = %q, want response body", responseBody)
	}
	if got := response.Header.Get("X-Upstream"); got != "preserved" {
		t.Errorf("X-Upstream = %q, want preserved", got)
	}
	if got := response.Header.Get("X-Response-Remove"); got != "" {
		t.Errorf("hop-by-hop response header leaked with value %q", got)
	}
	if got := response.Trailer.Get("X-Checksum"); got != "sha256:test" {
		t.Errorf("response trailer = %q, want sha256:test", got)
	}

	select {
	case <-requestObserved:
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe request")
	}
}

func TestHTTPForwardingReturnsRedirectWithoutFollowing(t *testing.T) {
	var finalRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			finalRequests.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	t.Cleanup(upstream.Close)

	handler := NewHandler(Config{}, &countingDialer{})
	t.Cleanup(func() { shutdownTestHandler(t, handler) })
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, upstream.URL+"/redirect", nil))

	if recorder.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/final" {
		t.Errorf("Location = %q, want /final", got)
	}
	if got := finalRequests.Load(); got != 0 {
		t.Errorf("redirect target requests = %d, want 0", got)
	}
}

func TestHTTPForwardingPreservesRequestTrailers(t *testing.T) {
	trailerObserved := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("read request body: %v", err)
		}
		trailerObserved <- r.Trailer.Get("X-Request-Checksum")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	handler := NewHandler(Config{}, &countingDialer{})
	t.Cleanup(func() { shutdownTestHandler(t, handler) })
	request := httptest.NewRequest(http.MethodPost, upstream.URL, strings.NewReader("chunked body"))
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Trailer = http.Header{"X-Request-Checksum": {"sha256:request"}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	select {
	case got := <-trailerObserved:
		if got != "sha256:request" {
			t.Errorf("request trailer = %q, want sha256:request", got)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe request trailer")
	}
}

func TestHTTPForwardingStreamsResponse(t *testing.T) {
	releaseUpstream := make(chan struct{})
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(upstreamDone)
		if _, err := io.WriteString(w, "first"); err != nil {
			t.Errorf("write first response chunk: %v", err)
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush first response chunk: %v", err)
			return
		}
		<-releaseUpstream
		if _, err := io.WriteString(w, "second"); err != nil {
			t.Errorf("write second response chunk: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)

	handler := NewHandler(Config{}, &countingDialer{})
	t.Cleanup(func() { shutdownTestHandler(t, handler) })
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)
	proxyURL := mustParseURL(t, proxyServer.URL)
	clientTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(clientTransport.CloseIdleConnections)
	client := &http.Client{Transport: clientTransport}

	type responseResult struct {
		response *http.Response
		err      error
	}
	responseCh := make(chan responseResult, 1)
	go func() {
		response, err := client.Get(upstream.URL)
		responseCh <- responseResult{response: response, err: err}
	}()

	var response *http.Response
	select {
	case result := <-responseCh:
		if result.err != nil {
			t.Fatalf("proxy request: %v", result.err)
		}
		response = result.response
	case <-time.After(time.Second):
		close(releaseUpstream)
		t.Fatal("response headers were not streamed")
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close streamed response: %v", err)
		}
	}()

	first := make([]byte, len("first"))
	readCh := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(response.Body, first)
		readCh <- err
	}()
	select {
	case err := <-readCh:
		if err != nil {
			close(releaseUpstream)
			t.Fatalf("read first streamed chunk: %v", err)
		}
	case <-time.After(time.Second):
		close(releaseUpstream)
		t.Fatal("first response chunk was not flushed")
	}
	if string(first) != "first" {
		t.Errorf("first chunk = %q, want first", first)
	}

	close(releaseUpstream)
	remaining, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read remaining response: %v", err)
	}
	if string(remaining) != "second" {
		t.Errorf("remaining response = %q, want second", remaining)
	}
	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Fatal("upstream handler did not finish")
	}
}

func TestHTTPTransportIsSharedAcrossRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2")
		if _, err := io.WriteString(w, "ok"); err != nil {
			t.Errorf("write upstream response: %v", err)
		}
	}))
	t.Cleanup(upstream.Close)

	dialer := &countingDialer{}
	handler := NewHandler(Config{}, dialer)
	t.Cleanup(func() { shutdownTestHandler(t, handler) })
	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, upstream.URL, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
	}

	if got := dialer.calls.Load(); got != 1 {
		t.Errorf("network dials = %d, want one reused connection", got)
	}
}

func TestHTTPDialHonorsRequestCancellation(t *testing.T) {
	dialer := &cancelAwareDialer{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	handler := NewHandler(Config{}, dialer)
	t.Cleanup(func() { shutdownTestHandler(t, handler) })

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "http://blocked.example/resource", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(recorder, request)
		close(done)
	}()

	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	cancel()

	select {
	case <-dialer.canceled:
	case <-time.After(time.Second):
		t.Fatal("dial context was not canceled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not return after cancellation")
	}
	if recorder.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), context.Canceled.Error()) {
		t.Errorf("response exposed internal error: %q", recorder.Body.String())
	}
}

func TestWriteDialErrorMapsResourceLimit(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantRetry  string
	}{
		{name: "upstream failure", err: errors.New("dial failed"), wantStatus: http.StatusBadGateway},
		{name: "capacity exhausted", err: resourceLimitError{}, wantStatus: http.StatusServiceUnavailable, wantRetry: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeDialError(recorder, tt.err)
			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if got := recorder.Header().Get("Retry-After"); got != tt.wantRetry {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetry)
			}
		})
	}
}

type cancelAwareDialer struct {
	started  chan struct{}
	canceled chan struct{}
}

type resourceLimitError struct{}

func (resourceLimitError) Error() string {
	return "capacity exhausted"
}

func (resourceLimitError) ResourceLimit() bool {
	return true
}

func (d *cancelAwareDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	close(d.canceled)
	return nil, ctx.Err()
}

func shutdownTestHandler(t *testing.T, handler *Handler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Shutdown(ctx); err != nil {
		t.Errorf("shutdown handler: %v", err)
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return parsed
}
