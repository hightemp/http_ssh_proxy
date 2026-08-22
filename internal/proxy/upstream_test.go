package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingUpstreamRoute struct {
	name   string
	record func(string)
	calls  atomic.Int64
	closed atomic.Bool
}

func (r *recordingUpstreamRoute) DialContext(context.Context, string, string) (net.Conn, error) {
	r.calls.Add(1)
	r.record(r.name)
	conn, peer := net.Pipe()
	if err := peer.Close(); err != nil {
		return nil, err
	}
	return conn, nil
}

func (r *recordingUpstreamRoute) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	r.record(r.name)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

func (r *recordingUpstreamRoute) CloseIdleConnections() {
	r.closed.Store(true)
}

func TestUpstreamPoolRoundRobinAcrossHTTPAndConnect(t *testing.T) {
	var mu sync.Mutex
	var selected []string
	record := func(name string) {
		mu.Lock()
		selected = append(selected, name)
		mu.Unlock()
	}
	routes := []upstreamRoute{
		&recordingUpstreamRoute{name: "first", record: record},
		&recordingUpstreamRoute{name: "second", record: record},
		&recordingUpstreamRoute{name: "third", record: record},
	}
	pool := &upstreamPool{routes: routes, strategy: upstreamStrategyRoundRobin}

	for index := range 6 {
		if index%2 == 0 {
			response, err := pool.RoundTrip(httptest.NewRequest(http.MethodGet, "http://target.example", nil))
			if err != nil {
				t.Fatalf("RoundTrip() error = %v", err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatalf("close response: %v", err)
			}
			continue
		}
		conn, err := pool.DialContext(context.Background(), "tcp", "target.example:443")
		if err != nil {
			t.Fatalf("DialContext() error = %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("close connection: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"first", "second", "third", "first", "second", "third"}
	if len(selected) != len(want) {
		t.Fatalf("selected routes = %v, want %v", selected, want)
	}
	for index := range want {
		if selected[index] != want[index] {
			t.Fatalf("selected routes = %v, want %v", selected, want)
		}
	}
	pool.CloseIdleConnections()
	for _, route := range routes {
		if !route.(*recordingUpstreamRoute).closed.Load() {
			t.Errorf("route %q was not closed", route.(*recordingUpstreamRoute).name)
		}
	}
}

func TestUpstreamPoolStrategiesAreConcurrentSafe(t *testing.T) {
	tests := []struct {
		name        string
		strategy    string
		randomIndex func(int) int
		wantCalls   []int64
	}{
		{
			name:      "roundrobin",
			strategy:  upstreamStrategyRoundRobin,
			wantCalls: []int64{40, 40, 40},
		},
		{
			name:        "random",
			strategy:    upstreamStrategyRandom,
			randomIndex: func(int) int { return 1 },
			wantCalls:   []int64{0, 120, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := []*recordingUpstreamRoute{
				{name: "first", record: func(string) {}},
				{name: "second", record: func(string) {}},
				{name: "third", record: func(string) {}},
			}
			pool := &upstreamPool{
				routes:      []upstreamRoute{routes[0], routes[1], routes[2]},
				strategy:    tt.strategy,
				randomIndex: tt.randomIndex,
			}

			const requests = 120
			errorsCh := make(chan error, requests)
			for range requests {
				go func() {
					response, err := pool.RoundTrip(httptest.NewRequest(http.MethodGet, "http://target.example", nil))
					if err == nil {
						err = response.Body.Close()
					}
					errorsCh <- err
				}()
			}
			for range requests {
				if err := <-errorsCh; err != nil {
					t.Errorf("RoundTrip() error = %v", err)
				}
			}
			for index, route := range routes {
				if got := route.calls.Load(); got != tt.wantCalls[index] {
					t.Errorf("route %d calls = %d, want %d", index, got, tt.wantCalls[index])
				}
			}
		})
	}
}

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantScheme  string
		wantAddress string
		wantErr     bool
	}{
		{name: "HTTP default port", rawURL: "http://proxy.example.com", wantScheme: "http", wantAddress: "proxy.example.com:80"},
		{name: "HTTPS port", rawURL: "https://user:secret@proxy.example.com:8443/", wantScheme: "https", wantAddress: "proxy.example.com:8443"},
		{name: "SOCKS alias", rawURL: "socks://proxy.example.com", wantScheme: "socks5", wantAddress: "proxy.example.com:1080"},
		{name: "SOCKS5h", rawURL: "socks5h://proxy.example.com", wantScheme: "socks5h", wantAddress: "proxy.example.com:1080"},
		{name: "IPv6", rawURL: "http://[::1]:3128", wantScheme: "http", wantAddress: "[::1]:3128"},
		{name: "unsupported", rawURL: "ftp://proxy.example.com", wantErr: true},
		{name: "missing hostname", rawURL: "http://", wantErr: true},
		{name: "empty port", rawURL: "http://proxy.example.com:", wantErr: true},
		{name: "path", rawURL: "http://proxy.example.com/path", wantErr: true},
		{name: "query", rawURL: "http://proxy.example.com?token=secret", wantErr: true},
		{name: "empty username", rawURL: "http://:secret@proxy.example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, address, err := parseProxyURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProxyURL() succeeded: %v, %q", parsed, address)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyURL() error = %v", err)
			}
			if parsed.Scheme != tt.wantScheme || address != tt.wantAddress {
				t.Errorf("parseProxyURL() = scheme %q, address %q; want %q, %q", parsed.Scheme, address, tt.wantScheme, tt.wantAddress)
			}
		})
	}

	_, _, err := parseProxyURL("http://user:supersecret@proxy.example.com/%zz")
	if err == nil {
		t.Fatal("parseProxyURL() succeeded for invalid escaped path")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("parseProxyURL() error exposed password: %v", err)
	}
}

type mappedDialer struct {
	mu      sync.Mutex
	targets map[string]string
	calls   []string
}

func (d *mappedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, address)
	target := d.targets[address]
	d.mu.Unlock()
	if target == "" {
		return nil, fmt.Errorf("unexpected dial address %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func TestHTTPRequestsUseSelectedForwardProxies(t *testing.T) {
	type observedRequest struct {
		proxy   string
		uri     string
		auth    string
		request *http.Request
	}
	observed := make(chan observedRequest, 4)
	newProxy := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observed <- observedRequest{proxy: name, uri: r.RequestURI, auth: r.Header.Get("Proxy-Authorization"), request: r}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(name)))
			if _, err := io.WriteString(w, name); err != nil {
				t.Errorf("write proxy response: %v", err)
			}
		}))
	}
	first := newProxy("first")
	second := newProxy("second")
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)

	dialer := &mappedDialer{targets: map[string]string{
		"proxy-a.example:3128": first.Listener.Addr().String(),
		"proxy-b.example:3128": second.Listener.Addr().String(),
	}}
	handler, err := NewHandlerWithUpstreams(Config{}, dialer, UpstreamConfig{
		Enabled:  true,
		Strategy: upstreamStrategyRoundRobin,
		Proxies: []string{
			"http://user:secret@proxy-a.example:3128",
			"http://user:secret@proxy-b.example:3128",
		},
	})
	if err != nil {
		t.Fatalf("NewHandlerWithUpstreams() error = %v", err)
	}
	t.Cleanup(func() { shutdownTestHandler(t, handler) })

	wantBodies := []string{"first", "second", "first", "second"}
	for index, wantBody := range wantBodies {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://target.example/resource/%d", index), nil)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != wantBody {
			t.Fatalf("request %d = status %d body %q, want 200 %q", index, recorder.Code, recorder.Body.String(), wantBody)
		}
		got := <-observed
		if got.proxy != wantBody {
			t.Errorf("request %d used proxy %q, want %q", index, got.proxy, wantBody)
		}
		if got.uri != fmt.Sprintf("http://target.example/resource/%d", index) || !got.request.URL.IsAbs() {
			t.Errorf("proxy request URI = %q, want absolute target URL", got.uri)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
		if got.auth != wantAuth {
			t.Errorf("Proxy-Authorization = %q, want configured Basic auth", got.auth)
		}
	}
}

type connectObservation struct {
	target string
	auth   string
}

func TestHTTPAndHTTPSProxyConnectHandshake(t *testing.T) {
	tests := []struct {
		name   string
		useTLS bool
	}{
		{name: "HTTP", useTLS: false},
		{name: "HTTPS", useTLS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observed := make(chan connectObservation, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- connectObservation{target: r.Host, auth: r.Header.Get("Proxy-Authorization")}
				conn, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack upstream proxy: %v", err)
					return
				}
				defer func() {
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Errorf("close upstream proxy connection: %v", err)
					}
				}()
				if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\nready"); err != nil {
					t.Errorf("write CONNECT response: %v", err)
					return
				}
				if err := buffered.Flush(); err != nil {
					t.Errorf("flush CONNECT response: %v", err)
					return
				}
				if _, err := io.Copy(io.Discard, conn); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("drain tunneled connection: %v", err)
				}
			}))
			if tt.useTLS {
				server.StartTLS()
			} else {
				server.Start()
			}
			t.Cleanup(server.Close)

			proxyURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("parse proxy URL: %v", err)
			}
			proxyURL.User = url.UserPassword("proxy-user", "proxy-secret")
			var tlsConfig *tls.Config
			if tt.useTLS {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				tlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			}
			endpoint, err := newProxyEndpoint(&countingDialer{}, proxyURL.String(), tlsConfig)
			if err != nil {
				t.Fatalf("newProxyEndpoint() error = %v", err)
			}
			t.Cleanup(endpoint.CloseIdleConnections)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := endpoint.DialContext(ctx, "tcp", "target.example:443")
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			ready := make([]byte, len("ready"))
			if _, err := io.ReadFull(conn, ready); err != nil {
				t.Fatalf("read buffered target bytes: %v", err)
			}
			if string(ready) != "ready" {
				t.Errorf("target bytes = %q, want ready", ready)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("close tunneled connection: %v", err)
			}

			got := <-observed
			if got.target != "target.example:443" {
				t.Errorf("CONNECT target = %q, want target.example:443", got.target)
			}
			wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
			if got.auth != wantAuth {
				t.Errorf("Proxy-Authorization = %q, want configured Basic auth", got.auth)
			}
		})
	}
}

func TestHTTPProxyConnectFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "authentication required", http.StatusProxyAuthRequired)
	}))
	t.Cleanup(server.Close)
	endpoint, err := newProxyEndpoint(&countingDialer{}, server.URL, nil)
	if err != nil {
		t.Fatalf("newProxyEndpoint() error = %v", err)
	}
	_, err = endpoint.DialContext(context.Background(), "tcp", "target.example:443")
	if err == nil || !strings.Contains(err.Error(), "status 407") {
		t.Fatalf("DialContext() error = %v, want status 407", err)
	}
}

func TestSOCKS5ProxyConnect(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		username string
		password string
	}{
		{name: "without authentication", proxyURL: "socks5://proxy.example:1080"},
		{name: "username and password", proxyURL: "socks://alice:secret@proxy.example:1080", username: "alice", password: "secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			serverErr := make(chan error, 1)
			go func() {
				serverErr <- serveSOCKS5Handshake(server, tt.username, tt.password, "target.example", 8443, "ready")
			}()
			endpoint, err := newProxyEndpoint(&fakeDialer{conn: client}, tt.proxyURL, nil)
			if err != nil {
				t.Fatalf("newProxyEndpoint() error = %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := endpoint.DialContext(ctx, "tcp", "target.example:8443")
			if err != nil {
				t.Fatalf("DialContext() error = %v", err)
			}
			ready := make([]byte, len("ready"))
			if _, err := io.ReadFull(conn, ready); err != nil {
				t.Fatalf("read SOCKS target bytes: %v", err)
			}
			if string(ready) != "ready" {
				t.Errorf("target bytes = %q, want ready", ready)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("close SOCKS connection: %v", err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("SOCKS5 server: %v", err)
			}
		})
	}
}

func TestHTTPForwardingThroughSOCKS5Proxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/through-socks" {
			t.Errorf("target path = %q, want /through-socks", r.URL.Path)
		}
		w.Header().Set("Content-Length", "8")
		if _, err := io.WriteString(w, "socks-ok"); err != nil {
			t.Errorf("write target response: %v", err)
		}
	}))
	t.Cleanup(target.Close)
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 proxy: %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close SOCKS5 listener: %v", err)
		}
	})
	observedTarget := make(chan string, 1)
	proxyDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			proxyDone <- acceptErr
			return
		}
		proxyDone <- serveSOCKS5ForwardProxy(conn, targetURL.Host, observedTarget)
	}()

	dialer := &mappedDialer{targets: map[string]string{
		"proxy.example:1080": listener.Addr().String(),
	}}
	handler, err := NewHandlerWithUpstreams(Config{}, dialer, UpstreamConfig{
		Enabled:  true,
		Strategy: upstreamStrategyRoundRobin,
		Proxies:  []string{"socks5://proxy.example:1080"},
	})
	if err != nil {
		t.Fatalf("NewHandlerWithUpstreams() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://target.example/through-socks", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "socks-ok" {
		t.Fatalf("response = status %d body %q, want 200 socks-ok", recorder.Code, recorder.Body.String())
	}
	select {
	case got := <-observedTarget:
		if got != "target.example:80" {
			t.Errorf("SOCKS5 target = %q, want target.example:80", got)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 proxy did not observe target")
	}
	shutdownTestHandler(t, handler)
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatalf("SOCKS5 proxy: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 proxy did not stop")
	}
}

func TestUpstreamHandshakeHonorsContextCancellation(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { closePipe(t, server) })
	endpoint, err := newProxyEndpoint(&fakeDialer{conn: client}, "socks5://proxy.example:1080", nil)
	if err != nil {
		t.Fatalf("newProxyEndpoint() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := endpoint.DialContext(ctx, "tcp", "target.example:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext() error = %v, want context deadline exceeded", err)
	}
}

func serveSOCKS5Handshake(conn net.Conn, username, password, targetHost string, targetPort uint16, payload string) error {
	defer func() { _ = conn.Close() }()
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read greeting header: %w", err)
	}
	if header[0] != 0x05 || header[1] == 0 {
		return fmt.Errorf("greeting = %v", header)
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read greeting methods: %w", err)
	}
	method := byte(0x00)
	if username != "" {
		method = 0x02
	}
	if !containsByte(methods, method) {
		return fmt.Errorf("methods = %v, missing %d", methods, method)
	}
	if err := writeAll(conn, []byte{0x05, method}); err != nil {
		return fmt.Errorf("write selected method: %w", err)
	}
	if method == 0x02 {
		if err := verifySOCKS5Credentials(conn, username, password); err != nil {
			return err
		}
	}

	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return fmt.Errorf("read CONNECT request header: %w", err)
	}
	if requestHeader[0] != 0x05 || requestHeader[1] != 0x01 || requestHeader[3] != 0x03 {
		return fmt.Errorf("CONNECT request header = %v", requestHeader)
	}
	length := make([]byte, 1)
	// The domain length is already the fourth byte following VER/CMD/RSV in a
	// domain request, so read it separately after the fixed header.
	if _, err := io.ReadFull(conn, length); err != nil {
		return fmt.Errorf("read target hostname length: %w", err)
	}
	host := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, host); err != nil {
		return fmt.Errorf("read target hostname: %w", err)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return fmt.Errorf("read target port: %w", err)
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	if string(host) != targetHost || port != targetPort {
		return fmt.Errorf("target = %s:%d, want %s:%d", host, port, targetHost, targetPort)
	}
	reply := []byte{0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
	if err := writeAll(conn, append(reply, payload...)); err != nil {
		return fmt.Errorf("write CONNECT reply: %w", err)
	}
	return nil
}

func serveSOCKS5ForwardProxy(client net.Conn, targetAddress string, observed chan<- string) error {
	defer func() { _ = client.Close() }()
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return fmt.Errorf("read greeting header: %w", err)
	}
	methods := make([]byte, int(header[1]))
	if header[0] != 0x05 || header[1] == 0 {
		return fmt.Errorf("greeting = %v", header)
	}
	if _, err := io.ReadFull(client, methods); err != nil {
		return fmt.Errorf("read greeting methods: %w", err)
	}
	if !containsByte(methods, 0x00) {
		return fmt.Errorf("methods = %v, missing no-auth", methods)
	}
	if err := writeAll(client, []byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("write selected method: %w", err)
	}

	target, err := readSOCKS5RequestTarget(client)
	if err != nil {
		return err
	}
	observed <- target
	remote, err := net.Dial("tcp", targetAddress)
	if err != nil {
		return fmt.Errorf("dial mapped target: %w", err)
	}
	defer func() { _ = remote.Close() }()
	if err := writeAll(client, []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return fmt.Errorf("write CONNECT success: %w", err)
	}

	results := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(remote, client)
		results <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(client, remote)
		results <- copyErr
	}()
	firstErr := <-results
	if err := remote.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		firstErr = errors.Join(firstErr, err)
	}
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		firstErr = errors.Join(firstErr, err)
	}
	secondErr := <-results
	if errors.Is(firstErr, net.ErrClosed) {
		firstErr = nil
	}
	if errors.Is(secondErr, net.ErrClosed) {
		secondErr = nil
	}
	return errors.Join(firstErr, secondErr)
}

func readSOCKS5RequestTarget(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read CONNECT request header: %w", err)
	}
	if header[0] != 0x05 || header[1] != 0x01 {
		return "", fmt.Errorf("CONNECT request header = %v", header)
	}

	var host string
	switch header[3] {
	case 0x01:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", fmt.Errorf("read IPv4 target: %w", err)
		}
		host = net.IP(address).String()
	case 0x04:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", fmt.Errorf("read IPv6 target: %w", err)
		}
		host = net.IP(address).String()
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", fmt.Errorf("read hostname length: %w", err)
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", fmt.Errorf("read hostname: %w", err)
		}
		host = string(address)
	default:
		return "", fmt.Errorf("CONNECT address type = %d", header[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return "", fmt.Errorf("read target port: %w", err)
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", uint16(port[0])<<8|uint16(port[1]))), nil
}

func verifySOCKS5Credentials(conn net.Conn, wantUsername, wantPassword string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != 0x01 {
		return fmt.Errorf("auth version = %d", header[0])
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(conn, length); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if string(username) != wantUsername || string(password) != wantPassword {
		return errors.New("unexpected SOCKS5 credentials")
	}
	if err := writeAll(conn, []byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}
	return nil
}

func containsByte(values []byte, want byte) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
