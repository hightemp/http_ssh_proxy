package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStealthResponses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin body")
	}))
	t.Cleanup(origin.Close)
	dialer := fixedAddressDialer{address: origin.Listener.Addr().String()}

	authenticated := Config{
		Username:          "proxy",
		Password:          "secret",
		TunnelIdleTimeout: time.Second,
		Stealth:           StealthConfig{Enabled: true, ServerHeader: "nginx", AuthHost: "login.proxy"},
	}
	open := Config{
		TunnelIdleTimeout: time.Second,
		Stealth:           StealthConfig{Enabled: true, ServerHeader: "nginx"},
	}
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy:secret"))
	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy:wrong"))

	tests := []struct {
		name       string
		cfg        Config
		method     string
		target     string
		auth       string
		wantStatus int
		wantBody   string
		wantAuth   bool
	}{
		{name: "direct request", cfg: authenticated, method: http.MethodGet, target: "/", wantStatus: http.StatusNotFound, wantBody: "404 Not Found"},
		{name: "direct request with credentials", cfg: authenticated, method: http.MethodGet, target: "/", auth: valid, wantStatus: http.StatusNotFound},
		{name: "proxy request without credentials", cfg: authenticated, method: http.MethodGet, target: "http://example.com/", wantStatus: http.StatusNotFound},
		{name: "proxy request with wrong password", cfg: authenticated, method: http.MethodGet, target: "http://example.com/", auth: wrong, wantStatus: http.StatusNotFound},
		{name: "proxy request with malformed credentials", cfg: authenticated, method: http.MethodGet, target: "http://example.com/", auth: "Bearer token", wantStatus: http.StatusNotFound},
		{name: "CONNECT without credentials", cfg: authenticated, method: http.MethodConnect, target: "example.com:443", wantStatus: http.StatusNotFound},
		{name: "auth host challenge", cfg: authenticated, method: http.MethodGet, target: "http://login.proxy/", wantStatus: http.StatusProxyAuthRequired, wantAuth: true},
		{name: "auth host challenge over CONNECT", cfg: authenticated, method: http.MethodConnect, target: "login.proxy:443", auth: wrong, wantStatus: http.StatusProxyAuthRequired, wantAuth: true},
		{name: "auth host authenticated", cfg: authenticated, method: http.MethodGet, target: "http://LOGIN.proxy/", auth: valid, wantStatus: http.StatusOK, wantBody: "<h1>OK</h1>"},
		{name: "authenticated proxy request", cfg: authenticated, method: http.MethodGet, target: "http://example.com/", auth: valid, wantStatus: http.StatusOK, wantBody: "origin body"},
		{name: "open proxy direct request", cfg: open, method: http.MethodGet, target: "/", wantStatus: http.StatusNotFound},
		{name: "open proxy request", cfg: open, method: http.MethodGet, target: "http://example.com/", wantStatus: http.StatusOK, wantBody: "origin body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(tt.cfg, dialer)
			t.Cleanup(func() { shutdownTestHandler(t, handler) })
			request := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.method == http.MethodConnect {
				request.Host = tt.target
				request.URL.Host = tt.target
			}
			if tt.auth != "" {
				request.Header.Set("Proxy-Authorization", tt.auth)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			if got := recorder.Header().Get("Proxy-Authenticate") != ""; got != tt.wantAuth {
				t.Errorf("Proxy-Authenticate present = %t, want %t", got, tt.wantAuth)
			}
			if !strings.Contains(recorder.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", recorder.Body.String(), tt.wantBody)
			}
			if tt.wantStatus == http.StatusNotFound {
				assertStealthPage(t, recorder, "404 Not Found", "nginx")
			}
		})
	}
}

func TestStealthErrorPages(t *testing.T) {
	cfg := Config{TunnelIdleTimeout: time.Second, Stealth: StealthConfig{Enabled: true, ServerHeader: "Apache"}}

	t.Run("dial failure", func(t *testing.T) {
		handler := NewHandler(cfg, &fakeDialer{err: errors.New("dial failed")})
		t.Cleanup(func() { shutdownTestHandler(t, handler) })
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", recorder.Code)
		}
		assertStealthPage(t, recorder, "502 Bad Gateway", "Apache")
	})

	t.Run("invalid CONNECT target", func(t *testing.T) {
		handler := NewHandler(cfg, &fakeDialer{})
		t.Cleanup(func() { shutdownTestHandler(t, handler) })
		request := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
		request.Host = "example.com"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", recorder.Code)
		}
		assertStealthPage(t, recorder, "400 Bad Request", "Apache")
	})

	t.Run("shutting down", func(t *testing.T) {
		handler := NewHandler(cfg, &fakeDialer{})
		shutdownTestHandler(t, handler)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", recorder.Code)
		}
		assertStealthPage(t, recorder, "503 Service Unavailable", "Apache")
	})

	t.Run("panic without server header", func(t *testing.T) {
		handler := &Handler{config: Config{Stealth: StealthConfig{Enabled: true}}}
		recorder := httptest.NewRecorder()
		panicRecoveryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom")
		}), handler.writeError).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", recorder.Code)
		}
		assertStealthPage(t, recorder, "500 Internal Server Error", "")
	})
}

func TestStealthConnectStatusLine(t *testing.T) {
	proxySide, remoteSide := net.Pipe()
	handler := NewHandler(Config{
		TunnelIdleTimeout: 5 * time.Second,
		Stealth:           StealthConfig{Enabled: true},
	}, &fakeDialer{conn: proxySide})
	// Cleanups run in reverse: close both tunnel ends before shutdown waits.
	t.Cleanup(func() { shutdownTestHandler(t, handler) })
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = remoteSide.Close() })

	clientConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test proxy: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	status, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if status != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("CONNECT status = %q, want a plain 200 OK", status)
	}
}

func TestCheckProxyAuthorizationReasons(t *testing.T) {
	cfg := Config{Username: "proxy", Password: "secret"}
	tests := []struct {
		header     string
		wantOK     bool
		wantReason string
	}{
		{header: "", wantReason: "no Proxy-Authorization header"},
		{header: "Basic !!!", wantReason: "invalid Proxy-Authorization header"},
		{header: "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy:nope")), wantReason: "invalid credentials"},
		{header: "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy:secret")), wantOK: true},
	}
	for _, tt := range tests {
		ok, reason := checkProxyAuthorization(tt.header, cfg)
		if ok != tt.wantOK || reason != tt.wantReason {
			t.Errorf("checkProxyAuthorization(%q) = %t, %q, want %t, %q", tt.header, ok, reason, tt.wantOK, tt.wantReason)
		}
	}
}

func assertStealthPage(t *testing.T, recorder *httptest.ResponseRecorder, title, server string) {
	t.Helper()
	body := recorder.Body.String()
	if got := recorder.Header().Get("Server"); got != server {
		t.Errorf("Server = %q, want %q", got, server)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html" {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if recorder.Header().Get("X-Content-Type-Options") != "" {
		t.Error("stealth page carries the net/http error header X-Content-Type-Options")
	}
	if !strings.Contains(body, "<title>"+title+"</title>") {
		t.Errorf("body = %q, want title %q", body, title)
	}
	if hasFooter := strings.Contains(body, "<hr>"); hasFooter != (server != "") {
		t.Errorf("body = %q, footer present = %t, want %t", body, hasFooter, server != "")
	}
	for _, leak := range []string{"proxy", "Proxy", "Connection Established"} {
		if strings.Contains(body, leak) {
			t.Errorf("body = %q, reveals %q", body, leak)
		}
	}
}
