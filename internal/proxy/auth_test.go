package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("proxy:secret"))
	tests := []struct {
		name       string
		header     string
		wantOK     bool
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusProxyAuthRequired},
		{name: "valid", header: "Basic " + valid, wantOK: true, wantStatus: http.StatusOK},
		{name: "case insensitive scheme", header: "bAsIc\t" + valid, wantOK: true, wantStatus: http.StatusOK},
		{name: "wrong scheme", header: "Bearer " + valid, wantStatus: http.StatusProxyAuthRequired},
		{name: "missing payload", header: "Basic ", wantStatus: http.StatusProxyAuthRequired},
		{name: "invalid base64", header: "Basic !!!", wantStatus: http.StatusProxyAuthRequired},
		{name: "missing colon", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy")), wantStatus: http.StatusProxyAuthRequired},
		{name: "wrong username", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("other:secret")), wantStatus: http.StatusProxyAuthRequired},
		{name: "wrong password", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy:other")), wantStatus: http.StatusProxyAuthRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			request.Header.Set("Proxy-Authorization", tt.header)
			recorder := httptest.NewRecorder()
			got := basicAuth(recorder, request, Config{Username: "proxy", Password: "secret"}, 1)
			if got != tt.wantOK {
				t.Errorf("basicAuth() = %t, want %t", got, tt.wantOK)
			}
			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if !tt.wantOK && recorder.Header().Get("Proxy-Authenticate") != proxyAuthChallenge {
				t.Errorf("Proxy-Authenticate = %q, want %q", recorder.Header().Get("Proxy-Authenticate"), proxyAuthChallenge)
			}
		})
	}
}

func TestCredentialsMatch(t *testing.T) {
	if !credentialsMatch("proxy", "secret", "proxy", "secret") {
		t.Error("credentialsMatch() rejected matching credentials")
	}
	if credentialsMatch("proxy", "wrong", "proxy", "secret") {
		t.Error("credentialsMatch() accepted a wrong password")
	}
}

func FuzzParseBasicProxyAuthorization(f *testing.F) {
	for _, seed := range []string{
		"",
		"Basic cHJveHk6c2VjcmV0",
		"basic\tcHJveHk6c2VjcmV0",
		"Bearer token",
		"Basic !!!",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		username, password, ok := parseBasicProxyAuthorization(header)
		if ok && !credentialsMatch(username, password, username, password) {
			t.Fatal("parsed credentials do not compare equal to themselves")
		}
	})
}
