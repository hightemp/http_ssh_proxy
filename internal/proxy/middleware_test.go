package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPanicRecoveryMiddleware(t *testing.T) {
	handler := panicRecoveryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("sensitive panic detail")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "sensitive panic detail") {
		t.Errorf("response exposed panic detail: %q", recorder.Body.String())
	}
}
