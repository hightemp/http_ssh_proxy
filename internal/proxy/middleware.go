package proxy

import (
	"log"
	"net/http"
	"runtime/debug"
)

func panicRecoveryMiddleware(next http.Handler, writeError func(http.ResponseWriter, int, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[PANIC] Recovered from panic in %s %s: %v\n%s", r.Method, r.URL, recovered, debug.Stack())
				writeError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
