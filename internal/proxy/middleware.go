package proxy

import (
	"log"
	"net/http"
	"runtime/debug"
)

func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[PANIC] Recovered from panic in %s %s: %v\n%s", r.Method, r.URL, recovered, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
