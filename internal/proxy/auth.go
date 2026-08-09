package proxy

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"
)

func basicAuth(w http.ResponseWriter, r *http.Request, cfg Config, reqID uint64) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		log.Printf("[REQ-%d] No Proxy-Authorization header", reqID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		log.Printf("[REQ-%d] Error decoding auth: %v", reqID, err)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		log.Printf("[REQ-%d] Invalid auth format", reqID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	if pair[0] != cfg.Username || pair[1] != cfg.Password {
		log.Printf("[REQ-%d] Failed auth from %s user=%s", reqID, r.RemoteAddr, pair[0])
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	return true
}
