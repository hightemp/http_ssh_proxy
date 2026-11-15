package proxy

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"strings"
)

// StealthConfig makes the listener look like an ordinary web server to
// clients that do not use it as an authenticated proxy.
type StealthConfig struct {
	// Enabled turns stealth responses on.
	Enabled bool
	// ServerHeader is sent as the Server header of decoy and error pages and
	// shown in their footer. Empty omits both.
	ServerHeader string
	// AuthHost is a secret target hostname. Unauthenticated proxy requests to
	// it receive the 407 challenge so browsers can prompt for credentials;
	// every other unauthenticated request receives a decoy 404.
	AuthHost string
}

const stealthAuthSucceededBody = "<html>\r\n<head><title>OK</title></head>\r\n<body>\r\n<center><h1>OK</h1></center>\r\n</body>\r\n</html>\r\n"

// stealthAdmit decides whether r may use the proxy in stealth mode. When it
// returns false, a response has already been written.
func (h *Handler) stealthAdmit(w http.ResponseWriter, r *http.Request, reqID uint64) bool {
	isProxyRequest := r.Method == http.MethodConnect || r.URL.IsAbs()

	// Always evaluate credentials, even for requests that are rejected for
	// another reason, so response timing does not reveal which check failed.
	authenticated, authReason := true, ""
	if h.config.Username != "" {
		authenticated, authReason = checkProxyAuthorization(r.Header.Get("Proxy-Authorization"), h.config)
	}

	authHost := h.config.Stealth.AuthHost
	if authHost != "" && isProxyRequest && strings.EqualFold(requestTargetHostname(r), authHost) {
		if !authenticated {
			log.Printf("[REQ-%d] Stealth auth host challenge from %s: %s", reqID, r.RemoteAddr, authReason)
			writeProxyAuthRequired(w)
			return false
		}
		log.Printf("[REQ-%d] Stealth auth host authenticated from %s", reqID, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stealthAuthSucceededBody))
		return false
	}

	switch {
	case !isProxyRequest:
		log.Printf("[REQ-%d] Stealth decoy for non-proxy request from %s", reqID, r.RemoteAddr)
	case !authenticated:
		log.Printf("[REQ-%d] Stealth decoy from %s: %s", reqID, r.RemoteAddr, authReason)
	default:
		return true
	}
	h.config.Stealth.writePage(w, http.StatusNotFound)
	return false
}

// requestTargetHostname returns the destination hostname of a proxy request.
func requestTargetHostname(r *http.Request) string {
	if r.Method == http.MethodConnect {
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			return host
		}
		return r.Host
	}
	return r.URL.Hostname()
}

// writeError writes an error response that does not reveal the proxy in
// stealth mode and keeps the plain-text proxy messages otherwise.
func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	if h.config.Stealth.Enabled {
		h.config.Stealth.writePage(w, status)
		return
	}
	http.Error(w, message, status)
}

// writePage writes a minimal HTML status page in the style of common web
// servers.
func (s StealthConfig) writePage(w http.ResponseWriter, status int) {
	title := fmt.Sprintf("%d %s", status, http.StatusText(status))
	footer := ""
	if s.ServerHeader != "" {
		w.Header().Set("Server", s.ServerHeader)
		footer = "<hr><center>" + html.EscapeString(s.ServerHeader) + "</center>\r\n"
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<html>\r\n<head><title>%s</title></head>\r\n<body>\r\n<center><h1>%s</h1></center>\r\n%s</body>\r\n</html>\r\n",
		title, title, footer)
}

// connectEstablishedLine returns the CONNECT success status line.
func (h *Handler) connectEstablishedLine() string {
	if h.config.Stealth.Enabled {
		return "HTTP/1.1 200 OK\r\n\r\n"
	}
	return "HTTP/1.1 200 Connection Established\r\n\r\n"
}
