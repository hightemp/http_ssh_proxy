package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"strings"
)

const proxyAuthChallenge = `Basic realm="Proxy Authorization Required"`

func basicAuth(w http.ResponseWriter, r *http.Request, cfg Config, reqID uint64) bool {
	ok, reason := checkProxyAuthorization(r.Header.Get("Proxy-Authorization"), cfg)
	if !ok {
		log.Printf("[REQ-%d] Proxy authentication from %s failed: %s", reqID, r.RemoteAddr, reason)
		writeProxyAuthRequired(w)
		return false
	}
	return true
}

// checkProxyAuthorization validates a Proxy-Authorization header against cfg.
// It always performs the constant-time credential comparison, even for a
// missing or malformed header, so timing does not reveal the failure reason.
// The returned reason is safe to log and never contains credentials.
func checkProxyAuthorization(header string, cfg Config) (bool, string) {
	reason := ""
	username, password, parsed := "", "", false
	if header == "" {
		reason = "no Proxy-Authorization header"
	} else if username, password, parsed = parseBasicProxyAuthorization(header); !parsed {
		reason = "invalid Proxy-Authorization header"
	}

	matches := credentialsMatch(username, password, cfg.Username, cfg.Password)
	if reason != "" {
		return false, reason
	}
	if !matches {
		return false, "invalid credentials"
	}
	return true, ""
}

func parseBasicProxyAuthorization(header string) (string, string, bool) {
	separator := strings.IndexAny(header, " \t")
	if separator <= 0 || !strings.EqualFold(header[:separator], "Basic") {
		return "", "", false
	}

	payload := strings.TrimSpace(header[separator:])
	if payload == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", "", false
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func credentialsMatch(username, password, expectedUsername, expectedPassword string) bool {
	usernameDigest := sha256.Sum256([]byte(username))
	expectedUsernameDigest := sha256.Sum256([]byte(expectedUsername))
	passwordDigest := sha256.Sum256([]byte(password))
	expectedPasswordDigest := sha256.Sum256([]byte(expectedPassword))
	usernameMatches := subtle.ConstantTimeCompare(usernameDigest[:], expectedUsernameDigest[:])
	passwordMatches := subtle.ConstantTimeCompare(passwordDigest[:], expectedPasswordDigest[:])
	return usernameMatches&passwordMatches == 1
}

func writeProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", proxyAuthChallenge)
	w.WriteHeader(http.StatusProxyAuthRequired)
}
