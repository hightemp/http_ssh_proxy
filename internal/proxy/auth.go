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
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		log.Printf("[REQ-%d] No Proxy-Authorization header", reqID)
		writeProxyAuthRequired(w)
		return false
	}

	username, password, ok := parseBasicProxyAuthorization(auth)
	if !ok {
		log.Printf("[REQ-%d] Invalid Proxy-Authorization header", reqID)
		writeProxyAuthRequired(w)
		return false
	}

	if !credentialsMatch(username, password, cfg.Username, cfg.Password) {
		log.Printf("[REQ-%d] Failed proxy authentication from %s", reqID, r.RemoteAddr)
		writeProxyAuthRequired(w)
		return false
	}

	return true
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
