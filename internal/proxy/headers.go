package proxy

import (
	"net/http"
	"strings"
)

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(header http.Header) {
	for _, connectionValue := range header.Values("Connection") {
		for _, token := range strings.Split(connectionValue, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

func isHopByHopHeader(name string) bool {
	for _, hopByHop := range hopByHopHeaders {
		if strings.EqualFold(name, hopByHop) {
			return true
		}
	}
	return false
}

func joinHeaderTokens(tokens []string) string {
	return strings.Join(tokens, ", ")
}
