package proxy

import (
	"net/http"
	"testing"
)

func FuzzRemoveHopByHopHeaders(f *testing.F) {
	for _, seed := range []string{
		"X-Remove",
		"keep-alive, x-private",
		"Upgrade",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, connectionValue string) {
		header := http.Header{
			"Connection":       {connectionValue},
			"Keep-Alive":       {"timeout=5"},
			"Proxy-Connection": {"keep-alive"},
			"Upgrade":          {"websocket"},
		}
		removeHopByHopHeaders(header)
		for _, name := range hopByHopHeaders {
			if header.Get(name) != "" {
				t.Fatalf("hop-by-hop header %q was not removed", name)
			}
		}
	})
}
