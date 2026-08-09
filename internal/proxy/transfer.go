package proxy

import (
	"io"
	"log"
	"strings"
)

func transfer(destination io.Writer, source io.Reader, reqID uint64, direction string) {
	n, err := io.Copy(destination, source)
	if err != nil {
		// Don't log "use of closed network connection" as error — it's expected on tunnel close.
		errStr := err.Error()
		if strings.Contains(errStr, "use of closed network connection") ||
			strings.Contains(errStr, "connection reset by peer") ||
			strings.Contains(errStr, "broken pipe") {
			log.Printf("[REQ-%d] %s closed (%d bytes)", reqID, direction, n)
		} else {
			log.Printf("[REQ-%d] %s transfer error after %d bytes: %v", reqID, direction, n, err)
		}
	} else {
		log.Printf("[REQ-%d] %s done (%d bytes)", reqID, direction, n)
	}
}
