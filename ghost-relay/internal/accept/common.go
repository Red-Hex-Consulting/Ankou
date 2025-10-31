package accept

import (
	"io"
	"log"
	"net/http"
)

// LogRequest logs incoming HTTP request details
func LogRequest(logger *log.Logger, protocolName, endpoint string, req *http.Request) {
	logger.Printf("[%s:%s] === INCOMING REQUEST ===", protocolName, endpoint)
	logger.Printf("[%s:%s] Method: %s", protocolName, endpoint, req.Method)
	logger.Printf("[%s:%s] URL: %s", protocolName, endpoint, req.URL.String())
	logger.Printf("[%s:%s] Host: %s", protocolName, endpoint, req.Host)
	logger.Printf("[%s:%s] RemoteAddr: %s", protocolName, endpoint, req.RemoteAddr)
	logger.Printf("[%s:%s] Proto: %s", protocolName, endpoint, req.Proto)

	// Log headers
	if len(req.Header) > 0 {
		logger.Printf("[%s:%s] Headers:", protocolName, endpoint)
		for name, values := range req.Header {
			for _, value := range values {
				logger.Printf("[%s:%s]   %s: %s", protocolName, endpoint, name, value)
			}
		}
	}
}

// ReadBody reads request body with size limit
func ReadBody(w http.ResponseWriter, req *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024 // 10MB default
	}
	reader := http.MaxBytesReader(w, req.Body, maxBytes)
	return io.ReadAll(reader)
}

// CopyResponse copies C2 response back to client
func CopyResponse(w http.ResponseWriter, resp *http.Response, logger *log.Logger) error {
	// Filter out hop-by-hop headers
	hopByHopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	// Copy headers
	for key, values := range resp.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body
	if _, err := io.Copy(w, resp.Body); err != nil {
		if logger != nil {
			logger.Printf("Error copying response body: %v", err)
		}
		return err
	}

	return nil
}
