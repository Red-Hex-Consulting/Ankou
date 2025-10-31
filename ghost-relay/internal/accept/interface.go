package accept

import (
	"context"
	"net/http"
)

// AcceptHandler defines the interface for custom protocol handlers
type AcceptHandler interface {
	// Start begins listening for connections on the specified address
	Start(ctx context.Context, addr string) error

	// Stop gracefully shuts down the handler
	Stop() error

	// GetName returns the name of this handler (e.g., "https", "quic", "smb")
	GetName() string
}

// SendToC2Func defines the function signature for sending data to C2
type SendToC2Func func(ctx context.Context, endpoint string, headers map[string]string, body []byte) (*http.Response, error)

// RequestData contains all the data from an incoming request
type RequestData struct {
	Method     string
	URL        string
	Headers    map[string]string
	Body       []byte
	RemoteAddr string
	Endpoint   string
}

// HandlerConfig contains configuration for accept handlers
type HandlerConfig struct {
	UpstreamURL      string
	Timeout          int
	InsecureTLS      bool
	RequestReadLimit int64
	AgentType        string // Agent type this handler serves (e.g., "phantasm", "geist")
}
