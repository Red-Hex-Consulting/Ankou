package accept

import (
	"context"
	"log"
	"net/http"
	"time"
)

// BaseHandler provides common functionality for all protocol handlers
type BaseHandler struct {
	sendToC2     SendToC2Func
	logger       *log.Logger
	config       *HandlerConfig
	protocolName string
	agentType    string
}

// NewBaseHandler creates a new base handler with common functionality
func NewBaseHandler(sendToC2 SendToC2Func, logger *log.Logger, config *HandlerConfig, protocolName string) *BaseHandler {
	agentType := config.AgentType
	if agentType == "" {
		agentType = "any" // Default for handlers that accept any agent type
	}

	return &BaseHandler{
		sendToC2:     sendToC2,
		logger:       logger,
		config:       config,
		protocolName: protocolName,
		agentType:    agentType,
	}
}

// HandleHTTPRequest processes an HTTP request and forwards to C2
func (b *BaseHandler) HandleHTTPRequest(ctx context.Context, endpoint string, req *http.Request, w http.ResponseWriter) {
	// Read request body
	body, err := ReadBody(w, req, b.config.RequestReadLimit)
	if err != nil {
		b.logger.Printf("[%s:%s:%s] failed to read body: %v", b.protocolName, b.agentType, endpoint, err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Create minimal headers - only Content-Type and agent type for routing
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	headers["X-Agent-Type"] = b.agentType // Only for relay routing, not sent to C2

	// Send to C2
	start := time.Now()
	resp, err := b.sendToC2(ctx, endpoint, headers, body)
	if err != nil {
		b.logger.Printf("[%s:%s:%s] C2 send error: %v", b.protocolName, b.agentType, endpoint, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response back to client
	if err := CopyResponse(w, resp, b.logger); err != nil {
		b.logger.Printf("[%s:%s:%s] failed to copy response: %v", b.protocolName, b.agentType, endpoint, err)
		return
	}

	b.logger.Printf("[%s:%s:%s] processed in %v", b.protocolName, b.agentType, endpoint, time.Since(start))
}

// CreateHTTPHandler creates a standard HTTP handler function
func (b *BaseHandler) CreateHTTPHandler(endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Enforce POST method
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		b.HandleHTTPRequest(req.Context(), endpoint, req, w)
	}
}

// RegisterCatchAll registers a catch-all handler that accepts any path
func (b *BaseHandler) RegisterCatchAll(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		b.HandleHTTPRequest(req.Context(), req.URL.Path, req, w)
	})
}

// Logger returns the handler's logger
func (b *BaseHandler) Logger() *log.Logger {
	return b.logger
}

// Config returns the handler's config
func (b *BaseHandler) Config() *HandlerConfig {
	return b.config
}

// ProtocolName returns the protocol name
func (b *BaseHandler) ProtocolName() string {
	return b.protocolName
}

// AgentType returns the agent type this handler serves
func (b *BaseHandler) AgentType() string {
	return b.agentType
}
