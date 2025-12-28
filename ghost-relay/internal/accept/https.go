package accept

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"
)

// HTTPSHandler implements AcceptHandler for HTTPS protocol
type HTTPSHandler struct {
	*BaseHandler
	server    *http.Server
	tlsConfig *tls.Config
}

// NewHTTPSHandler creates a new HTTPS accept handler
func NewHTTPSHandler(sendToC2 SendToC2Func, logger *log.Logger, config *HandlerConfig, tlsConfig *tls.Config) *HTTPSHandler {
	return &HTTPSHandler{
		BaseHandler: NewBaseHandler(sendToC2, logger, config, "https"),
		tlsConfig:   tlsConfig,
	}
}

// Start begins listening for HTTPS connections
func (h *HTTPSHandler) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()

	// Register catch-all handler (routes based on X-Action header)
	h.RegisterCatchAll(mux)

	// Create HTTPS server with TLS config
	h.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         h.tlsConfig,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,              // Prevent slow-read attacks
		MaxHeaderBytes:    1 << 20,                       // 1 MB max header size
	}

	h.Logger().Printf("[https] Starting HTTPS listener on %s", addr)

	// Start server in goroutine to not block
	go func() {
		if err := h.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			h.Logger().Printf("[https] Server error: %v", err)
		}
	}()

	// Wait for context cancellation
	go func() {
		<-ctx.Done()
		h.Logger().Printf("[https] Context cancelled, shutting down")
		h.Stop()
	}()

	return nil
}

// Stop gracefully shuts down the HTTPS handler
func (h *HTTPSHandler) Stop() error {
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return h.server.Shutdown(ctx)
	}
	return nil
}

// GetName returns the handler name
func (h *HTTPSHandler) GetName() string {
	return "https"
}
