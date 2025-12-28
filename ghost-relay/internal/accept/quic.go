package accept

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// QUICHandler implements AcceptHandler for QUIC/HTTP3 protocol
type QUICHandler struct {
	*BaseHandler
	server    *http3.Server
	tlsConfig *tls.Config
}

// NewQUICHandler creates a new QUIC accept handler
func NewQUICHandler(sendToC2 SendToC2Func, logger *log.Logger, config *HandlerConfig, tlsConfig *tls.Config) *QUICHandler {
	return &QUICHandler{
		BaseHandler: NewBaseHandler(sendToC2, logger, config, "quic"),
		tlsConfig:   tlsConfig,
	}
}

// Start begins listening for QUIC/HTTP3 connections
func (q *QUICHandler) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()

	// Register catch-all handler (routes based on X-Action header)
	q.RegisterCatchAll(mux)

	// Create HTTP3 server with QUIC
	q.server = &http3.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: q.tlsConfig,
	}

	q.Logger().Printf("[quic] Starting QUIC/HTTP3 listener on %s", addr)

	// ListenAndServe blocks, so we need to run it in a goroutine
	go func() {
		if err := q.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			q.Logger().Printf("[quic] Server error: %v", err)
		}
	}()

	// Wait for context cancellation and shutdown gracefully
	go func() {
		<-ctx.Done()
		q.Logger().Printf("[quic] Context cancelled, shutting down")
		q.Stop()
	}()

	return nil
}

// Stop gracefully shuts down the QUIC handler
func (q *QUICHandler) Stop() error {
	if q.server != nil {
		return q.server.Close()
	}
	return nil
}

// GetName returns the handler name
func (q *QUICHandler) GetName() string {
	return "quic"
}
