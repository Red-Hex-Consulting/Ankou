package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupGeistHandler configures and starts the QUIC handler for geist agents
// Note: With body-based agent identification, this handler can accept any agent type
// that declares itself in the request body. The "geist" name is for logging only.
func setupGeistHandler(ctx context.Context, tlsConfig *tls.Config) {
	geistConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any", // Accepts any agent type from body
	}

	quicHandler := accept.NewQUICHandler(sendToC2, logger, geistConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8081", cfg.ListenAddr)
	go func() {
		if err := quicHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("QUIC handler error on %s: %v", bindAddr, err)
		}
	}()

	// Register handler for proper shutdown
	handlers = append(handlers, quicHandler)

	logger.Printf("[+] QUIC handler on %s (accepts any agent type via body)", bindAddr)
}
