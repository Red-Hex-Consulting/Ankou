package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupGeistHandler starts the QUIC handler on port 8081
func setupGeistHandler(ctx context.Context, tlsConfig *tls.Config) {
	geistConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any",
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

	logger.Printf("[+] QUIC handler on %s", bindAddr)
}
