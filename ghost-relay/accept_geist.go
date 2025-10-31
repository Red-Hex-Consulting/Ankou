package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupGeistHandler configures and starts the QUIC handler for geist agents
func setupGeistHandler(ctx context.Context, tlsConfig *tls.Config) {
	geistConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "geist", // Protocol binding: QUIC = geist
	}

	quicHandler := accept.NewQUICHandler(sendToC2, logger, geistConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8081", cfg.ListenAddr)
	go func() {
		if err := quicHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("Geist QUIC handler error: %v", err)
		}
	}()

	logger.Printf("[+] Registered geist agent (QUIC on %s)", bindAddr)
}
