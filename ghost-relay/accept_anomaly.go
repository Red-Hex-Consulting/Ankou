package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupAnomalyHandler starts the HTTPS handler on port 8082
func setupAnomalyHandler(ctx context.Context, tlsConfig *tls.Config) {
	anomalyConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any",
	}

	httpsHandler := accept.NewHTTPSHandler(sendToC2, logger, anomalyConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8082", cfg.ListenAddr)
	go func() {
		if err := httpsHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("HTTPS handler error on %s: %v", bindAddr, err)
		}
	}()

	// Register handler for proper shutdown
	handlers = append(handlers, httpsHandler)

	logger.Printf("[+] HTTPS handler on %s", bindAddr)
}
