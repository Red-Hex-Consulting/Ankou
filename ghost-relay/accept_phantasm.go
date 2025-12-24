package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupPhantasmHandler configures and starts the HTTPS handler for phantasm agents
// Note: With body-based agent identification, this handler can accept any agent type
// that declares itself in the request body. The "phantasm" name is for logging only.
func setupPhantasmHandler(ctx context.Context, tlsConfig *tls.Config) {
	phantasmConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any", // Accepts any agent type from body
	}

	httpsHandler := accept.NewHTTPSHandler(sendToC2, logger, phantasmConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8080", cfg.ListenAddr)
	go func() {
		if err := httpsHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("HTTPS handler error on %s: %v", bindAddr, err)
		}
	}()

	// Register handler for proper shutdown
	handlers = append(handlers, httpsHandler)

	logger.Printf("[+] HTTPS handler on %s (accepts any agent type via body)", bindAddr)
}
