package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupPhantasmHandler configures and starts the HTTPS handler for phantasm agents
func setupPhantasmHandler(ctx context.Context, tlsConfig *tls.Config) {
	phantasmConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "phantasm", // Protocol binding: HTTPS = phantasm
	}

	httpsHandler := accept.NewHTTPSHandler(sendToC2, logger, phantasmConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8080", cfg.ListenAddr)
	go func() {
		if err := httpsHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("Phantasm HTTPS handler error: %v", err)
		}
	}()

	logger.Printf("[+] Registered phantasm agent (HTTPS on %s)", bindAddr)
}
