package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"ghost-relay/internal/accept"
)

// setupHTTPSHandler starts the HTTPS handler on port 8080
func setupHTTPSHandler(ctx context.Context, tlsConfig *tls.Config) {
	httpsConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
	}

	httpsHandler := accept.NewHTTPSHandler(sendToC2, logger, httpsConfig, tlsConfig)

	bindAddr := fmt.Sprintf("%s:8080", cfg.ListenAddr)
	go func() {
		if err := httpsHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("HTTPS handler error on %s: %v", bindAddr, err)
		}
	}()

	// Register handler for proper shutdown
	handlers = append(handlers, httpsHandler)

	logger.Printf("[+] HTTPS handler on %s", bindAddr)
}
