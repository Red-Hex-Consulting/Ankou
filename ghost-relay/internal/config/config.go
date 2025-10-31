package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config captures runtime configuration for the relay server.
type Config struct {
	ListenAddr         string // Base bind address/interface for all handlers
	UpstreamBaseURL    *url.URL
	ClientTimeout      time.Duration
	InsecureSkipVerify bool
	RequestReadLimit   int64
	AgentHMACKey       []byte // HMAC key for validating agent requests
	ServerHMACKey      []byte // HMAC key for relay -> C2 authentication
}

// Load reads configuration values from the environment, applying sensible defaults.
// If upstreamURLOverride is provided (non-empty), it takes precedence over the config file/environment variable.
// If bindAddrOverride is provided (non-empty), it takes precedence over the config file/environment variable.
func Load(upstreamURLOverride, bindAddrOverride string) (*Config, error) {
	// Load relay config for upstream URL and HMAC keys
	relayConfig := loadRelayConfigFile()

	// Use command-line override if provided, otherwise config file, then environment variable, then default
	listenAddr := bindAddrOverride
	if listenAddr == "" && relayConfig["LISTEN_ADDR"] != "" {
		listenAddr = relayConfig["LISTEN_ADDR"]
	}
	if listenAddr == "" {
		listenAddr = envOrDefault("GHOST_RELAY_LISTEN_ADDR", "0.0.0.0")
	}

	// Use command-line override if provided, otherwise config file, then environment variable, then default
	upstreamRaw := upstreamURLOverride
	if upstreamRaw == "" && relayConfig["UPSTREAM_URL"] != "" {
		upstreamRaw = relayConfig["UPSTREAM_URL"]
	}
	if upstreamRaw == "" {
		upstreamRaw = envOrDefault("GHOST_RELAY_UPSTREAM_BASE_URL", "https://localhost:8444")
	}

	upstreamURL, err := url.Parse(upstreamRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream base URL %q: %w", upstreamRaw, err)
	}
	if upstreamURL.Scheme != "https" {
		return nil, fmt.Errorf("upstream base URL must use https scheme")
	}

	timeoutRaw := envOrDefault("GHOST_RELAY_CLIENT_TIMEOUT", "15s")
	timeout, err := time.ParseDuration(timeoutRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid GHOST_RELAY_CLIENT_TIMEOUT %q: %w", timeoutRaw, err)
	}

	insecureRaw := envOrDefault("GHOST_RELAY_INSECURE_SKIP_VERIFY", "true")
	insecure, err := strconv.ParseBool(insecureRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid GHOST_RELAY_INSECURE_SKIP_VERIFY %q: %w", insecureRaw, err)
	}

	limitRaw := envOrDefault("GHOST_RELAY_REQUEST_READ_LIMIT", "10485760") // 10 MiB
	readLimit, err := strconv.ParseInt(limitRaw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GHOST_RELAY_REQUEST_READ_LIMIT %q: %w", limitRaw, err)
	}

	// Load HMAC keys from relay.config (already loaded) or environment variables
	agentHMACKey, serverHMACKey, err := loadHMACKeys(relayConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load HMAC keys: %w", err)
	}

	return &Config{
		ListenAddr:         listenAddr,
		UpstreamBaseURL:    upstreamURL,
		ClientTimeout:      timeout,
		InsecureSkipVerify: insecure,
		RequestReadLimit:   readLimit,
		AgentHMACKey:       []byte(agentHMACKey),
		ServerHMACKey:      []byte(serverHMACKey),
	}, nil
}

// loadRelayConfigFile loads the relay.config file and returns key-value pairs
func loadRelayConfigFile() map[string]string {
	config := make(map[string]string)
	configFile := "relay.config"

	data, err := os.ReadFile(configFile)
	if err != nil {
		// Config file not found, will use environment variables or defaults
		return config
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx >= 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			config[key] = value
		}
	}

	if len(config) > 0 {
		log.Printf("Loaded configuration from %s", configFile)
	}
	return config
}

// loadHMACKeys loads HMAC keys from relay config or environment variables
func loadHMACKeys(relayConfig map[string]string) (agentKey, serverKey string, err error) {
	// Try to get from relay.config first
	agentKey = relayConfig["AGENT_HMAC_KEY"]
	serverKey = relayConfig["SERVER_HMAC_KEY"]

	// Fallback to environment variables if not in config
	if agentKey == "" {
		agentKey = os.Getenv("AGENT_HMAC_KEY")
	}
	if serverKey == "" {
		serverKey = os.Getenv("SERVER_HMAC_KEY")
	}

	if agentKey == "" || serverKey == "" {
		return "", "", fmt.Errorf("HMAC keys not found. Create relay.config (see relay.config.example) or set AGENT_HMAC_KEY and SERVER_HMAC_KEY environment variables")
	}

	return agentKey, serverKey, nil
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
