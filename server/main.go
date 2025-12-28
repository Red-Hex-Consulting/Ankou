package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Agent struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	IP                string    `json:"ip"`
	LastSeen          time.Time `json:"lastSeen"`
	OS                string    `json:"os"`
	CreatedAt         time.Time `json:"createdAt"`
	HandlerID         string    `json:"handlerId"`
	HandlerName       string    `json:"handlerName"`
	ReconnectInterval int       `json:"reconnectInterval"`
	Privileges        string    `json:"privileges"`
}

type Listener struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Endpoint    string    `json:"endpoint"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

type AgentHandler struct {
	ID                string   `json:"id"`
	AgentName         string   `json:"agentName"`
	AgentHeaderID     string   `json:"agentHttpHeaderId"`
	SupportedCommands []string `json:"supportedCommands"`
}

type AgentRegistration struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	IP                string `json:"ip"`
	OS                string `json:"os"`
	AgentType         string `json:"agent_type,omitempty"` // Agent type identifier (e.g., "phantasm", "anomaly")
	ReconnectInterval int    `json:"reconnectInterval"`    // Beacon interval in seconds (0 = unknown)
	Privileges        string `json:"privileges"`           // JSON: {isRoot: bool, isAdmin: bool}
}

type Command struct {
	ID             int        `json:"id"`
	AgentID        string     `json:"agentId"`
	Command        string     `json:"command"`
	ClientUsername string     `json:"clientUsername"`
	Status         string     `json:"status"`
	Output         string     `json:"output"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExecutedAt     *time.Time `json:"executedAt"`
}

type CommandSubmission struct {
	AgentID string `json:"agentId"`
	Command string `json:"command"`
}

type CommandResponse struct {
	CommandID int    `json:"commandId"`
	Output    string `json:"output"`
	Status    string `json:"status"`
	IsFile    bool   `json:"isFile,omitempty"`
	MD5Hash   string `json:"md5Hash,omitempty"`
}

var (
	db       *sql.DB
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for development
		},
	}
	clients               = make(map[*Client]bool)
	listeners             = make(map[string]*Listener)
	listenersMutex        sync.RWMutex
	agentHandlers         = make(map[string]*AgentHandler)
	agentHandlersByHeader = make(map[string]*AgentHandler)
	jwtSecret             []byte
	hmacKey               []byte
	registrationKey       string
	mainHandler           http.Handler
)

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // Don't include in JSON
	CreatedAt time.Time `json:"created_at"`
}

type AuthRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	RegistrationKey string `json:"registrationKey,omitempty"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type contextKey string

const listenerOriginalPathKey contextKey = "listenerOriginalPath"

// generateSelfSignedCert generates a self-signed certificate for development
func generateSelfSignedCert() error {
	// Check if certificates already exist
	if _, err := os.Stat("server.crt"); err == nil {
		if _, err := os.Stat("server.key"); err == nil {
			fmt.Println("TLS certificates already exist, using existing ones")
			return nil
		}
	}

	fmt.Println("Generating self-signed TLS certificates...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Get all local IP addresses
	localIPs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() {
					localIPs = append(localIPs, ip)
				}
			}
		}
	}

	// Get hostname for DNS name
	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Ankou C2"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: localIPs,
		DNSNames:    dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	certOut, err := os.Create("server.crt")
	if err != nil {
		return fmt.Errorf("failed to open server.crt for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save private key
	keyOut, err := os.Create("server.key")
	if err != nil {
		return fmt.Errorf("failed to open server.key for writing: %v", err)
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	fmt.Println("[+] TLS certificates generated successfully")
	return nil
}

// Auth functions
func generateRegistrationKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", key), nil
}

// AnkouConfig holds all server secrets/keys
type AnkouConfig struct {
	JWTSecret       string
	HMACKey         string
	RegistrationKey string
}

// loadOrCreateConfig loads ankou.config or creates it (migrating from old files if they exist)
func loadOrCreateConfig() (*AnkouConfig, error) {
	configFile := "ankou.config"
	config := &AnkouConfig{}

	// Try to load existing config
	if data, err := os.ReadFile(configFile); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				switch key {
				case "JWT_SECRET":
					config.JWTSecret = value
				case "HMAC_KEY":
					config.HMACKey = value
				case "REGISTRATION_KEY":
					config.RegistrationKey = value
				}
			}
		}

		// Validate all keys are present
		if config.JWTSecret != "" && config.HMACKey != "" && config.RegistrationKey != "" {
			log.Printf("Loaded configuration from %s", configFile)
			return config, nil
		}
	}

	// Config doesn't exist or is incomplete - try to migrate from old files
	log.Printf("Configuration incomplete or missing, checking for legacy files to migrate...")

	// Try to migrate from old JWT secret file
	if config.JWTSecret == "" {
		if data, err := os.ReadFile("jwt.secret"); err == nil {
			config.JWTSecret = strings.TrimSpace(string(data))
			log.Printf("Migrated JWT secret from jwt.secret")
		}
	}

	// Try to migrate from old HMAC key file
	if config.HMACKey == "" {
		if data, err := os.ReadFile("hmac.key"); err == nil {
			config.HMACKey = strings.TrimSpace(string(data))
			log.Printf("Migrated HMAC key from hmac.key")
		}
	}

	// Try to migrate from old registration key file
	if config.RegistrationKey == "" {
		if data, err := os.ReadFile("registration.key"); err == nil {
			config.RegistrationKey = strings.TrimSpace(string(data))
			log.Printf("Migrated registration key from registration.key")
		}
	}

	// Generate any missing keys
	if config.JWTSecret == "" {
		secret := make([]byte, 64)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %v", err)
		}
		config.JWTSecret = fmt.Sprintf("%x", secret)
		log.Printf("Generated new JWT secret")
	}

	if config.HMACKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate HMAC key: %v", err)
		}
		config.HMACKey = fmt.Sprintf("%x", key)
		log.Printf("Generated new HMAC key")
	}

	if config.RegistrationKey == "" {
		key := make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate registration key: %v", err)
		}
		config.RegistrationKey = fmt.Sprintf("%x", key)
		log.Printf("Generated new registration key")
	}

	// Save the consolidated config
	configContent := fmt.Sprintf(`# Ankou Server Configuration
# Auto-generated - Do not share these keys!

JWT_SECRET=%s
HMAC_KEY=%s
REGISTRATION_KEY=%s
`, config.JWTSecret, config.HMACKey, config.RegistrationKey)

	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to save config: %v", err)
	}

	log.Printf("Saved consolidated configuration to %s", configFile)

	// Clean up old files if they exist and were migrated
	oldFiles := []string{"jwt.secret", "hmac.key", "registration.key"}
	for _, oldFile := range oldFiles {
		if _, err := os.Stat(oldFile); err == nil {
			if err := os.Remove(oldFile); err != nil {
				log.Printf("Warning: Could not remove old config file %s: %v", oldFile, err)
			} else {
				log.Printf("Removed legacy config file: %s", oldFile)
			}
		}
	}

	return config, nil
}

// HMAC validation functions
func generateHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// unwrapAgentData extracts the data field from agent's JSON wrapper
func unwrapAgentData(r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("unwrapAgentData: failed to read body: %v", err)
		return false
	}

	var wrapper struct {
		Data      json.RawMessage `json:"data"`
		Timestamp string          `json:"timestamp"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		log.Printf("unwrapAgentData: failed to parse JSON: %v", err)
		return false
	}

	if len(wrapper.Data) == 0 {
		log.Printf("unwrapAgentData: missing data field")
		return false
	}

	// Replace request body with just the data portion
	r.Body = io.NopCloser(bytes.NewReader(wrapper.Data))
	return true
}

// HMAC middleware to protect agent endpoints
func hmacMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// All requests must come from relay with relay HMAC headers
		relayTimestamp := r.Header.Get("X-Relay-Timestamp")
		relaySignature := r.Header.Get("X-Relay-Signature")

		if relayTimestamp == "" || relaySignature == "" {
			log.Printf("[Security] Missing relay HMAC headers from %s", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing relay authentication"})
			return
		}

		// Validate relay HMAC only
		// The relay is responsible for validating agent HMAC
		if !validateRelayHMAC(r, relayTimestamp, relaySignature, hmacKey) {
			log.Printf("[Security] Relay HMAC validation failed from %s", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid relay HMAC"})
			return
		}

		// Unwrap the agent data from the wrapper for handlers
		if !unwrapAgentData(r) {
			log.Printf("Failed to unwrap agent data")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request format"})
			return
		}

		next(w, r)
	}
}

func validateRelayHMAC(r *http.Request, timestamp, signature string, key []byte) bool {
	// Check timestamp
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		log.Printf("Relay HMAC: Invalid timestamp: %v", err)
		return false
	}

	now := time.Now().Unix()
	if now-ts > 300 || ts-now > 300 {
		log.Printf("Relay HMAC: Timestamp out of window (diff: %d seconds)", now-ts)
		return false
	}

	// Use the original path before listener routing (if available)
	pathForHMAC := r.URL.Path
	if originalPath, ok := r.Context().Value(listenerOriginalPathKey).(string); ok && originalPath != "" {
		pathForHMAC = originalPath
	}

	// Validate relay signature (method + path + timestamp only - body already validated by agent HMAC)
	message := fmt.Sprintf("%s%s%s", r.Method, pathForHMAC, timestamp)
	expectedMAC := generateHMAC(message, key)
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID, username string) (string, error) {
	now := time.Now()
	expTime := now.Add(time.Hour * 1).Unix() // 1 hour
	log.Printf("Generating JWT with exp: %d (current time: %d, difference: %d seconds)", expTime, now.Unix(), expTime-now.Unix())

	// Generate a truly unique JWT ID using timestamp + random bytes
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	jti := fmt.Sprintf("%d-%x", now.UnixNano(), randomBytes)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"exp":      expTime,    // 1 hour
		"iat":      now.Unix(), // issued at - current time
		"jti":      jti,        // unique token ID with timestamp + random component
	})

	return token.SignedString(jwtSecret)
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		log.Printf("JWT validation error: %v", err)
		return token, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			now := time.Now().Unix()
			log.Printf("JWT exp: %f, now: %d, valid: %t", exp, now, exp > float64(now))
		}
	}

	return token, err
}

type ServerConfig struct {
	Relay struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Description string `json:"description"`
	} `json:"relay"`
	Operator struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Description string `json:"description"`
	} `json:"operator"`
}

func loadServerConfig() (*ServerConfig, error) {
	configPath := "server_config.json"

	// Check if config exists, if not create default
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := &ServerConfig{}
		defaultConfig.Relay.Host = "127.0.0.1"
		defaultConfig.Relay.Port = 8444
		defaultConfig.Relay.Description = "Agent relay communication endpoint (REST API for agent tasking)"
		defaultConfig.Operator.Host = "0.0.0.0"
		defaultConfig.Operator.Port = 8443
		defaultConfig.Operator.Description = "Operator console endpoint (WebSocket/GraphQL for frontend)"

		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal default config: %w", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to write default config: %w", err)
		}

		log.Printf("Created default server config at %s", configPath)
		return defaultConfig, nil
	}

	// Load existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config ServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

func main() {
	// Load server configuration
	config, err := loadServerConfig()
	if err != nil {
		log.Fatalf("Failed to load server config: %v", err)
	}

	log.Printf("Relay API: %s:%d - %s", config.Relay.Host, config.Relay.Port, config.Relay.Description)
	log.Printf("Operator API: %s:%d - %s", config.Operator.Host, config.Operator.Port, config.Operator.Description)

	// Open database with concurrency-friendly settings
	db, err = sql.Open("sqlite", "./agents.db?_busy_timeout=5000")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Set connection pool settings for better concurrency
	db.SetMaxOpenConns(1) // SQLite works best with single writer
	db.SetMaxIdleConns(1)

	// Explicitly enable WAL mode and other performance settings
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA cache_size=1000;",
		"PRAGMA temp_store=memory;",
		"PRAGMA busy_timeout=5000;",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			log.Printf("Warning: Failed to set %s: %v", pragma, err)
		}
	}

	// Create tables
	if err := createUsersTable(); err != nil {
		log.Fatal("Failed to create users table:", err)
	}
	if err := createLogsTable(); err != nil {
		log.Fatal("Failed to create logs table:", err)
	}

	// Load or create unified configuration
	ankouConfig, err := loadOrCreateConfig()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Set global configuration variables
	jwtSecret = []byte(ankouConfig.JWTSecret)
	hmacKey = []byte(ankouConfig.HMACKey)
	registrationKey = ankouConfig.RegistrationKey

	log.Printf("Configuration loaded successfully")
	log.Printf("Registration key: %s", registrationKey)

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		status TEXT NOT NULL,
		ip TEXT NOT NULL,
		last_seen DATETIME NOT NULL,
		os TEXT NOT NULL,
		created_at DATETIME
	);
	
	CREATE TABLE IF NOT EXISTS commands (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		command TEXT NOT NULL,
		client_username TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		output TEXT,
		created_at DATETIME NOT NULL,
		executed_at DATETIME,
		FOREIGN KEY (agent_id) REFERENCES agents (id)
	);
	
	CREATE TABLE IF NOT EXISTS loot_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		command_id INTEGER NOT NULL,
		agent_id TEXT NOT NULL,
		filename TEXT NOT NULL,
		original_path TEXT,
		stored_path TEXT NOT NULL,
		md5_hash TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		is_organized BOOLEAN NOT NULL DEFAULT 0,
		file_content TEXT NOT NULL,
		file_type TEXT NOT NULL DEFAULT 'file',
		created_at DATETIME NOT NULL,
		FOREIGN KEY (command_id) REFERENCES commands (id),
		FOREIGN KEY (agent_id) REFERENCES agents (id),
		UNIQUE(agent_id, original_path, md5_hash)
	);
	
	CREATE TABLE IF NOT EXISTS temp_file_transfers (
		session_id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		command_id INTEGER NOT NULL,
		filename TEXT NOT NULL,
		original_path TEXT NOT NULL,
		total_size INTEGER NOT NULL,
		total_chunks INTEGER NOT NULL,
		expected_md5 TEXT NOT NULL,
		chunks_received INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (agent_id) REFERENCES agents (id),
		FOREIGN KEY (command_id) REFERENCES commands (id)
	);
	
	CREATE TABLE IF NOT EXISTS temp_file_chunks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		chunk_index INTEGER NOT NULL,
		chunk_data BLOB NOT NULL,
		chunk_md5 TEXT NOT NULL,
		received_at DATETIME NOT NULL,
		FOREIGN KEY (session_id) REFERENCES temp_file_transfers (session_id) ON DELETE CASCADE,
		UNIQUE(session_id, chunk_index)
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	// Ensure handler columns exist on agents table
	if _, err := db.Exec("ALTER TABLE agents ADD COLUMN handler_id TEXT"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add handler_id column: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE agents ADD COLUMN handler_name TEXT"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add handler_name column: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE agents ADD COLUMN reconnect_interval INTEGER DEFAULT 0"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add reconnect_interval column: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE agents ADD COLUMN is_removed BOOLEAN DEFAULT 0"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add is_removed column: %v", err)
		}
	}
	if _, err := db.Exec("ALTER TABLE agents ADD COLUMN privileges TEXT DEFAULT ''"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add privileges column: %v", err)
		}
	}

	// Add file_type column if it doesn't exist (migration for existing databases)
	_, err = db.Exec("ALTER TABLE loot_files ADD COLUMN file_type TEXT")
	if err != nil {
		// Column might already exist, which is fine - only log if it's a real error
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			log.Printf("Warning: unable to add file_type column: %v", err)
		}
	} else {
		// Update existing rows to have 'file' as default
		_, err = db.Exec("UPDATE loot_files SET file_type = 'file' WHERE file_type IS NULL")
		if err != nil {
			log.Printf("Warning: unable to update file_type defaults: %v", err)
		}
	}

	// Load agent handlers from config files
	if err := loadAgentHandlersFromConfig(); err != nil {
		log.Printf("Error loading agent handlers: %v", err)
	}

	// Load listeners from config files
	if err := loadListenersFromConfig(); err != nil {
		log.Printf("Error loading listeners: %v", err)
	}

	// Broadcast agent updates periodically (status calculated client-side)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			broadcastAgents()
		}
	}()

	// Start periodic cleanup of expired file transfer sessions (every 10 minutes)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredTransfers()
		}
	}()

	// Start periodic cleanup of stale WebSocket connections (every 30 seconds)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			staleTimeout := 90 * time.Second // Close connections with no pong for 90 seconds
			for client := range clients {
				if !client.IsAlive(staleTimeout) {
					log.Printf("Closing stale WebSocket connection (no pong for >90s)")
					client.Close()
					delete(clients, client)
				}
			}
		}
	}()

	// Generate TLS certificates if they don't exist
	if err := generateSelfSignedCert(); err != nil {
		log.Fatalf("Failed to generate TLS certificates: %v", err)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// ===== Operator Server (WebSocket/GraphQL for frontend) =====
	operatorRouter := mux.NewRouter()

	// Add CORS middleware for operators
	operatorCorsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With"}),
		handlers.AllowCredentials(),
	)(operatorRouter)
	mainHandler = operatorCorsHandler

	// Auth endpoints
	operatorRouter.HandleFunc("/api/auth/register", handleRegister).Methods("POST")
	operatorRouter.HandleFunc("/api/auth/login", handleLogin).Methods("POST")
	operatorRouter.HandleFunc("/api/auth/validate", handleValidate).Methods("POST")
	operatorRouter.HandleFunc("/api/auth/refresh", handleRefresh).Methods("POST")
	operatorRouter.HandleFunc("/api/auth/logout", handleLogout).Methods("POST")

	// WebSocket for GraphQL over WebSocket (client communication)
	operatorRouter.HandleFunc("/ws", handleWebSocket)

	// GraphQL endpoint
	schema, _ := createSchema()
	h := handler.New(&handler.Config{
		Schema:   &schema,
		Pretty:   true,
		GraphiQL: true,
	})
	operatorRouter.Handle("/graphql", h)

	operatorAddress := fmt.Sprintf("%s:%d", config.Operator.Host, config.Operator.Port)
	operatorServer := &http.Server{
		Addr:      operatorAddress,
		Handler:   operatorCorsHandler,
		TLSConfig: tlsConfig,
	}

	// ===== Relay Server (Agent REST API for relay microservice) =====
	relayRouter := mux.NewRouter()

	// Add CORS middleware for relay
	relayCorsHandler := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With", "X-Agent-Type", "X-Relay-Timestamp", "X-Relay-Signature"}),
		handlers.AllowCredentials(),
	)(relayRouter)

	// Agent communication endpoint (HMAC protected) - unified dispatcher
	relayRouter.HandleFunc("/{path:.*}", hmacMiddleware(handleAgentRequest)).Methods("POST")

	relayAddress := fmt.Sprintf("%s:%d", config.Relay.Host, config.Relay.Port)
	relayServer := &http.Server{
		Addr:      relayAddress,
		Handler:   relayCorsHandler,
		TLSConfig: tlsConfig,
	}

	// Start both servers in goroutines
	fmt.Printf("\n========================================\n")
	fmt.Printf("    Ankou C2 Server Starting\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Operator API: https://%s\n", operatorAddress)
	fmt.Printf("  - WebSocket: wss://%s/ws\n", operatorAddress)
	fmt.Printf("  - GraphQL:   https://%s/graphql\n", operatorAddress)
	fmt.Printf("\nRelay API:    https://%s\n", relayAddress)
	fmt.Printf("  - Endpoint:  https://%s/*\n", relayAddress)
	fmt.Printf("========================================\n\n")

	// Start relay server in goroutine
	go func() {
		log.Printf("Relay API starting on %s", relayAddress)
		if err := relayServer.ListenAndServeTLS("server.crt", "server.key"); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Relay server error: %v", err)
		}
	}()

	// Start operator server (blocks)
	log.Printf("Operator API starting on %s", operatorAddress)
	log.Fatal(operatorServer.ListenAndServeTLS("server.crt", "server.key"))
}

func handleGraphQLMessage(client *Client, msg map[string]interface{}) {
	query, ok := msg["query"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"id":    msg["id"],
			"error": "Invalid query",
		})
		return
	}

	// Execute GraphQL query
	schema, err := createSchema()
	if err != nil {
		log.Printf("Failed to create schema: %v", err)
		client.WriteJSON(map[string]interface{}{
			"id":    msg["id"],
			"error": "Failed to create schema",
		})
		return
	}

	result := graphql.Do(graphql.Params{
		Schema:        schema,
		RequestString: query,
	})

	client.WriteJSON(map[string]interface{}{
		"id":   msg["id"],
		"data": result,
	})
}

func handleGraphQLQuery(client *Client, msg map[string]interface{}) {
	query, ok := msg["query"].(string)
	if !ok {
		client.WriteJSON(map[string]interface{}{
			"type":    "error",
			"message": "Invalid GraphQL query",
		})
		return
	}

	// Execute GraphQL query
	schema, _ := createSchema()
	result := graphql.Do(graphql.Params{
		Schema:        schema,
		RequestString: query,
	})

	// Check if this is a command history load
	agentID, _ := msg["agentId"].(string)
	loadHistory, _ := msg["loadHistory"].(bool)
	isPaginated, _ := msg["isPaginated"].(bool)
	offset, _ := msg["offset"].(float64) // JSON numbers come as float64

	response := map[string]interface{}{
		"type":   "graphql_response",
		"data":   result.Data,
		"errors": result.Errors,
	}

	// If loading history, also broadcast the commands update
	if loadHistory && agentID != "" {
		response["agentId"] = agentID
		response["loadHistory"] = true

		// Add pagination metadata
		if isPaginated {
			response["isPaginated"] = true
			response["offset"] = int(offset)

			// Extract total count from result data if available
			if resultData, ok := result.Data.(map[string]interface{}); ok {
				if commandCount, ok := resultData["commandCount"].(int); ok {
					response["totalCount"] = commandCount
				}
			}
		}
	}

	client.WriteJSON(response)
}

func handleGraphQLSubscription(client *Client, msg map[string]interface{}) {
	// For now, handle subscriptions as regular queries
	// In a full implementation, you'd use GraphQL subscriptions
	handleGraphQLQuery(client, msg)
}

// handleAgentRequest is the unified dispatcher for agent requests
// Routes based on payload structure instead of headers/URLs for OPSEC
func handleAgentRequest(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.Path
	if !isListenerActive(endpoint) {
		log.Printf("No active listener for endpoint: %s", endpoint)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	r.Body = io.NopCloser(strings.NewReader(string(body)))

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Failed to parse JSON payload: %v", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Determine action by payload structure (order matters: check most specific first)
	var action string
	if _, hasUUID := payload["uuid"]; hasUUID {
		action = "register"
	} else if _, hasSessionID := payload["sessionId"]; hasSessionID {
		if _, hasChunkIndex := payload["chunkIndex"]; hasChunkIndex {
			action = "chunk-upload"
		} else if _, hasComplete := payload["complete"]; hasComplete {
			action = "chunk-complete"
		} else {
			action = "chunk-init"
		}
	} else if _, hasFilename := payload["filename"]; hasFilename {
		action = "chunk-init"
	} else if _, hasOutput := payload["output"]; hasOutput {
		action = "command-response"
	} else if _, hasAgentID := payload["agentId"]; hasAgentID {
		action = "poll"
	} else {
		log.Printf("Unable to determine request type from payload: %v", payload)
		http.Error(w, "Unable to determine request type", http.StatusBadRequest)
		return
	}

	switch action {
	case "register":
		registerAgent(w, r)
	case "poll":
		handlePollCommands(w, r)
	case "command-response":
		handleCommandResponse(w, r)
	case "chunk-init":
		handleChunkInit(w, r)
	case "chunk-upload":
		handleChunkUpload(w, r)
	case "chunk-complete":
		handleChunkComplete(w, r)
	default:
		http.Error(w, "Unknown request type", http.StatusBadRequest)
	}
}

// REST endpoints for agent communication
func registerAgent(w http.ResponseWriter, r *http.Request) {
	var reg AgentRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Try to get agent type from body first, fall back to header for backward compatibility
	var handlerID, handlerName string
	agentType := strings.TrimSpace(reg.AgentType)
	if agentType == "" {
		// Fallback: check header for backward compatibility
		agentType = strings.TrimSpace(r.Header.Get("X-Agent-Type"))
	}
	
	if agentType != "" {
		if handler, ok := getAgentHandlerByHeader(agentType); ok {
			handlerID = handler.ID
			handlerName = handler.AgentName
		} else {
			log.Printf("No agent handler registered for agent type '%s'", agentType)
		}
	}

	// Check if agent already exists
	var existingID string
	err := db.QueryRow("SELECT id FROM agents WHERE id = ?", reg.UUID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if existingID != "" {
		// Agent already registered, just update heartbeat
		handleHeartbeat(w, r)
		return
	}

	// Insert new agent
	now := time.Now()
	_, err = db.Exec("INSERT INTO agents (id, name, status, ip, last_seen, os, created_at, handler_id, handler_name, reconnect_interval, privileges) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		reg.UUID, reg.Name, "online", reg.IP, now, reg.OS, now, handlerID, handlerName, reg.ReconnectInterval, reg.Privileges)
	if err != nil {
		http.Error(w, "Failed to register agent", http.StatusInternalServerError)
		return
	}

	broadcastAgents()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	uuid := r.Header.Get("X-Agent-UUID")
	if uuid == "" {
		http.Error(w, "Missing UUID header", http.StatusBadRequest)
		return
	}

	// Try to get agent type from body first (for body-based identification)
	var bodyWrapper struct {
		AgentType string `json:"agent_type,omitempty"`
	}
	var handler *AgentHandler
	
	// Read body to check for agent_type
	bodyBytes, err := io.ReadAll(r.Body)
	if err == nil && len(bodyBytes) > 0 {
		json.Unmarshal(bodyBytes, &bodyWrapper)
		// Restore body for potential further processing
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	
	agentType := strings.TrimSpace(bodyWrapper.AgentType)
	if agentType == "" {
		// Fallback: check header for backward compatibility
		agentType = strings.TrimSpace(r.Header.Get("X-Agent-Type"))
	}
	
	if agentType != "" {
		if found, ok := getAgentHandlerByHeader(agentType); ok {
			handler = found
		}
	}

	now := time.Now()
	query := "UPDATE agents SET last_seen = ?, status = 'online'"
	args := []interface{}{now}
	if handler != nil {
		query += ", handler_id = ?, handler_name = ?"
		args = append(args, handler.ID, handler.AgentName)
	}
	query += " WHERE id = ?"
	args = append(args, uuid)

	result, err := db.Exec(query, args...)
	if err != nil {
		http.Error(w, "Failed to update heartbeat", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	broadcastAgents()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "heartbeat_received"})
}

// handlePollCommands handles agent polling for pending commands (no GraphQL)
func handlePollCommands(w http.ResponseWriter, r *http.Request) {
	var pollRequest struct {
		AgentID string `json:"agentId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&pollRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if pollRequest.AgentID == "" {
		http.Error(w, "agentId is required", http.StatusBadRequest)
		return
	}

	// Update agent heartbeat
	now := time.Now()
	_, err := db.Exec("UPDATE agents SET last_seen = ? WHERE id = ?", now, pollRequest.AgentID)
	if err != nil {
		log.Printf("Error updating agent heartbeat during poll: %v", err)
	}

	// Query pending commands directly from database
	rows, err := db.Query(`
		SELECT id, agent_id, command, status, created_at 
		FROM commands 
		WHERE agent_id = ? AND status = 'pending'
		ORDER BY created_at ASC
	`, pollRequest.AgentID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var commands []Command
	for rows.Next() {
		var cmd Command
		var createdAtStr string
		err := rows.Scan(&cmd.ID, &cmd.AgentID, &cmd.Command, &cmd.Status, &createdAtStr)
		if err != nil {
			log.Printf("Error scanning command: %v", err)
			continue
		}

		// Parse the timestamp
		cmd.CreatedAt, _ = time.Parse("2006-01-02 15:04:05.999999999-07:00", createdAtStr)
		commands = append(commands, cmd)
	}

	// Return commands in simple JSON format
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"commands": commands,
	})
}

func handleCommandResponse(w http.ResponseWriter, r *http.Request) {
	var response CommandResponse
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check for headers
	typeHeader := r.Header.Get("type")
	lootDataHeader := r.Header.Get("loot-data")

	// Determine agent ID once so we can reuse it for storage and broadcasts
	var agentID string
	if err := db.QueryRow("SELECT agent_id FROM commands WHERE id = ?", response.CommandID).Scan(&agentID); err != nil {
		log.Printf("Error getting agent ID for command %d: %v", response.CommandID, err)
	}

	lootUpdated := false

	// Handle loot entries (from ls command)
	if typeHeader == "loot" && lootDataHeader != "" {

		if agentID == "" {
			log.Printf("Skipping loot storage for command %d because agent ID was not found", response.CommandID)
		} else {
			// Parse loot entries
			var lootEntries []map[string]interface{}
			if err := json.Unmarshal([]byte(lootDataHeader), &lootEntries); err != nil {
				log.Printf("Error parsing loot entries: %v", err)
			} else {
				if len(lootEntries) > 0 {
					// Store each loot entry
					for _, entry := range lootEntries {
						if err := storeLootEntry(agentID, entry, response.CommandID); err != nil {
							log.Printf("Error storing loot entry: %v", err)
						}
					}
					lootUpdated = true
				}
				log.Printf("Stored %d loot entries", len(lootEntries))
			}
		}
	}

	// Also check for loot entries embedded in output (simple format)
	// Only run if no loot-data header was already processed
	if strings.Contains(response.Output, "LOOT_ENTRIES:") && lootDataHeader == "" {
		log.Printf("Loot entries found in output - CommandID: %d", response.CommandID)

		if agentID == "" {
			log.Printf("Skipping loot storage from output for command %d because agent ID was not found", response.CommandID)
		} else {
			// Extract loot data from simple format
			start := strings.Index(response.Output, "LOOT_ENTRIES:")
			if start != -1 {
				start += len("LOOT_ENTRIES:")
				lootData := response.Output[start:]

				// Parse loot entries
				var lootEntries []map[string]interface{}
				if err := json.Unmarshal([]byte(lootData), &lootEntries); err != nil {
					log.Printf("Error parsing loot entries from output: %v", err)
				} else {
					if len(lootEntries) > 0 {
						// Store each loot entry
						for _, entry := range lootEntries {
							if err := storeLootEntry(agentID, entry, response.CommandID); err != nil {
								log.Printf("Error storing loot entry: %v", err)
							}
						}
						lootUpdated = true
					}
					log.Printf("Stored %d loot entries from output", len(lootEntries))
				}
			}
		}
	}

	if lootUpdated && agentID != "" {
		broadcastLootUpdate(agentID)
	}

	// Update command in database
	now := time.Now()
	_, err := db.Exec("UPDATE commands SET output = ?, status = ?, executed_at = ? WHERE id = ?",
		response.Output, response.Status, now, response.CommandID)
	if err != nil {
		log.Printf("Error updating command response: %v", err)
		http.Error(w, "Failed to update command", http.StatusInternalServerError)
		return
	}

	// Log the command response
	logCommandResponse(response.CommandID, response.Output, response.Status)

	// Check if this was a reconnect command and update the agent's interval
	if agentID != "" && response.Status == "completed" {
		var command string
		if err := db.QueryRow("SELECT command FROM commands WHERE id = ?", response.CommandID).Scan(&command); err == nil {
			// Check if command is "reconnect"
			if strings.HasPrefix(command, "reconnect ") {
				// Parse the new interval from the output
				// Expected format: "Reconnect interval changed from X to Y seconds"
				if strings.Contains(response.Output, "changed from") && strings.Contains(response.Output, "to") {
					parts := strings.Fields(response.Output)
					for i, part := range parts {
						if part == "to" && i+1 < len(parts) {
							if newInterval, err := strconv.Atoi(parts[i+1]); err == nil {
								// Update the agent's reconnect_interval
								_, err := db.Exec("UPDATE agents SET reconnect_interval = ? WHERE id = ?", newInterval, agentID)
								if err != nil {
									log.Printf("Error updating agent reconnect interval: %v", err)
								} else {
									log.Printf("Updated agent %s reconnect interval to %d seconds", agentID, newInterval)
								}
								break
							}
						}
					}
				}
			}
		}
	}

	// Broadcast command updates (if we knew which agent the command belonged to)
	if agentID != "" {
		// Broadcast command update to all clients
		broadcastCommandUpdate(agentID)
	} else {
		log.Printf("Skipping command broadcast for command %d because agent ID was not found earlier", response.CommandID)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// Chunked File Transfer Handlers for Geist agent
// Supports uploading large files in manageable chunks

// ChunkInitRequest represents the initial file transfer request
type ChunkInitRequest struct {
	AgentID      string `json:"agentId"`
	CommandID    int    `json:"commandId"`
	Filename     string `json:"filename"`
	OriginalPath string `json:"originalPath"`
	TotalSize    int64  `json:"totalSize"`
	TotalChunks  int    `json:"totalChunks"`
	ExpectedMD5  string `json:"expectedMd5"`
}

// ChunkUploadRequest represents a single chunk upload
type ChunkUploadRequest struct {
	SessionID  string `json:"sessionId"`
	ChunkIndex int    `json:"chunkIndex"`
	ChunkData  string `json:"chunkData"`
	ChunkMD5   string `json:"chunkMd5"`
}

// ChunkCompleteRequest represents the completion signal
type ChunkCompleteRequest struct {
	SessionID string `json:"sessionId"`
	Complete  bool   `json:"complete"`
}

// handleChunkInit initializes a new chunked file transfer session
func handleChunkInit(w http.ResponseWriter, r *http.Request) {
	var req ChunkInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate session ID
	sessionID := fmt.Sprintf("%s-%d-%d", req.AgentID, req.CommandID, time.Now().Unix())

	// Create transfer session (expires in 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO temp_file_transfers (
			session_id, agent_id, command_id, filename, original_path,
			total_size, total_chunks, expected_md5, chunks_received,
			created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
	`, sessionID, req.AgentID, req.CommandID, req.Filename, req.OriginalPath,
		req.TotalSize, req.TotalChunks, req.ExpectedMD5, time.Now(), expiresAt)

	if err != nil {
		log.Printf("Error creating transfer session: %v", err)
		http.Error(w, "Failed to create transfer session", http.StatusInternalServerError)
		return
	}

	log.Printf("Chunked transfer initiated: sessionID=%s, file=%s, chunks=%d, size=%d",
		sessionID, req.Filename, req.TotalChunks, req.TotalSize)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    200,
		"sessionId": sessionID,
		"message":   "Transfer session created",
	})
}

// handleChunkUpload receives and stores a single file chunk
func handleChunkUpload(w http.ResponseWriter, r *http.Request) {
	var req ChunkUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	chunkData, err := base64.StdEncoding.DecodeString(req.ChunkData)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}

	// Verify chunk MD5
	hash := md5.Sum(chunkData)
	actualMD5 := hex.EncodeToString(hash[:])
	if actualMD5 != strings.ToLower(req.ChunkMD5) {
		log.Printf("Chunk MD5 mismatch: expected %s, got %s", req.ChunkMD5, actualMD5)
		http.Error(w, "Chunk MD5 mismatch", http.StatusBadRequest)
		return
	}

	// Store chunk as base64 (keep it encoded for storage)
	_, err = db.Exec(`
		INSERT INTO temp_file_chunks (session_id, chunk_index, chunk_data, chunk_md5, received_at)
		VALUES (?, ?, ?, ?, ?)
	`, req.SessionID, req.ChunkIndex, req.ChunkData, req.ChunkMD5, time.Now())

	if err != nil {
		log.Printf("Error storing chunk: %v", err)
		http.Error(w, "Failed to store chunk", http.StatusInternalServerError)
		return
	}

	// Update chunks_received count
	_, err = db.Exec(`
		UPDATE temp_file_transfers 
		SET chunks_received = chunks_received + 1 
		WHERE session_id = ?
	`, req.SessionID)

	if err != nil {
		log.Printf("Error updating chunk count: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  200,
		"message": "Chunk received",
	})
}

// handleChunkComplete assembles chunks and creates final loot entry
func handleChunkComplete(w http.ResponseWriter, r *http.Request) {
	var req ChunkCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get transfer session metadata
	var agentID, commandIDStr, filename, originalPath, expectedMD5 string
	var totalSize int64
	var totalChunks, chunksReceived int
	err := db.QueryRow(`
		SELECT agent_id, command_id, filename, original_path, total_size, total_chunks, expected_md5, chunks_received
		FROM temp_file_transfers
		WHERE session_id = ?
	`, req.SessionID).Scan(&agentID, &commandIDStr, &filename, &originalPath, &totalSize, &totalChunks, &expectedMD5, &chunksReceived)

	if err != nil {
		log.Printf("Error retrieving transfer session: %v", err)
		http.Error(w, "Transfer session not found", http.StatusNotFound)
		return
	}

	commandID, _ := strconv.Atoi(commandIDStr)

	// Verify all chunks received
	if chunksReceived != totalChunks {
		log.Printf("Incomplete transfer: expected %d chunks, received %d", totalChunks, chunksReceived)
		http.Error(w, fmt.Sprintf("Incomplete transfer: %d/%d chunks", chunksReceived, totalChunks), http.StatusBadRequest)
		return
	}

	// Retrieve and assemble chunks in order
	rows, err := db.Query(`
		SELECT chunk_data
		FROM temp_file_chunks
		WHERE session_id = ?
		ORDER BY chunk_index ASC
	`, req.SessionID)

	if err != nil {
		log.Printf("Error retrieving chunks: %v", err)
		http.Error(w, "Failed to retrieve chunks", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var fileContent []byte
	for rows.Next() {
		var chunkDataBase64 string
		if err := rows.Scan(&chunkDataBase64); err != nil {
			log.Printf("Error scanning chunk: %v", err)
			http.Error(w, "Failed to read chunk", http.StatusInternalServerError)
			return
		}
		chunkData, err := base64.StdEncoding.DecodeString(chunkDataBase64)
		if err != nil {
			log.Printf("Error decoding chunk: %v", err)
			http.Error(w, "Failed to decode chunk", http.StatusInternalServerError)
			return
		}
		fileContent = append(fileContent, chunkData...)
	}

	// Verify final MD5
	finalHash := md5.Sum(fileContent)
	finalMD5 := hex.EncodeToString(finalHash[:])
	if finalMD5 != strings.ToLower(expectedMD5) {
		log.Printf("Final MD5 mismatch: expected %s, got %s", expectedMD5, finalMD5)
		http.Error(w, "Final MD5 mismatch", http.StatusBadRequest)
		return
	}

	// Re-encode the complete file as base64 for storage
	base64Content := base64.StdEncoding.EncodeToString(fileContent)

	// Store in loot_files
	err = storeLootFile(agentID, filename, originalPath, base64Content, finalMD5, "file", commandID)
	if err != nil {
		log.Printf("Error storing loot file: %v", err)
		http.Error(w, "Failed to store file", http.StatusInternalServerError)
		return
	}

	// Clean up temp tables
	_, err = db.Exec("DELETE FROM temp_file_chunks WHERE session_id = ?", req.SessionID)
	if err != nil {
		log.Printf("Error cleaning up chunks: %v", err)
	}
	_, err = db.Exec("DELETE FROM temp_file_transfers WHERE session_id = ?", req.SessionID)
	if err != nil {
		log.Printf("Error cleaning up transfer session: %v", err)
	}

	log.Printf("Chunked transfer completed: sessionID=%s, file=%s, size=%d bytes, md5=%s",
		req.SessionID, filename, len(fileContent), finalMD5)

	// Broadcast loot update to connected clients
	broadcastLootUpdate(agentID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  200,
		"message": "File transfer completed successfully",
		"md5":     finalMD5,
		"size":    len(fileContent),
	})
}

// cleanupExpiredTransfers removes transfer sessions that have expired
func cleanupExpiredTransfers() {
	result, err := db.Exec("DELETE FROM temp_file_transfers WHERE expires_at < ?", time.Now())
	if err != nil {
		log.Printf("Error cleaning up expired transfers: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d expired transfer session(s)", rowsAffected)
	}
}

// Auth handlers
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Validate registration key
	if req.RegistrationKey != registrationKey {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid registration key"})
		return
	}

	// Check if user already exists
	var existingID string
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", req.Username).Scan(&existingID)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "Username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server error"})
		return
	}

	// Create user
	userID := fmt.Sprintf("user_%d", time.Now().Unix())
	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
		userID, req.Username, hashedPassword)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create user"})
		return
	}

	// Generate JWT token (30 minutes)
	token, err := generateJWT(userID, req.Username)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server error"})
		return
	}

	// Set HttpOnly cookie (30 minutes)
	http.SetCookie(w, &http.Cookie{
		Name:     "ankou_token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   1800, // 30 minutes
		Path:     "/",
	})

	// Return success with token (for Electron)
	response := AuthResponse{
		Token: token, // Include token in response for Electron
		User: User{
			ID:        userID,
			Username:  req.Username,
			CreatedAt: time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Broadcast updated users list
	broadcastUsers()
}

func handleLogin(w http.ResponseWriter, r *http.Request) {

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Get user from database
	var userID, hashedPassword string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", req.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Check password
	if !checkPassword(req.Password, hashedPassword) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token (30 minutes)
	token, err := generateJWT(userID, req.Username)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server error"})
		return
	}

	// Set HttpOnly cookie (30 minutes)
	http.SetCookie(w, &http.Cookie{
		Name:     "ankou_token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   1800, // 30 minutes
		Path:     "/",
	})

	// Return success with token (for Electron)
	response := AuthResponse{
		Token: token, // Include token in response for Electron
		User: User{
			ID:        userID,
			Username:  req.Username,
			CreatedAt: time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	// Get token from HttpOnly cookie
	cookie, err := r.Cookie("ankou_token")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "No token found"})
		return
	}

	// Validate JWT token
	token, err := validateJWT(cookie.Value)
	if err != nil || !token.Valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	// Extract user info from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	userID, ok := claims["user_id"].(string)
	username, ok := claims["username"].(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	// Return user info
	response := User{
		ID:        userID,
		Username:  username,
		CreatedAt: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {

	// Get token from Authorization header or cookie
	var tokenString string

	// Try Authorization header first (for Electron)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Fallback to cookie
		cookie, err := r.Cookie("ankou_token")
		if err != nil {
			log.Printf("No token found in refresh request: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "No token found"})
			return
		}
		tokenString = cookie.Value
	}

	// Validate existing token
	token, err := validateJWT(tokenString)
	if err != nil || !token.Valid {
		log.Printf("[Security] Token validation failed from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	// Extract user info from existing token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid user_id in token"})
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username in token"})
		return
	}

	// Generate new JWT token (30 minutes)
	newToken, err := generateJWT(userID, username)
	if err != nil {
		log.Printf("Failed to generate new JWT token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server error"})
		return
	}

	log.Printf("Successfully refreshed token for user: %s", username)

	// Return success with new token (for Electron)
	response := AuthResponse{
		Token: newToken, // Include token in response for Electron
		User: User{
			ID:        userID,
			Username:  username,
			CreatedAt: time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the HttpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "ankou_token",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Expire immediately
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Limit maximum concurrent WebSocket connections to prevent resource exhaustion
	const maxClients = 100
	if len(clients) >= maxClients {
		log.Printf("WebSocket connection limit reached (%d), rejecting connection from %s", maxClients, r.RemoteAddr)
		http.Error(w, "Server at capacity", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	// Wrap the connection in a Client for thread-safe writes
	client := &Client{conn: conn, lastPong: time.Now()}
	clients[client] = true
	defer delete(clients, client)

	// Configure ping/pong handlers for connection health checks
	const (
		pongWait   = 60 * time.Second    // Time allowed to read pong from client
		pingPeriod = (pongWait * 9) / 10 // Send pings at this interval (54 seconds)
		writeWait  = 10 * time.Second    // Time allowed to write a message
	)

	// Set read deadline and pong handler
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		client.UpdatePong()
		return nil
	})

	// Start ping sender goroutine
	pingTicker := time.NewTicker(pingPeriod)
	defer pingTicker.Stop()

	go func() {
		for range pingTicker.C {
			client.mutex.Lock()
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				client.mutex.Unlock()
				conn.Close()
				return
			}
			client.mutex.Unlock()
		}
	}()

	log.Printf("WebSocket client connected from %s (total clients: %d)", r.RemoteAddr, len(clients))

	// Send initial agents list
	agents, err := getAllAgents()
	if err != nil {
		log.Printf("Error getting agents for WebSocket: %v", err)
	} else {
		client.WriteJSON(map[string]interface{}{
			"type": "agents",
			"data": agents,
		})
	}

	// Send initial users list
	users, err := getAllUsers()
	if err != nil {
		log.Printf("Error getting users for WebSocket: %v", err)
	} else {
		client.WriteJSON(map[string]interface{}{
			"type": "users",
			"data": users,
		})
	}

	// Send initial listeners list
	allListeners, err := getAllListeners()
	if err != nil {
		log.Printf("Error getting listeners for WebSocket: %v", err)
	} else {
		client.WriteJSON(map[string]interface{}{
			"type": "listeners",
			"data": allListeners,
		})
	}

	// Send initial handler list
	allHandlers, err := getAllAgentHandlers()
	if err != nil {
		log.Printf("Error getting handlers for WebSocket: %v", err)
	} else {
		client.WriteJSON(map[string]interface{}{
			"type": "handlers",
			"data": allHandlers,
		})
	}

	// Handle incoming messages
	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				log.Printf("WebSocket unexpected close error: %v", err)
			} else {
				log.Printf("WebSocket client disconnected from %s (total clients: %d)", r.RemoteAddr, len(clients)-1)
			}
			break
		}

		// Handle GraphQL over WebSocket
		switch msg["type"] {
		case "graphql":
			handleGraphQLMessage(client, msg)
		case "graphql_query":
			handleGraphQLQuery(client, msg)
		case "graphql_subscription":
			handleGraphQLSubscription(client, msg)
		case "submit_command":
			handleCommandSubmission(client, msg)
		case "global_command":
			handleGlobalCommand(client, msg)
		case "loot_request":
			handleLootRequest(client, msg)
		case "loot_file_request":
			handleLootFileRequest(client, msg)
		case "pong":
			client.UpdatePong()
		case "remove_agent":
			handleRemoveAgent(client, msg)
		}
	}
}

// createUser creates a new user with admin verification
func createUser(username, password, regKey string) (map[string]interface{}, error) {
	// Verify registration key
	if regKey != registrationKey {
		return nil, fmt.Errorf("invalid registration key")
	}

	// Check if user already exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}
	if count > 0 {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash password
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Generate user ID
	userID := fmt.Sprintf("user_%d", time.Now().Unix())

	// Insert user
	_, err = db.Exec("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
		userID, username, hashedPassword, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	// Broadcast users update
	broadcastUsers()

	return map[string]interface{}{
		"id":         userID,
		"username":   username,
		"created_at": time.Now().Format(time.RFC3339),
	}, nil
}

// revokeUser removes a user with admin verification
func revokeUser(userID, regKey string) (map[string]interface{}, error) {
	// Verify registration key
	if regKey != registrationKey {
		return nil, fmt.Errorf("invalid registration key")
	}

	// Check if user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}
	if count == 0 {
		return nil, fmt.Errorf("user not found")
	}

	// Delete user
	_, err = db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete user: %v", err)
	}

	// Broadcast users update
	broadcastUsers()

	return map[string]interface{}{
		"success": true,
	}, nil
}
