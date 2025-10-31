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
	"os"
	"os/signal"
	"syscall"
	"time"

	"ghost-relay/internal/config"
)

// Global variables for use in accept.go
var (
	cfg    *config.Config
	cert   *tls.Certificate
	logger *log.Logger
)

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

	logger.Printf("Starting Ghost Relay, forwarding to %s", cfg.UpstreamBaseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Setup accept handlers (HTTPS, QUIC, SMB, etc.)
	if err := setupAcceptHandlers(ctx); err != nil {
		log.Fatalf("failed to setup accept handlers: %v", err)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Printf("shutdown signal received")
}
