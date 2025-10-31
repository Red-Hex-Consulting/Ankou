# Ankou Relay - Exceptional Modular C2 Proxy

A production-ready, minimal-boilerplate C2 proxy that makes it **trivial** to add new protocol handlers. Built with a powerful `BaseHandler` that eliminates code duplication.

## 🎯 Design Philosophy

**Write 30 lines, not 200.** Focus on protocol-specific logic. Everything else is handled.

## 🔒 OPSEC: Protocol = Agent Type

**Key Security Feature:** Agent types are **never sent in headers**. Instead, each protocol is bound to an agent type at the relay level.

```
HTTPS Protocol → Phantasm Agents
QUIC Protocol  → Geist Agents  
DNS Protocol   → Your Custom Agent
```

**Why this matters:**
- ✅ No agent metadata in network traffic
- ✅ Protocol itself identifies the agent
- ✅ Harder for defenders to fingerprint
- ✅ Clean separation of concerns

**How it works:**
1. Agent connects to specific port (e.g., 8080 for HTTPS) - **no agent type in headers**
2. Relay knows: "Port 8080 = HTTPS Handler = Phantasm"
3. Relay logs with context: `[https:phantasm] request received`
4. **Relay injects `X-Agent-Type` header** when forwarding to C2
5. C2 receives traffic with agent type context and processes accordingly

**Key Point:** Agent traffic is clean (no metadata). Relay adds context for C2.

## 🏗️ Architecture

### Core Components

1. **AcceptHandler Interface** - Minimal contract for protocol handlers
2. **BaseHandler** - Shared functionality (logging, forwarding, response handling)
3. **Common Utilities** - Reusable helpers for all handlers
4. **sendToC2** - Abstracted C2 communication

### The Magic: BaseHandler

All handlers inherit from `BaseHandler` which provides:
- ✅ Automatic request logging with protocol context
- ✅ Header extraction and normalization
- ✅ Body reading with configurable size limits
- ✅ C2 forwarding with error handling
- ✅ Response proxying with hop-by-hop header filtering
- ✅ Timing and metrics logging

## 📝 Adding a New Protocol Handler

### Step 1: Create Your Handler (30-50 lines)

```go
// internal/accept/myprotocol.go
package accept

import (
    "context"
    "log"
)

type MyProtocolHandler struct {
    *BaseHandler  // Inherit all the common functionality
    // Add protocol-specific fields
}

func NewMyProtocolHandler(sendToC2 SendToC2Func, logger *log.Logger, config *HandlerConfig) *MyProtocolHandler {
    return &MyProtocolHandler{
        BaseHandler: NewBaseHandler(sendToC2, logger, config, "myprotocol"),
    }
}

func (m *MyProtocolHandler) Start(ctx context.Context, addr string) error {
    m.Logger().Printf("[myprotocol] Starting listener on %s", addr)
    
    // 1. Set up your protocol listener
    // 2. Parse incoming protocol-specific data
    // 3. Convert to HTTP-compatible format
    // 4. Call m.HandleHTTPRequest() or m.sendToC2()
    // That's it! BaseHandler handles the rest.
    
    return nil
}

func (m *MyProtocolHandler) Stop() error {
    // Clean shutdown logic
    return nil
}

func (m *MyProtocolHandler) GetName() string {
    return "myprotocol"
}
```

### Step 2: Register in accept.go (8 lines)

```go
func setupAcceptHandlers(ctx context.Context) error {
    // ... existing handlers ...
    
    // Add your new protocol bound to your agent
    myAgentConfig := &accept.HandlerConfig{
        UpstreamURL:      cfg.UpstreamBaseURL.String(),
        Timeout:          int(cfg.ClientTimeout.Seconds()),
        InsecureTLS:      cfg.InsecureSkipVerify,
        RequestReadLimit: cfg.RequestReadLimit,
        AgentType:        "myagent",  // Protocol binding!
    }
    
    myHandler := accept.NewMyProtocolHandler(sendToC2, logger, myAgentConfig)
    go myHandler.Start(ctx, "127.0.0.1:8081")
    
    return nil
}
```

**Done!** You now have a fully functional protocol handler with logging, error handling, and C2 forwarding.

The `AgentType` field binds your protocol to your agent. No headers needed!

## 📦 What's Included

### Current Handlers

**HTTPS Handler** (64 lines total - was 164!)
- Serves: **Phantasm agents**
- Protocol: HTTPS with TLS
- Port: 8080 (configurable)
- Auto-generated self-signed certs
- Automatic endpoint registration

**QUIC Handler** (Template ready)
- Serves: **Geist agents**
- Protocol: QUIC/HTTP3
- Port: 8081 (configurable)
- Ready to implement with BaseHandler

### Common Utilities (`internal/accept/common.go`)

- `LogRequest()` - Comprehensive request logging
- `ExtractHeaders()` - Header normalization
- `ReadBody()` - Size-limited body reading
- `CopyResponse()` - Smart response proxying
- Endpoint constants (`EndpointRegister`, `EndpointHeartbeat`, etc.)

### BaseHandler Features (`internal/accept/base.go`)

- `HandleHTTPRequest()` - Complete request processing pipeline
- `CreateHTTPHandler()` - Wraps for use with http.ServeMux
- `RegisterEndpoints()` - Automatic endpoint registration
- Helper methods: `Logger()`, `Config()`, `ProtocolName()`

## 🎨 Standard C2 Endpoints

All handlers automatically support:

```go
/wiki/api/register          // Agent registration
/wiki/api/heartbeat         // Keep-alive/status
/wiki/api/command-response  // Command execution results
/wiki                       // GraphQL API
```

Defined as constants - change once, applies everywhere.

## ⚙️ Configuration

### Command-Line Flags

```bash
# Override upstream C2 server URL (takes precedence over environment variable)
./ghost-relay --upstream https://10.0.0.1:8444

# Override base bind address/interface (takes precedence over environment variable)
./ghost-relay --bind 0.0.0.0        # Listen on all interfaces
./ghost-relay --bind 192.168.1.5    # Listen on specific IP

# Combine both flags
./ghost-relay --upstream https://10.0.0.1:8444 --bind 0.0.0.0
```

**Priority:** Command-line flag > Environment variable > Default value

**How bind addresses work:**
- The `--bind` flag sets the base interface/IP address
- Each handler uses this base address with its assigned port:
  - Phantasm (HTTPS): `{bind}:8080`
  - Geist (QUIC): `{bind}:8081`
  - Shade (SSH): `{bind}:2222`
- Default: `127.0.0.1` (localhost only)
- Use `0.0.0.0` to accept connections from any interface

### Environment Variables

```bash
PHANTASM_RELAY_UPSTREAM_BASE_URL=https://localhost:8444  # Overridden by --upstream flag if provided
PHANTASM_RELAY_LISTEN_ADDR=127.0.0.1                     # Base bind address, overridden by --bind flag if provided
PHANTASM_RELAY_INSECURE_SKIP_VERIFY=true
PHANTASM_RELAY_CLIENT_TIMEOUT=15s
PHANTASM_RELAY_REQUEST_READ_LIMIT=10485760  # 10MB
RELAY_HMAC_KEY=your_hmac_key_here           # HMAC key for relay -> C2 authentication
```

### Handler Config

```go
type HandlerConfig struct {
    UpstreamURL      string  // C2 server URL
    Timeout          int     // Request timeout
    InsecureTLS      bool    // Skip TLS verification
    RequestReadLimit int64   // Max request body size
    AgentType        string  // Agent type this handler serves (protocol binding)
}
```

## 🧪 Testing

BaseHandler uses dependency injection making it trivial to test:

```go
mockSendToC2 := func(ctx context.Context, endpoint string, headers map[string]string, body []byte) (*http.Response, error) {
    // Return mock response
}

handler := NewMyProtocolHandler(mockSendToC2, logger, config)
// Test your protocol-specific logic
```

## 📊 Comparison: Before vs After

### Before (Old Design)
- **164 lines** per handler
- **80%+ code duplication**
- Endpoint hardcoding everywhere
- Hard to test
- Error-prone

### After (Current Design)
- **~50 lines** per handler
- **Zero duplication** (BaseHandler + common utils)
- Centralized endpoint constants
- Easily testable
- Production-ready

## 🔥 Why This Design Wins

1. **DRY Principle** - Write common code once
2. **Single Responsibility** - Handlers focus only on their protocol
3. **Composition over Inheritance** - BaseHandler uses composition
4. **Open/Closed** - Add protocols without modifying existing code
5. **Dependency Injection** - Easy testing and mocking

## 🎯 Real-World Deployment Scenarios

### **Scenario 1: Single Relay, Multiple Agents**
```go
// One relay serves phantasm (HTTPS) and geist (QUIC)
phantasmConfig := &accept.HandlerConfig{
    UpstreamURL: "https://c2:8444",
    AgentType:   "phantasm",
}
httpsHandler := accept.NewHTTPSHandler(sendToC2, logger, phantasmConfig, tlsConfig)
httpsHandler.Start(ctx, ":8080")

geistConfig := &accept.HandlerConfig{
    UpstreamURL: "https://c2:8444",
    AgentType:   "geist",
}
quicHandler := accept.NewQUICHandler(sendToC2, logger, geistConfig, tlsConfig)
quicHandler.Start(ctx, ":8081")
```

### **Scenario 2: Multi-Protocol Agent**
```go
// Phantasm agents can use HTTPS OR QUIC (same agent type, different protocols)
phantasmHTTPS := accept.NewHTTPSHandler(sendToC2, logger, phantasmConfig, tlsConfig)
phantasmHTTPS.Start(ctx, ":8080")

phantasmQUIC := accept.NewQUICHandler(sendToC2, logger, phantasmConfig, tlsConfig)
phantasmQUIC.Start(ctx, ":8081")

// Both protocols serve phantasm agents - same AgentType, different protocols
```

### **Scenario 3: Regional/Tiered Infrastructure**
```go
// Different C2 servers per agent type
phantasmConfig := &accept.HandlerConfig{
    UpstreamURL: "https://c2-east:8444",  // Phantasm → East C2
    AgentType:   "phantasm",
}

geistConfig := &accept.HandlerConfig{
    UpstreamURL: "https://c2-west:8444",  // Geist → West C2
    AgentType:   "geist",
}
```

### **Scenario 4: Custom Agent with Multiple Transports**
```go
// Your custom "shadownet" agent with 3 transport options
shadownetConfig := &accept.HandlerConfig{
    UpstreamURL: "https://c2:8444",
    AgentType:   "shadownet",
}

// Operators deploy shadownet agents with their choice of protocol
httpsTransport := accept.NewHTTPSHandler(sendToC2, logger, shadownetConfig, tlsConfig)
quicTransport := accept.NewQUICHandler(sendToC2, logger, shadownetConfig, tlsConfig)
sshTransport := accept.NewSSHHandler(sendToC2, logger, shadownetConfig, sshConfig)
```

## 📚 Protocol-Specific Examples

### HTTP-Based Protocols (HTTPS, QUIC)
Use `BaseHandler.RegisterEndpoints()` for automatic endpoint setup.

### Non-HTTP Protocols (SSH)
Parse your protocol → extract data → call `BaseHandler.sendToC2()` directly.

## 🎯 Production Checklist

- ✅ Centralized logging with protocol context
- ✅ Configurable timeouts and size limits
- ✅ Graceful shutdown support
- ✅ Auto-generated TLS certificates
- ✅ Hop-by-hop header filtering
- ✅ Comprehensive error handling
- ✅ Zero code duplication
- ✅ Easily extensible

## 🤝 Contributing New Protocols

1. Use an existing handler (like `ssh.go`, `https.go`, or `quic.go`) as a template
2. Implement protocol-specific parsing/encoding
3. Use `BaseHandler` for everything else
4. Add to your relay's `main.go` or create a new `accept_*.go` file
5. Done!

---

**Bottom Line:** This relay system is now production-ready and developer-friendly. Adding a new protocol takes minutes, not hours.