# Ghost Relay: Adding a New Communication Transport

One of the design goals of the Ghost Relay is making protocol extensions **fast, repeatable, and low-risk**. Every transport handler is a thin layer that:

1. Listens for traffic in its native protocol
2. Normalizes any data into an HTTP-style request
3. Hands the request off to the shared `BaseHandler`, which signs, forwards, and returns the response

Because the heavy lifting lives in `BaseHandler`, most new transports come together in **30–60 lines of code**.

---

## Project Layout Recap

```text
ghost-relay/
├── accept.go                 // shared HMAC signing + handler registration
├── internal/accept/
│   ├── base.go               // BaseHandler with all the shared logic
│   ├── common.go             // helper utils + standard endpoint list
│   ├── https.go              // HTTPS handler (reference implementation)
│   ├── websocket.go          // WebSocket handler (another example)
│   └── ...                   // your protocol file goes here
└── main.go                   // bootstraps config + registers handlers
```

Every protocol lives in its own `accept_<protocol>.go` file and exports a single `setup<Protocol>Handler(ctx, tlsConfig)` function. Registration happens in `setupAcceptHandlers` (see `ghost-relay/accept.go`).

---

## Step-by-Step: Adding `MyProtocol`

### 1. Create the Handler File

Create `ghost-relay/accept_myprotocol.go`:

```go
package main

import (
	"context"
	"crypto/tls"

	"ghost-relay/internal/accept"
)

func setupMyProtocolHandler(ctx context.Context, tlsConfig *tls.Config) {
	cfg := &accept.HandlerConfig{
		UpstreamURL:      cfg.UpstreamBaseURL.String(),
		Timeout:          int(cfg.ClientTimeout.Seconds()),
		InsecureTLS:      cfg.InsecureSkipVerify,
		RequestReadLimit: cfg.RequestReadLimit,
		AgentType:        "any", // accepts any agent type from request body
	}

	handler := accept.NewMyProtocolHandler(sendToC2, logger, cfg, tlsConfig)

	go func() {
		if err := handler.Start(ctx, ":9000"); err != nil {
			logger.Printf("MyProtocol handler error: %v", err)
		}
	}()

	logger.Printf("✓ MyProtocol handler on :9000 (accepts any agent type)")
}
```

*Only* the protocol-specific constructor and port change from the HTTPS example.

### 2. Implement the Minimal Handler

Create `ghost-relay/internal/accept/myprotocol.go`:

```go
package accept

import (
	"context"
	"log"
)

type MyProtocolHandler struct {
	*BaseHandler
	// add protocol-specific fields here (listener, decoder, etc.)
}

func NewMyProtocolHandler(sendToC2 SendToC2Func, logger *log.Logger, cfg *HandlerConfig, tlsConfig interface{}) *MyProtocolHandler {
	return &MyProtocolHandler{
		BaseHandler: NewBaseHandler(sendToC2, logger, cfg, "myprotocol"),
	}
}

func (h *MyProtocolHandler) Start(ctx context.Context, addr string) error {
	h.Logger().Printf("[myprotocol:%s] starting on %s", h.AgentType(), addr)

	// 1. Set up the protocol listener (UDP, QUIC, DNS, etc.)
	// 2. Parse the native packet and extract relevant data
	// 3. Convert the payload to an HTTP-style body + headers
	// 4. Call h.HandleHTTPRequest(ctx, endpoint, request, responseWriter)

	return nil
}

func (h *MyProtocolHandler) Stop() error {
	// Close sockets, stop goroutines, etc.
	return nil
}
```

There’s no command queue, no database touch, no HMAC work here—`BaseHandler` handles all of it.

### 3. Register the Handler

Edit `ghost-relay/accept.go` and add a single line inside `setupAcceptHandlers`:

```go
setupMyProtocolHandler(ctx, tlsConfig)
```

That's it. The relay now forwards `MyProtocol` traffic to the C2, signing the request with the configured HMAC key and passing the agent type straight through from the request body.

---

## Why It's This Simple

`BaseHandler` (see `internal/accept/base.go`) centralizes everything that used to be duplicated per transport:

- **Logging** (incoming request, headers, timing)
- **Body reading / size limits**
- **C2 forwarding + TLS options via `HandlerConfig`**
- **Response proxying** back to the agent

All you implement is "how do I listen for my protocol, and how do I translate it into an HTTP-style request?" Rounded out with `common.go`, you even get the standard endpoints (`/wiki/api/register`, `/wiki/api/heartbeat`, `/wiki/api/command-response`, `/wiki/api/poll`, `/wiki`) for free.

---

## Tips & Patterns

- **Agent type identification**: agents declare their type in the request body with `"agent_type": "myagent"`. The relay reads this for logging but doesn't modify it—everything passes through to the C2 server unchanged. No port-based coupling means any agent can use any transport.
- **Multiple agent types per transport**: set `AgentType: "any"` in `HandlerConfig` and let agents identify themselves in their payloads. One HTTPS handler can serve phantasm, anomaly, and whatever else you build.
- **Non-HTTP protocols**: parse the packet, build an `http.Request` (method, URL, body), then call `BaseHandler.HandleHTTPRequest`. See `accept_geist.go` for QUIC or `accept_shade.go` for SSH examples.
- **Graceful shutdown**: watch the `ctx` passed into `Start` and cleanup resources in `Stop`.
- **Testing**: `BaseHandler` is designed for dependency injection; you can pass a mock `sendToC2` and assert translations in isolation.

---

## TL;DR

- Drop in ~50 lines for your transport
- Register the handler
- Enjoy full forwarding, logging, and security guarantees with zero boilerplate

This modular design keeps the Ghost Relay nimble—perfect for quickly adding new comms channels during an engagement without touching the core C2 server. Design the protocol listener, plug in `BaseHandler`, and you’re live.

When in doubt, look at a working example. For instance, `ghost-relay/accept_geist.go` shows how the QUIC transport registers itself, and `ghost-relay/internal/accept/quic.go` demonstrates the protocol-specific implementation that still leans on `BaseHandler`. Copy that structure, swap in your protocol’s listener, and you’re done.
