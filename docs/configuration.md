# Configuration Notes

## Quick Start (Recommended)

Run `quickstart.py` from the repository root to generate all configuration files automatically:

```bash
python3 quickstart.py
```

This creates:
- `server/ankou.config` - Server secrets (JWT_SECRET, HMAC_KEY, REGISTRATION_KEY)
- `server/server_config.json` - Network bindings for operator and relay endpoints
- `ghost-relay/relay.config` - Relay configuration with matching HMAC keys

The script ensures HMAC keys match across all components. Save the registration key it displays - you'll need it for first login.

## Manual Configuration

If you prefer manual setup or need to customize beyond quickstart.py:

### Server Configuration

Create `server/ankou.config`:
```bash
JWT_SECRET=<128-char hex string>
HMAC_KEY=<64-char hex string>
REGISTRATION_KEY=<32-char hex string>
```

Create `server/server_config.json`:
```json
{
  "relay": {
    "host": "127.0.0.1",
    "port": 8444
  },
  "operator": {
    "host": "0.0.0.0",
    "port": 8443
  }
}
```

### Relay Configuration

Create `ghost-relay/relay.config`:
```bash
UPSTREAM_URL=https://127.0.0.1:8444
AGENT_HMAC_KEY=<same 64-char hex as server HMAC_KEY>
SERVER_HMAC_KEY=<same 64-char hex as server HMAC_KEY>
LISTEN_ADDR=0.0.0.0
```

### Agent Configuration

Before building agents, update their `main.go` files:
- Set `hmacKeyHex` to match the relay's `AGENT_HMAC_KEY`
- Configure `listenerHost` and `listenerPort` to point at your relay
- Adjust `listenerProtocol` and `listenerEndpoint` as needed

**Critical HMAC alignment:**
- Agent `hmacKeyHex` must match relay's `AGENT_HMAC_KEY` (agent → relay authentication)
- Relay's `SERVER_HMAC_KEY` must match server's `HMAC_KEY` (relay → server authentication)
- Note: `quickstart.py` sets all three to the same value for simplicity, but they could theoretically differ

## Key Rotation

To rotate keys:
1. Stop server, relay, and all active agents
2. Generate new keys and update all config files
3. Rebuild all agents with the new HMAC key
4. Restart components and redeploy agents
