# Configuration Notes

## Registration Key Generation
- Running the Ankou server (`go run .` or the packaged binary in `server/`) automatically generates a unique operator registration key on first boot.
- The key is written to `server/registration.key` and reused on subsequent launches. Distribute it securely to the first operator who registers through the desktop client, then rotate or revoke it as operational policy requires.
- If you delete `server/registration.key`, the server will issue a new value the next time it starts; make sure every operator updates their bootstrap workflow accordingly.

## HMAC Key Alignment
- Every agent request is protected with an HMAC, and the relay adds its own HMAC headers before forwarding traffic to the server. All three components **must** share the exact same key.
- The server reads its HMAC secret from `server/hmac.key` (auto-generated on first launch unless you set the `HMAC_KEY` environment variable).
- The ghost relay expects the matching value via the `RELAY_HMAC_KEY` environment variable. Export the content of `server/hmac.key` before starting the relay, for example:
  ```bash
  export RELAY_HMAC_KEY=$(cat ../server/hmac.key)
  ```
- Agents need the identical key embedded or configured through their respective build-time settings. Make sure each agent’s configuration references the same string so the relay and server accept their traffic.
- Rotate the HMAC key only when you can stop all three components together. Update the server, export the new value to the relay, rebuild/redeploy agents, and then bring services back online to avoid signature mismatches.
