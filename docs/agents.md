# Agent Catalog

This reference summarises the three sample agents that ship with Ankou. Each
agent shares the same tasking model (HMAC-wrapped JSON payloads, command ID
decoding, chunked file transfers, loot metadata), but they intentionally differ
in transport choice and operational extras.

## Geist

- **Transport**: QUIC.
- **Operational highlights**:
  - Supports operator-controlled beacon jitter (`jitter`) alongside the base
    reconnect interval.
  - Executes shellcode (`injectsc`) via direct system calls to evade anti-virus hooks.
  - Expands the built-in task set with file removal primitives (`rm`, `rmdir`)
    in addition to the shared command core.
  - Marks loot-rich responses (`ls`, `get`, `put`) so the relay can handle them
    without custom headers.
- **Tasking and payload support**:
  - Registration and polling performed through HMAC-signed JSON bodies (no
    custom headers) sent over QUIC.
  - Command set: `ls`, `get`, `put`, `cd`, `kill`, `ps`, `exec`, `reconnect`,
    `injectsc`, `rm`, `rmdir`, `jitter`, plus raw shell execution for everything
    else.
  - File download logic automatically switches to 2 MB chunking for artefacts
    >=10 MB and verifies each chunk and the aggregate via MD5.
  - File uploads expect hex-encoded payloads, persist them, and respond with
    embedded `LOOT_ENTRIES` metadata for UI ingestion.
  - Process enumeration uses the Toolhelp snapshot APIs; `kill` calls
    `TerminateProcess`.

## Phantasm

- **Transport**: HTTPS.
- **Operational highlights**:
  - Functions as the baseline web transport; traffic resembles standard JSON
    POST exchanges.
  - Submits loot to `/api/loot` for every local file write, avoiding secondary
    parsing steps.
- **Tasking and payload support**:
  - Registration, polling, and command responses use the same HMAC-wrapped JSON
    envelope shipped over HTTPS without bespoke headers.
  - Command set: `ls`, `get`, `put`, `cd`, `kill`, `ps`, `exec`, `reconnect`
    (command IDs 1-8 map to these names).
  - Large file downloads transparently chunk at 2 MB with MD5 validation and a
    final session checksum; smaller files travel in a single response.
  - File uploads accept hex-encoded content, create directories as needed, write
    to disk, then register a loot event with the server.
  - Directory listings and downloads append `LOOT_ENTRIES:<json>` to the output
    for GUI-side extraction; `ps` surfaces full Toolhelp snapshots.

## Shade

- **Transport**: SSH.
- **Operational highlights**:
  - Presents on the wire as routine SSH activity, which supports operational
    blending with administrative access.
  - Reuses the established SSH session for tasking and loot so no new sockets
    are opened after the initial beacon.
- **Tasking and payload support**:
  - Registration, polling, command execution, and loot posts all move through
    SSH channels using the shared HMAC-wrapped JSON body convention.
  - Command set mirrors Phantasm: `ls`, `get`, `put`, `cd`, `kill`, `ps`,
    `exec`, `reconnect`.
  - Large file downloads/upload logic matches Phantasm (2 MB chunks, MD5 checks)
    but routes via SSH messages instead of HTTP calls.
  - `ls`/`get`/`put` outputs embed `LOOT_ENTRIES` for the UI; `ps` and `kill`
    wrap the same Windows APIs as the other agents.
  - Uses system shell execution (`cmd /C` or `sh -c`) for non-builtin commands,
    ensuring full pipe/redirect support over the SSH transport.

Refer back to each agent’s `main.go` for configuration knobs (listener host,
port, reconnect interval) before compiling for operations.
