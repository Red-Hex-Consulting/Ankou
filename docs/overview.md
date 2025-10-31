# Ankou Architecture Overview

This document explains how the major pieces of the Ankou platform interact and
shows where the provided architecture diagram fits within the overall system.

## Architecture Diagram

![Ankou Architecture Diagram](src/AnkouArchOverview.png)

## Core Components

1. **Agent**  
   The agent is deployed onto the target computer. It communicates with the server via the Ghost-Relay in order to send tasking results and gather tasking requests.

2. **Ghost Relay**  
  The Ghost-Relay is a server that sits between the agent and the server. There are two primary advantages to this component. First, it obscures the location of the Server that contains collect and tasking. Second, it provides an interface for agents to communicate with the server via any communications protocol. The Ghost-Relay was designed with the intent to add new communications plugins extremely easily—see [Adding a New Transport](ghost-relay-new-transport.md) for a fast recipe.

3. **Server**  
   The server is responsible for the storage and management of all data related to collection and tasking. It authenticates operators, schedules work for agents, and tracks operational state. The server also emits real-time notifications so everyone connected sees status changes the moment they happen.

4. **Client**  
   Operator dashboard delivered as a desktop app that keeps a live WebSocket session with the server. It provides a unified view of agents, tasks, and collection, enabling quick decision-making and rapid follow-up actions.

Together, these four elements create a responsive C2 workflow while keeping sensitive infrastructure layered and resilient.

## Quickstart

Each part of the stack bootstraps itself with sensible defaults. If you enter the directory for a component and run its default command (`go run .` for Go services, `npm run electron` for the desktop UI), the tooling will generate whatever files it needs and come up in a working development configuration. Bring the system online in the order below—Ghost Relay is mandatory for agent traffic.

### 1) Server

- `cd server`
- Launch with the built-in defaults and let it generate certificates/keys on first run:

  ```sh
  go run .
  # or
  go build && ./ankou-server -ip 0.0.0.0 -port 8443
  ```

- What happens automatically:
  - Binds to `0.0.0.0:8443` over HTTPS.
  - Creates self-signed TLS material (`server.crt`, `server.key`) plus secrets (`jwt.secret`, `hmac.key`, `registration.key`) inside `server/` if they do not exist.
  - Initializes the SQLite database (`agents.db`) and required tables.
- Leave this process running; the other components will connect to it.

---

### 2) Client

- In a new terminal: `cd frontend`
- Install dependencies and start the desktop app (the scripts handle the build step for you):

  ```sh
  npm install
  npm run build
  npm run electron
  ```

- The launcher opens the login window. Use the defaults:
  - Server URL: `https://localhost:8443` (matches the server you just started).
  - First-time setup: click **Register**, copy the contents of `server/registration.key`, then choose a username/password. Subsequent logins use **Sign In** with the same URL.

---

### 3) Listener

- Still inside the client:
  1. Open the **Listeners** view.
  2. Click **Add Listener** and accept these defaults:
     - Host: `0.0.0.0`
     - Port: `8444`
     - Endpoint: `/wiki`
  3. Save, then immediately click **Start** to bring it online.
- This listener exposes `https://<server>:8444/wiki` for agent traffic coming from the relay. The UI will show the listener status flip to **running** when it is ready.

---

### 4) Ghost Relay (Required)

- In a third terminal: `cd ghost-relay`
- Point the relay at the listener you created and reuse the server’s HMAC key:

  ```sh
  export PHANTASM_RELAY_UPSTREAM_BASE_URL=https://localhost:8444
  export RELAY_HMAC_KEY=$(cat ../server/hmac.key)
  go run .
  ```

- What you get out of the box:
  - Self-signed TLS for the relay endpoints (generated automatically on first launch).
  - HTTPS handler (`phantasm`) listening on `127.0.0.1:8080`.
  - QUIC handler (`geist`) listening on `127.0.0.1:8081`.
  - Relay-to-server requests are re-signed with the shared HMAC key you exported.
- The upstream URL defaults to `https://localhost:8444`; setting the variable explicitly helps if you later move the listener. The relay will automatically preserve the `/wiki` prefix defined in the listener step.
- Keep the relay running so agents can connect. For remote testing, deploy it near the agent host or put it behind a reverse proxy.

---

### 5) Agent

- Sample agents live in `agents/<name>`. Each ships with defaults that match the quickstart environment:

  ```sh
  # Example: start the HTTPS-based Phantasm agent
  cd agents/phantasm
  go run .
  ```

- Out of the box the agent:
  - Uses `https://127.0.0.1:8080/wiki` (the relay) as its transport.
  - Shares the same HMAC key value embedded in `hmacKeyHex`—update that constant if you generated a new key earlier.
  - Registers with the server, polls for tasks, executes them, and sends responses back through the relay. The relay forwards everything to the listener you created.
- Repeat with other agent binaries as needed (e.g., `agents/geist` for QUIC).
