# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Repository: e2ee-chat-js

Overview
- End-to-end encrypted (password-based) group chat. The server only relays ciphertext; encryption happens in the browser using WebCrypto (AES-GCM) with a key derived via PBKDF2(SHA-256) from the shared room password.
- Tech: Node.js (Express + ws), static frontend (HTML/CSS/JS), no build tooling, no test/lint setup.

Commands
- Install dependencies
  - npm install
- Start the server (serves static files and runs WebSocket relay)
  - npm start
  - Environment: PORT=4000 npm start (defaults to 3000)
- Open the app
  - http://localhost:3000 (or the chosen PORT)

Notes on tooling
- There are no configured scripts for build, lint, or tests in package.json. Single-test invocation is not applicable unless a test framework is added later.
- Engines (from package.json): Node >= 18, npm >= 8.

High-level architecture
- Server (server.js)
  - Express serves ./public as static assets.
  - WebSocket server (ws) manages rooms via an in-memory Map<room, Set<ws>>.
  - Message types (JSON):
    - join: client joins a room with sanitized room/name and a password verifier; server acknowledges via joined; broadcasts presence and a system event (join/leave/disconnect) to peers.
    - chat: server relays an envelope {type, room, iv, ciphertext, ts} to all peers in the room; it does not inspect plaintext.
    - typing: anonymous typing on/off indicator relayed to peers.
    - leave: server removes the client from the room and broadcasts a system event and presence update.
  - Presence: broadcasts {type: "presence", room, count, users} where users is a list of current display names in that room.
  - Heartbeat: periodic ping/pong to clean up dead connections.
  - No persistence; rooms and membership live in memory. A room's password verifier is set by the first joiner and applies to subsequent joins.

- Client (public/index.html, public/client.js, public/styles.css)
  - UI: Discord-like native layout
    - Left rail (icons): home and "+" to add a room
    - Left sidebar: saved rooms list (room name + display name), remove button per room
    - Center: chat header, messages list (auto-scrolls to newest), sticky composer, typing indicator
    - Right sidebar: members list for the current room (from presence users)
  - Rooms model: multiple rooms can be saved locally; one active room at a time (single WebSocket connection). Switching rooms issues a new join for that room.
  - Storage: rooms (name + display name) in localStorage; per-room password in sessionStorage only (cleared on browser restart).
  - Crypto: PBKDF2(SHA-256, salt = "e2ee-chat|" + room, 150k) -> AES-GCM(256) key.
  - Transport: WebSocket to the same host (wss on HTTPS, ws otherwise). JSON envelopes only.
  - Decryption: attempts AES-GCM decryption; on failure shows “[Unable to decrypt]”.
  - Secure context warning: WebCrypto requires HTTPS (or localhost).

Important from README
- Educational demo; no forward secrecy, deniability, or authenticated key exchange.
- For real deployments: use well-reviewed protocols (MLS, Signal Double Ratchet) and proper authentication.

Repository structure (essential only)
- server.js: Express server + WebSocket relay (no plaintext content inspection). Presence includes users list for member sidebar.
- public/index.html: Multi-pane UI (rail, rooms sidebar, chat pane, members sidebar) + modal for adding rooms.
- public/client.js: UI logic (rooms persistence, join/switch, presence rendering), crypto, and transport.
- public/styles.css: Layout and component styles (full-height app, sticky composer, scrollable messages).

Operational tips
- If reverse-proxying behind TLS, the client will automatically use wss based on the page protocol.
- Presence count and member list derive from active connections; restarting the server clears rooms, connections, and resets password verifiers.
