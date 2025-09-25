# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Repository: e2ee-chat-js

Overview
- Minimal end-to-end encrypted (password-based) group chat. The server only relays ciphertext; encryption happens in the browser using WebCrypto (AES-GCM) with a key derived via PBKDF2(SHA-256) from the shared room password.
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
    - join: client joins a room with a sanitized room/name; server acknowledges via joined; broadcasts presence and a system event to peers.
    - chat: server relays an envelope {type, room, from, iv, ciphertext, ts, [replyTo]} to all peers in the room; it does not inspect plaintext.
    - leave: server removes the client from the room and broadcasts a system event and presence update.
  - Presence: broadcasts {type: "presence", room, count} when membership changes.
  - Heartbeat: periodic ping/pong to clean up dead connections.
  - No persistence; rooms and membership live in memory.

- Client (public/index.html, public/client.js, public/styles.css)
  - UI: simple connect form (room, display name, password), presence count, messages list, composer; shows a short key fingerprint for human verification.
  - Key derivation: PBKDF2(SHA-256, salt = "e2ee-chat|" + room, 150k iterations) -> AES-GCM(256) CryptoKey.
  - Encryption: AES-GCM with 12-byte random IV per message; encodes iv and ciphertext in Base64.
  - Transport: WebSocket to the server host; uses wss when on HTTPS, ws otherwise; relays JSON envelopes.
  - Decryption: attempts to decrypt received ciphertext; on failure shows a placeholder “[Unable to decrypt]”.
  - Secure context warning: WebCrypto subtle requires a secure context (HTTPS) except on localhost; the client warns if not secure.

Important from README
- This is an educational demo; it does not implement forward secrecy, deniability, or authenticated key exchange. Do not use as-is for production.
- Recommended for real deployments: well-reviewed protocols (e.g., MLS or Signal Double Ratchet) with proper authentication.

Repository structure (essential only)
- server.js: Express server + WebSocket relay (no plaintext handling).
- public/index.html, public/client.js, public/styles.css: frontend and crypto logic (PBKDF2 + AES-GCM).

Operational tips
- If reverse-proxying behind TLS, the client will automatically use wss based on the page protocol.
- Presence count is derived from active WebSocket connections in a room; restarting the server clears all rooms.
