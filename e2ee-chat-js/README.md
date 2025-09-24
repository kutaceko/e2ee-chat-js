# E2EE Chat (JavaScript, AES-GCM)

This is a minimal, educational chat app that demonstrates end-to-end encryption in the browser using a shared password. The server only relays ciphertext and cannot read messages.

What it provides
- Group chat via WebSockets
- End-to-end encryption using WebCrypto AES-GCM
- Password-derived key (PBKDF2 + SHA-256) scoped to the room name
- Per-message random IVs, Base64 transport
- Key fingerprint display for human verification

Important notes
- This is a demo. It does not implement forward secrecy, deniability, or authenticated key exchange. Do not use as-is for production.
- For real deployments, use well-reviewed protocols like MLS (Messaging Layer Security) or the Signal Double Ratchet, and a formal authentication mechanism.

Requirements
- Node.js 16+ recommended

Setup
- Install dependencies:
  npm install
- Start the server:
  npm start
- Open in your browser:
  http://localhost:3000

Usage
- Enter a room name, a display name, and a shared password
- Share the same room and password with others to read/participate
- Compare the Key fingerprint displayed by each participant to mitigate MITM on the password exchange

Project structure
- server.js: Express static server + WebSocket relay (no plaintext logging)
- public/index.html: UI
- public/client.js: Chat logic + WebCrypto
- public/styles.css: Styles

Security overview
- Key derivation: PBKDF2(SHA-256, salt = "e2ee-chat|" + room, 150k iterations)
- Symmetric encryption: AES-GCM(256-bit) with 12-byte random IV per message
- Transport: Base64-encoded ciphertext + IV over WebSocket
- The server cannot decrypt messages and only relays envelopes within a room

Limitations
- Password security is as strong as the password you choose
- No out-of-band authentication or public-key identity built-in
- No persistence or message history (in-memory relay only)

License
MIT