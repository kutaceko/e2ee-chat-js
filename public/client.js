// Client-side logic for password-based E2EE chat using WebCrypto AES-GCM

const $ = (sel) => document.querySelector(sel);
const roomEl = $("#room");
const nameEl = $("#name");
const passwordEl = $("#password");
const connectBtn = $("#connectBtn");
const disconnectBtn = $("#disconnectBtn");
const fingerprintEl = $("#fingerprint");
const statusTextEl = $("#statusText");
const onlineCountEl = $("#onlineCount");

const chatSection = $("#chatSection");
const messagesEl = $("#messages");
const messageInput = $("#messageInput");
const sendBtn = $("#sendBtn");
const disconnectCorner = $("#disconnectCorner");
const connectSection = document.querySelector(".connect");
const presenceContainer = document.querySelector(".appbar__presence");
const roomContainer = document.querySelector(".appbar__room");
const roomDisplay = $("#roomDisplay");
const toggleRoomVisibility = $("#toggleRoomVisibility");
const typingIndicator = $("#typingIndicator");

// Reply elements
const replyPreview = $("#replyPreview");
const replyToName = $("#replyToName");
const replyToText = $("#replyToText");
const closeReply = $("#closeReply");

let ws = null;
let aesKey = null; // CryptoKey
let currentRoom = null;
let currentName = null;
let replyTarget = null;
let roomHidden = false;
let typing = false;
let typingTimeout = null; // inactivity timeout to send typing: false
let typingHideTimeout = null; // hide UI after peer typing

function addMessage({ kind = "chat", from = "", text = "", error = false }) {
  const li = document.createElement("li");
  li.className = `message ${kind}${error ? " error" : ""}`;

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (kind === "chat" && from) {
    const nameSpan = document.createElement("span");
    nameSpan.className = "sender";
    nameSpan.textContent = `${from}:`;
    bubble.appendChild(nameSpan);
  }

  const textSpan = document.createElement("span");
  textSpan.className = "text";
  textSpan.textContent = text;
  bubble.appendChild(textSpan);

  li.appendChild(bubble);
  messagesEl.appendChild(li);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

// Render a decrypted chat message with optional reply preview and a Reply button
function renderChatMessage({ from = "?", text = "", ts = Date.now(), replyTo = null }) {
  const li = document.createElement("li");
  li.className = "message chat";
  if (from && currentName && from === currentName) li.classList.add("mine");

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  const nameSpan = document.createElement("span");
  nameSpan.className = "sender";
  nameSpan.textContent = `${from}:`;
  bubble.appendChild(nameSpan);

  if (replyTo && replyTo.from && replyTo.text) {
    const info = document.createElement("div");
    info.className = "reply-info";
    info.textContent = `Replying to ${replyTo.from}: ${replyTo.text}`;
    li.appendChild(info);
  }

  const textSpan = document.createElement("span");
  textSpan.className = "text";
  textSpan.textContent = text;
  bubble.appendChild(textSpan);

  const timeSpan = document.createElement("span");
  timeSpan.className = "time";
  timeSpan.textContent = formatTime(ts);
  bubble.appendChild(timeSpan);

  const btn = document.createElement("button");
  btn.className = "reply-btn";
  btn.textContent = "Reply";
  btn.addEventListener("click", () => {
    setReplyTarget({ from, text, ts });
  });
  bubble.appendChild(btn);

  li.appendChild(bubble);
  messagesEl.appendChild(li);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, room) {
  const enc = new TextEncoder();
  const salt = enc.encode(`e2ee-chat|${room}`);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 150000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return key;
}

async function keyFingerprint(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  const digest = await crypto.subtle.digest("SHA-256", raw);
  const bytes = new Uint8Array(digest).slice(0, 8);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function encryptText(plain) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(plain)
  );
  return { iv: bufToBase64(iv), ciphertext: bufToBase64(ciphertext) };
}

async function decryptText(b64, ivB64) {
  const dec = new TextDecoder();
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(base64ToBuf(ivB64)) },
      aesKey,
      base64ToBuf(b64)
    );
    return dec.decode(pt);
  } catch (e) {
    return null;
  }
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function setConnected(connected) {
  roomEl.disabled = connected;
  nameEl.disabled = connected;
  passwordEl.disabled = connected;
  connectBtn.disabled = connected;
  if (disconnectBtn) disconnectBtn.disabled = !connected;
  chatSection.hidden = !connected;
  sendBtn.disabled = (!connected) || !messageInput.value.trim();
  if (connectSection) connectSection.style.display = connected ? "none" : "block";
  if (disconnectCorner) disconnectCorner.style.display = connected ? "inline-block" : "none";
  if (presenceContainer) presenceContainer.style.display = connected ? "inline" : "none";
  if (roomContainer) roomContainer.style.display = connected ? "flex" : "none";
}

function setStatus(text, { ok = false, err = false } = {}) {
  if (!statusTextEl) return;
  statusTextEl.textContent = text;
  statusTextEl.classList.remove('ok', 'err');
  if (ok) statusTextEl.classList.add('ok');
  if (err) statusTextEl.classList.add('err');
}

function setReplyTarget(info) {
  replyTarget = {
    from: info.from,
    text: info.text,
    ts: info.ts || Date.now(),
  };
  if (replyToName) replyToName.textContent = replyTarget.from;
  if (replyToText) replyToText.textContent = replyTarget.text;
  if (replyPreview) replyPreview.style.display = "flex";
}

if (closeReply) {
  closeReply.addEventListener("click", () => {
    replyTarget = null;
    if (replyPreview) replyPreview.style.display = "none";
  });
}

function getWsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  if (location.host) {
    return `${proto}://${location.host}`;
  }
  return `${proto}://localhost:3000`;
}

// Warn early if not a secure context (required for crypto.subtle except on localhost)
window.addEventListener("DOMContentLoaded", () => {
  const insecure = !window.isSecureContext && location.hostname !== "localhost";
  if (insecure) {
    addMessage({
      kind: "system",
      text: "Secure connection required. Please access via HTTPS or localhost for full functionality.",
      error: true,
    });
  }
});

connectBtn.addEventListener("click", async () => {
  try {
    const room = roomEl.value.trim() || "lobby";
    const name = nameEl.value.trim() || "anon";
    const password = passwordEl.value;
    if (!password) {
      addMessage({ kind: "system", text: "Please provide a room password.", error: true });
      setStatus("Password required", { err: true });
      return;
    }

    if (!crypto || !crypto.subtle) {
      addMessage({ kind: "system", text: "Security features unavailable. Please use HTTPS or localhost.", error: true });
      setStatus("Security unavailable", { err: true });
      return;
    }

    addMessage({ kind: "system", text: "Establishing secure connection…" });
    setStatus("Connecting…");
    aesKey = await deriveKey(password, room);
    const fp = await keyFingerprint(aesKey);
    fingerprintEl.textContent = fp;

    currentRoom = room;
    currentName = name;

    const url = getWsUrl();
    ws = new WebSocket(url);

    ws.addEventListener("open", () => {
      setConnected(true);
      messagesEl.innerHTML = "";
      addMessage({ kind: "system", text: `Connected to room: ${room}` });
      setStatus("Connected", { ok: true });
      if (roomDisplay) roomDisplay.textContent = room;
      roomHidden = false;
      if (toggleRoomVisibility) toggleRoomVisibility.textContent = "👁";
      if (messageInput) messageInput.focus();
      ws.send(JSON.stringify({ type: "join", room, name }));
    });

    ws.addEventListener("message", async (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      if (data.type === "joined") {
        addMessage({ kind: "system", text: `Joined room ${data.room} as ${data.name}` });
        return;
      }
      if (data.type === "system") {
        const ev = data.event || "?";
        let text = ev;
        if (ev === "join") text = "User joined";
        else if (ev === "leave") text = "User left";
        else if (ev === "disconnect") text = "User disconnected";
        addMessage({ kind: "system", text });
        return;
      }
      if (data.type === "presence") {
        if (data.room === currentRoom && onlineCountEl) {
          onlineCountEl.textContent = String(data.count ?? 0);
        }
        return;
      }
      if (data.type === "typing") {
        if (typingIndicator) {
          if (data.active) {
            typingIndicator.style.display = "block";
            clearTimeout(typingHideTimeout);
            typingHideTimeout = setTimeout(() => {
              typingIndicator.style.display = "none";
            }, 2500);
          } else {
            typingIndicator.style.display = "none";
          }
        }
        return;
      }
      if (data.type === "chat") {
        const plaintext = await decryptText(data.ciphertext, data.iv);
        if (plaintext == null) {
          addMessage({ kind: "chat", from: "?", text: "[Unable to decrypt]", error: true });
        } else {
          try {
            const payload = JSON.parse(plaintext);
            const from = payload.from || "?";
            const text = payload.text ?? "";
            const ts = payload.ts || Date.now();
            const replyTo = payload.replyTo || null;
            renderChatMessage({ from, text, ts, replyTo });
          } catch {
            renderChatMessage({ from: "?", text: plaintext });
          }
        }
        return;
      }
    });

    ws.addEventListener("close", () => {
      setConnected(false);
      addMessage({ kind: "system", text: "Disconnected from room." });
      setStatus("Ready");
      ws = null; aesKey = null; currentRoom = null; currentName = null;
      fingerprintEl.textContent = "—";
      if (onlineCountEl) onlineCountEl.textContent = "0";
    });

    ws.addEventListener("error", () => {
      addMessage({ kind: "system", text: "Connection error.", error: true });
      setStatus("Connection error", { err: true });
    });
  } catch (err) {
    addMessage({ kind: "system", text: `Error: ${err?.message || err}`, error: true });
    setStatus(`Error: ${err?.message || err}`, { err: true });
  }
});

if (disconnectBtn) {
  disconnectBtn.addEventListener("click", () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ type: "leave" })); } catch {}
      ws.close();
    }
  });
}

if (disconnectCorner) {
  disconnectCorner.addEventListener("click", () => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify({ type: "leave" })); } catch {}
      ws.close();
    }
  });
}

if (toggleRoomVisibility) {
  toggleRoomVisibility.addEventListener("click", () => {
    roomHidden = !roomHidden;
    toggleRoomVisibility.textContent = roomHidden ? "🙈" : "👁";
    if (roomDisplay) roomDisplay.textContent = roomHidden ? "••••" : (currentRoom || "—");
  });
}

function sendTyping(active) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  try { ws.send(JSON.stringify({ type: "typing", active: !!active })); } catch {}
}

function handleTypingInput() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const hasText = !!messageInput.value.trim();
  if (hasText && !typing) {
    typing = true;
    sendTyping(true);
  }
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    if (typing) {
      sendTyping(false);
      typing = false;
    }
  }, 1500);
}

sendBtn.addEventListener("click", async () => {
  const text = messageInput.value;
  if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
  const payload = {
    from: currentName || "anon",
    text,
    ts: Date.now(),
  };
  if (replyTarget) {
    payload.replyTo = {
      from: replyTarget.from,
      text: replyTarget.text,
      ts: replyTarget.ts,
    };
  }
  const { ciphertext, iv } = await encryptText(JSON.stringify(payload));
  ws.send(JSON.stringify({ type: "chat", ciphertext, iv }));
  messageInput.value = "";
  if (replyPreview) replyPreview.style.display = "none";
  replyTarget = null;
  // stop typing immediately after sending
  if (typing) {
    sendTyping(false);
    typing = false;
    clearTimeout(typingTimeout);
  }
});

messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendBtn.click();
  }
});

messageInput.addEventListener("input", () => {
  sendBtn.disabled = !(ws && ws.readyState === WebSocket.OPEN) || !messageInput.value.trim();
  handleTypingInput();
});
