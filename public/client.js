// Client-side logic for password-based E2EE chat using WebCrypto AES-GCM

// Cross-browser compatibility checks
if (!window.crypto && window.msCrypto) {
  window.crypto = window.msCrypto;
}

// Polyfill for optional chaining fallback
function safeGet(obj, path, defaultValue = undefined) {
  return path.split('.').reduce((acc, part) => acc && acc[part], obj) || defaultValue;
}

const $ = (sel) => document.querySelector(sel);
const fingerprintEl = $("#fingerprint");
const statusTextEl = $("#statusText");
const onlineCountEl = $("#onlineCount");

// Sidebar and modal elements
const roomListEl = $("#roomList");
const addRoomBtn = $("#addRoomBtn");
const newRoomModal = $("#newRoomModal");
const newRoomNameEl = $("#newRoomName");
const newRoomDisplayNameEl = $("#newRoomDisplayName");
const newRoomPasswordEl = $("#newRoomPassword");
const createRoomConfirm = $("#createRoomConfirm");
const createRoomCancel = $("#createRoomCancel");
const memberListEl = $("#memberList");

const chatSection = $("#chatSection");
const messagesEl = $("#messages");
const messageInput = $("#messageInput");
const sendBtn = $("#sendBtn");
const disconnectCorner = $("#disconnectCorner");
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

// Toast notification container
const toastContainer = $("#toastContainer");

let ws = null;
let aesKey = null; // CryptoKey for the active room
let currentRoom = null; // active room id
let currentName = null; // active display name
let replyTarget = null;
let passwordHidden = true;
let typing = false;
let typingTimeout = null; // inactivity timeout to send typing: false
let typingHideTimeout = null; // hide UI after peer typing

// Rooms state: [{ room, name }]; passwords are stored in sessionStorage under key `e2ee.pwd.<room>`
let rooms = [];
const roomHistory = new Map(); // room -> [{kind, ...}] for re-render

function addMessage({ kind = "chat", from = "", text = "", error = false, ts = Date.now() }) {
  const li = document.createElement("li");
  li.className = `message ${kind}${error ? " error" : ""}`;

  // Show toast notification for system messages
  if (kind === "system") {
    showToast(text, error);
  }

  // Header with sender and time
  const header = document.createElement("div");
  header.className = "message-header";
  
  if (from) {
    const senderSpan = document.createElement("span");
    senderSpan.className = "message-sender";
    senderSpan.textContent = from;
    header.appendChild(senderSpan);
  }
  
  const timeSpan = document.createElement("span");
  timeSpan.className = "message-time";
  timeSpan.textContent = formatTime(ts);
  header.appendChild(timeSpan);
  
  li.appendChild(header);

  // Content with bubble and reply button
  const content = document.createElement("div");
  content.className = "message-content";

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";

  const textSpan = document.createElement("span");
  textSpan.className = "message-text";
  textSpan.textContent = text;
  bubble.appendChild(textSpan);
  
  content.appendChild(bubble);
  
  // Add reply button for chat messages only
  if (kind === "chat" && from) {
    const replyBtn = document.createElement("button");
    replyBtn.className = "message-reply-btn";
    replyBtn.textContent = "Reply";
    replyBtn.addEventListener("click", () => {
      setReplyTarget({ from, text, ts });
    });
    content.appendChild(replyBtn);
  }
  
  li.appendChild(content);
  messagesEl.appendChild(li);
  autoScrollIfNearBottom();
}

// Render a decrypted chat message with optional reply preview and a Reply button
function renderChatMessage({ from = "?", text = "", ts = Date.now(), replyTo = null }) {
  const li = document.createElement("li");
  li.className = "message chat";
  if (from && currentName && from === currentName) li.classList.add("mine");

  // Add reply info if present
  if (replyTo && replyTo.from && replyTo.text) {
    const info = document.createElement("div");
    info.className = "reply-info";
    info.textContent = `Replying to ${replyTo.from}: ${replyTo.text}`;
    li.appendChild(info);
  }

  // Header with sender and time
  const header = document.createElement("div");
  header.className = "message-header";
  
  const senderSpan = document.createElement("span");
  senderSpan.className = "message-sender";
  senderSpan.textContent = from;
  header.appendChild(senderSpan);
  
  const timeSpan = document.createElement("span");
  timeSpan.className = "message-time";
  timeSpan.textContent = formatTime(ts);
  header.appendChild(timeSpan);
  
  li.appendChild(header);

  // Content with bubble and reply button
  const content = document.createElement("div");
  content.className = "message-content";

  const bubble = document.createElement("div");
  bubble.className = "message-bubble";

  const textSpan = document.createElement("span");
  textSpan.className = "message-text";
  textSpan.textContent = text;
  bubble.appendChild(textSpan);
  
  content.appendChild(bubble);
  
  // Add reply button
  const replyBtn = document.createElement("button");
  replyBtn.className = "message-reply-btn";
  replyBtn.textContent = "Reply";
  replyBtn.addEventListener("click", () => {
    setReplyTarget({ from, text, ts });
  });
  content.appendChild(replyBtn);
  
  li.appendChild(content);
  messagesEl.appendChild(li);
  autoScrollIfNearBottom();
}

function autoScrollIfNearBottom() {
  const container = messagesEl.parentElement;
  if (!container) return;
  
  // Check if user is near bottom (within 100px)
  const isNearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
  
  // Only scroll if user is already near the bottom
  if (isNearBottom) {
    container.scrollTop = container.scrollHeight;
  }
}

function showToast(text, isError = false) {
  if (!toastContainer) return;
  
  // Create toast element
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'error' : ''}`;
  
  // Create content
  const content = document.createElement('div');
  content.className = 'toast-content';
  content.textContent = text;
  
  // Create progress bar
  const progress = document.createElement('div');
  progress.className = 'toast-progress';
  progress.style.width = '100%';
  
  toast.appendChild(content);
  toast.appendChild(progress);
  toastContainer.appendChild(toast);
  
  // Start progress bar animation
  setTimeout(() => {
    progress.style.width = '0%';
  }, 50);
  
  // Auto-dismiss after 3 seconds
  setTimeout(() => {
    toast.classList.add('hiding');
    setTimeout(() => {
      if (toast.parentElement) {
        toast.parentElement.removeChild(toast);
      }
    }, 300); // Wait for slide-out animation
  }, 3000);
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

async function computeVerifier(password, room) {
  const enc = new TextEncoder();
  const salt = enc.encode(`e2ee-chat-verifier|${room}`);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const verifierKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 1000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign"]
  );
  const raw = await crypto.subtle.exportKey("raw", verifierKey);
  const digest = await crypto.subtle.digest("SHA-256", raw);
  const bytes = new Uint8Array(digest).slice(0, 16);
  return bufToBase64(bytes.buffer);
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
  if (chatSection) chatSection.hidden = !connected;
  if (sendBtn) sendBtn.disabled = (!connected) || !messageInput.value.trim();
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
  // Initialize rooms list from localStorage
  loadRooms();
  renderRoomsList();
  const active = localStorage.getItem("e2ee.activeRoom");
  if (active && rooms.find(r => r.room === active)) {
    selectRoom(active);
  } else if (rooms.length) {
    selectRoom(rooms[0].room);
  }
});

// New multi-room workflow replaces legacy single connect
// Helpers for rooms persistence
function pwdKey(room) { return `e2ee.pwd.${room}`; }
function getRoomPassword(room) { return sessionStorage.getItem(pwdKey(room)) || ""; }
function setRoomPassword(room, pwd) { sessionStorage.setItem(pwdKey(room), pwd || ""); }
function loadRooms() {
  try {
    const raw = localStorage.getItem("e2ee.rooms");
    rooms = raw ? JSON.parse(raw) : [];
  } catch { rooms = []; }
}
function saveRooms() {
  try {
    localStorage.setItem("e2ee.rooms", JSON.stringify(rooms));
  } catch {}
}

function renderRoomsList() {
  if (!roomListEl) return;
  roomListEl.innerHTML = "";
  rooms.forEach((r) => {
    const li = document.createElement("li");
    li.dataset.room = r.room;
    if (currentRoom && r.room === currentRoom) li.classList.add("active");
    const left = document.createElement("div");
    left.className = "left";
    const nameSpan = document.createElement("div"); nameSpan.className = "name"; nameSpan.textContent = r.name || "anon";
    const roomSpan = document.createElement("div"); roomSpan.className = "room"; roomSpan.textContent = r.room;
    left.appendChild(nameSpan); left.appendChild(roomSpan);
    left.addEventListener("click", () => selectRoom(r.room));
    const removeBtn = document.createElement("button");
    removeBtn.className = "remove";
    removeBtn.textContent = "×";
    removeBtn.title = "Remove room";
    removeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteRoom(r.room);
    });
    li.appendChild(left);
    li.appendChild(removeBtn);
    roomListEl.appendChild(li);
  });
}

function showNewRoomModal(show) {
  if (!newRoomModal) return;
  newRoomModal.style.display = show ? "flex" : "none";
  if (show && newRoomNameEl) newRoomNameEl.focus();
}

async function selectRoom(room) {
  const entry = rooms.find((r) => r.room === room);
  if (!entry) return;
  
  // Update current room and re-render rooms list to show selection
  currentRoom = room;
  renderRoomsList();
  // Show censored password instead of room name
  const password = getRoomPassword(room);
  updatePasswordDisplay();
  currentName = entry.name || "anon";
  
  if (!password) {
    addMessage({ kind: "system", text: "Missing password for room. Please remove and re-add.", error: true });
    return;
  }
  try {
    aesKey = await deriveKey(password, room);
    const fp = await keyFingerprint(aesKey);
    fingerprintEl.textContent = fp;
    await ensureSocketAndJoin(room, entry.name || "anon", password);
    // Re-render history for the selected room
    redrawHistory(room);
    localStorage.setItem("e2ee.activeRoom", room);
  } catch (err) {
    addMessage({ kind: "system", text: `Error: ${err?.message || err}`, error: true });
  }
}

function redrawHistory(room) {
  messagesEl.innerHTML = "";
  const history = roomHistory.get(room) || [];
  history.forEach((item) => {
    if (item.kind === "chat") {
      renderChatMessage({ from: item.from, text: item.text, ts: item.ts, replyTo: item.replyTo || null });
    } else if (item.kind === "system") {
      addMessage({ kind: "system", text: item.text });
    }
  });
  // Scroll to bottom after loading history
  if (messagesEl.parentElement) {
    messagesEl.parentElement.scrollTop = messagesEl.parentElement.scrollHeight;
  }
}

function pushHistory(room, item) {
  const list = roomHistory.get(room) || [];
  list.push(item);
  roomHistory.set(room, list);
}

async function ensureSocketAndJoin(room, name, password) {
  const sendJoin = async () => {
    const joinVerifier = await computeVerifier(password, room);
    ws.send(JSON.stringify({ type: "join", room, name, verifier: joinVerifier }));
    if (toggleRoomVisibility) toggleRoomVisibility.textContent = passwordHidden ? "👁" : "🙈";
    if (messageInput) messageInput.focus();
  };
  if (!ws || ws.readyState === WebSocket.CLOSED) {
    const url = getWsUrl();
    ws = new WebSocket(url);
    ws.addEventListener("open", () => {
      setConnected(true);
      messagesEl.innerHTML = "";
      addMessage({ kind: "system", text: `Connected` });
      setStatus("Connected", { ok: true });
      sendJoin();
    });
    ws.addEventListener("message", handleWsMessage);
    ws.addEventListener("close", () => {
      setConnected(false);
      addMessage({ kind: "system", text: "Disconnected from server." });
      setStatus("Ready");
      ws = null; aesKey = null; currentRoom = null; currentName = null;
      fingerprintEl.textContent = "—";
      if (onlineCountEl) onlineCountEl.textContent = "0";
      if (memberListEl) memberListEl.innerHTML = "";
    });
    ws.addEventListener("error", () => {
      addMessage({ kind: "system", text: "Connection error.", error: true });
      setStatus("Connection error", { err: true });
    });
  } else if (ws.readyState === WebSocket.OPEN) {
    await sendJoin();
  }
}

function deleteRoom(room) {
  rooms = rooms.filter((r) => r.room !== room);
  saveRooms();
  try { sessionStorage.removeItem(pwdKey(room)); } catch {}
  if (currentRoom === room) {
    currentRoom = null;
    messagesEl.innerHTML = "";
    if (memberListEl) memberListEl.innerHTML = "";
    localStorage.removeItem("e2ee.activeRoom");
  }
  renderRoomsList();
}

function handleWsMessage(event) {
  let data;
  try { data = JSON.parse(event.data); } catch { return; }
  if (data.type === "joined") {
    currentRoom = data.room;
    localStorage.setItem("e2ee.activeRoom", currentRoom);
    addMessage({ kind: "system", text: `Joined room ${data.room} as ${currentName || "anon"}` });
    return;
  }
  if (data.type === "join-rejected") {
    // Do not close socket automatically; show error and status
    addMessage({ kind: "system", text: data.reason === "bad-password" ? "Incorrect room password." : "Join rejected.", error: true });
    setStatus("Join rejected", { err: true });
    if (memberListEl) memberListEl.innerHTML = "";
    return;
  }
  if (data.type === "system") {
    const ev = data.event || "?";
    let text = ev;
    if (ev === "join") text = "User joined";
    else if (ev === "leave") text = "User left";
    else if (ev === "disconnect") text = "User disconnected";
    addMessage({ kind: "system", text });
    if (currentRoom) pushHistory(currentRoom, { kind: "system", text });
    return;
  }
  if (data.type === "presence") {
    if (data.room === currentRoom) {
      if (onlineCountEl) onlineCountEl.textContent = String(data.count ?? 0);
      if (memberListEl) {
        memberListEl.innerHTML = "";
        const users = Array.isArray(data.users) ? data.users : [];
        users.forEach((u) => {
          const li = document.createElement("li");
          const dot = document.createElement("span"); dot.className = "dot";
          const name = document.createElement("span"); name.className = "name"; name.textContent = u;
          li.appendChild(dot); li.appendChild(name);
          if (currentName && u === currentName) li.style.opacity = "0.85";
          memberListEl.appendChild(li);
        });
      }
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
    (async () => {
      const plaintext = await decryptText(data.ciphertext, data.iv);
      if (plaintext == null) {
        // Don't show messages that can't be decrypted - likely wrong password
        console.warn("Message decryption failed - skipping display");
        return;
      }
      try {
        const payload = JSON.parse(plaintext);
        const from = payload.from || "?";
        const text = payload.text ?? "";
        const ts = payload.ts || Date.now();
        const replyTo = payload.replyTo || null;
        renderChatMessage({ from, text, ts, replyTo });
        if (currentRoom) pushHistory(currentRoom, { kind: "chat", from, text, ts, replyTo });
      } catch {
        // If JSON parsing fails, still show the message (backward compatibility)
        renderChatMessage({ from: "?", text: plaintext });
        if (currentRoom) pushHistory(currentRoom, { kind: "chat", from: "?", text: plaintext, ts: Date.now() });
      }
    })();
    return;
  }
}

// Sidebar actions
if (addRoomBtn) {
  addRoomBtn.addEventListener("click", () => {
    showNewRoomModal(true);
  });
}
if (createRoomCancel) {
  createRoomCancel.addEventListener("click", () => showNewRoomModal(false));
}
if (createRoomConfirm) {
  createRoomConfirm.addEventListener("click", async () => {
    const room = newRoomNameEl?.value.trim();
    const name = newRoomDisplayNameEl?.value.trim() || "anon";
    const password = newRoomPasswordEl?.value || "";
    if (!room || !password) {
      addMessage({ kind: "system", text: "Room and password are required.", error: true });
      return;
    }
    if (!rooms.find((r) => r.room === room)) {
      rooms.push({ room, name });
      saveRooms();
      setRoomPassword(room, password);
      renderRoomsList();
    } else {
      // Update name and password if room exists
      rooms = rooms.map((r) => (r.room === room ? { room, name } : r));
      saveRooms();
      setRoomPassword(room, password);
      renderRoomsList();
    }
    showNewRoomModal(false);
    // Auto-select the room we just added/updated
    await selectRoom(room);
    // Clear modal fields
    if (newRoomNameEl) newRoomNameEl.value = "";
    if (newRoomDisplayNameEl) newRoomDisplayNameEl.value = "";
    if (newRoomPasswordEl) newRoomPasswordEl.value = "";
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

function updatePasswordDisplay() {
  if (!currentRoom || !roomDisplay) return;
  const password = getRoomPassword(currentRoom);
  if (passwordHidden) {
    roomDisplay.textContent = "••••••••";
  } else {
    roomDisplay.textContent = password || "—";
  }
}

if (toggleRoomVisibility) {
  toggleRoomVisibility.addEventListener("click", () => {
    passwordHidden = !passwordHidden;
    toggleRoomVisibility.textContent = passwordHidden ? "👁" : "🙈";
    updatePasswordDisplay();
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

if (sendBtn) {
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
}

if (messageInput) {
  messageInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (sendBtn) sendBtn.click();
    }
  });

  messageInput.addEventListener("input", () => {
    if (sendBtn) sendBtn.disabled = !(ws && ws.readyState === WebSocket.OPEN) || !messageInput.value.trim();
    handleTypingInput();
  });
}

// Mobile Navigation Code
const mobileMenuBtn = $("#mobileMenuBtn");
const mobileMembersBtn = $("#mobileMembersBtn");
const roomsSidebar = $("#roomsSidebar");
const membersSidebar = $("#membersSidebar");
const mobileOverlay = $("#mobileOverlay");
const closeMembersBtn = $("#closeMembersBtn");

let touchStartX = null;
let touchStartY = null;
let isSwiping = false;

// Toggle rooms sidebar
if (mobileMenuBtn) {
  mobileMenuBtn.addEventListener("click", () => {
    toggleRoomsSidebar();
  });
}

// Toggle members sidebar
if (mobileMembersBtn) {
  mobileMembersBtn.addEventListener("click", () => {
    toggleMembersSidebar();
  });
}

// Close members sidebar
if (closeMembersBtn) {
  closeMembersBtn.addEventListener("click", () => {
    closeMembersSidebar();
  });
}

// Close sidebars when clicking overlay
if (mobileOverlay) {
  mobileOverlay.addEventListener("click", () => {
    closeAllSidebars();
  });
}

function toggleRoomsSidebar() {
  if (!roomsSidebar) return;
  const isActive = roomsSidebar.classList.contains("active");
  
  if (isActive) {
    closeRoomsSidebar();
  } else {
    openRoomsSidebar();
  }
}

function openRoomsSidebar() {
  if (!roomsSidebar) return;
  roomsSidebar.classList.add("active");
  if (mobileOverlay) {
    mobileOverlay.style.display = "block";
    setTimeout(() => mobileOverlay.classList.add("active"), 10);
  }
  document.body.style.overflow = "hidden";
}

function closeRoomsSidebar() {
  if (!roomsSidebar) return;
  roomsSidebar.classList.remove("active");
  if (mobileOverlay && !(membersSidebar && membersSidebar.classList.contains("active"))) {
    mobileOverlay.classList.remove("active");
    setTimeout(() => mobileOverlay.style.display = "none", 300);
    document.body.style.overflow = "";
  }
}

function toggleMembersSidebar() {
  if (!membersSidebar) return;
  const isActive = membersSidebar.classList.contains("active");
  
  if (isActive) {
    closeMembersSidebar();
  } else {
    openMembersSidebar();
  }
}

function openMembersSidebar() {
  if (!membersSidebar) return;
  membersSidebar.classList.add("active");
  if (mobileOverlay) {
    mobileOverlay.style.display = "block";
    setTimeout(() => mobileOverlay.classList.add("active"), 10);
  }
  document.body.style.overflow = "hidden";
}

function closeMembersSidebar() {
  if (!membersSidebar) return;
  membersSidebar.classList.remove("active");
  if (mobileOverlay && !(roomsSidebar && roomsSidebar.classList.contains("active"))) {
    mobileOverlay.classList.remove("active");
    setTimeout(() => mobileOverlay.style.display = "none", 300);
    document.body.style.overflow = "";
  }
}

function closeAllSidebars() {
  closeRoomsSidebar();
  closeMembersSidebar();
}

// Swipe gesture support for mobile
document.addEventListener("touchstart", handleTouchStart, { passive: true });
document.addEventListener("touchmove", handleTouchMove, { passive: true });
document.addEventListener("touchend", handleTouchEnd, { passive: true });

function handleTouchStart(e) {
  touchStartX = e.touches[0].clientX;
  touchStartY = e.touches[0].clientY;
  isSwiping = false;
}

function handleTouchMove(e) {
  if (!touchStartX || !touchStartY) return;
  
  const touchEndX = e.touches[0].clientX;
  const touchEndY = e.touches[0].clientY;
  
  const diffX = touchEndX - touchStartX;
  const diffY = touchEndY - touchStartY;
  
  // Only consider horizontal swipes
  if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 30) {
    isSwiping = true;
  }
}

function handleTouchEnd(e) {
  if (!touchStartX || !isSwiping) {
    touchStartX = null;
    touchStartY = null;
    return;
  }
  
  const touchEndX = e.changedTouches[0].clientX;
  const diffX = touchEndX - touchStartX;
  const windowWidth = window.innerWidth;
  
  // Swipe right from left edge - open rooms sidebar
  if (touchStartX < 30 && diffX > 100) {
    openRoomsSidebar();
  }
  // Swipe left from right edge - open members sidebar
  else if (touchStartX > windowWidth - 30 && diffX < -100) {
    openMembersSidebar();
  }
  // Swipe left on open rooms sidebar - close it
  else if (roomsSidebar && roomsSidebar.classList.contains("active") && diffX < -100) {
    closeRoomsSidebar();
  }
  // Swipe right on open members sidebar - close it
  else if (membersSidebar && membersSidebar.classList.contains("active") && diffX > 100) {
    closeMembersSidebar();
  }
  
  touchStartX = null;
  touchStartY = null;
  isSwiping = false;
}

// Handle room selection on mobile - close sidebar after selection
function handleMobileRoomSelection() {
  if (window.innerWidth <= 768) {
    closeRoomsSidebar();
  }
}

// Update existing selectRoom to close sidebar on mobile
const originalSelectRoom = window.selectRoom || selectRoom;
if (originalSelectRoom) {
  window.selectRoom = async function(room) {
    const result = await originalSelectRoom.call(this, room);
    handleMobileRoomSelection();
    return result;
  };
}

// Handle keyboard focus management for mobile
if (messageInput) {
  messageInput.addEventListener("focus", () => {
    // On mobile, ensure the composer is visible when keyboard opens
    if (window.innerWidth <= 768) {
      setTimeout(() => {
        messageInput.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 300);
    }
  });
}

// Handle window resize to reset sidebars
let resizeTimeout;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimeout);
  resizeTimeout = setTimeout(() => {
    // Close sidebars and reset on resize from mobile to desktop
    if (window.innerWidth > 768) {
      closeAllSidebars();
      document.body.style.overflow = "";
    }
  }, 250);
});

// Ensure proper viewport height on mobile (fixes iOS Safari issue)
function setViewportHeight() {
  const vh = window.innerHeight * 0.01;
  document.documentElement.style.setProperty('--vh', `${vh}px`);
}

setViewportHeight();
window.addEventListener('resize', setViewportHeight);
window.addEventListener('orientationchange', setViewportHeight);
