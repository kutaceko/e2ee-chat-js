const path = require("path");
const express = require("express");
const http = require("http");
const WebSocket = require("ws");

const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// roomName -> Set<ws>
const rooms = new Map();

function getRoomSet(room) {
  if (!rooms.has(room)) rooms.set(room, new Set());
  return rooms.get(room);
}

function broadcastToRoom(room, data, options = {}) {
  const { exclude } = options;
  const payload = JSON.stringify(data);
  const peers = rooms.get(room);
  if (!peers) return;
  for (const client of peers) {
    if (client.readyState !== WebSocket.OPEN) continue;
    if (exclude && client === exclude) continue;
    client.send(payload);
  }
}

function sanitizeString(s, max = 64) {
  if (typeof s !== "string") return "";
  return s.replace(/[\r\n\t]/g, " ").trim().slice(0, max);
}

wss.on("connection", (ws) => {
  ws.isAlive = true;
  ws.room = null;
  ws.name = null;

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (msg) => {
    let data;
    try {
      data = JSON.parse(msg.toString());
    } catch (e) {
      return; // ignore invalid JSON
    }

    const type = data?.type;

    if (type === "join") {
      const room = sanitizeString(data.room, 64) || "lobby";
      const name = sanitizeString(data.name, 32) || "anon";

      // Leave previous room if any
      if (ws.room) {
        const prevSet = rooms.get(ws.room);
        if (prevSet) {
          prevSet.delete(ws);
          if (prevSet.size === 0) rooms.delete(ws.room);
        }
      }

      ws.room = room;
      ws.name = name;

      const set = getRoomSet(room);
      set.add(ws);

      // Ack the join (plaintext meta message)
      ws.send(
        JSON.stringify({ type: "joined", room, name, ts: Date.now() })
      );

      // Notify others in room (plaintext meta message)
      broadcastToRoom(room, {
        type: "system",
        event: "join",
        name,
        ts: Date.now(),
      }, { exclude: ws });

      return;
    }

    // Encrypted chat payload relay
    if (type === "chat") {
      if (!ws.room || !ws.name) return;
      // Do not inspect payload, just relay within the room
      const envelope = {
        type: "chat",
        room: ws.room,
        from: ws.name,
        iv: data.iv, // base64
        ciphertext: data.ciphertext, // base64 (AES-GCM ciphertext+tag)
        ts: Date.now(),
      };
      broadcastToRoom(ws.room, envelope, { exclude: null });
      return;
    }

    if (type === "leave") {
      if (ws.room) {
        const set = rooms.get(ws.room);
        if (set) {
          set.delete(ws);
          if (set.size === 0) rooms.delete(ws.room);
        }
        broadcastToRoom(ws.room, {
          type: "system",
          event: "leave",
          name: ws.name || "anon",
          ts: Date.now(),
        }, { exclude: ws });
        ws.room = null;
      }
      return;
    }
  });

  ws.on("close", () => {
    if (ws.room) {
      const set = rooms.get(ws.room);
      if (set) {
        set.delete(ws);
        if (set.size === 0) rooms.delete(ws.room);
      }
      broadcastToRoom(ws.room, {
        type: "system",
        event: "disconnect",
        name: ws.name || "anon",
        ts: Date.now(),
      }, { exclude: ws });
    }
  });
});

// Heartbeat to terminate dead connections
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch (_) {}
  });
}, 30000);

wss.on("close", () => clearInterval(interval));

server.listen(PORT, () => {
  console.log(`E2EE chat server listening on http://localhost:${PORT}`);
});
