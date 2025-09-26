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

function broadcastPresence(room) {
  const set = rooms.get(room);
  const count = set ? set.size : 0;
  const users = set ? Array.from(set).map((c) => c.name).filter(Boolean).slice(0, 200) : [];
  broadcastToRoom(room, { type: "presence", room, count, users });
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
        const prevRoom = ws.room;
        const prevSet = rooms.get(prevRoom);
        if (prevSet) {
          prevSet.delete(ws);
          if (prevSet.size === 0) rooms.delete(prevRoom);
        }
        broadcastPresence(prevRoom);
      }

      ws.room = room;
      ws.name = name;

      const set = getRoomSet(room);
      set.add(ws);
      broadcastPresence(room);

      // Ack the join (plaintext meta message)
      ws.send(
        JSON.stringify({ type: "joined", room, name, ts: Date.now() })
      );

      // Notify others in room (no plaintext name)
      broadcastToRoom(room, {
        type: "system",
        event: "join",
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
        iv: data.iv, // base64
        ciphertext: data.ciphertext, // base64 (AES-GCM ciphertext+tag)
        ts: Date.now(),
      };

      // Do not include plaintext names or reply metadata; clients decrypt these from payload
      broadcastToRoom(ws.room, envelope, { exclude: null });
      return;
    }

    // Anonymous typing indicator relay (no plaintext names)
    if (type === "typing") {
      if (!ws.room) return;
      const envelope = {
        type: "typing",
        room: ws.room,
        active: !!data.active,
        ts: Date.now(),
      };
      broadcastToRoom(ws.room, envelope, { exclude: ws });
      return;
    }

    if (type === "leave") {
      if (ws.room) {
        const room = ws.room;
        const set = rooms.get(room);
        if (set) {
          set.delete(ws);
          if (set.size === 0) rooms.delete(room);
        }
        broadcastToRoom(room, {
          type: "system",
          event: "leave",
          ts: Date.now(),
        }, { exclude: ws });
        broadcastPresence(room);
        ws.room = null;
      }
      return;
    }
  });

  ws.on("close", () => {
    if (ws.room) {
      const room = ws.room;
      const set = rooms.get(room);
      if (set) {
        set.delete(ws);
        if (set.size === 0) rooms.delete(room);
      }
      broadcastToRoom(room, {
        type: "system",
        event: "disconnect",
        ts: Date.now(),
      }, { exclude: ws });
      broadcastPresence(room);
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
