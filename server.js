import express from "express";
import { WebSocketServer } from "ws";
import http from "http";
import dotenv from "dotenv";
dotenv.config();

const PORT = process.env.PORT || 3000;
const SPEED_PASSWORD = process.env.SPEED_PASSWORD || "speed";
const NOX_PASSWORD = process.env.NOX_PASSWORD || "nox";
const SPEED_IP = process.env.SPEED_IP || "72.76.122.61 ";  // IP whitelist for SPEED user
const NOX_IP = process.env.NOX_IP || "68.161.197.74";      // IP whitelist for NOX user
const HOSTNAME = process.env.HOSTNAME || "localhost";

const app = express();
app.use(express.static("public"));

app.get("/status", (req, res) => res.json({ ok: true, host: HOSTNAME }));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/*
 Protocol (JSON messages):
 - Client -> server:
   { type: "auth", username: "SPEED", password: "..." }
   { type: "pubkey", username: "SPEED", pubkey: "<base64>" }
   { type: "encrypted", to: "NOX", payload: "<base64>" }   // encrypted ciphertext (server does not inspect)
   { type: "presence_request" } // optional

 - Server -> client:
   { type: "auth_result", ok: true/false, reason? }
   { type: "presence", users: {SPEED: "online"/"offline", NOX: ...} }
   { type: "pubkey", from: "SPEED", pubkey: "<base64>" }
   { type: "encrypted", from: "SPEED", payload: "<base64>" }
*/

const clients = new Map(); // username -> { ws, pubkey?, status: "online"/"offline" }

function checkCredentials(username, password, ip) {
  if (username === "SPEED") {
    if (password !== SPEED_PASSWORD) return false;
    if (SPEED_IP && ip !== SPEED_IP) return false;
    return true;
  }
  if (username === "NOX") {
    if (password !== NOX_PASSWORD) return false;
    if (NOX_IP && ip !== NOX_IP) return false;
    return true;
  }
  return false;
}

function broadcastPresence() {
  const presence = {
    type: "presence",
    users: {
      SPEED: clients.has("SPEED") ? "online" : "offline",
      NOX: clients.has("NOX") ? "online" : "offline",
    },
  };
  for (const { ws } of clients.values()) {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(presence));
  }
}

wss.on("connection", (ws, req) => {
  let authedUser = null;
  const ip = req.socket.remoteAddress;

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === "auth") {
        const { username, password } = msg;
        if (!username || !password || !checkCredentials(username, password, ip)) {
          ws.send(JSON.stringify({ type: "auth_result", ok: false, reason: "invalid" }));
          ws.close();
          return;
        }
        authedUser = username;
        clients.set(username, { ws });
        ws.send(JSON.stringify({ type: "auth_result", ok: true }));
        broadcastPresence();
        return;
      }

      if (!authedUser) {
        ws.send(JSON.stringify({ type: "error", reason: "not authenticated" }));
        ws.close();
        return;
      }

      if (msg.type === "pubkey") {
        const { pubkey } = msg;
        const entry = clients.get(authedUser) || {};
        entry.pubkey = pubkey;
        clients.set(authedUser, entry);

        const other = authedUser === "SPEED" ? "NOX" : "SPEED";
        const otherEntry = clients.get(other);
        if (otherEntry && otherEntry.ws.readyState === otherEntry.ws.OPEN) {
          otherEntry.ws.send(JSON.stringify({ type: "pubkey", from: authedUser, pubkey }));
        }
        return;
      }

      if (msg.type === "encrypted") {
        const { to, payload } = msg;
        if (!to || !payload) return;
        const target = clients.get(to);
        if (target && target.ws.readyState === target.ws.OPEN) {
          target.ws.send(JSON.stringify({ type: "encrypted", from: authedUser, payload }));
        } else {
          ws.send(JSON.stringify({ type: "error", reason: "recipient_offline" }));
        }
        return;
      }

      if (msg.type === "presence_request") {
        broadcastPresence();
        return;
      }

    } catch (e) {
      console.error("ws message error", e.message);
    }
  });

  ws.on("close", () => {
    if (authedUser) {
      clients.delete(authedUser);
      broadcastPresence();
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
