// client.js - browser side E2EE + websocket
const wsUrl = (location.protocol === "https:" ? "wss:" : "ws:") + "//" + location.host;
let ws;
let usernameEl = document.getElementById("username");
let pwdEl = document.getElementById("pwd");
let connectBtn = document.getElementById("connectBtn");
let disconnectBtn = document.getElementById("disconnectBtn");
let sendBtn = document.getElementById("sendBtn");
let textEl = document.getElementById("text");
let messagesEl = document.getElementById("messages");
let presenceEl = document.getElementById("presence");
let fingerprintEl = document.getElementById("fingerprint");
let showKeyBtn = document.getElementById("showKeyBtn");
let verifyBtn = document.getElementById("verifyBtn");

let myKeyPair = null;
let theirPubKey = null;
let aesKey = null;
let authed = false;

// Store last presence state for comparison
let lastPresence = { SPEED: "offline", NOX: "offline" };

function logMessage(who, text, meta = "") {
  const el = document.createElement("div");
  el.className = "msg";
  el.innerHTML = `<div class="who">${who} ${meta ? `<span style="color:#888;font-weight:400">(${meta})</span>` : ""}</div><div>${sanitize(text)}</div>`;
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function sanitize(s) {
  return s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

async function ensureNotificationPermission() {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    await Notification.requestPermission();
  }
}

function notify(title, body) {
  if (!("Notification" in window)) return;
  if (Notification.permission === "granted") {
    const n = new Notification(title, { body });
    n.onclick = () => window.focus();
  }
}

async function generateKeyPair() {
  myKeyPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  return myKeyPair;
}

async function exportPublicKeyBase64(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(raw);
}

async function importTheirPubKey(base64) {
  const raw = base64ToArrayBuffer(base64);
  const key = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  return key;
}

async function deriveAESKey(myPrivKey, theirPubKey) {
  const derivedKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: theirPubKey },
    myPrivKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return derivedKey;
}

async function encryptMessage(plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(plaintext);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc
  );

  const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.byteLength);
  return arrayBufferToBase64(combined.buffer);
}

async function decryptMessage(base64) {
  const data = base64ToArrayBuffer(base64);
  const bytes = new Uint8Array(data);
  const iv = bytes.slice(0, 12);
  const cipher = bytes.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipher);
  return new TextDecoder().decode(plain);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function computeFingerprint(base64PubKey) {
  const buf = base64ToArrayBuffer(base64PubKey);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 16);
}

connectBtn.addEventListener("click", async () => {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  await ensureNotificationPermission();

  const username = usernameEl.value;
  const pwd = pwdEl.value;
  if (!pwd) { alert("Enter password"); return; }

  ws = new WebSocket(wsUrl);
  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "auth", username, password: pwd }));
  });
  ws.addEventListener("message", async (ev) => {
    try {
      const msg = JSON.parse(ev.data);

      if (msg.type === "auth_result") {
        if (msg.ok) {
          authed = true;
          connectBtn.disabled = true;
          disconnectBtn.disabled = false;
          textEl.disabled = false;
          sendBtn.disabled = false;
          logMessage("SYSTEM", "Authenticated");

          await generateKeyPair();

        } else {
          alert("Authentication failed: " + (msg.reason || "unknown"));
          ws.close();
        }
      } else if (msg.type === "presence") {
        presenceEl.textContent = `Presence — SPEED: ${msg.users.SPEED}, NOX: ${msg.users.NOX}`;

        // Check for changes and notify only on status change
        ["SPEED", "NOX"].forEach(user => {
          if (lastPresence[user] !== msg.users[user]) {
            notify("Presence update", `${user} is now ${msg.users[user]}`);
          }
        });
        lastPresence = { ...msg.users };

      } else if (msg.type === "pubkey") {
        theirPubKey = await importTheirPubKey(msg.pubkey);
        aesKey = await deriveAESKey(myKeyPair.privateKey, theirPubKey);
        const fp = await computeFingerprint(msg.pubkey);
        fingerprintEl.textContent = fp;
        notify("Public key received", `from ${msg.from}`);
      } else if (msg.type === "encrypted") {
        if (!aesKey) {
          logMessage("SYSTEM", "Received encrypted message but no AES key yet.");
          return;
        }
        try {
          const text = await decryptMessage(msg.payload);
          logMessage(msg.from, text);
          notify(`Message from ${msg.from}`, text.slice(0, 200));
        } catch (e) {
          console.error("decrypt failed", e);
          logMessage("SYSTEM", "Failed to decrypt message (possible key mismatch).");
        }
      } else if (msg.type === "error") {
        logMessage("SYSTEM", "Server error: " + (msg.reason || "unknown"));
      }
    } catch (e) {
      console.error("parse err", e);
    }
  });

  ws.addEventListener("close", () => {
    authed = false;
    connectBtn.disabled = false;
    disconnectBtn.disabled = true;
    textEl.disabled = true;
    sendBtn.disabled = true;
    logMessage("SYSTEM", "Disconnected.");
  });
});

disconnectBtn.addEventListener("click", () => {
  if (ws) ws.close();
});

showKeyBtn.addEventListener("click", async () => {
  if (!myKeyPair) { alert("Connect first to generate keypair"); return; }
  const pub64 = await exportPublicKeyBase64(myKeyPair.publicKey);
  ws.send(JSON.stringify({ type: "pubkey", pubkey: pub64 }));
  alert("Public key shared via server.");
});

verifyBtn.addEventListener("click", async () => {
  if (!myKeyPair) { alert("Connect first"); return; }
  const pub64 = await exportPublicKeyBase64(myKeyPair.publicKey);
  const fp = await computeFingerprint(pub64);
  alert("Your local public key fingerprint (share/compare with your friend):\n" + fp);
});

sendBtn.addEventListener("click", async () => {
  const to = usernameEl.value === "SPEED" ? "NOX" : "SPEED";
  const plaintext = textEl.value.trim();
  if (!plaintext) return;
  if (!aesKey) { alert("No encryption key yet — ensure both users have exchanged public keys."); return; }
  const payload = await encryptMessage(plaintext);
  ws.send(JSON.stringify({ type: "encrypted", to, payload }));
  logMessage("You", plaintext, "encrypted");
  textEl.value = "";
});

textEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendBtn.click();
});
