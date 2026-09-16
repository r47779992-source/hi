import os
import asyncio
import json
import logging
import sqlite3
import time
import uuid
from typing import Dict, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LanGramServer")

app = FastAPI(title="LanGram Secure Blind Relay Server")

# ---------------------------------------------------------
# SQLite Database Setup (Zero-Knowledge Storage)
# ---------------------------------------------------------
DB_FILE = "server.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uid TEXT PRIMARY KEY,
                username TEXT,
                pass_hash TEXT,
                role TEXT,
                blocked INTEGER,
                ban_until INTEGER,
                ban_reason TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                name TEXT PRIMARY KEY
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_uid TEXT,
                sender_name TEXT,
                channel TEXT,
                to_uid TEXT,
                payload_data TEXT,
                ts INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS account_requests (
                id TEXT PRIMARY KEY,
                uid TEXT,
                username TEXT,
                pass_hash TEXT,
                ts INTEGER
            )
        """)
        c.execute("INSERT OR IGNORE INTO channels (name) VALUES ('Общий чат')")
        conn.commit()

init_db()

# ---------------------------------------------------------
# Connected Clients Manager
# ---------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[WebSocket, str] = {} # ws -> uid
        self.uid_connections: Dict[str, Set[WebSocket]] = {} # uid -> set(ws)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()

    def register_user(self, websocket: WebSocket, uid: str):
        self.active_connections[websocket] = uid
        if uid not in self.uid_connections:
            self.uid_connections[uid] = set()
        self.uid_connections[uid].add(websocket)

    def disconnect(self, websocket: WebSocket):
        uid = self.active_connections.pop(websocket, None)
        if uid and uid in self.uid_connections:
            self.uid_connections[uid].discard(websocket)
            if not self.uid_connections[uid]:
                del self.uid_connections[uid]

    async def send_json(self, websocket: WebSocket, data: dict):
        try:
            await websocket.send_json(data)
        except Exception:
            pass

    async def broadcast(self, data: dict):
        for ws in list(self.active_connections.keys()):
            await self.send_json(ws, data)

    async def send_to_uid(self, uid: str, data: dict):
        if uid in self.uid_connections:
            for ws in list(self.uid_connections[uid]):
                await self.send_json(ws, data)

manager = ConnectionManager()

# ---------------------------------------------------------
# Helper DB operations
# ---------------------------------------------------------
def get_user(uid: str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT uid, username, pass_hash, role, blocked, ban_until, ban_reason FROM users WHERE uid = ?", (uid,))
        return c.fetchone()

def save_user(uid: str, username: str, pass_hash: str, role: str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO users (uid, username, pass_hash, role, blocked, ban_until, ban_reason)
            VALUES (?, ?, ?, ?, 0, NULL, NULL)
        """, (uid, username, pass_hash, role))
        conn.commit()

def get_channels():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM channels")
        return [row[0] for row in c.fetchall()]

def add_channel(name: str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO channels (name) VALUES (?)", (name,))
        conn.commit()

def save_message(msg_id: str, sender_uid: str, sender_name: str, channel: str, to_uid: str, payload_data: str, ts: int):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR IGNORE INTO messages (id, sender_uid, sender_name, channel, to_uid, payload_data, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (msg_id, sender_uid, sender_name, channel, to_uid, payload_data, ts))
        conn.commit()

# ---------------------------------------------------------
# HTTP Health & Status Endpoint
# ---------------------------------------------------------
@app.get("/")
def root():
    return {
        "status": "online",
        "service": "LanGram Zero-Knowledge Relay Server",
        "security": "E2EE AES-256-GCM + ECDH Relay Mode"
    }

# ---------------------------------------------------------
# WebSocket Message Handler
# ---------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    user_uid = None

    try:
        while True:
            text_data = await websocket.receive_text()
            try:
                frame = json.loads(text_data)
            except Exception:
                continue

            msg_type = frame.get("t")

            # ---------------- LOGIN / AUTH ----------------
            if msg_type == "login":
                uid = frame.get("uid", "").strip()
                pw = frame.get("password", "").strip()
                
                # Auto-bootstrap admin account with default password 'admin' if empty
                if not get_user("admin"):
                    save_user("admin", "Admin", "admin", "admin")

                u = get_user(uid)
                if not u:
                    await manager.send_json(websocket, {"t": "err", "text": "Пользователь не найден"})
                    continue
                
                db_uid, db_name, db_hash, db_role, db_blocked, db_ban_until, db_ban_reason = u

                if db_blocked:
                    await manager.send_json(websocket, {"t": "err", "text": "Аккаунт заблокирован"})
                    continue

                if db_ban_until and db_ban_until > int(time.time() * 1000):
                    await manager.send_json(websocket, {"t": "banned", "banUntil": db_ban_until, "reason": db_ban_reason})
                    continue

                if db_hash != pw:
                    await manager.send_json(websocket, {"t": "err", "text": "Неверный пароль"})
                    continue

                user_uid = uid
                manager.register_user(websocket, uid)

                # Confirm Login
                token = f"token_{uid}_{uuid.uuid4().hex[:8]}"
                await manager.send_json(websocket, {
                    "t": "login_ok",
                    "token": token,
                    "uid": uid,
                    "from": db_name,
                    "role": db_role
                })

                # Send channels list
                await manager.send_json(websocket, {
                    "t": "channel_list",
                    "channels": get_channels()
                })

            # ---------------- CHAT / MESSAGES ----------------
            elif msg_type == "msg":
                if not user_uid:
                    await manager.send_json(websocket, {"t": "err", "text": "Авторизуйтесь"})
                    continue

                sender = get_user(user_uid)
                sender_name = sender[1] if sender else user_uid

                msg_id = frame.get("id") or str(uuid.uuid4())
                channel = frame.get("channel") or "Общий чат"
                to_uid = frame.get("toUid")
                payload_text = frame.get("text") or ""
                payload_data = frame.get("data") or ""
                ts = frame.get("ts") or int(time.time() * 1000)

                save_message(msg_id, user_uid, sender_name, channel, to_uid or "", payload_text or payload_data, ts)

                msg_frame = {
                    "t": "msg",
                    "id": msg_id,
                    "from": sender_name,
                    "uid": user_uid,
                    "channel": channel,
                    "toUid": to_uid,
                    "text": payload_text,
                    "data": payload_data,
                    "ts": ts
                }

                if to_uid:
                    # Direct message to specific UID and echo back to sender
                    await manager.send_to_uid(to_uid, msg_frame)
                    await manager.send_to_uid(user_uid, msg_frame)
                else:
                    # Channel broadcast
                    await manager.broadcast(msg_frame)

            # ---------------- CREATE CHANNEL ----------------
            elif msg_type == "create_channel":
                ch_name = frame.get("channel", "").strip()
                if ch_name:
                    add_channel(ch_name)
                    await manager.broadcast({
                        "t": "channel_list",
                        "channels": get_channels()
                    })

            # ---------------- REQUEST ACCOUNT ----------------
            elif msg_type == "request_account":
                req_uid = frame.get("uid", "").strip()
                req_pw = frame.get("password", "").strip()
                req_name = frame.get("username", "").strip() or req_uid
                if req_uid and req_pw:
                    save_user(req_uid, req_name, req_pw, "user")
                    await manager.send_json(websocket, {"t": "sys", "text": "Аккаунт создан! Можете войти."})

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
