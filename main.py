import os
import asyncio
import json
import logging
import sqlite3
import time
import uuid
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LanGramServer")

app = FastAPI(title="LanGram Secure Relay Server")

DB_FILE = "server.db"

# Gmail SMTP configuration (optional via environment variables)
GMAIL_SENDER_EMAIL = os.environ.get("GMAIL_SENDER_EMAIL", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uid TEXT PRIMARY KEY,
                username TEXT,
                pass_hash TEXT,
                role TEXT,
                blocked INTEGER DEFAULT 0,
                ban_until INTEGER,
                ban_reason TEXT,
                email TEXT,
                email_verified INTEGER DEFAULT 0,
                last_seen INTEGER
            )
        """)
        try:
            c.execute("ALTER TABLE users ADD COLUMN last_seen INTEGER")
        except Exception:
            pass
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
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_verifications (
                uid TEXT PRIMARY KEY,
                email TEXT,
                code TEXT,
                expires INTEGER,
                verified INTEGER DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS friend_requests (
                id TEXT PRIMARY KEY,
                from_uid TEXT,
                to_uid TEXT,
                status TEXT,
                ts INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS friends (
                user_a TEXT,
                user_b TEXT,
                PRIMARY KEY (user_a, user_b)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT,
                tag TEXT,
                privacy TEXT,
                owner_uid TEXT,
                invite_code TEXT,
                ts INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT,
                uid TEXT,
                PRIMARY KEY (group_id, uid)
            )
        """)
        # Ensure default preset Admin account
        c.execute("""
            INSERT OR REPLACE INTO users (uid, username, pass_hash, role, blocked, ban_until, ban_reason)
            VALUES ('admin', 'Admin', '161120s40000000s', 'admin', 0, NULL, NULL)
        """)
        conn.commit()

init_db()

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

# Helper DB Functions
def get_user(uid: str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT uid, username, pass_hash, role, blocked, ban_until, ban_reason, email, email_verified, last_seen FROM users WHERE uid = ? OR username = ?", (uid, uid))
        return c.fetchone()

def update_last_seen(uid: str):
    now = int(time.time() * 1000)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET last_seen = ? WHERE uid = ?", (now, uid))
        conn.commit()

def get_user_status(uid: str) -> dict:
    is_online = uid in manager.uid_connections and len(manager.uid_connections[uid]) > 0
    u = get_user(uid)
    last_seen = u[9] if u and len(u) > 9 else None
    return {
        "uid": uid,
        "online": is_online,
        "lastSeen": last_seen
    }

def save_user(uid: str, username: str, pass_hash: str, role: str):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO users (uid, username, pass_hash, role, blocked, ban_until, ban_reason)
            VALUES (?, ?, ?, ?, 0, NULL, NULL)
        """, (uid, username, pass_hash, role))
        conn.commit()

def save_message(msg_id: str, sender_uid: str, sender_name: str, channel: str, to_uid: str, payload_data: str, ts: int):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT OR IGNORE INTO messages (id, sender_uid, sender_name, channel, to_uid, payload_data, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (msg_id, sender_uid, sender_name, channel, to_uid, payload_data, ts))
        conn.commit()

def send_gmail_otp_sync(recipient_email: str, code: str) -> tuple[bool, str]:
    """Sends OTP code via Gmail SMTP trying port 587 (STARTTLS) and fallback port 465 (SSL)."""
    sender = os.environ.get("GMAIL_SENDER_EMAIL", "").strip()
    password = os.environ.get("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()

    if not sender or not password:
        msg = f"Внимание: переменные GMAIL_SENDER_EMAIL или GMAIL_APP_PASSWORD не настроены в Render! (Тестовый код: {code})"
        logger.warning(msg)
        return (False, msg)

    body = f"Ваш код подтверждения личности для LanGram: {code}\nКод действителен 10 минут."
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = 'Код подтверждения LanGram'
    msg['From'] = sender
    msg['To'] = recipient_email

    # Attempt 1: Port 587 TLS
    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=12) as server:
            server.ehlo()
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, [recipient_email], msg.as_string())
        logger.info(f"SUCCESS: Gmail OTP sent via port 587 to {recipient_email}")
        return (True, "OK")
    except Exception as e1:
        logger.warning(f"Port 587 failed ({e1}), trying port 465 SSL...")

    # Attempt 2: Port 465 SSL
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=12) as server:
            server.login(sender, password)
            server.sendmail(sender, [recipient_email], msg.as_string())
        logger.info(f"SUCCESS: Gmail OTP sent via port 465 to {recipient_email}")
        return (True, "OK")
    except Exception as e2:
        err_msg = f"Ошибка отправки Gmail SMTP: {e2}"
        logger.error(err_msg)
        return (False, err_msg)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "LanGram Relay Server",
        "security": "E2EE AES-256-GCM + ECDH Relay Mode"
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    logger.info("New WebSocket client connected to Render relay!")
    user_uid = None

    try:
        while True:
            text_data = await websocket.receive_text()
            try:
                frame = json.loads(text_data)
            except Exception:
                continue

            msg_type = frame.get("t")

            # ---------------- PING / HEARTBEAT ----------------
            if msg_type == "ping":
                if user_uid:
                    update_last_seen(user_uid)
                await manager.send_json(websocket, {"t": "pong", "ts": int(time.time() * 1000)})

            # ---------------- GET USER STATUS ----------------
            elif msg_type == "get_user_status":
                target_uid = frame.get("target") or user_uid
                if target_uid:
                    status = get_user_status(target_uid)
                    await manager.send_json(websocket, {
                        "t": "user_status",
                        "target": status["uid"],
                        "text": "online" if status["online"] else "offline",
                        "ts": status["lastSeen"]
                    })

            # ---------------- HELLO ----------------
            elif msg_type == "hello":
                client_name = frame.get("from") or "Guest"
                client_uid = frame.get("uid") or "none"
                logger.info(f"CLIENT HELLO: Name='{client_name}', UID='{client_uid}'")
                await manager.send_json(websocket, {"t": "sys", "text": "Сервер LanGram Render на связи!"})

            # ---------------- LOGIN / AUTH ----------------
            elif msg_type == "login":
                uid = frame.get("uid", "").strip()
                pw = frame.get("password", "").strip()
                logger.info(f"INCOMING LOGIN: UID='{uid}'")

                u = get_user(uid)
                if not u:
                    logger.warning(f"LOGIN FAIL: User '{uid}' not found")
                    await manager.send_json(websocket, {"t": "err", "text": "Пользователь не найден"})
                    continue
                
                db_uid, db_name, db_hash, db_role, db_blocked, db_ban_until, db_ban_reason, db_email, db_verified = u

                if db_blocked:
                    await manager.send_json(websocket, {"t": "err", "text": "Аккаунт заблокирован"})
                    continue

                if db_ban_until and db_ban_until > int(time.time() * 1000):
                    await manager.send_json(websocket, {"t": "banned", "banUntil": db_ban_until, "reason": db_ban_reason})
                    continue

                if db_hash != pw:
                    await manager.send_json(websocket, {"t": "err", "text": "Неверный пароль"})
                    continue

                user_uid = db_uid
                manager.register_user(websocket, db_uid)
                logger.info(f"LOGIN SUCCESS: User '{db_uid}' (@{db_name}) logged in")

                token = f"token_{db_uid}_{uuid.uuid4().hex[:8]}"
                await manager.send_json(websocket, {
                    "t": "login_ok",
                    "token": token,
                    "uid": db_uid,
                    "from": db_name,
                    "role": db_role
                })

            # ---------------- REQUEST ACCOUNT (SUBMIT TO ADMIN) ----------------
            elif msg_type in ("request_account", "account_request_create"):
                req_uid = frame.get("uid", "").strip()
                req_pw = frame.get("password", "").strip()
                req_name = frame.get("username", "").strip() or req_uid
                req_id = str(uuid.uuid4())
                now = int(time.time() * 1000)
                if req_uid and req_pw:
                    with sqlite3.connect(DB_FILE) as conn:
                        c = conn.cursor()
                        c.execute("INSERT OR REPLACE INTO account_requests (id, uid, username, pass_hash, ts) VALUES (?, ?, ?, ?, ?)",
                                  (req_id, req_uid, req_name, req_pw, now))
                        conn.commit()
                    logger.info(f"ACCOUNT REQUEST SUBMITTED TO ADMIN: UID='{req_uid}'")
                    await manager.send_json(websocket, {"t": "sys", "text": "Заявка отправлена администратору! Ожидайте одобрения."})

            # ---------------- EMAIL VERIFICATION OTP ----------------
            elif msg_type == "send_email_code":
                email = frame.get("email", "").strip()
                if not user_uid or not email:
                    await manager.send_json(websocket, {"t": "err", "text": "Укажите email"})
                    continue
                code = f"{uuid.uuid4().int % 1000000:06d}"
                expires = int(time.time() * 1000) + 600_000
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("INSERT OR REPLACE INTO email_verifications (uid, email, code, expires, verified) VALUES (?, ?, ?, ?, 0)",
                              (user_uid, email, code, expires))
                    conn.commit()
                success, detail = await asyncio.to_thread(send_gmail_otp_sync, email, code)
                if success:
                    await manager.send_json(websocket, {"t": "sys", "text": f"Код подтверждения отправлен на {email}"})
                else:
                    await manager.send_json(websocket, {"t": "err", "text": detail})

            elif msg_type == "verify_email_code":
                code_input = frame.get("code", "").strip()
                if not user_uid or not code_input:
                    await manager.send_json(websocket, {"t": "err", "text": "Введите код"})
                    continue
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("SELECT email, code, expires FROM email_verifications WHERE uid = ?", (user_uid,))
                    row = c.fetchone()
                    if row and row[1] == code_input and row[2] > int(time.time() * 1000):
                        email = row[0]
                        c.execute("UPDATE email_verifications SET verified = 1 WHERE uid = ?", (user_uid,))
                        c.execute("UPDATE users SET email = ?, email_verified = 1 WHERE uid = ?", (email, user_uid))
                        conn.commit()
                        logger.info(f"EMAIL VERIFIED: User '{user_uid}' -> '{email}'")
                        await manager.send_json(websocket, {"t": "email_verified", "email": email})
                    else:
                        await manager.send_json(websocket, {"t": "err", "text": "Неверный или просроченный код"})

            # ---------------- FRIEND REQUESTS ----------------
            elif msg_type == "friend_request_send":
                target_handle = frame.get("target", "").strip()
                target_user = get_user(target_handle)
                if not target_user:
                    await manager.send_json(websocket, {"t": "err", "text": "Пользователь не найден"})
                    continue
                target_uid = target_user[0]
                req_id = str(uuid.uuid4())
                now = int(time.time() * 1000)
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO friend_requests (id, from_uid, to_uid, status, ts) VALUES (?, ?, ?, 'pending', ?)",
                              (req_id, user_uid, target_uid, now))
                    conn.commit()
                logger.info(f"FRIEND REQUEST: From '{user_uid}' to '{target_uid}'")
                await manager.send_to_uid(target_uid, {
                    "t": "friend_request_incoming",
                    "id": req_id,
                    "fromUid": user_uid,
                    "fromName": get_user(user_uid)[1]
                })
                await manager.send_json(websocket, {"t": "sys", "text": f"Заявка в друзья отправлена {target_handle}"})

            elif msg_type == "friend_request_accept":
                req_id = frame.get("id", "").strip()
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("SELECT from_uid, to_uid FROM friend_requests WHERE id = ?", (req_id,))
                    row = c.fetchone()
                    if row:
                        from_u, to_u = row
                        c.execute("UPDATE friend_requests SET status = 'accepted' WHERE id = ?", (req_id,))
                        c.execute("INSERT OR IGNORE INTO friends (user_a, user_b) VALUES (?, ?)", (from_u, to_u))
                        c.execute("INSERT OR IGNORE INTO friends (user_a, user_b) VALUES (?, ?)", (to_u, from_u))
                        conn.commit()
                        logger.info(f"FRIEND ACCEPTED: '{from_u}' and '{to_u}' are now friends")
                        await manager.send_to_uid(from_u, {"t": "sys", "text": f"Пользователь {to_u} принял заявку в друзья!"})
                        await manager.send_json(websocket, {"t": "sys", "text": "Заявка в друзья принята!"})

            # ---------------- GROUPS (PUBLIC & PRIVATE) ----------------
            elif msg_type == "create_group":
                name = frame.get("name", "").strip()
                tag = frame.get("tag", "").strip()
                privacy = frame.get("privacy", "public").strip() # 'public' or 'private'
                members = frame.get("members") or []
                group_id = str(uuid.uuid4())
                invite_code = uuid.uuid4().hex[:10]
                now = int(time.time() * 1000)

                if name:
                    with sqlite3.connect(DB_FILE) as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO groups (id, name, tag, privacy, owner_uid, invite_code, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                  (group_id, name, tag, privacy, user_uid, invite_code, now))
                        c.execute("INSERT OR IGNORE INTO group_members (group_id, uid) VALUES (?, ?)", (group_id, user_uid))
                        for m_uid in members:
                            c.execute("INSERT OR IGNORE INTO group_members (group_id, uid) VALUES (?, ?)", (group_id, m_uid))
                        conn.commit()
                    logger.info(f"GROUP CREATED: Name='{name}', Tag='@{tag}', Privacy='{privacy}', Invite='{invite_code}'")
                    await manager.send_json(websocket, {
                        "t": "group_created",
                        "groupId": group_id,
                        "name": name,
                        "tag": tag,
                        "privacy": privacy,
                        "inviteLink": f"langram://join/{invite_code}"
                    })

            # ---------------- CHAT MESSAGES ----------------
            elif msg_type == "msg":
                if not user_uid:
                    user_uid = frame.get("uid") or "anonymous"

                sender = get_user(user_uid)
                sender_name = sender[1] if sender else (frame.get("from") or user_uid)

                msg_id = frame.get("id") or str(uuid.uuid4())
                channel = frame.get("channel") or "Чат"
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
                    await manager.send_to_uid(to_uid, msg_frame)
                    await manager.send_to_uid(user_uid, msg_frame)
                else:
                    await manager.broadcast(msg_frame)

    except WebSocketDisconnect:
        logger.info(f"Client '{user_uid}' disconnected")
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
