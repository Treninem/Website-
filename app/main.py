import hashlib
import secrets
import string
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from .db import init_db, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALPHABET = string.ascii_uppercase + string.digits
SESSION_DAYS = 30

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Website", version="0.2.0", lifespan=lifespan)

class InviteRequest(BaseModel):
    role: str = Field(default="worker", max_length=50)

class RegisterRequest(BaseModel):
    invite_code: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)

class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    current_password: str = Field(min_length=1, max_length=128)

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

def generate_code():
    raw = ''.join(secrets.choice(ALPHABET) for _ in range(16))
    return '-'.join(raw[i:i+4] for i in range(0, 16, 4))

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def create_session(db, user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    db.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (hash_token(token), user_id, expires))
    return token

def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("""
            SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.is_active = 1
        """, (hash_token(token), now)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    return dict(row)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/invites", status_code=status.HTTP_201_CREATED)
def create_invite(data: InviteRequest):
    # Temporary bootstrap endpoint; admin authorization will protect it in the owner panel.
    with get_db() as db:
        for _ in range(20):
            code = generate_code()
            try:
                db.execute("INSERT INTO invite_keys (code, role) VALUES (?, ?)", (code, data.role))
                return {"code": code, "role": data.role, "uses": 1}
            except sqlite3.IntegrityError:
                continue
    raise HTTPException(500, "Could not generate a unique invitation code")

@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    code = data.invite_code.strip().upper()
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        invite = db.execute("SELECT * FROM invite_keys WHERE code = ?", (code,)).fetchone()
        if not invite or invite["used_by"] is not None:
            raise HTTPException(400, "Invalid or already used invitation code")
        try:
            cur = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (data.username, pwd_context.hash(data.password), invite["role"]))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username is already taken")
        updated = db.execute("UPDATE invite_keys SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_by IS NULL", (cur.lastrowid, invite["id"]))
        if updated.rowcount != 1:
            raise HTTPException(409, "Invitation was used by another registration")
        token = create_session(db, cur.lastrowid)
        return {"id": cur.lastrowid, "username": data.username, "role": invite["role"], "access_token": token, "token_type": "bearer"}

@app.post("/api/login")
def login(data: LoginRequest):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
        if not user or not user["is_active"] or not pwd_context.verify(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        token = create_session(db, user["id"])
        return {"access_token": token, "token_type": "bearer", "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

@app.get("/api/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "username": user["username"], "role": user["role"]}

@app.put("/api/me/username")
def change_username(data: ChangeUsernameRequest, user=Depends(get_current_user)):
    if not pwd_context.verify(data.current_password, user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    with get_db() as db:
        try:
            db.execute("UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (data.new_username, user["id"]))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username is already taken")
    return {"username": data.new_username}

@app.put("/api/me/password")
def change_password(data: ChangePasswordRequest, user=Depends(get_current_user)):
    if not pwd_context.verify(data.current_password, user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    with get_db() as db:
        db.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (pwd_context.hash(data.new_password), user["id"]))
        # Keep the current request's token valid only until logout in this initial version.
        db.execute("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ?", (user["id"],))
    return {"message": "Password changed. Please sign in again on all devices."}

@app.post("/api/logout")
def logout(authorization: str | None = Header(default=None), user=Depends(get_current_user)):
    token = authorization.removeprefix("Bearer ").strip()
    with get_db() as db:
        db.execute("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?", (hash_token(token),))
    return {"message": "Logged out"}
