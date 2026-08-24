import secrets
import string
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from .db import init_db, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALPHABET = string.ascii_uppercase + string.digits

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Website", version="0.1.0", lifespan=lifespan)

class InviteRequest(BaseModel):
    role: str = Field(default="worker", max_length=50)

class RegisterRequest(BaseModel):
    invite_code: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    username: str
    password: str

def generate_code():
    raw = ''.join(secrets.choice(ALPHABET) for _ in range(16))
    return '-'.join(raw[i:i+4] for i in range(0, 16, 4))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/invites", status_code=status.HTTP_201_CREATED)
def create_invite(data: InviteRequest):
    # Admin authentication will be connected before exposing this endpoint publicly.
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
            cur = db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (data.username, pwd_context.hash(data.password), invite["role"]),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username is already taken")
        updated = db.execute(
            "UPDATE invite_keys SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_by IS NULL",
            (cur.lastrowid, invite["id"]),
        )
        if updated.rowcount != 1:
            raise HTTPException(409, "Invitation was used by another registration")
        return {"id": cur.lastrowid, "username": data.username, "role": invite["role"]}

@app.post("/api/login")
def login(data: LoginRequest):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (data.username,)).fetchone()
        if not user or not user["is_active"] or not pwd_context.verify(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        # Session/token issuance will be added with the access-control layer.
        return {"id": user["id"], "username": user["username"], "role": user["role"]}
