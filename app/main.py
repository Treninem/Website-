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
ROLES = {"owner", "admin", "manager", "worker"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Website", version="0.5.0", lifespan=lifespan)

class InviteRequest(BaseModel): role: str = Field(default="worker", max_length=50)
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
class ChangeRoleRequest(BaseModel): role: str = Field(max_length=50)
class WorkEntryRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=5000)

def generate_code():
    raw = ''.join(secrets.choice(ALPHABET) for _ in range(16))
    return '-'.join(raw[i:i+4] for i in range(0, 16, 4))
def hash_token(token): return hashlib.sha256(token.encode()).hexdigest()
def create_session(db, user_id):
    token = secrets.token_urlsafe(48)
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    db.execute("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)",(hash_token(token),user_id,expires))
    return token
def audit(db, actor_id, action, target_type=None, target_id=None):
    db.execute("INSERT INTO audit_log (actor_user_id,action,target_type,target_id) VALUES (?,?,?,?)",(actor_id,action,target_type,str(target_id) if target_id is not None else None))

def get_current_user(authorization: str|None=Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    with get_db() as db:
        row=db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.is_active=1",(hash_token(authorization[7:].strip()),datetime.now(timezone.utc).isoformat())).fetchone()
    if not row: raise HTTPException(401,"Session is invalid or expired")
    return dict(row)
def require_owner(user=Depends(get_current_user)):
    if user["role"]!="owner": raise HTTPException(403,"Owner access required")
    return user
def require_admin(user=Depends(get_current_user)):
    if user["role"] not in {"owner","admin"}: raise HTTPException(403,"Administrative access required")
    return user
def require_manager(user=Depends(get_current_user)):
    if user["role"] not in {"owner","admin","manager"}: raise HTTPException(403,"Manager access required")
    return user

@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/api/invites",status_code=201)
def create_invite(data:InviteRequest,owner=Depends(require_owner)):
    if data.role not in ROLES or data.role=="owner": raise HTTPException(400,"Invalid role for invitation")
    with get_db() as db:
        for _ in range(20):
            try:
                code=generate_code(); cur=db.execute("INSERT INTO invite_keys (code,role) VALUES (?,?)",(code,data.role))
                audit(db,owner["id"],"invite.created","invite",cur.lastrowid)
                return {"id":cur.lastrowid,"code":code,"role":data.role,"uses":1}
            except sqlite3.IntegrityError: continue
    raise HTTPException(500,"Could not generate unique invitation code")
@app.get("/api/invites")
def list_invites(owner=Depends(require_owner)):
    with get_db() as db: rows=db.execute("SELECT id,code,role,created_at,used_at,CASE WHEN used_by IS NULL THEN 0 ELSE 1 END is_used FROM invite_keys ORDER BY id DESC").fetchall()
    return [dict(x) for x in rows]
@app.post("/api/register",status_code=201)
def register(data:RegisterRequest):
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE"); invite=db.execute("SELECT * FROM invite_keys WHERE code=?",(data.invite_code.strip().upper(),)).fetchone()
        if not invite or invite["used_by"] is not None: raise HTTPException(400,"Invalid or already used invitation code")
        try: cur=db.execute("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",(data.username,pwd_context.hash(data.password),invite["role"]))
        except sqlite3.IntegrityError: raise HTTPException(409,"Username is already taken")
        if db.execute("UPDATE invite_keys SET used_by=?,used_at=CURRENT_TIMESTAMP WHERE id=? AND used_by IS NULL",(cur.lastrowid,invite["id"])).rowcount!=1: raise HTTPException(409,"Invitation was used by another registration")
        audit(db,cur.lastrowid,"account.registered","user",cur.lastrowid); token=create_session(db,cur.lastrowid)
        return {"id":cur.lastrowid,"username":data.username,"role":invite["role"],"access_token":token,"token_type":"bearer"}
@app.post("/api/login")
def login(data:LoginRequest):
    with get_db() as db:
        u=db.execute("SELECT * FROM users WHERE username=?",(data.username,)).fetchone()
        if not u or not u["is_active"] or not pwd_context.verify(data.password,u["password_hash"]): raise HTTPException(401,"Invalid username or password")
        token=create_session(db,u["id"]); audit(db,u["id"],"account.login","user",u["id"])
        return {"access_token":token,"token_type":"bearer","user":{"id":u["id"],"username":u["username"],"role":u["role"]}}
@app.get("/api/me")
def me(user=Depends(get_current_user)): return {"id":user["id"],"username":user["username"],"role":user["role"]}
@app.put("/api/me/username")
def change_username(data:ChangeUsernameRequest,user=Depends(get_current_user)):
    if not pwd_context.verify(data.current_password,user["password_hash"]): raise HTTPException(400,"Current password is incorrect")
    with get_db() as db:
        try: db.execute("UPDATE users SET username=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(data.new_username,user["id"]))
        except sqlite3.IntegrityError: raise HTTPException(409,"Username is already taken")
        audit(db,user["id"],"account.username_changed","user",user["id"])
    return {"username":data.new_username}
@app.put("/api/me/password")
def change_password(data:ChangePasswordRequest,user=Depends(get_current_user)):
    if not pwd_context.verify(data.current_password,user["password_hash"]): raise HTTPException(400,"Current password is incorrect")
    with get_db() as db:
        db.execute("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(pwd_context.hash(data.new_password),user["id"]))
        db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=?",(user["id"],)); audit(db,user["id"],"account.password_changed","user",user["id"])
    return {"message":"Password changed. Please sign in again."}
@app.get("/api/admin/users")
def list_users(admin=Depends(require_admin)):
    with get_db() as db: rows=db.execute("SELECT id,username,role,is_active,created_at FROM users ORDER BY id DESC").fetchall()
    return [dict(x) for x in rows]
@app.put("/api/admin/users/{user_id}/role")
def change_role(user_id:int,data:ChangeRoleRequest,owner=Depends(require_owner)):
    if data.role not in ROLES or data.role=="owner": raise HTTPException(400,"Invalid role")
    with get_db() as db:
        if not db.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone(): raise HTTPException(404,"User not found")
        db.execute("UPDATE users SET role=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(data.role,user_id)); audit(db,owner["id"],"user.role_changed","user",user_id)
    return {"id":user_id,"role":data.role}
@app.put("/api/admin/users/{user_id}/active")
def toggle_user(user_id:int,active:bool,admin=Depends(require_admin)):
    if user_id==admin["id"]: raise HTTPException(400,"You cannot disable your own account")
    with get_db() as db:
        if not db.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone(): raise HTTPException(404,"User not found")
        db.execute("UPDATE users SET is_active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(1 if active else 0,user_id))
        if not active: db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=?",(user_id,))
        audit(db,admin["id"],"user.activated" if active else "user.deactivated","user",user_id)
    return {"id":user_id,"is_active":active}
@app.post("/api/work-entries",status_code=201)
def create_work_entry(data:WorkEntryRequest,user=Depends(get_current_user)):
    with get_db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS work_entries (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,value TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))")
        cur=db.execute("INSERT INTO work_entries (user_id,title,value) VALUES (?,?,?)",(user["id"],data.title,data.value)); audit(db,user["id"],"work_entry.created","work_entry",cur.lastrowid)
        return {"id":cur.lastrowid,"title":data.title,"value":data.value}
@app.get("/api/work-entries")
def list_work_entries(user=Depends(get_current_user)):
    with get_db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS work_entries (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,value TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))")
        if user["role"] in {"owner","admin","manager"}: rows=db.execute("SELECT w.*,u.username FROM work_entries w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC").fetchall()
        else: rows=db.execute("SELECT w.*,u.username FROM work_entries w JOIN users u ON u.id=w.user_id WHERE w.user_id=? ORDER BY w.id DESC",(user["id"],)).fetchall()
    return [dict(x) for x in rows]
@app.post("/api/logout")
def logout(authorization:str|None=Header(default=None),user=Depends(get_current_user)):
    with get_db() as db: db.execute("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=?",(hash_token(authorization[7:].strip()),)); audit(db,user["id"],"account.logout","user",user["id"])
    return {"message":"Logged out"}
