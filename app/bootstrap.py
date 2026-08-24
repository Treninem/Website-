import os
import sqlite3
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from .db import get_db

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class BootstrapOwnerRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)

@router.post("/api/bootstrap/owner", status_code=status.HTTP_201_CREATED)
def bootstrap_owner(data: BootstrapOwnerRequest, x_bootstrap_key: str | None = Header(default=None)):
    configured = os.getenv("OWNER_BOOTSTRAP_KEY")
    if not configured or x_bootstrap_key != configured:
        raise HTTPException(status_code=403, detail="Bootstrap is not authorized")
    with get_db() as db:
        exists = db.execute("SELECT id FROM users WHERE role = 'owner' LIMIT 1").fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Owner account already exists")
        try:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'owner')",
                (data.username, pwd_context.hash(data.password)),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username is already taken")
    return {"id": cur.lastrowid, "username": data.username, "role": "owner"}
