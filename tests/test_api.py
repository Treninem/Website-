import os
from pathlib import Path
from fastapi.testclient import TestClient


def client_for(tmp_path: Path):
    os.environ["DATABASE_PATH"] = str(tmp_path / "website.db")
    from app.site import app
    return TestClient(app)


def test_import_and_health(tmp_path: Path):
    with client_for(tmp_path) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_invite_is_owner_protected(tmp_path: Path):
    with client_for(tmp_path) as client:
        response = client.post("/api/invites", json={"role": "worker"})
        assert response.status_code == 401


def test_owner_bootstrap_and_invite_flow(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OWNER_BOOTSTRAP_KEY", "test-secret")
    with client_for(tmp_path) as client:
        owner = client.post("/api/bootstrap/owner", headers={"X-Bootstrap-Key": "test-secret"}, json={"username": "owner", "password": "password123"})
        assert owner.status_code == 201
        login = client.post("/api/login", json={"username": "owner", "password": "password123"})
        assert login.status_code == 200
        token = login.json()["access_token"]
        invite = client.post("/api/invites", headers={"Authorization": f"Bearer {token}"}, json={"role": "worker"})
        assert invite.status_code == 201
        registration = client.post("/api/register", json={"invite_code": invite.json()["code"], "username": "worker", "password": "password123"})
        assert registration.status_code == 201
        repeated = client.post("/api/register", json={"invite_code": invite.json()["code"], "username": "worker2", "password": "password123"})
        assert repeated.status_code == 400
