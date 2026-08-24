import os
from pathlib import Path


def test_import_and_health(tmp_path: Path):
    os.environ["DATABASE_PATH"] = str(tmp_path / "website.db")
    from fastapi.testclient import TestClient
    from app.site import app

    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_invite_is_owner_protected(tmp_path: Path):
    os.environ["DATABASE_PATH"] = str(tmp_path / "website.db")
    from fastapi.testclient import TestClient
    from app.site import app

    with TestClient(app) as client:
        response = client.post("/api/invites", json={"role": "worker"})
        assert response.status_code == 401
