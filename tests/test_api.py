import os
import importlib
from pathlib import Path
from fastapi.testclient import TestClient


def client_for(tmp_path: Path):
    os.environ["DATABASE_PATH"] = str(tmp_path / "website.db")
    # Reload modules so each test database path is respected.
    import app.db, app.main, app.bootstrap, app.site
    importlib.reload(app.db); importlib.reload(app.main); importlib.reload(app.bootstrap); importlib.reload(app.site)
    return TestClient(app.site.app)


def test_import_health_and_site(tmp_path):
    with client_for(tmp_path) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 200


def test_complete_employee_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("OWNER_BOOTSTRAP_KEY", "test-secret")
    with client_for(tmp_path) as client:
        owner = client.post("/api/bootstrap/owner", headers={"X-Bootstrap-Key": "test-secret"}, json={"username": "owner", "password": "password123"})
        assert owner.status_code == 201
        login = client.post("/api/login", json={"username": "owner", "password": "password123"})
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        invite = client.post("/api/invites", headers=headers, json={"role": "worker"})
        assert invite.status_code == 201
        worker = client.post("/api/register", json={"invite_code": invite.json()["code"], "username": "worker", "password": "password123"})
        assert worker.status_code == 201
        assert client.post("/api/register", json={"invite_code": invite.json()["code"], "username": "worker2", "password": "password123"}).status_code == 400
        form = client.post("/api/forms", headers=headers, json={"name":"Отчёт","description":"Тест","fields":[{"label":"Количество","field_type":"number","required":True}]})
        assert form.status_code == 201
        worker_headers={"Authorization":f"Bearer {worker.json()['access_token']}"}
        form_id=form.json()["id"]
        entry=client.post(f"/api/forms/{form_id}/entries",headers=worker_headers,json={"data":{}})
        assert entry.status_code == 400
        entry=client.post(f"/api/forms/{form_id}/entries",headers=worker_headers,json={"data":{"1":"10"}})
        assert entry.status_code == 201
        entries=client.get(f"/api/forms/{form_id}/entries",headers=headers)
        assert entries.status_code == 200 and len(entries.json())==1
        notifications=client.get("/api/notifications",headers=headers)
        assert notifications.status_code == 200
