from datetime import timedelta

from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app
from app.models import BrowserSession
from app.security.crypto import seal
from app.util import utcnow


def test_missing_session_is_rejected():
    with TestClient(app) as client:
        health = client.get("/api/v1/system/health")
        assert health.status_code == 200
        assert health.json()["database"] is True
        denied = client.get("/api/v1/identities")
        assert denied.status_code == 401


def test_cookie_mutation_requires_csrf_and_role():
    session_id = "session-test"
    csrf = "csrf-test"
    db = SessionLocal()
    now = utcnow()
    db.add(
        BrowserSession(
            id=session_id,
            subject="subject",
            username="elena.vasquez",
            email="elena.vasquez@northstar.example",
            roles=["identitygate-user"],
            access_token=seal("test-session-secret", "access"),
            refresh_token=seal("test-session-secret", "refresh"),
            id_token=seal("test-session-secret", "id"),
            access_expires_at=now + timedelta(minutes=5),
            csrf_token=csrf,
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )
    )
    db.commit()
    db.close()
    with TestClient(app) as client:
        client.cookies.set("ig_session", session_id)
        missing = client.post("/api/v1/lifecycle/leavers", json={"employee_number": "NS-10001"})
        assert missing.status_code == 403
        assert "CSRF" in missing.json()["detail"]
        forbidden = client.post(
            "/api/v1/lifecycle/leavers",
            json={"employee_number": "NS-10001"},
            headers={"X-CSRF-Token": csrf},
        )
        assert forbidden.status_code == 403
        assert "not allowed" in forbidden.json()["detail"]
