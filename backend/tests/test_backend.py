import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.db.database import Base, get_db
from app.core.security import create_access_token
from app.db.seed import init_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    init_db(db)
    db.close()
    yield

client = TestClient(app)

def get_auth_header(username="analyst", role="analyst"):
    token = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {token}"}

def test_login_success():
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "analyst123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "analyst"

def test_login_invalid_password():
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "wrongpassword"}
    )
    assert response.status_code == 401

def test_ingest_synthetic_brute_force():
    headers = get_auth_header()
    response = client.post("/api/v1/logs/synthetic/ingest/brute_force", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "sha256_hash" in data
    assert data["line_count"] > 0

    # Verify alerts created
    alerts_resp = client.get("/api/v1/alerts", headers=headers)
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 1

def test_evidence_integrity_verification():
    headers = get_auth_header()
    # First ingest synthetic dataset
    ingest_resp = client.post("/api/v1/logs/synthetic/ingest/suspicious_process", headers=headers)
    evidence_id = ingest_resp.json()["id"]

    # Trigger verification
    verify_resp = client.post(f"/api/v1/evidence/{evidence_id}/verify", headers=headers)
    assert verify_resp.status_code == 200
    res = verify_resp.json()
    assert res["is_verified"] is True
    assert res["status"] == "INTEGRITY_VERIFIED"

def test_incident_creation_and_notes():
    headers = get_auth_header()
    # Ingest scenario
    client.post("/api/v1/logs/synthetic/ingest/privilege_escalation", headers=headers)

    # Get auto-correlated incidents
    inc_resp = client.get("/api/v1/incidents", headers=headers)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) >= 1
    incident_id = incidents[0]["id"]

    # Add analyst note
    note_resp = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"content": "Investigated backup account privilege escalation. Confirmed unauthorized group add."},
        headers=headers
    )
    assert note_resp.status_code == 200
    assert note_resp.json()["content"].startswith("Investigated backup account")

def test_report_generation():
    headers = get_auth_header()
    client.post("/api/v1/logs/synthetic/ingest/brute_force", headers=headers)
    incidents = client.get("/api/v1/incidents", headers=headers).json()
    assert len(incidents) >= 1
    incident_id = incidents[0]["id"]

    gen_resp = client.post(f"/api/v1/reports/generate/{incident_id}", headers=headers)
    assert gen_resp.status_code == 200
    report_data = gen_resp.json()
    assert report_data["file_format"] == "PDF"

def test_benchmark_endpoint():
    headers = get_auth_header()
    resp = client.post("/api/v1/benchmark/run", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "precision" in data
    assert "recall" in data
    assert data["precision"] > 0
