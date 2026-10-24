from fastapi.testclient import TestClient

from commandcompass.ui.app import create_app


def test_index():
    client = TestClient(create_app())
    r = client.get("/")
    assert r.status_code == 200
    assert "CommandCompass" in r.text


def test_api_analyze():
    client = TestClient(create_app())
    r = client.post("/api/analyze", json={"command": "git status", "shell": "auto"})
    assert r.status_code == 200
    data = r.json()
    assert data["result"]["assessment"] == "informational"


def test_api_rules():
    client = TestClient(create_app())
    r = client.get("/api/rules")
    assert r.status_code == 200
    assert "rules" in r.json()


def test_security_headers():
    client = TestClient(create_app())
    r = client.get("/")
    assert r.headers.get("X-Frame-Options") == "DENY"
