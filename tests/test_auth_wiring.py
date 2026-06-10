# tests/test_auth_wiring.py
# Regressionstests für die RBAC-Anbindung an die Web-API (app.py).
# Stellt sicher, dass sensible Routen ohne gültige Session/Berechtigung
# gesperrt sind und mit passenden Rechten funktionieren.
import os
import sys

import pytest

pytest.importorskip("flask")
pytest.importorskip("argon2")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Flask-Test-Client mit isoliertem Arbeitsverzeichnis (eigene config/logs)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(REPO_ROOT)
    # Frischer Import, damit Module relativ zum tmp-cwd arbeiten
    for mod in [m for m in list(sys.modules) if m == "app" or m.startswith("modules")]:
        sys.modules.pop(mod, None)
    import app as gva
    return gva.app.test_client()


def _login(client, username, password):
    res = client.post("/api/login", json={"username": username, "password": password})
    return res


def test_protected_routes_reject_without_token(client):
    for method, path in [
        ("get", "/api/sysinfo"),
        ("post", "/api/scan"),
        ("get", "/api/users"),
        ("get", "/api/targets"),
        ("post", "/api/config"),
    ]:
        res = getattr(client, method)(path, json={})
        assert res.status_code == 401, f"{method} {path} sollte 401 liefern"


def test_admin_can_access_after_login(client):
    from modules import rbac
    rbac.create_user("admin", "Sup3rSecret!", "admin", created_by="test")

    res = _login(client, "admin", "Sup3rSecret!")
    assert res.status_code == 200
    token = res.get_json()["token"]
    headers = {"X-Session-Token": token}

    assert client.get("/api/sysinfo", headers=headers).status_code == 200
    assert client.get("/api/users", headers=headers).status_code == 200

    who = client.get("/api/whoami", headers=headers).get_json()
    assert who["authenticated"] is True
    assert who["role"] == "admin"


def test_viewer_lacks_user_management_permission(client):
    from modules import rbac
    rbac.create_user("bob", "Sup3rSecret!", "viewer", created_by="test")

    token = _login(client, "bob", "Sup3rSecret!").get_json()["token"]
    headers = {"X-Session-Token": token}

    # viewer darf history sehen ...
    assert client.get("/api/targets", headers=headers).status_code == 200
    # ... aber keine Benutzer verwalten
    assert client.get("/api/users", headers=headers).status_code == 403


def test_invalid_login_is_rejected(client):
    from modules import rbac
    rbac.create_user("admin", "Sup3rSecret!", "admin", created_by="test")
    assert _login(client, "admin", "falsch").status_code == 401
    assert _login(client, "ghost", "egal").status_code == 401


def test_sse_token_via_query_param(client):
    """EventSource kann keine Header setzen — Token muss als ?token=… greifen."""
    from modules import rbac
    rbac.create_user("bob", "Sup3rSecret!", "viewer", created_by="test")
    token = _login(client, "bob", "Sup3rSecret!").get_json()["token"]

    # viewer hat kein scan:run -> 403 (Token wurde aber akzeptiert/geprüft)
    res = client.get("/api/agents/stream", query_string={"target": "127.0.0.1", "token": token})
    assert res.status_code == 403
    # ganz ohne Token -> 401
    assert client.get("/api/agents/stream", query_string={"target": "127.0.0.1"}).status_code == 401
