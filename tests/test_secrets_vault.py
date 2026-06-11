# tests/test_secrets_vault.py
# Regressionstests für die Vault-Anbindung der Web-API (Punkt 2):
# Secrets (API-Keys, SMTP-Passwort) werden verschlüsselt im Vault gespeichert
# und nicht mehr im Klartext in config.json.
import importlib
import json
import os
import sys

import pytest

pytest.importorskip("flask")
pytest.importorskip("Crypto")  # pycryptodome

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Isoliertes Arbeitsverzeichnis + gesetztes VAULT_PASSWORD; liefert (app, key_manager)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(REPO_ROOT)
    monkeypatch.setenv("VAULT_PASSWORD", "vault-test-pass-123")
    # Keys nicht aus der echten Umgebung erben
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    for mod in [m for m in list(sys.modules) if m == "app" or m.startswith("modules")]:
        sys.modules.pop(mod, None)
    import app as gva
    from modules import key_manager
    return gva, key_manager


def _config_raw(tmp_path_cwd="."):
    with open(os.path.join(tmp_path_cwd, "config.json"), "r", encoding="utf-8") as f:
        return f.read()


def _auth_headers(gva):
    """Legt einen Admin an, loggt ein und liefert die Auth-Header.
    Seit PR #1 sind /api/config & /api/alerts/smtp RBAC-geschützt."""
    from modules import rbac
    if "admin" not in rbac._load_users():
        rbac.create_user("admin", "Sup3rSecret!", "admin", created_by="test")
    client = gva.app.test_client()
    res = client.post("/api/login", json={"username": "admin", "password": "Sup3rSecret!"})
    return {"X-Session-Token": res.get_json()["token"]}


def test_key_manager_round_trip(env):
    _, km = env
    assert km.vault_available() is True
    km.store_secret("ANTHROPIC_API_KEY", "sk-ant-secret-xyz")
    # Sofort lesbar (Cache/Env) ...
    assert km.get_secret("ANTHROPIC_API_KEY") == "sk-ant-secret-xyz"
    # ... und persistent: frisch aus dem Vault entschlüsseln
    assert km.open_vault("vault-test-pass-123")["ANTHROPIC_API_KEY"] == "sk-ant-secret-xyz"


def test_api_key_goes_to_vault_not_config(env):
    gva, km = env
    headers = _auth_headers(gva)
    client = gva.app.test_client()
    res = client.post("/api/config", json={"anthropic_key": "sk-ant-TOPSECRET"}, headers=headers)
    assert res.status_code == 200

    raw = _config_raw()
    assert "sk-ant-TOPSECRET" not in raw          # nicht im Klartext in config.json
    assert "anthropic_key" not in json.loads(raw)  # Feld gar nicht persistiert
    assert km.get_secret("ANTHROPIC_API_KEY") == "sk-ant-TOPSECRET"  # aber im Vault


def test_smtp_password_goes_to_vault_not_config(env):
    gva, km = env
    headers = _auth_headers(gva)
    client = gva.app.test_client()
    res = client.post("/api/alerts/smtp", json={
        "host": "smtp.example.com", "port": 587, "user": "alerts@example.com",
        "from": "alerts@example.com", "to": "soc@example.com",
        "password": "smtp-TOPSECRET",
    }, headers=headers)
    assert res.status_code == 200

    cfg = json.loads(_config_raw())
    smtp = cfg["enterprise"]["notifications"]["smtp"]
    assert "password" not in smtp                 # kein Klartext-Passwort
    assert smtp.get("password_in_vault") is True
    assert "smtp-TOPSECRET" not in _config_raw()
    assert km.get_secret("SMTP_PASSWORD") == "smtp-TOPSECRET"


def test_alerting_reads_smtp_password_from_vault(env):
    gva, km = env
    km.store_secret("SMTP_PASSWORD", "from-vault-pw")
    # config.json mit SMTP-Block ohne Passwort
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump({"enterprise": {"notifications": {"smtp": {
            "host": "smtp.example.com", "user": "u@example.com", "to": "x@example.com",
        }}}}, f)
    from modules import alerting
    smtp = alerting._load_smtp_config()
    assert smtp["password"] == "from-vault-pw"


def test_fallback_without_vault_warns_but_works(env, monkeypatch):
    gva, _ = env
    headers = _auth_headers(gva)  # Login funktioniert ohne Vault (Argon2)
    monkeypatch.delenv("VAULT_PASSWORD", raising=False)  # Vault gesperrt
    client = gva.app.test_client()
    res = client.post("/api/config", json={"openai_key": "sk-legacy"}, headers=headers)
    assert res.status_code == 200
    # Ohne Vault: Legacy-Verhalten (Klartext), aber kein Absturz
    assert json.loads(_config_raw()).get("openai_key") == "sk-legacy"
