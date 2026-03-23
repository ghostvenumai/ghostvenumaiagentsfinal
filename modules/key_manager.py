# modules/key_manager.py — GhostVenumAI Enterprise
# Verschlüsselter API-Key-Vault (ISO 27001 A.10, BSI CON.1)
# AES-256-GCM + PBKDF2-HMAC-SHA256 (600.000 Iterationen, NIST 2024)

import os
import json
import base64
import hashlib
import secrets
import getpass
from typing import Optional, Dict, Any
from Crypto.Cipher import AES

VAULT_PATH   = "config.vault"          # Verschlüsselter Key-Speicher
VAULT_META   = "config.vault.meta"     # Metadaten (Salt, Iterationen, Version)
SALT_BYTES   = 32
KEY_BYTES    = 32                      # AES-256
NONCE_BYTES  = 16                      # GCM Nonce
PBKDF2_ITER  = 600_000                 # NIST SP 800-132 (2024)
VAULT_VER    = "1.0"

_vault_cache: Optional[Dict[str, str]] = None  # In-Memory Cache (Laufzeit)


# ── Schlüsselableitung ──────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER, KEY_BYTES)


# ── Vault-Verschlüsselung ───────────────────────────────────────────────────────

def _encrypt(plaintext: bytes, key: bytes) -> Dict[str, str]:
    nonce  = secrets.token_bytes(NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
        "tag":   base64.b64encode(tag).decode(),
    }


def _decrypt(blob: Dict[str, str], key: bytes) -> bytes:
    nonce  = base64.b64decode(blob["nonce"])
    ct     = base64.b64decode(blob["ct"])
    tag    = base64.b64decode(blob["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)   # raises ValueError on tamper


# ── Vault erstellen / öffnen ───────────────────────────────────────────────────

def create_vault(password: str, keys: Dict[str, str]) -> None:
    """Erstellt einen neuen verschlüsselten Vault mit den angegebenen Keys."""
    salt = secrets.token_bytes(SALT_BYTES)
    key  = _derive_key(password, salt)

    plaintext = json.dumps(keys, ensure_ascii=False).encode("utf-8")
    blob      = _encrypt(plaintext, key)

    meta = {
        "version":   VAULT_VER,
        "salt":      base64.b64encode(salt).decode(),
        "pbkdf2_iter": PBKDF2_ITER,
        "algo":      "AES-256-GCM",
    }

    with open(VAULT_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    with open(VAULT_PATH, "w", encoding="utf-8") as f:
        json.dump(blob, f, indent=2)

    # Berechtigungen einschränken (Unix: owner-only read/write)
    try:
        os.chmod(VAULT_PATH, 0o600)
        os.chmod(VAULT_META, 0o600)
    except Exception:
        pass


def open_vault(password: str) -> Dict[str, str]:
    """Öffnet und entschlüsselt den Vault. Gibt Key-Dict zurück."""
    if not os.path.exists(VAULT_PATH) or not os.path.exists(VAULT_META):
        raise FileNotFoundError("Vault nicht gefunden. Bitte vault_init() ausführen.")

    with open(VAULT_META, "r", encoding="utf-8") as f:
        meta = json.load(f)

    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        blob = json.load(f)

    salt = base64.b64decode(meta["salt"])
    key  = _derive_key(password, salt)

    try:
        plaintext = _decrypt(blob, key)
    except (ValueError, KeyError) as e:
        raise PermissionError(f"Vault-Entschlüsselung fehlgeschlagen (falsches Passwort oder Tampering): {e}")

    return json.loads(plaintext.decode("utf-8"))


def update_vault(password: str, updates: Dict[str, str]) -> None:
    """Fügt Keys hinzu oder aktualisiert bestehende im Vault."""
    existing = open_vault(password)
    existing.update(updates)
    create_vault(password, existing)


# ── Laufzeit-Schlüsselzugriff ─────────────────────────────────────────────────

def load_keys_to_env(password: str) -> None:
    """
    Entschlüsselt Vault und setzt API-Keys als Umgebungsvariablen.
    Keys verlassen den Prozess nicht (kein Schreiben in Dateien).
    """
    global _vault_cache
    keys = open_vault(password)
    _vault_cache = keys
    for env_name, value in keys.items():
        os.environ[env_name] = value


def get_key(name: str) -> Optional[str]:
    """
    Gibt einen Key zurück.
    Reihenfolge: Umgebungsvariable → Vault-Cache → None
    """
    val = os.environ.get(name)
    if val:
        return val
    if _vault_cache:
        return _vault_cache.get(name)
    return None


def get_anthropic_key() -> Optional[str]:
    return (
        get_key("ANTHROPIC_API_KEY") or
        get_key("anthropic_key")
    )


def get_openai_key() -> Optional[str]:
    return (
        get_key("OPENAI_API_KEY") or
        get_key("openai_key")
    )


# ── Migration: config.json → Vault ────────────────────────────────────────────

def migrate_from_config(config_path: str = "config.json") -> bool:
    """
    Migriert Klartext-Keys aus config.json in den verschlüsselten Vault.
    Entfernt Keys aus config.json nach erfolgreicher Migration.
    """
    if not os.path.exists(config_path):
        return False

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    key_fields = ["openai_key", "anthropic_key", "ssh_password"]
    keys_to_migrate = {k: v for k, v in cfg.items() if k in key_fields and v}

    if not keys_to_migrate:
        print("[KeyManager] Keine Klartext-Keys in config.json gefunden.")
        return False

    print(f"[KeyManager] Migriere {len(keys_to_migrate)} Key(s) in verschlüsselten Vault...")
    print("[KeyManager] Vault-Passwort festlegen (mindestens 12 Zeichen empfohlen):")

    try:
        pw1 = getpass.getpass("  Vault-Passwort: ")
        pw2 = getpass.getpass("  Wiederholen:    ")
    except Exception:
        print("[KeyManager] Passworteingabe fehlgeschlagen.")
        return False

    if pw1 != pw2:
        print("[KeyManager] Passwörter stimmen nicht überein.")
        return False

    if len(pw1) < 8:
        print("[KeyManager] Passwort zu kurz (min. 8 Zeichen).")
        return False

    # Vault erstellen
    vault_keys = {
        "ANTHROPIC_API_KEY": keys_to_migrate.get("anthropic_key", ""),
        "OPENAI_API_KEY":    keys_to_migrate.get("openai_key", ""),
    }
    vault_keys = {k: v for k, v in vault_keys.items() if v}

    if os.path.exists(VAULT_PATH):
        existing = open_vault(pw1)
        existing.update(vault_keys)
        create_vault(pw1, existing)
    else:
        create_vault(pw1, vault_keys)

    # Keys aus config.json entfernen
    for field in key_fields:
        cfg.pop(field, None)

    cfg["vault_enabled"] = True

    tmp = config_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, config_path)

    print("[KeyManager] ✅ Migration abgeschlossen. Keys sicher im Vault gespeichert.")
    print(f"[KeyManager] Vault: {VAULT_PATH}")
    print("[KeyManager] Starte GhostVenum mit: VAULT_PASSWORD=<pw> python main.py")
    return True


# ── Vault-Status ───────────────────────────────────────────────────────────────

def vault_status() -> Dict[str, Any]:
    return {
        "vault_exists": os.path.exists(VAULT_PATH),
        "meta_exists":  os.path.exists(VAULT_META),
        "cache_loaded": _vault_cache is not None,
        "env_anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "env_openai":    bool(os.environ.get("OPENAI_API_KEY")),
        "vault_path":    VAULT_PATH,
        "algo":          "AES-256-GCM / PBKDF2-HMAC-SHA256",
        "pbkdf2_iter":   PBKDF2_ITER,
    }


# ── CLI ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

    if cmd == "migrate":
        migrate_from_config()
    elif cmd == "status":
        import json as _json
        print(_json.dumps(vault_status(), indent=2))
    elif cmd == "add":
        if len(sys.argv) < 4:
            print("Usage: key_manager.py add KEY_NAME KEY_VALUE")
            sys.exit(1)
        pw = getpass.getpass("Vault-Passwort: ")
        update_vault(pw, {sys.argv[2]: sys.argv[3]})
        print(f"✅ Key '{sys.argv[2]}' gespeichert.")
    else:
        print("Befehle: migrate | status | add KEY_NAME KEY_VALUE")
