# modules/report_crypto.py
"""
ReportCrypto — AES-256-GCM Verschlüsselung für GhostVenumAI Reports.

Warum AES-256-GCM quantensicher ist:
  - Symmetrische 256-Bit-Schlüssel sind gegen Grover-Algorithmus resistent
    (Grover halbiert effektive Schlüssellänge: 256 Bit → 128 Bit effektiv)
  - 128-Bit effektive Sicherheit gilt als unknackbar auch für Quantencomputer
  - GCM-Modus liefert zusätzlich Authentifizierung (Tampering-Schutz)
  - PBKDF2-HMAC-SHA256 mit 600.000 Iterationen erschwert Brute-Force

Ausgabe pro verschlüsseltem Report:
  ├── report_DATUM.pdf.enc          (verschlüsselte PDF)
  └── report_DATUM.verification.json (Verifikationsdatei für Versicherungen)
       enthält: SHA-256-Hash, Zeitstempel, Metadaten, Verschlüsselungsparameter

Nutzung:
    from modules.report_crypto import encrypt_report, decrypt_report, verify_report

    # Verschlüsseln
    enc_path, veri_path = encrypt_report("report.pdf", password="geheim")

    # Prüfen (ohne zu entschlüsseln)
    ok, info = verify_report(enc_path, veri_path)

    # Entschlüsseln
    out_path = decrypt_report(enc_path, password="geheim", out_path="decrypted.pdf")

Abhängigkeit: pycryptodome  (pip install pycryptodome)
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

# ── Konstanten ────────────────────────────────────────────────────────────────
_SALT_LEN    = 32      # 256 Bit Salt
_KEY_LEN     = 32      # AES-256
_ITERATIONS  = 600_000 # PBKDF2 Iterationen (NIST-Empfehlung 2024)
_NONCE_LEN   = 16      # GCM Nonce
_TAG_LEN     = 16      # GCM Auth-Tag
_VERSION     = "GVA-AES256GCM-v1"


def _require_crypto():
    if not _CRYPTO:
        raise ImportError(
            "pycryptodome ist nicht installiert.\n"
            "Bitte installieren: pip install pycryptodome"
        )


def _derive_key(password: str, salt: bytes) -> bytes:
    """Leitet einen 256-Bit-Schlüssel aus Passwort + Salt ab (PBKDF2-HMAC-SHA256)."""
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen     = _KEY_LEN,
        count     = _ITERATIONS,
        prf       = lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )


def _sha256_file(path: str) -> str:
    """Berechnet den SHA-256-Hash einer Datei."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def encrypt_report(
    pdf_path:  str,
    password:  str,
    out_dir:   str = "",
    metadata:  dict = None,
) -> tuple[str, str]:
    """
    Verschlüsselt einen PDF-Report mit AES-256-GCM.

    Args:
        pdf_path:  Pfad zur PDF-Datei
        password:  Verschlüsselungspasswort
        out_dir:   Ausgabeverzeichnis (Standard: selbes Verzeichnis wie PDF)
        metadata:  Optionale Metadaten (Client, Ziel, etc.) für Verifikationsdatei

    Returns:
        Tuple (enc_path, verification_path)

    Raises:
        ImportError:  wenn pycryptodome fehlt
        FileNotFoundError: wenn pdf_path nicht existiert
    """
    _require_crypto()

    pdf_path = Path(pdf_path)
    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF nicht gefunden: {pdf_path}")

    out_dir = Path(out_dir) if out_dir else pdf_path.parent

    # Originale PDF-Daten lesen
    plaintext = pdf_path.read_bytes()

    # Hash der unverschlüsselten PDF (für Verifikation)
    original_hash = hashlib.sha256(plaintext).hexdigest()

    # Schlüssel ableiten
    salt      = get_random_bytes(_SALT_LEN)
    key       = _derive_key(password, salt)

    # AES-256-GCM verschlüsseln
    nonce     = get_random_bytes(_NONCE_LEN)
    cipher    = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Format: VERSION(20) | SALT(32) | NONCE(16) | TAG(16) | CIPHERTEXT
    enc_data = (
        _VERSION.encode("utf-8").ljust(20)[:20]
        + salt
        + nonce
        + tag
        + ciphertext
    )

    enc_path = out_dir / (pdf_path.name + ".enc")
    enc_path.write_bytes(enc_data)

    # Verschlüsselungs-Hash (der .enc Datei)
    enc_hash = _sha256_file(str(enc_path))

    # ── Verifikationsdatei ────────────────────────────────────────────────────
    now = datetime.now()
    verification = {
        "ghostvenumai_version":    "2.0",
        "encryption_standard":     "AES-256-GCM",
        "key_derivation":          f"PBKDF2-HMAC-SHA256 ({_ITERATIONS:,} Iterationen)",
        "quantum_resistance_note": (
            "AES-256 bietet 128-Bit effektive Sicherheit gegen "
            "Quantencomputer (Grover-Algorithmus). Gilt als "
            "quantensicher nach aktuellem Stand der Technik (2024)."
        ),
        "created_at":              now.isoformat(),
        "created_at_human":        now.strftime("%d.%m.%Y %H:%M:%S"),
        "original_file":           pdf_path.name,
        "encrypted_file":          enc_path.name,
        "original_sha256":         original_hash,
        "encrypted_sha256":        enc_hash,
        "original_size_bytes":     len(plaintext),
        "encrypted_size_bytes":    len(enc_data),
        "salt_hex":                salt.hex(),
        "pbkdf2_iterations":       _ITERATIONS,
        "metadata":                metadata or {},
        "verification_note": (
            "Diese Datei beweist, dass der verschlüsselte Report zu einem "
            "bestimmten Zeitpunkt existierte und nicht verändert wurde. "
            "Der SHA-256-Hash des Originals kann nach Entschlüsselung "
            "zur Integritätsprüfung verwendet werden."
        ),
    }

    veri_path = out_dir / (pdf_path.stem + "_" +
                           now.strftime("%Y%m%d_%H%M%S") + ".verification.json")
    veri_path.write_text(
        json.dumps(verification, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    return str(enc_path), str(veri_path)


def decrypt_report(
    enc_path:  str,
    password:  str,
    out_path:  str = "",
) -> str:
    """
    Entschlüsselt einen verschlüsselten Report.

    Args:
        enc_path:  Pfad zur .enc-Datei
        password:  Passwort (muss identisch mit encrypt_report sein)
        out_path:  Ausgabepfad (Standard: .enc entfernt)

    Returns:
        Pfad zur entschlüsselten PDF-Datei.

    Raises:
        ValueError: bei falschem Passwort oder beschädigter Datei
    """
    _require_crypto()

    enc_path = Path(enc_path)
    enc_data = enc_path.read_bytes()

    # Header parsen
    version    = enc_data[:20].rstrip(b"\x00").decode("utf-8", errors="ignore")
    if not version.startswith("GVA-AES256GCM"):
        raise ValueError("Unbekanntes Dateiformat — keine GhostVenumAI-verschlüsselte Datei.")

    offset    = 20
    salt      = enc_data[offset:offset + _SALT_LEN];    offset += _SALT_LEN
    nonce     = enc_data[offset:offset + _NONCE_LEN];   offset += _NONCE_LEN
    tag       = enc_data[offset:offset + _TAG_LEN];     offset += _TAG_LEN
    ciphertext = enc_data[offset:]

    # Schlüssel ableiten + entschlüsseln
    key    = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_LEN)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Entschlüsselung fehlgeschlagen — falsches Passwort "
            "oder die Datei wurde verändert (Integritätsfehler)."
        )

    if not out_path:
        name = enc_path.name
        out_path = str(enc_path.parent / (
            name[:-4] if name.endswith(".enc") else name + ".decrypted.pdf"
        ))

    Path(out_path).write_bytes(plaintext)
    return out_path


def verify_report(
    enc_path:   str,
    veri_path:  str,
) -> tuple[bool, dict]:
    """
    Prüft Integrität des verschlüsselten Reports anhand der Verifikationsdatei.
    Kein Passwort nötig — nur Hash-Vergleich.

    Args:
        enc_path:   Pfad zur .enc-Datei
        veri_path:  Pfad zur .verification.json-Datei

    Returns:
        Tuple (is_valid: bool, info: dict)
    """
    try:
        veri = json.loads(Path(veri_path).read_text(encoding="utf-8"))
        current_hash = _sha256_file(enc_path)
        expected     = veri.get("encrypted_sha256", "")
        is_valid     = current_hash == expected
        return is_valid, {
            "valid":          is_valid,
            "created_at":     veri.get("created_at_human", ""),
            "original_file":  veri.get("original_file", ""),
            "original_hash":  veri.get("original_sha256", ""),
            "current_hash":   current_hash,
            "expected_hash":  expected,
            "encryption":     veri.get("encryption_standard", ""),
            "metadata":       veri.get("metadata", {}),
        }
    except Exception as e:
        return False, {"error": str(e)}


def check_pycryptodome() -> bool:
    return _CRYPTO
