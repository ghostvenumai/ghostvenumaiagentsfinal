# modules/backup.py — GhostVenumAI Enterprise
# Automatisches lokales Backup (BSI 3-2-1-Regel, ISO 27001 A.17.1)
# Täglich 02:00 Uhr via Cron

import os
import json
import shutil
import tarfile
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# Basis-Pfad: Projektverzeichnis
_BASE    = Path(__file__).parent.parent.resolve()
_BACKUP  = _BASE / "backup"
_KEEP_DAYS = 30   # Backups älter als 30 Tage werden gelöscht


# ── Was wird gesichert ────────────────────────────────────────────────────────

BACKUP_SOURCES = [
    ("output/history",          "scan_history"),
    ("output",                  "reports"),
    ("logs",                    "logs"),
    ("compliance",              "compliance"),
    ("config.users.json",       "config_users"),
    ("config.json",             "config"),
    ("config.vault",            "vault"),
    ("config.vault.meta",       "vault_meta"),
]


# ── Backup erstellen ──────────────────────────────────────────────────────────

def create_backup(label: str = "auto") -> dict:
    """
    Erstellt ein komprimiertes tar.gz-Backup aller wichtigen Dateien.
    Gibt Zusammenfassung zurück.
    """
    _BACKUP.mkdir(parents=True, exist_ok=True)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"ghostvenum_backup_{label}_{ts}.tar.gz"
    filepath = _BACKUP / filename

    included  = []
    skipped   = []
    total_size = 0

    try:
        with tarfile.open(filepath, "w:gz", compresslevel=6) as tar:
            for rel_path, arc_name in BACKUP_SOURCES:
                src = _BASE / rel_path
                if not src.exists():
                    skipped.append(rel_path)
                    continue
                arc_path = f"ghostvenum_backup/{arc_name}"
                tar.add(str(src), arcname=arc_path)
                included.append(rel_path)
                if src.is_file():
                    total_size += src.stat().st_size
                else:
                    total_size += sum(f.stat().st_size for f in src.rglob("*") if f.is_file())

        # SHA-256 Prüfsumme für Integritätsprüfung
        checksum = _sha256(filepath)

        # Manifest erstellen
        manifest = {
            "created_at":  datetime.now(timezone.utc).isoformat(),
            "label":       label,
            "filename":    filename,
            "size_bytes":  filepath.stat().st_size,
            "source_bytes":total_size,
            "sha256":      checksum,
            "included":    included,
            "skipped":     skipped,
        }
        manifest_path = _BACKUP / f"ghostvenum_backup_{label}_{ts}.manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

        _audit_backup("created", filename, checksum, len(included))

        return {
            "ok":       True,
            "path":     str(filepath),
            "filename": filename,
            "size_mb":  round(filepath.stat().st_size / 1024 / 1024, 2),
            "sha256":   checksum,
            "included": included,
            "skipped":  skipped,
        }

    except Exception as e:
        _audit_backup("failed", filename, "", 0, str(e))
        return {"ok": False, "error": str(e)}


# ── Alte Backups bereinigen ────────────────────────────────────────────────────

def cleanup_old_backups(keep_days: int = _KEEP_DAYS) -> dict:
    """Löscht Backups die älter als keep_days Tage sind."""
    if not _BACKUP.exists():
        return {"deleted": 0, "kept": 0}

    cutoff  = datetime.now(timezone.utc) - timedelta(days=keep_days)
    deleted = []
    kept    = []

    for f in sorted(_BACKUP.iterdir()):
        if not f.name.startswith("ghostvenum_backup_"):
            continue
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            f.unlink()
            deleted.append(f.name)
        else:
            kept.append(f.name)

    return {"deleted": len(deleted), "kept": len(kept), "files_deleted": deleted}


# ── Backup-Liste ──────────────────────────────────────────────────────────────

def list_backups() -> list:
    """Gibt alle vorhandenen Backups zurück."""
    if not _BACKUP.exists():
        return []

    backups = []
    for f in sorted(_BACKUP.iterdir(), reverse=True):
        if not (f.name.endswith(".tar.gz") and f.name.startswith("ghostvenum_backup_")):
            continue
        manifest_path = Path(str(f).replace(".tar.gz", ".manifest.json"))
        entry = {
            "filename": f.name,
            "size_mb":  round(f.stat().st_size / 1024 / 1024, 2),
            "created":  datetime.fromtimestamp(
                f.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
        }
        if manifest_path.exists():
            try:
                m = json.loads(manifest_path.read_text())
                entry["sha256"]   = m.get("sha256", "")
                entry["included"] = len(m.get("included", []))
            except Exception:
                pass
        backups.append(entry)

    return backups


# ── Backup verifizieren ───────────────────────────────────────────────────────

def verify_backup(filename: str) -> dict:
    """Prüft SHA-256-Integrität eines Backups."""
    filepath = _BACKUP / filename
    if not filepath.exists():
        return {"ok": False, "error": "Datei nicht gefunden"}

    manifest_path = Path(str(filepath).replace(".tar.gz", ".manifest.json"))
    if not manifest_path.exists():
        return {"ok": False, "error": "Kein Manifest vorhanden"}

    try:
        manifest = json.loads(manifest_path.read_text())
        expected = manifest.get("sha256", "")
        actual   = _sha256(filepath)
        ok       = hmac_compare(expected, actual)
        return {
            "ok":       ok,
            "expected": expected,
            "actual":   actual,
            "filename": filename,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hmac_compare(a: str, b: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a.encode(), b.encode())


def _audit_backup(action: str, filename: str, checksum: str,
                  file_count: int, error: str = ""):
    try:
        from modules.audit_logger import log, AuditLevel, AuditCategory
        level = AuditLevel.INFO if not error else AuditLevel.ERROR
        log(level, AuditCategory.SYSTEM, f"backup_{action}",
            result="success" if not error else "failure",
            details={
                "filename":   filename,
                "sha256":     checksum[:16] + "…" if checksum else "",
                "file_count": file_count,
                "error":      error,
            })
    except Exception:
        pass


# ── Vollständiger Backup-Lauf (Auto + Cleanup) ────────────────────────────────

def run_nightly_backup() -> dict:
    """Wird vom Cron-Job täglich um 02:00 Uhr aufgerufen."""
    backup_result  = create_backup(label="nightly")
    cleanup_result = cleanup_old_backups(keep_days=_KEEP_DAYS)

    return {
        "backup":  backup_result,
        "cleanup": cleanup_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "backup"

    if cmd == "backup":
        label = sys.argv[2] if len(sys.argv) > 2 else "manual"
        r = create_backup(label)
        if r["ok"]:
            print(f"✅ Backup erstellt: {r['filename']} ({r['size_mb']} MB)")
            print(f"   SHA-256: {r['sha256']}")
            print(f"   Gesichert: {', '.join(r['included'])}")
        else:
            print(f"❌ Backup fehlgeschlagen: {r['error']}")

    elif cmd == "list":
        backups = list_backups()
        if not backups:
            print("Keine Backups vorhanden.")
        for b in backups:
            print(f"  {b['filename']}  {b['size_mb']} MB  {b['created'][:10]}")

    elif cmd == "cleanup":
        r = cleanup_old_backups()
        print(f"Gelöscht: {r['deleted']} | Behalten: {r['kept']}")

    elif cmd == "nightly":
        r = run_nightly_backup()
        print(json.dumps(r, indent=2, ensure_ascii=False))

    else:
        print("Befehle: backup [label] | list | cleanup | nightly")
