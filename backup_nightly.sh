#!/bin/bash
# GhostVenumAI — Nächtlicher Backup-Job
# Wird täglich um 02:00 Uhr von cron ausgeführt
# Cron-Eintrag: 0 2 * * * /home/serverserver/Desktop/ghostvenumaiagents/backup_nightly.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/logs/backup.log"
PYTHON=$(which python3)

mkdir -p "$SCRIPT_DIR/logs"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starte Nacht-Backup..." >> "$LOG"

cd "$SCRIPT_DIR" && $PYTHON -c "
import sys
sys.path.insert(0, '.')
from modules.backup import run_nightly_backup
import json
result = run_nightly_backup()
if result['backup']['ok']:
    print(f\"OK: {result['backup']['filename']} ({result['backup']['size_mb']} MB)\")
    print(f\"SHA-256: {result['backup']['sha256']}\")
    print(f\"Bereinigt: {result['cleanup']['deleted']} alte Backup(s) gelöscht\")
else:
    print(f\"FEHLER: {result['backup'].get('error','unbekannt')}\")
    sys.exit(1)
" >> "$LOG" 2>&1

if [ $? -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup erfolgreich." >> "$LOG"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] BACKUP FEHLGESCHLAGEN!" >> "$LOG"
fi
