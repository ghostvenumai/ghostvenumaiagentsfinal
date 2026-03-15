# modules/memory.py
"""
Memory-System für GhostVenumAI v2.0 — Persistente Scan-Historie.
Speichert jeden abgeschlossenen Scan als JSON in output/history/.
"""
import os
import re
import json
from datetime import datetime

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_HISTORY_DIR = os.path.join(_ROOT, "output", "history")


def _ensure_history_dir():
    """Erstellt das history-Verzeichnis falls nicht vorhanden."""
    try:
        os.makedirs(_HISTORY_DIR, exist_ok=True)
    except Exception as e:
        print(f"[memory] Konnte history-Verzeichnis nicht erstellen: {e}")


def _target_safe(target: str) -> str:
    """Ersetzt Punkte und Schrägstriche durch Unterstriche für Dateinamen."""
    return re.sub(r"[./\\]", "_", target)


def _parse_ports(raw_scan: str) -> list:
    r"""
    Parst offene Ports aus Nmap-Output.
    Regex: r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
    """
    ports = []
    try:
        pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", re.IGNORECASE)
        for match in pattern.finditer(raw_scan):
            port_num, proto, service, version = match.groups()
            ports.append({
                "port":    int(port_num),
                "proto":   proto.lower(),
                "service": service.lower(),
                "version": version.strip(),
                "state":   "open"
            })
    except Exception as e:
        print(f"[memory] Port-Parsing Fehler: {e}")
    return ports


def _parse_cves(raw_cves: str) -> list:
    r"""
    Parst CVEs aus CVE-Analyse-Text.
    Regex: r"(CVE-\d{4}-\d+).*?CVSS[:\s]*([\d.]+)"
    """
    cves = []
    try:
        pattern = re.compile(r"(CVE-\d{4}-\d+).*?CVSS[:\s]*([\d.]+)", re.IGNORECASE | re.DOTALL)
        seen = set()
        for match in pattern.finditer(raw_cves):
            cve_id, cvss_str = match.groups()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            cvss = float(cvss_str)

            # Severity bestimmen
            if cvss >= 9.0:
                severity = "KRITISCH"
            elif cvss >= 7.0:
                severity = "HOCH"
            elif cvss >= 4.0:
                severity = "MITTEL"
            else:
                severity = "NIEDRIG"

            # Versuche zugehörigen Service aus dem Kontext zu extrahieren
            service = ""
            ctx_start = max(0, match.start() - 200)
            ctx = raw_cves[ctx_start:match.end()]
            svc_match = re.search(
                r"(openssh|apache|nginx|vsftpd|proftpd|bind|postfix|dovecot|mysql|postgresql|samba|openssl)",
                ctx, re.IGNORECASE
            )
            if svc_match:
                service = svc_match.group(1).lower()

            cves.append({
                "cve_id":   cve_id,
                "cvss":     cvss,
                "service":  service,
                "severity": severity
            })
    except Exception as e:
        print(f"[memory] CVE-Parsing Fehler: {e}")
    return cves


def save_scan(
    target: str,
    ports: list,
    cves: list,
    raw_scan: str,
    raw_cves: str,
    raw_remediation: str,
    summary: str
) -> str:
    """
    Speichert einen abgeschlossenen Scan als JSON-Datei.
    Gibt die scan_id zurück.
    """
    _ensure_history_dir()

    ts_obj = datetime.now()
    scan_id = ts_obj.strftime("%Y%m%d_%H%M%S")
    timestamp = ts_obj.strftime("%Y-%m-%dT%H:%M:%S")

    # Falls ports/cves leer, aus raw-Text parsen
    if not ports and raw_scan:
        ports = _parse_ports(raw_scan)
    if not cves and raw_cves:
        cves = _parse_cves(raw_cves)

    scan_data = {
        "scan_id":         scan_id,
        "target":          target,
        "timestamp":       timestamp,
        "ports":           ports,
        "cves":            cves,
        "raw_scan":        raw_scan,
        "raw_cves":        raw_cves,
        "raw_remediation": raw_remediation,
        "summary":         summary
    }

    filename = f"{_target_safe(target)}_{scan_id}.json"
    filepath = os.path.join(_HISTORY_DIR, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[memory] Fehler beim Speichern von {filepath}: {e}")

    return scan_id


def _load_scan_files(target: str) -> list:
    """
    Gibt alle JSON-Dateien für ein Target zurück, sortiert (neueste zuerst).
    """
    _ensure_history_dir()
    prefix = _target_safe(target) + "_"
    files = []
    try:
        for fname in os.listdir(_HISTORY_DIR):
            if fname.startswith(prefix) and fname.endswith(".json"):
                files.append(os.path.join(_HISTORY_DIR, fname))
        files.sort(reverse=True)
    except Exception as e:
        print(f"[memory] Fehler beim Lesen von history-Dir: {e}")
    return files


def load_last_scan(target: str) -> dict | None:
    """
    Lädt den zuletzt gespeicherten Scan für dieses Target.
    Gibt None zurück wenn kein Scan vorhanden.
    """
    files = _load_scan_files(target)
    if not files:
        return None
    try:
        with open(files[0], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[memory] Fehler beim Laden von {files[0]}: {e}")
        return None


def load_all_scans(target: str) -> list:
    """
    Lädt alle gespeicherten Scans für dieses Target, neueste zuerst.
    """
    files = _load_scan_files(target)
    scans = []
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                scans.append(json.load(f))
        except Exception as e:
            print(f"[memory] Fehler beim Laden von {fpath}: {e}")
    return scans


def list_all_targets() -> list:
    """
    Gibt alle Targets zurück, für die History-Daten existieren.
    """
    _ensure_history_dir()
    targets = set()
    try:
        for fname in os.listdir(_HISTORY_DIR):
            if not fname.endswith(".json"):
                continue
            # Dateiname: {target_safe}_{YYYYMMDD_HHMMSS}.json
            # Timestamp-Suffix hat Format: _20260315_153000.json (17 Zeichen + .json = 22)
            # Wir extrahieren alles vor dem letzten _YYYYMMDD_HHMMSS.json
            base = fname[:-5]  # entfernt .json
            # Timestamp-Teil ist immer _YYYYMMDD_HHMMSS (16 Zeichen)
            if len(base) > 16:
                target_safe_part = base[:-16]  # entfernt _YYYYMMDD_HHMMSS
                if target_safe_part:
                    # Lade die Datei um echtes Target zu lesen
                    fpath = os.path.join(_HISTORY_DIR, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            if "target" in data:
                                targets.add(data["target"])
                    except Exception:
                        pass
    except Exception as e:
        print(f"[memory] Fehler beim Auflisten der Targets: {e}")
    return sorted(list(targets))


def generate_diff(old_scan: dict, new_scan: dict) -> dict:
    """
    Vergleicht zwei Scans und gibt die Unterschiede zurück.
    """
    result = {
        "ports": {
            "new":       [],
            "closed":    [],
            "unchanged": []
        },
        "cves": {
            "new":       [],
            "resolved":  [],
            "unchanged": []
        },
        "summary": ""
    }

    try:
        # Ports vergleichen (key: port+proto)
        def port_key(p):
            return f"{p.get('port', 0)}/{p.get('proto', 'tcp')}"

        old_ports = {port_key(p): p for p in old_scan.get("ports", [])}
        new_ports = {port_key(p): p for p in new_scan.get("ports", [])}

        for key, port in new_ports.items():
            if key in old_ports:
                result["ports"]["unchanged"].append(port)
            else:
                result["ports"]["new"].append(port)

        for key, port in old_ports.items():
            if key not in new_ports:
                result["ports"]["closed"].append(port)

        # CVEs vergleichen (key: cve_id)
        old_cves = {c.get("cve_id", ""): c for c in old_scan.get("cves", [])}
        new_cves = {c.get("cve_id", ""): c for c in new_scan.get("cves", [])}

        for cve_id, cve in new_cves.items():
            if cve_id in old_cves:
                result["cves"]["unchanged"].append(cve)
            else:
                result["cves"]["new"].append(cve)

        for cve_id, cve in old_cves.items():
            if cve_id not in new_cves:
                result["cves"]["resolved"].append(cve)

        # Summary erstellen
        n_ports  = len(result["ports"]["new"])
        cl_ports = len(result["ports"]["closed"])
        n_cves   = len(result["cves"]["new"])
        r_cves   = len(result["cves"]["resolved"])

        parts = []
        if n_ports:
            parts.append(f"{n_ports} neue Port{'s' if n_ports != 1 else ''}")
        if cl_ports:
            parts.append(f"{cl_ports} geschlossene{'r' if cl_ports == 1 else ''} Port{'s' if cl_ports != 1 else ''}")
        if n_cves:
            parts.append(f"{n_cves} neue CVE{'s' if n_cves != 1 else ''}")
        if r_cves:
            parts.append(f"{r_cves} CVE{'s' if r_cves != 1 else ''} behoben")
        if not parts:
            parts.append("Keine Änderungen")

        result["summary"] = " | ".join(parts)

    except Exception as e:
        print(f"[memory] Fehler beim Diff-Generieren: {e}")
        result["summary"] = f"Diff-Fehler: {e}"

    return result
