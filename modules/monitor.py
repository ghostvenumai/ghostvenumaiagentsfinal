# modules/monitor.py
"""
MonitorEngine — 24/7 Netzwerk-Überwachung für GhostVenumAI.

Ablauf pro Zyklus:
  1. Nmap-Scan (lokal, keine API-Kosten)
  2. Vergleich mit letztem Scan aus memory.py (lokal, keine API-Kosten)
  3a. Keine Änderung → schlafen, kein API-Aufruf
  3b. Änderung gefunden → Orchestrator-Vollanalyse → Benachrichtigung

Was als relevante Änderung gilt:
  - Neuer Port offen
  - Port geschlossen (Gerät/Dienst nicht mehr erreichbar)
  - Software-Version geändert
  - Neues Gerät im Netz aufgetaucht
  - Gerät verschwunden (war vorher online)

Nutzung:
    engine = MonitorEngine()
    engine.start(
        target          = "192.168.178.0/24",
        interval_min    = 60,
        on_change       = my_change_callback,   # (diff, scan_output) → None
        on_log          = my_log_callback,       # (message) → None
    )
    engine.stop()
"""

import threading
import time
from datetime import datetime
from typing import Callable, Optional

from modules.scanner import run_nmap_scan
from modules import memory


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _quick_diff(old_scan: dict, new_raw: str) -> dict | None:
    """
    Vergleicht neuen Scan-Output mit letztem gespeicherten Scan.
    Gibt None zurück wenn keine relevante Änderung gefunden.
    Gibt dict mit Diff-Infos zurück wenn etwas geändert hat.
    """
    new_ports = memory._parse_ports(new_raw)

    temp_new = {"ports": new_ports, "cves": []}
    diff = memory.generate_diff(old_scan, temp_new)

    # Relevante Änderungen prüfen
    has_new_ports    = len(diff["ports"]["new"]) > 0
    has_closed_ports = len(diff["ports"]["closed"]) > 0

    # Versions-Änderung: Port vorhanden aber Version unterschiedlich
    version_changes = []
    old_ports_by_key = {
        f"{p['port']}/{p['proto']}": p
        for p in old_scan.get("ports", [])
    }
    for p in new_ports:
        key = f"{p['port']}/{p['proto']}"
        if key in old_ports_by_key:
            old_ver = old_ports_by_key[key].get("version", "").strip()
            new_ver = p.get("version", "").strip()
            if old_ver and new_ver and old_ver != new_ver:
                version_changes.append({
                    "port":        key,
                    "service":     p.get("service", ""),
                    "old_version": old_ver,
                    "new_version": new_ver,
                })

    if not has_new_ports and not has_closed_ports and not version_changes:
        return None

    diff["version_changes"] = version_changes
    return diff


# ── MonitorEngine ─────────────────────────────────────────────────────────────

class MonitorEngine:
    """
    Thread-basierte Monitoring-Engine.
    Kann gestartet und gestoppt werden. Threadsicher.
    """

    def __init__(self):
        self._thread:        Optional[threading.Thread] = None
        self._stop_event:    threading.Event            = threading.Event()
        self._lock:          threading.Lock             = threading.Lock()

        # Status-Infos (für GUI lesbar)
        self.target:         str      = ""
        self.interval_min:   int      = 60
        self.is_running:     bool     = False
        self.last_scan_time: str      = "—"
        self.next_scan_time: str      = "—"
        self.scan_count:     int      = 0
        self.change_count:   int      = 0

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def start(
        self,
        target:        str,
        interval_min:  int                       = 60,
        on_change:     Callable[[dict, str], None] = None,
        on_log:        Callable[[str], None]       = None,
        nmap_args:     str                         = "-sV -T4 --open",
    ) -> None:
        """
        Startet den Monitoring-Loop im Hintergrund.

        Args:
            target:       Ziel-IP oder Netzwerk-Range
            interval_min: Intervall in Minuten zwischen Scans (min. 5)
            on_change:    Callback bei Änderung: on_change(diff, raw_scan)
            on_log:       Callback für Log-Nachrichten: on_log(message)
            nmap_args:    Nmap-Argumente für den Monitoring-Scan
        """
        with self._lock:
            if self.is_running:
                return

            self.target       = target
            self.interval_min = max(5, interval_min)
            self._stop_event.clear()
            self.scan_count   = 0
            self.change_count = 0
            self.is_running   = True

        self._thread = threading.Thread(
            target=self._loop,
            args=(target, nmap_args, on_change, on_log),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stoppt den Monitoring-Loop."""
        self._stop_event.set()
        with self._lock:
            self.is_running   = False
            self.next_scan_time = "—"

    def status(self) -> dict:
        """Gibt den aktuellen Status zurück (für GUI)."""
        return {
            "running":       self.is_running,
            "target":        self.target,
            "interval_min":  self.interval_min,
            "last_scan":     self.last_scan_time,
            "next_scan":     self.next_scan_time,
            "scan_count":    self.scan_count,
            "change_count":  self.change_count,
        }

    # ── Interner Loop ─────────────────────────────────────────────────────────

    def _loop(
        self,
        target:    str,
        nmap_args: str,
        on_change: Callable | None,
        on_log:    Callable | None,
    ) -> None:
        def log(msg: str):
            if on_log:
                on_log(f"[Monitor] {msg}")

        log(f"Monitoring gestartet — Ziel: {target} | Intervall: {self.interval_min} min")

        while not self._stop_event.is_set():

            # ── Scan ─────────────────────────────────────────────────────────
            log(f"Scan #{self.scan_count + 1} gestartet ({_now()})")
            raw_scan = ""
            try:
                raw_scan = run_nmap_scan(target, nmap_args)
                self.scan_count += 1
                self.last_scan_time = _now()
                log(f"Scan abgeschlossen. ({len(raw_scan)} Zeichen)")
            except Exception as e:
                log(f"Scan FEHLER: {e}")

            # ── Diff-Vergleich (lokal, keine API) ────────────────────────────
            if raw_scan:
                try:
                    old_scan = memory.load_last_scan(target)

                    if old_scan is None:
                        # Erster Scan — als Baseline speichern
                        memory.save_scan(
                            target=target, ports=[], cves=[],
                            raw_scan=raw_scan, raw_cves="",
                            raw_remediation="", summary="Baseline-Scan"
                        )
                        log("Erster Scan — als Baseline gespeichert. Kein API-Aufruf.")

                    else:
                        diff = _quick_diff(old_scan, raw_scan)

                        if diff is None:
                            log("✅ Keine Änderungen — kein API-Aufruf.")
                        else:
                            self.change_count += 1
                            self._report_change(diff, raw_scan, target,
                                                on_change, on_log, log)

                except Exception as e:
                    log(f"Diff-Vergleich FEHLER: {e}")

            # ── Warten bis zum nächsten Scan ──────────────────────────────────
            if self._stop_event.is_set():
                break

            wait_sec = self.interval_min * 60
            next_dt  = datetime.fromtimestamp(time.time() + wait_sec)
            self.next_scan_time = next_dt.strftime("%Y-%m-%d %H:%M:%S")
            log(f"Nächster Scan um {self.next_scan_time}")

            # In kleinen Schritten warten → Stop reagiert sofort
            for _ in range(wait_sec):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        log("Monitoring gestoppt.")
        with self._lock:
            self.is_running = False

    def _report_change(
        self,
        diff:      dict,
        raw_scan:  str,
        target:    str,
        on_change: Callable | None,
        on_log:    Callable | None,
        log:       Callable,
    ) -> None:
        """Verarbeitet eine erkannte Änderung."""

        # Änderungen zusammenfassen
        parts = []
        if diff["ports"]["new"]:
            names = [f"{p['port']}/{p['proto']} ({p.get('service','')})"
                     for p in diff["ports"]["new"]]
            parts.append(f"Neue Ports: {', '.join(names)}")
        if diff["ports"]["closed"]:
            names = [f"{p['port']}/{p['proto']}"
                     for p in diff["ports"]["closed"]]
            parts.append(f"Geschlossene Ports: {', '.join(names)}")
        if diff.get("version_changes"):
            for vc in diff["version_changes"]:
                parts.append(
                    f"Versions-Änderung {vc['port']} {vc['service']}: "
                    f"{vc['old_version']} → {vc['new_version']}"
                )

        change_summary = " | ".join(parts) if parts else diff.get("summary", "Änderung erkannt")
        log(f"⚠️  ÄNDERUNG ERKANNT: {change_summary}")
        log("Starte KI-Vollanalyse...")

        # Neuen Scan in Memory speichern (vor API-Aufruf)
        try:
            memory.save_scan(
                target=target, ports=[], cves=[],
                raw_scan=raw_scan, raw_cves="",
                raw_remediation="", summary=change_summary
            )
        except Exception as e:
            log(f"Memory-Speichern fehlgeschlagen: {e}")

        # Callback aufrufen (startet Orchestrator-Analyse in GUI)
        if on_change:
            try:
                on_change(diff, raw_scan)
            except Exception as e:
                log(f"on_change Callback FEHLER: {e}")
