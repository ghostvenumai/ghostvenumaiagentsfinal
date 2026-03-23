# monitor_tab.py — GhostVenumAI 24/7 Monitoring Tab
"""
Eigenständiger Tkinter-Frame für den Monitoring-Tab.
Wird in gui.py als einzeiliger Import eingebunden:

    from monitor_tab import MonitorTab
    tab = MonitorTab(notebook, cfg=self._cfg,
                     save_cfg_fn=self._save_config, theme=THEME)
    notebook.add(tab, text="📡 Monitoring")
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox

from modules.monitor import MonitorEngine

_DEFAULT_THEME = {
    "BG":  "#1a1a2e",
    "BG2": "#16213e",
    "BG3": "#0f3460",
    "FG":  "#e0e0e0",
    "ACC": "#e94560",
}

# Vordefinierte Intervalle (Minuten)
_INTERVALS = {
    "5 Minuten (Test)":  5,
    "30 Minuten":       30,
    "1 Stunde":         60,
    "6 Stunden":       360,
    "12 Stunden":      720,
    "24 Stunden":     1440,
}

_STATUS_COLORS = {
    "running": "#81c784",   # grün
    "stopped": "#e57373",   # rot
    "change":  "#ffb74d",   # orange
}


class MonitorTab(ttk.Frame):
    """
    24/7 Monitoring-Tab.

    Args:
        parent:      Tkinter-Parent (ttk.Notebook)
        cfg:         Config-Dict aus config.json
        save_cfg_fn: Callable[[], None] — speichert cfg zurück
        theme:       Dict mit BG/BG2/BG3/FG/ACC Farben
    """

    def __init__(self, parent, cfg: dict,
                 save_cfg_fn=None, theme: dict | None = None):
        super().__init__(parent)
        self._cfg      = cfg
        self._save_cfg = save_cfg_fn or (lambda: None)
        self._t        = theme or _DEFAULT_THEME
        self._engine   = MonitorEngine()

        self._build()
        self._tick()   # Status-Anzeige alle 2s aktualisieren

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        t = self._t

        # ── Konfigurationsbereich ─────────────────────────────────────────────
        cfg_frame = ttk.LabelFrame(self, text="Konfiguration", padding=10)
        cfg_frame.pack(fill="x", padx=12, pady=(10, 4))

        # Zeile 1: Ziel + Intervall
        ttk.Label(cfg_frame, text="Ziel (IP / Range):").grid(
            row=0, column=0, sticky="w", padx=4, pady=3)
        self._var_target = tk.StringVar(
            value=self._cfg.get("target", "192.168.178.1"))
        ttk.Entry(cfg_frame, textvariable=self._var_target,
                  width=28).grid(row=0, column=1, padx=6, sticky="w")

        ttk.Label(cfg_frame, text="Intervall:").grid(
            row=0, column=2, sticky="w", padx=4)
        self._var_interval = tk.StringVar(value="1 Stunde")
        ttk.Combobox(
            cfg_frame, textvariable=self._var_interval,
            values=list(_INTERVALS.keys()),
            width=20, state="readonly",
        ).grid(row=0, column=3, padx=6)

        # Zeile 2: Nmap-Args
        ttk.Label(cfg_frame, text="Nmap-Args:").grid(
            row=1, column=0, sticky="w", padx=4, pady=3)
        self._var_nmap = tk.StringVar(
            value=self._cfg.get("monitor_nmap_args", "-sV -T4 --open"))
        ttk.Entry(cfg_frame, textvariable=self._var_nmap,
                  width=28).grid(row=1, column=1, padx=6, sticky="w")

        ttk.Label(cfg_frame, text="(--open = nur offene Ports)").grid(
            row=1, column=2, columnspan=2, sticky="w", padx=4,
            ipadx=0)

        # ── Status-Bereich ────────────────────────────────────────────────────
        status_frame = ttk.LabelFrame(self, text="Status", padding=8)
        status_frame.pack(fill="x", padx=12, pady=4)

        self._lbl_status = tk.Label(
            status_frame, text="● Gestoppt",
            fg=_STATUS_COLORS["stopped"],
            bg=t["BG"], font=("Segoe UI", 10, "bold"))
        self._lbl_status.grid(row=0, column=0, sticky="w", padx=8)

        ttk.Label(status_frame, text="Letzter Scan:").grid(
            row=0, column=1, sticky="w", padx=(20, 4))
        self._lbl_last = ttk.Label(status_frame, text="—")
        self._lbl_last.grid(row=0, column=2, sticky="w")

        ttk.Label(status_frame, text="Nächster Scan:").grid(
            row=0, column=3, sticky="w", padx=(20, 4))
        self._lbl_next = ttk.Label(status_frame, text="—")
        self._lbl_next.grid(row=0, column=4, sticky="w")

        ttk.Label(status_frame, text="Scans:").grid(
            row=0, column=5, sticky="w", padx=(20, 4))
        self._lbl_scans = ttk.Label(status_frame, text="0")
        self._lbl_scans.grid(row=0, column=6, sticky="w")

        ttk.Label(status_frame, text="Änderungen:").grid(
            row=0, column=7, sticky="w", padx=(16, 4))
        self._lbl_changes = ttk.Label(status_frame, text="0")
        self._lbl_changes.grid(row=0, column=8, sticky="w")

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", padx=12, pady=6)

        self._btn_start = ttk.Button(
            btn_row, text="▶  Monitoring starten",
            command=self._on_start)
        self._btn_start.pack(side="left", padx=4)

        self._btn_stop = ttk.Button(
            btn_row, text="■  Stoppen",
            command=self._on_stop, state="disabled")
        self._btn_stop.pack(side="left", padx=4)

        ttk.Button(btn_row, text="🗑 Log leeren",
                   command=self._on_clear).pack(side="left", padx=4)

        # ── Log-Widget ────────────────────────────────────────────────────────
        log_frame = tk.Frame(self, bg=t["BG2"], bd=1, relief="sunken")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(4, 10))

        self._log_widget = tk.Text(
            log_frame,
            bg=t["BG2"], fg=t["FG"], insertbackground=t["FG"],
            font=("Courier New", 10), state="disabled",
            wrap="word", relief="flat",
        )
        sb = ttk.Scrollbar(log_frame, command=self._log_widget.yview)
        self._log_widget.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._log_widget.pack(side="left", fill="both", expand=True)

        # Farb-Tags
        self._log_widget.tag_configure("INFO",   foreground="#4fc3f7")
        self._log_widget.tag_configure("OK",     foreground="#81c784")
        self._log_widget.tag_configure("WARN",   foreground="#ffb74d")
        self._log_widget.tag_configure("ERR",    foreground="#e57373")
        self._log_widget.tag_configure("CHANGE", foreground="#ffb74d",
                                       font=("Courier New", 10, "bold"))

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, tag: str = "INFO"):
        def _write():
            self._log_widget.configure(state="normal")
            self._log_widget.insert("end", msg + "\n", tag)
            self._log_widget.see("end")
            self._log_widget.configure(state="disabled")
        self._log_widget.after(0, _write)

    def _on_log(self, msg: str):
        """Callback für MonitorEngine — erkennt Typ anhand des Textes."""
        lower = msg.lower()
        if "fehler" in lower or "error" in lower:
            tag = "ERR"
        elif "änderung" in lower or "⚠️" in lower:
            tag = "CHANGE"
        elif "✅" in lower or "keine änderungen" in lower:
            tag = "OK"
        else:
            tag = "INFO"
        self._log(msg, tag)

    # ── Status-Ticker ─────────────────────────────────────────────────────────

    def _tick(self):
        """Aktualisiert die Status-Labels alle 2 Sekunden."""
        s = self._engine.status()

        if s["running"]:
            self._lbl_status.configure(
                text="● Läuft", fg=_STATUS_COLORS["running"])
        else:
            self._lbl_status.configure(
                text="● Gestoppt", fg=_STATUS_COLORS["stopped"])

        self._lbl_last.configure(text=s["last_scan"])
        self._lbl_next.configure(text=s["next_scan"])
        self._lbl_scans.configure(text=str(s["scan_count"]))

        changes = s["change_count"]
        color   = _STATUS_COLORS["change"] if changes > 0 else "#e0e0e0"
        self._lbl_changes.configure(text=str(changes), foreground=color)

        self.after(2000, self._tick)

    # ── Event-Handler ─────────────────────────────────────────────────────────

    def _on_start(self):
        target = self._var_target.get().strip()
        if not target:
            messagebox.showwarning(
                "Fehler", "Bitte Ziel-IP oder Netzwerk-Range eingeben.")
            return

        interval_label = self._var_interval.get()
        interval_min   = _INTERVALS.get(interval_label, 60)
        nmap_args      = self._var_nmap.get().strip() or "-sV -T4 --open"

        # Config speichern
        self._cfg["target"]             = target
        self._cfg["monitor_nmap_args"]  = nmap_args
        self._save_cfg()

        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")

        self._log(
            f"Monitoring gestartet — Ziel: {target} | "
            f"Intervall: {interval_label}", "INFO")

        self._engine.start(
            target       = target,
            interval_min = interval_min,
            nmap_args    = nmap_args,
            on_log       = self._on_log,
            on_change    = self._on_change,
        )

    def _on_stop(self):
        self._engine.stop()
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._log("Monitoring gestoppt.", "WARN")

    def _on_clear(self):
        self._log_widget.configure(state="normal")
        self._log_widget.delete("1.0", "end")
        self._log_widget.configure(state="disabled")

    def _on_change(self, diff: dict, raw_scan: str):
        """Callback wenn MonitorEngine eine Änderung meldet."""
        # Änderungen im Log ausgeben
        if diff["ports"]["new"]:
            for p in diff["ports"]["new"]:
                self._log(
                    f"  🔴 Neuer Port: {p['port']}/{p['proto']} "
                    f"({p.get('service','')}) {p.get('version','')}",
                    "CHANGE")
        if diff["ports"]["closed"]:
            for p in diff["ports"]["closed"]:
                self._log(
                    f"  🟡 Port geschlossen: {p['port']}/{p['proto']} "
                    f"({p.get('service','')})",
                    "WARN")
        if diff.get("version_changes"):
            for vc in diff["version_changes"]:
                self._log(
                    f"  🔵 Versions-Änderung {vc['port']} {vc['service']}: "
                    f"{vc['old_version']} → {vc['new_version']}",
                    "CHANGE")

        # KI-Vollanalyse im Hintergrund starten
        self._log("🤖 Starte KI-Analyse der Änderungen...", "INFO")

        def run_analysis():
            try:
                from modules.agents.orchestrator import run_full_analysis
                target = self._engine.target
                summary = run_full_analysis(
                    target,
                    log_callback=lambda agent, msg: self._on_log(
                        f"[{agent}] {msg}")
                )
                self._log("✅ KI-Analyse abgeschlossen.", "OK")
                self._log(summary, "OK")
            except Exception as e:
                self._log(f"KI-Analyse FEHLER: {e}", "ERR")

        threading.Thread(target=run_analysis, daemon=True).start()
