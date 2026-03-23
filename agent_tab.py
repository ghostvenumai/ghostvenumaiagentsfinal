# agent_tab.py — GhostVenumAI Agent Mode Tab
"""
Eigenständiger Tkinter-Frame für den Agent-Mode-Tab.
Wird in gui.py als einzeiliger Import eingebunden:

    from agent_tab import AgentTab
    tab = AgentTab(notebook, cfg=self._cfg, theme=THEME)
    notebook.add(tab, text="🤖 Agent Mode")

Der Tab enthält:
  - Ziel-Eingabe + Claude-Modell-Auswahl
  - Checkboxen: ReconAgent / VulnAgent / RemediationAgent
  - Start-Button → startet Orchestrator in Background-Thread
  - Live-Log mit farbiger Agent-Kennzeichnung
  - Speichern-Button + Anthropic-Key-Dialog
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox

# ── Farben (werden von gui.py übergeben oder hier als Fallback) ───────────────
_DEFAULT_THEME = {
    "BG":  "#1a1a2e",
    "BG2": "#16213e",
    "BG3": "#0f3460",
    "FG":  "#e0e0e0",
    "ACC": "#e94560",
}

# Agenten-Farben
_TAG_COLORS = {
    "AGENT_ORCH":  "#ce93d8",   # lila   — OrchestratorAgent
    "AGENT_RECON": "#64b5f6",   # blau   — ReconAgent
    "AGENT_VULN":  "#ffb74d",   # orange — VulnAgent
    "AGENT_REMED": "#81c784",   # grün   — RemediationAgent
    "AGENT_ERR":   "#e57373",   # rot    — Fehler
    "INFO":        "#4fc3f7",   # hellblau
}
_AGENT_TAG_MAP = {
    "OrchestratorAgent": "AGENT_ORCH",
    "ReconAgent":        "AGENT_RECON",
    "VulnAgent":         "AGENT_VULN",
    "RemediationAgent":  "AGENT_REMED",
}

_MODELS_CLAUDE = [
    "claude-sonnet-4-6",
    "claude-opus-4-6",
    "claude-haiku-4-5-20251001",
]


class AgentTab(ttk.Frame):
    """
    Agent-Mode-Tab als eigenständiger Frame.

    Args:
        parent:      Tkinter-Parent (ttk.Notebook)
        cfg:         Config-Dict aus config.json (wird direkt referenziert)
        save_cfg_fn: Callable[[], None] — speichert cfg zurück in config.json
        theme:       Dict mit BG/BG2/BG3/FG/ACC Farben
    """

    def __init__(
        self,
        parent,
        cfg: dict,
        save_cfg_fn=None,
        theme: dict | None = None,
    ):
        super().__init__(parent)
        self._cfg        = cfg
        self._save_cfg   = save_cfg_fn or (lambda: None)
        self._t          = theme or _DEFAULT_THEME
        self._output     = ""          # gespeicherter Agent-Output
        self._running    = False       # läuft gerade ein Scan?

        self._build()
        self._log("OrchestratorAgent",
                  "Agent Mode bereit. Ziel eingeben und Vollanalyse starten.")

    # ── UI aufbauen ───────────────────────────────────────────────────────────

    def _build(self):
        t = self._t

        # Ziel + Modell
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Ziel (IP / Range):").grid(
            row=0, column=0, sticky="w", padx=4)
        self._var_target = tk.StringVar(
            value=self._cfg.get("target", "192.168.178.1"))
        ttk.Entry(top, textvariable=self._var_target, width=30).grid(
            row=0, column=1, padx=6, sticky="w")

        ttk.Label(top, text="Claude-Modell:").grid(
            row=0, column=2, sticky="w", padx=4)
        self._var_model = tk.StringVar(
            value=self._cfg.get("claude_model", "claude-sonnet-4-6"))
        ttk.Combobox(
            top, textvariable=self._var_model,
            values=_MODELS_CLAUDE, width=28, state="readonly",
        ).grid(row=0, column=3, padx=6)

        # Agenten-Checkboxen
        chk = ttk.Frame(self)
        chk.pack(fill="x", padx=12, pady=2)
        ttk.Label(chk, text="Agenten:").pack(side="left", padx=(0, 8))

        self._var_recon = tk.BooleanVar(value=True)
        self._var_vuln  = tk.BooleanVar(value=True)
        self._var_remed = tk.BooleanVar(value=True)
        ttk.Checkbutton(chk, text="ReconAgent",
                        variable=self._var_recon).pack(side="left", padx=6)
        ttk.Checkbutton(chk, text="VulnAgent",
                        variable=self._var_vuln).pack(side="left", padx=6)
        ttk.Checkbutton(chk, text="RemediationAgent",
                        variable=self._var_remed).pack(side="left", padx=6)

        # Buttons
        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", padx=12, pady=4)

        self._btn_start = ttk.Button(
            btn_row, text="▶  Vollanalyse starten",
            command=self._on_start)
        self._btn_start.pack(side="left", padx=4)

        ttk.Button(btn_row, text="💾 Speichern",
                   command=self._on_save).pack(side="left", padx=4)
        ttk.Button(btn_row, text="🗑 Log leeren",
                   command=self._on_clear).pack(side="left", padx=4)
        ttk.Button(btn_row, text="🔑 Anthropic Key",
                   command=self._on_set_key).pack(side="left", padx=4)

        # Log-Widget
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

        # Farb-Tags registrieren
        for tag, color in _TAG_COLORS.items():
            self._log_widget.tag_configure(tag, foreground=color)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, agent: str, msg: str):
        """Thread-sicheres Schreiben in den Log-Widget."""
        tag    = _AGENT_TAG_MAP.get(agent, "INFO")
        prefix = f"[{agent}] " if agent else ""
        line   = prefix + msg

        def _write():
            self._log_widget.configure(state="normal")
            self._log_widget.insert("end", line + "\n", tag)
            self._log_widget.see("end")
            self._log_widget.configure(state="disabled")

        self._log_widget.after(0, _write)

    # ── Event-Handler ─────────────────────────────────────────────────────────

    def _on_start(self):
        if self._running:
            self._log("OrchestratorAgent", "Analyse läuft bereits...")
            return

        target = self._var_target.get().strip()
        if not target:
            messagebox.showwarning("Fehler", "Bitte Ziel-IP oder Netzwerk-Range eingeben.")
            return

        self._cfg["target"]       = target
        self._cfg["claude_model"] = self._var_model.get()
        self._save_cfg()

        self._output  = ""
        self._running = True
        self._btn_start.configure(state="disabled")

        def work():
            try:
                from modules.agents.orchestrator import stream_analysis
                self._log("OrchestratorAgent",
                          f"Starte Vollanalyse für: {target}")
                for msg in stream_analysis(target):
                    agent   = msg.get("agent", "")
                    content = msg.get("content", "")
                    if content.strip():
                        self._log(agent, content)
                        self._output += f"[{agent}] {content}\n"
                self._log("OrchestratorAgent", "✅ Vollanalyse abgeschlossen.")
            except Exception as exc:
                self._log("OrchestratorAgent", f"FEHLER: {exc}")
            finally:
                self._running = False
                self._btn_start.after(0,
                    lambda: self._btn_start.configure(state="normal"))

        threading.Thread(target=work, daemon=True).start()

    def _on_save(self):
        if not self._output:
            self._log("OrchestratorAgent", "Kein Output zum Speichern.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Textdateien", "*.txt"), ("Alle Dateien", "*.*")],
            initialfile="agent_analyse.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._output)
            self._log("OrchestratorAgent", f"Output gespeichert: {path}")

    def _on_clear(self):
        self._log_widget.configure(state="normal")
        self._log_widget.delete("1.0", "end")
        self._log_widget.configure(state="disabled")
        self._output = ""

    def _on_set_key(self):
        key = simpledialog.askstring(
            "Anthropic API-Key",
            "Anthropic API-Key eingeben (sk-ant-...):",
            show="*",
        )
        if key:
            self._cfg["anthropic_key"] = key.strip()
            self._save_cfg()
            self._log("OrchestratorAgent", "Anthropic API-Key gespeichert.")
