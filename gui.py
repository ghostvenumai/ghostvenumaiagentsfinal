# gui.py — GhostVenumAI v2.0 Agent Edition
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import os
import json
import sys

from modules import i18n_quick as i18n
from modules.scanner     import run_nmap_scan
from modules.gpt_analysis import analyze_scan_with_gpt
from modules.report      import create_report
from modules.system_info import collect_system_info

# ── Farb-Tags ──────────────────────────────────────────────────────────────────
TAG_COLORS = {
    # Classic Scan
    "INFO":        ("#4fc3f7", None),   # hellblau
    "OK":          ("#81c784", None),   # grün
    "WARN":        ("#ffb74d", None),   # amber
    "ERR":         ("#e57373", None),   # rot
    "DIM":         ("#78909c", None),   # grau
    # Agent Mode
    "AGENT_ORCH":  ("#ce93d8", None),   # lila  — OrchestratorAgent
    "AGENT_RECON": ("#64b5f6", None),   # blau  — ReconAgent
    "AGENT_VULN":  ("#ffb74d", None),   # orange — VulnAgent
    "AGENT_REMED": ("#81c784", None),   # grün  — RemediationAgent
    "AGENT_ERR":   ("#e57373", None),   # rot   — Fehler
}

AGENT_TAG_MAP = {
    "OrchestratorAgent": "AGENT_ORCH",
    "ReconAgent":        "AGENT_RECON",
    "VulnAgent":         "AGENT_VULN",
    "RemediationAgent":  "AGENT_REMED",
}

MODELS_OPENAI   = ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4o", "gpt-4.1"]
MODELS_CLAUDE   = ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"]
LANGUAGES       = ["de", "en", "es"]

BG   = "#1a1a2e"   # Hintergrund dunkel
BG2  = "#16213e"   # Zweiter Hintergrund
BG3  = "#0f3460"   # Akzent
FG   = "#e0e0e0"   # Text
ACC  = "#e94560"   # Akzentfarbe


class GhostVenumApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("GhostVenumAI v2.0 — Agent Edition")
        self.geometry("1120x740")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self._cfg     = self._load_config()
        self._scan_output  = ""
        self._agent_output = ""

        style = ttk.Style(self)
        style.theme_use("clam")
        self._apply_theme(style)

        i18n.set_language(self._cfg.get("language", "de"))
        self._build_ui()

    # ── Config ─────────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_config(self):
        try:
            with open("config.json", "w", encoding="utf-8") as f:
                json.dump(self._cfg, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log_classic(f"Config-Fehler: {e}", "ERR")

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _apply_theme(self, style: ttk.Style):
        style.configure(".",          background=BG,  foreground=FG,  font=("Segoe UI", 10))
        style.configure("TNotebook",  background=BG2, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=FG,
                        padding=[12, 6], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", ACC)],
                  foreground=[("selected", "#ffffff")])
        style.configure("TFrame",     background=BG)
        style.configure("TLabel",     background=BG,  foreground=FG)
        style.configure("TButton",    background=BG3, foreground=FG, padding=6,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("TButton", background=[("active", ACC)])
        style.configure("TEntry",     fieldbackground=BG2, foreground=FG,
                        insertcolor=FG, borderwidth=1, relief="solid")
        style.configure("TCombobox",  fieldbackground=BG2, foreground=FG,
                        selectbackground=BG3)
        style.configure("TCheckbutton", background=BG, foreground=FG)

    # ── UI aufbauen ────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=BG3, height=48)
        hdr.pack(fill="x", side="top")
        tk.Label(hdr, text="👻 GhostVenumAI v2.0 — Agent Edition",
                 bg=BG3, fg="#ffffff",
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=16, pady=10)
        tk.Label(hdr, text="Defensives Netzwerk-Analyse-Tool",
                 bg=BG3, fg="#b0bec5", font=("Segoe UI", 9)).pack(side="left", padx=4)

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        tab_classic = ttk.Frame(nb)
        tab_agents  = ttk.Frame(nb)
        nb.add(tab_classic, text=i18n.get("tab_classic"))
        nb.add(tab_agents,  text=i18n.get("tab_agents"))

        self._build_classic_tab(tab_classic)
        self._build_agent_tab(tab_agents)

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 1: Classic Scan
    # ══════════════════════════════════════════════════════════════════════════

    def _build_classic_tab(self, parent: ttk.Frame):
        # Eingabe-Bereich
        top = ttk.Frame(parent)
        top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text=i18n.get("target_label")).grid(row=0, column=0, sticky="w", padx=4)
        self.var_target_c = tk.StringVar(value=self._cfg.get("target", "192.168.178.1"))
        ttk.Entry(top, textvariable=self.var_target_c, width=30).grid(row=0, column=1, padx=6, sticky="w")

        ttk.Label(top, text=i18n.get("args_label")).grid(row=0, column=2, sticky="w", padx=4)
        self.var_args = tk.StringVar(value=self._cfg.get("nmap_args", "-sS -T4 -v -sV"))
        ttk.Entry(top, textvariable=self.var_args, width=28).grid(row=0, column=3, padx=6, sticky="w")

        ttk.Label(top, text=i18n.get("model_label")).grid(row=0, column=4, sticky="w", padx=4)
        self.var_model_c = tk.StringVar(value=self._cfg.get("openai_model", "gpt-4o-mini"))
        ttk.Combobox(top, textvariable=self.var_model_c, values=MODELS_OPENAI, width=16,
                     state="readonly").grid(row=0, column=5, padx=6)

        # Buttons
        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", padx=12, pady=4)

        ttk.Button(btn_row, text=i18n.get("btn_scan"),
                   command=self._on_classic_scan).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_gpt"),
                   command=self._on_gpt_analysis).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_sysinfo"),
                   command=self._on_sysinfo).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_save"),
                   command=self._on_save_classic).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_open_output"),
                   command=lambda: self._open_folder("output")).pack(side="left", padx=4)

        # Sprache / API-Key
        right = ttk.Frame(btn_row)
        right.pack(side="right")
        ttk.Button(right, text=i18n.get("btn_set_key"),
                   command=self._on_set_openai_key).pack(side="left", padx=4)
        self.var_lang = tk.StringVar(value=self._cfg.get("language", "de"))
        lang_cb = ttk.Combobox(right, textvariable=self.var_lang,
                                values=LANGUAGES, width=4, state="readonly")
        lang_cb.pack(side="left", padx=4)
        lang_cb.bind("<<ComboboxSelected>>", self._on_lang_change)

        # Log-Ausgabe
        log_frame = tk.Frame(parent, bg=BG2, bd=1, relief="sunken")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(4, 10))

        self.log_classic = tk.Text(log_frame, bg=BG2, fg=FG, insertbackground=FG,
                                   font=("Courier New", 10), state="disabled",
                                   wrap="word", relief="flat")
        sb_c = ttk.Scrollbar(log_frame, command=self.log_classic.yview)
        self.log_classic.configure(yscrollcommand=sb_c.set)
        sb_c.pack(side="right", fill="y")
        self.log_classic.pack(side="left", fill="both", expand=True)

        self._configure_tags(self.log_classic)
        self._log_classic("GhostVenumAI v2.0 gestartet. Ziel eingeben und Scan starten.", "INFO")

    # ══════════════════════════════════════════════════════════════════════════
    # Tab 2: Agent Mode
    # ══════════════════════════════════════════════════════════════════════════

    def _build_agent_tab(self, parent: ttk.Frame):
        # Eingabe
        top = ttk.Frame(parent)
        top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text=i18n.get("target_label")).grid(row=0, column=0, sticky="w", padx=4)
        self.var_target_a = tk.StringVar(value=self._cfg.get("target", "192.168.178.1"))
        ttk.Entry(top, textvariable=self.var_target_a, width=30).grid(row=0, column=1, padx=6, sticky="w")

        ttk.Label(top, text="Claude-Modell:").grid(row=0, column=2, sticky="w", padx=4)
        self.var_model_a = tk.StringVar(value=self._cfg.get("claude_model", "claude-sonnet-4-6"))
        ttk.Combobox(top, textvariable=self.var_model_a, values=MODELS_CLAUDE, width=28,
                     state="readonly").grid(row=0, column=3, padx=6)

        # Agent-Checkboxen
        chk_frame = ttk.Frame(parent)
        chk_frame.pack(fill="x", padx=12, pady=2)
        self.var_use_recon = tk.BooleanVar(value=True)
        self.var_use_vuln  = tk.BooleanVar(value=True)
        self.var_use_remed = tk.BooleanVar(value=True)
        ttk.Label(chk_frame, text="Agents:").pack(side="left", padx=(0, 8))
        ttk.Checkbutton(chk_frame, text="ReconAgent",       variable=self.var_use_recon).pack(side="left", padx=6)
        ttk.Checkbutton(chk_frame, text="VulnAgent",        variable=self.var_use_vuln).pack(side="left", padx=6)
        ttk.Checkbutton(chk_frame, text="RemediationAgent", variable=self.var_use_remed).pack(side="left", padx=6)

        # Buttons
        btn_row = ttk.Frame(parent)
        btn_row.pack(fill="x", padx=12, pady=4)

        ttk.Button(btn_row, text=i18n.get("btn_full_analysis"),
                   command=self._on_agent_run).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_save"),
                   command=self._on_save_agent).pack(side="left", padx=4)
        ttk.Button(btn_row, text=i18n.get("btn_open_output"),
                   command=lambda: self._open_folder("output")).pack(side="left", padx=4)
        ttk.Button(btn_row, text="🔑 Anthropic Key",
                   command=self._on_set_anthropic_key).pack(side="left", padx=4)

        # Log-Ausgabe
        log_frame = tk.Frame(parent, bg=BG2, bd=1, relief="sunken")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(4, 10))

        self.log_agents = tk.Text(log_frame, bg=BG2, fg=FG, insertbackground=FG,
                                  font=("Courier New", 10), state="disabled",
                                  wrap="word", relief="flat")
        sb_a = ttk.Scrollbar(log_frame, command=self.log_agents.yview)
        self.log_agents.configure(yscrollcommand=sb_a.set)
        sb_a.pack(side="right", fill="y")
        self.log_agents.pack(side="left", fill="both", expand=True)

        self._configure_tags(self.log_agents)
        self._log_agents("OrchestratorAgent", "Agent Mode bereit. Ziel eingeben und Vollanalyse starten.")

    # ── Hilfsmethoden ─────────────────────────────────────────────────────────

    def _configure_tags(self, widget: tk.Text):
        for tag, (fg, bg) in TAG_COLORS.items():
            kw = {"foreground": fg}
            if bg:
                kw["background"] = bg
            widget.tag_configure(tag, **kw)

    def _log_classic(self, msg: str, tag: str = "INFO"):
        self._append_to_log(self.log_classic, msg, tag)

    def _log_agents(self, agent_name: str, msg: str):
        tag = AGENT_TAG_MAP.get(agent_name, "INFO")
        prefix = f"[{agent_name}] " if agent_name else ""
        self._append_to_log(self.log_agents, prefix + msg, tag)

    def _append_to_log(self, widget: tk.Text, msg: str, tag: str):
        def _do():
            widget.configure(state="normal")
            widget.insert("end", msg + "\n", tag)
            widget.see("end")
            widget.configure(state="disabled")
        self.after(0, _do)

    def _bg(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def _open_folder(self, path: str):
        abs_path = os.path.abspath(path)
        os.makedirs(abs_path, exist_ok=True)
        if sys.platform == "linux":
            import subprocess
            subprocess.Popen(["xdg-open", abs_path])

    # ── Classic Tab — Events ──────────────────────────────────────────────────

    def _on_classic_scan(self):
        target = self.var_target_c.get().strip()
        if not target:
            messagebox.showwarning("Fehler", i18n.get("msg_no_target"))
            return

        self._cfg["target"]    = target
        self._cfg["nmap_args"] = self.var_args.get().strip()
        self._save_config()

        def work():
            self._log_classic(f"{i18n.get('msg_scan_start')} Ziel: {target}", "INFO")
            output = run_nmap_scan(target, self.var_args.get().strip())
            self._scan_output = output
            self._log_classic(output, "DIM")
            self._log_classic(i18n.get("msg_scan_done"), "OK")

        self._bg(work)

    def _on_gpt_analysis(self):
        if not self._scan_output:
            self._log_classic(i18n.get("msg_gpt_nodata"), "WARN")
            return

        model = self.var_model_c.get()
        self._cfg["openai_model"] = model
        self._save_config()

        def work():
            self._log_classic(i18n.get("msg_gpt_start"), "INFO")
            try:
                path = analyze_scan_with_gpt(self._scan_output, model=model)
                self._log_classic(f"{i18n.get('msg_gpt_done')} {path}", "OK")
            except Exception as e:
                self._log_classic(f"GPT-Fehler: {e}", "ERR")

        self._bg(work)

    def _on_sysinfo(self):
        def work():
            info = collect_system_info()
            lines = [f"  {k}: {v}" for k, v in info.items()]
            self._log_classic("System-Info:\n" + "\n".join(lines), "INFO")
        self._bg(work)

    def _on_save_classic(self):
        if not self._scan_output:
            self._log_classic("Kein Scan-Output zum Speichern.", "WARN")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Textdateien", "*.txt"), ("Alle Dateien", "*.*")],
            initialfile="ghostvenumai_report.txt"
        )
        if path:
            create_report(self._scan_output, path)
            self._log_classic(f"{i18n.get('msg_report_saved')} {path}", "OK")

    def _on_set_openai_key(self):
        key = simpledialog.askstring(
            i18n.get("dialog_key_title"),
            i18n.get("dialog_key_prompt"),
            show="*"
        )
        if key:
            self._cfg["openai_key"] = key.strip()
            self._save_config()
            self._log_classic("OpenAI API-Key gespeichert.", "OK")

    def _on_lang_change(self, _event=None):
        lang = self.var_lang.get()
        i18n.set_language(lang)
        self._cfg["language"] = lang
        self._save_config()

    # ── Agent Tab — Events ────────────────────────────────────────────────────

    def _on_agent_run(self):
        target = self.var_target_a.get().strip()
        if not target:
            messagebox.showwarning("Fehler", i18n.get("msg_no_target"))
            return

        self._cfg["target"]       = target
        self._cfg["claude_model"] = self.var_model_a.get()
        self._save_config()

        def work():
            self._log_agents("OrchestratorAgent",
                             f"{i18n.get('msg_agents_start')} {target}")
            try:
                from modules.agents.orchestrator import stream_analysis
                for msg in stream_analysis(target):
                    agent   = msg.get("agent", "")
                    content = msg.get("content", "")
                    if content.strip():
                        self._log_agents(agent, content)
                        self._agent_output += f"[{agent}] {content}\n"
                self._log_agents("OrchestratorAgent", i18n.get("msg_agents_done"))
            except Exception as e:
                self._log_agents("OrchestratorAgent", f"FEHLER: {e}")

        self._bg(work)

    def _on_save_agent(self):
        if not self._agent_output:
            self._log_agents("OrchestratorAgent", "Kein Agent-Output zum Speichern.", )
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Textdateien", "*.txt"), ("Alle Dateien", "*.*")],
            initialfile="agent_analysis.txt"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._agent_output)
            self._log_agents("OrchestratorAgent", f"Agent-Output gespeichert: {path}")

    def _on_set_anthropic_key(self):
        key = simpledialog.askstring(
            "Anthropic API-Key",
            "Anthropic API-Key eingeben (sk-ant-...):",
            show="*"
        )
        if key:
            self._cfg["anthropic_key"] = key.strip()
            self._save_config()
            self._log_agents("OrchestratorAgent", "Anthropic API-Key gespeichert.")


# ── Einstiegspunkt ─────────────────────────────────────────────────────────────

def launch():
    app = GhostVenumApp()
    app.mainloop()

if __name__ == "__main__":
    launch()
