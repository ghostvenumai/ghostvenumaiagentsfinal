# 👻 GhostVenumAI v2.0 — Agent Edition

> **Defensive network analysis platform with autonomous AI agents, persistent memory and before/after comparison.**

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Claude](https://img.shields.io/badge/Claude-Anthropic-purple?logo=anthropic)
![Flask](https://img.shields.io/badge/Web--GUI-Flask-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Screenshots

### 🔎 Classic Scan
![Classic Scan](screenshots/classic-scan.png)

### 🤖 Agent Mode — Live Analysis
![Agent Mode Start](screenshots/agent-mode-start.png)

### ✅ Agent Mode — Analysis Complete + Memory Diff
![Agent Mode Done](screenshots/agent-mode-done.png)

### 📊 History — Before/After Comparison
![History Diff](screenshots/history-diff.png)

---

## What is GhostVenumAI?

GhostVenumAI is a **defensive network security tool** that combines Nmap scanning with autonomous AI agents powered by **Claude (Anthropic)**. It runs fully locally, has a modern web GUI and a CLI.

**Purely defensive** — no exploit code, no brute force, no payloads. Only for systems you own or have explicit permission to scan.

---

## Key Features

### 🤖 4 Autonomous AI Agents (Claude)
| Agent | Task |
|---|---|
| **OrchestratorAgent** | Coordinates the full workflow, generates management summary |
| **ReconAgent** | Decides scan strategy automatically, runs Nmap |
| **VulnAgent** | Parses services, queries NVD CVE database (free, no key needed) |
| **RemediationAgent** | Generates fix commands per OS, saves remediation report |

### 🧠 Persistent Memory — Before/After Comparison
- Every scan is saved as JSON in `output/history/`
- On the next scan of the same target: automatic diff
- Shows: **NEW ports**, **CLOSED ports**, **NEW CVEs**, **RESOLVED CVEs**
- History tab in the GUI with visual timeline and color-coded diff view

### 🌐 Modern Web GUI (JavaScript + Flask)
- Dark theme, 4 tabs: Classic Scan / Agent Mode / Settings / History
- Live streaming agent log (Server-Sent Events)
- Progress steps: Recon → Vuln-Analysis → Remediation → Done
- No Electron, no heavy framework — pure HTML/CSS/JS

### 🔎 Classic Scan Mode
- Manual Nmap parameters
- Optional GPT analysis (OpenAI)
- Save reports as .txt

---

## Architecture

```
ghostvenumaiagents/
├── main.py                      # Entry point (Web-GUI + CLI)
├── app.py                       # Flask backend + SSE streaming
├── templates/index.html         # Web GUI
├── static/css/style.css         # Dark theme
├── static/js/app.js             # Frontend JavaScript
└── modules/
    ├── scanner.py               # Nmap execution (-sS → -sT fallback)
    ├── gpt_analysis.py          # OpenAI GPT analysis (Classic mode)
    ├── report.py                # Text report generator
    ├── system_info.py           # Hostname, IP, MAC, platform
    ├── auth.py                  # PBKDF2-HMAC-SHA256 + anti-brute-force
    ├── memory.py                # Persistent scan history + diff engine
    ├── i18n_quick.py            # DE / EN / ES
    └── agents/
        ├── orchestrator.py      # Coordinates all 3 agents + summary
        ├── recon_agent.py       # Claude + Nmap tools
        ├── vuln_agent.py        # Claude + NVD CVE API
        ├── remediation_agent.py # Claude + fix generator + report save
        └── run_agents.py        # Entry point for agent workflow
```

---

## Quick Start

### Requirements
- Python 3.10+
- Nmap installed (`sudo apt install nmap`)
- Anthropic API key (for Agent Mode)
- OpenAI API key (optional, for Classic GPT analysis)

### Install & Run

```bash
git clone https://github.com/ghostvenumai/ghostvenumai-agent-edition.git
cd ghostvenumai-agent-edition

pip install -r requirements.txt

cp config.example.json config.json
# Enter your API keys in config.json

python3 main.py
# Opens browser at http://localhost:5000
```

### CLI — Agent Mode (no GUI)

```bash
python3 main.py --agents --target 192.168.178.1
```

---

## How the Agent Workflow Works

```
User: "Analyze 192.168.178.1"
  │
  ▼
OrchestratorAgent
  ├─ Checks memory for previous scan of this target
  ├─ Handoff → ReconAgent
  │    ├─ ping_check(target)
  │    └─ nmap_scan(target, args)  ← decides strategy automatically
  ├─ Handoff → VulnAgent
  │    ├─ parse_services_from_scan(output)
  │    └─ lookup_cve(service, version)  ← NVD API, free
  ├─ Handoff → RemediationAgent
  │    ├─ generate_fix_commands(service, os_type)
  │    └─ save_remediation_report(content)  → output/remediation_*.txt
  ├─ Saves scan to memory  → output/history/*.json
  ├─ Generates diff vs. previous scan
  └─ Management Summary:
       "3 hosts found | 2 critical CVEs | Top action: update OpenSSH"
```

---

## Memory & Diff System

After each agent run, the full scan is saved:

```json
{
  "scan_id": "20260315_153000",
  "target": "192.168.178.1",
  "timestamp": "2026-03-15T15:30:00",
  "ports": [{"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1"}],
  "cves":  [{"cve_id": "CVE-2023-38408", "cvss": 9.8, "severity": "KRITISCH"}],
  "raw_scan": "...",
  "raw_cves": "...",
  "summary": "..."
}
```

On the next scan of the same target, a diff is generated:

| Status | Meaning |
|---|---|
| 🟢 NEW | Port or CVE appeared since last scan |
| 🔴 CLOSED | Port was closed since last scan |
| ✅ RESOLVED | CVE no longer found (patch applied) |
| ⬜ UNCHANGED | No change |

---

## API Keys

| Key | Used for | Where |
|---|---|---|
| `ANTHROPIC_API_KEY` | Agent Mode (all 4 agents) | env var or `config.json` |
| `OPENAI_API_KEY` | Classic GPT analysis | env var or `config.json` |

Priority: environment variable > config.json

---

## Ethical Usage

This tool is designed for **defensive security analysis only**:
- Only scan systems you own or have explicit written permission to scan
- No exploit generation, no payload creation, no brute force
- CVE lookup is informational only — no automated exploitation

---

## Built by

**Serkan Iazurlo** — [github.com/ghostvenumai](https://github.com/ghostvenumai)

*GhostVenumAI v2.0 Agent Edition — March 2026*
