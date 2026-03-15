# modules/scanner.py
import os
import shlex
import shutil
import subprocess

NMAP_BIN = shutil.which("nmap") or "/usr/bin/nmap"

def _run(cmd_list, timeout=900):
    try:
        p = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, f"[!] nmap Timeout nach {timeout}s\n{e.stdout or ''}"
    except FileNotFoundError:
        return 127, f"[!] nmap nicht gefunden unter: {NMAP_BIN}"
    except Exception as e:
        return 1, f"[!] Unerwarteter Fehler beim Ausführen: {e}"

def _args_list(args_str: str):
    return shlex.split(args_str or "")

def _contains_syn(args_list):
    return "-sS" in args_list

def run_nmap_scan(target: str, args_str: str) -> str:
    """
    Führt nmap aus und gibt IMMER den vollständigen Textoutput zurück.
    Strategie:
      - Wenn -sS gesetzt:
          1) mit sudo -n versuchen (falls sudoers-Regel besteht)
          2) ohne sudo versuchen (falls setcap konfiguriert ist)
          3) bei 'requires root' → Fallback ohne -sS (entspricht -sT)
      - Ohne -sS: direkt normal ausführen
    """
    args = _args_list(args_str)
    if not target:
        return "[!] Kein Ziel übergeben."

    base_cmd = [NMAP_BIN] + args + [target]

    if _contains_syn(args):
        sudo_cmd = ["sudo", "-n"] + base_cmd
        rc, out = _run(sudo_cmd)
        if rc == 0:
            return out

        rc2, out2 = _run(base_cmd)
        if rc2 == 0:
            return out2

        if "requires root" in out2.lower() or "quitting!" in out2.lower():
            fallback_args = [a for a in args if a != "-sS"]
            fallback_cmd = [NMAP_BIN] + fallback_args + [target]
            rc3, out3 = _run(fallback_cmd)
            header = "[i] Fallback aktiv: -sT statt -sS (keine Root-Rechte für SYN-Scan)\n"
            return header + out3

        return out2

    rc, out = _run(base_cmd)
    return out
