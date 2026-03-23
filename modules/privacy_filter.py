# modules/privacy_filter.py
"""
PrivacyFilter — Anonymisiert sensible Daten aus Nmap-Output
bevor sie die KI-API erreichen.

Was anonymisiert wird:
  - IPv4-Adressen        → HOST_A, HOST_B, HOST_C, ...
  - IPv6-Adressen        → HOST_V6_A, HOST_V6_B, ...
  - MAC-Adressen         → [MAC ENTFERNT]
  - Hostnamen / FQDNs    → HOSTNAME_A, HOSTNAME_B, ...
  - Netzwerk-Ranges      → NET_A, NET_B, ...

Was NICHT anonymisiert wird (für KI-Analyse benötigt):
  - Port-Nummern
  - Dienst-Namen (ssh, http, mysql, ...)
  - Software-Versionen   (OpenSSH 8.9, Apache 2.4.51, ...)
  - CVE-IDs
  - Protokolle (tcp/udp)
  - Scan-Metadaten (Timing, Scan-Typ)

Nutzung:
    from modules.privacy_filter import PrivacyFilter
    pf = PrivacyFilter()
    anonymized = pf.anonymize(raw_nmap_output)
    # ... API-Aufruf mit anonymized ...
    result = pf.restore(api_response)   # echte Werte wieder einsetzen
"""

import re
from typing import Optional


# ── Regex-Muster ───────────────────────────────────────────────────────────────

_RE_IPV4 = re.compile(
    r"\b(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
)
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
    r"|\b[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
)
_RE_MAC = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b",
    re.IGNORECASE
)
# Hostnamen: mindestens zwei Segmente, kein reines Netz-Prefix
_RE_HOSTNAME = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
    r"[a-zA-Z]{2,}\b"
)
# Netzwerk-Ranges (x.x.x.x/y) werden bereits durch _RE_IPV4 erfasst,
# aber wir brauchen ein separates Mapping-Präfix
_RANGE_SUFFIX = re.compile(r"/\d{1,2}$")

# Bekannte öffentliche Domains, die nicht anonymisiert werden sollen
_PUBLIC_DOMAINS = {
    "nist.gov", "nvd.nist.gov", "github.com", "microsoft.com",
    "google.com", "ubuntu.com", "debian.org", "redhat.com",
    "apache.org", "openssl.org", "openssh.com",
}


def _label(prefix: str, index: int) -> str:
    """Erzeugt ein lesbares Label: HOST_A, HOST_B, ..., HOST_AA, ..."""
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if index < 26:
        return f"{prefix}_{letters[index]}"
    return f"{prefix}_{letters[index // 26 - 1]}{letters[index % 26]}"


class PrivacyFilter:
    """
    Zustandsbehafteter Filter: merkt sich alle Ersetzungen,
    damit restore() die Originale zurückschreiben kann.
    """

    def __init__(self):
        self._reset()

    def _reset(self):
        self._ip_map:       dict[str, str] = {}   # original → placeholder
        self._ip_rev:       dict[str, str] = {}   # placeholder → original
        self._host_map:     dict[str, str] = {}
        self._host_rev:     dict[str, str] = {}
        self._net_map:      dict[str, str] = {}   # für Ranges
        self._net_rev:      dict[str, str] = {}

    # ── Interne Hilfsmethoden ─────────────────────────────────────────────────

    def _get_ip_placeholder(self, ip: str) -> str:
        if ip not in self._ip_map:
            # Unterscheide Ranges von Einzeladressen
            if "/" in ip:
                idx   = len(self._net_map)
                label = _label("NET", idx)
                self._net_map[ip]   = label
                self._net_rev[label] = ip
                return label
            else:
                idx   = len(self._ip_map)
                label = _label("HOST", idx)
                self._ip_map[ip]   = label
                self._ip_rev[label] = ip
        return self._ip_map.get(ip, ip)

    def _get_host_placeholder(self, hostname: str) -> str:
        low = hostname.lower()
        # Öffentliche Domains nicht anonymisieren
        for pub in _PUBLIC_DOMAINS:
            if low == pub or low.endswith("." + pub):
                return hostname
        if hostname not in self._host_map:
            idx   = len(self._host_map)
            label = _label("HOSTNAME", idx)
            self._host_map[hostname]  = label
            self._host_rev[label]     = hostname
        return self._host_map[hostname]

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def anonymize(self, text: str, reset: bool = True) -> str:
        """
        Ersetzt alle sensiblen Daten im Text durch Platzhalter.

        Args:
            text:  Roher Nmap-Output oder sonstiger Scan-Text
            reset: True (Standard) = Mapping für jeden neuen Scan zurücksetzen.
                   False = Mapping beibehalten (nützlich für mehrteilige Texte).

        Returns:
            Anonymisierter Text.
        """
        if reset:
            self._reset()

        result = text

        # 1. MAC-Adressen komplett entfernen
        result = _RE_MAC.sub("[MAC ENTFERNT]", result)

        # 2. Hostnamen VOR IPs ersetzen (damit FQDNs nicht durch IP-Regex zerstört werden)
        def replace_hostname(m: re.Match) -> str:
            return self._get_host_placeholder(m.group(0))

        result = _RE_HOSTNAME.sub(replace_hostname, result)

        # 3. IPv6
        def replace_ipv6(m: re.Match) -> str:
            val = m.group(0)
            if val not in self._ip_map:
                idx   = len(self._ip_map)
                label = _label("HOST_V6", idx)
                self._ip_map[val]   = label
                self._ip_rev[label] = val
            return self._ip_map[val]

        result = _RE_IPV6.sub(replace_ipv6, result)

        # 4. IPv4 (inkl. Ranges)
        def replace_ipv4(m: re.Match) -> str:
            return self._get_ip_placeholder(m.group(0))

        result = _RE_IPV4.sub(replace_ipv4, result)

        return result

    def restore(self, text: str) -> str:
        """
        Setzt in einem KI-generierten Text alle Platzhalter durch
        die ursprünglichen Werte zurück.

        Args:
            text: Text mit Platzhaltern (z.B. KI-Antwort)

        Returns:
            Text mit echten IPs, Hostnamen usw.
        """
        result = text

        # Längste Labels zuerst ersetzen (verhindert Teilersetzungen)
        all_replacements: dict[str, str] = {
            **self._ip_rev,
            **self._net_rev,
            **self._host_rev,
        }
        for placeholder, original in sorted(
            all_replacements.items(), key=lambda x: len(x[0]), reverse=True
        ):
            result = result.replace(placeholder, original)

        return result

    def get_mapping(self) -> dict:
        """
        Gibt das aktuelle Mapping zurück (für Debugging / Logging).

        Returns:
            Dict mit 'ips', 'hostnames', 'networks'
        """
        return {
            "ips":       dict(self._ip_map),
            "hostnames": dict(self._host_map),
            "networks":  dict(self._net_map),
        }

    def summary(self) -> str:
        """Kurze Zusammenfassung wieviel anonymisiert wurde."""
        n_ip   = len(self._ip_map)
        n_host = len(self._host_map)
        n_net  = len(self._net_map)
        return (
            f"PrivacyFilter: {n_ip} IP(s), "
            f"{n_host} Hostname(s), "
            f"{n_net} Netzwerk-Range(s) anonymisiert."
        )
