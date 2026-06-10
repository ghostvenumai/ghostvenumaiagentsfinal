// auth.js — GhostVenumAI Login-Gate & Session-Handling
// Bindet das RBAC-gesicherte Backend an die Web-UI an, ohne dass jeder
// einzelne fetch()-/EventSource-Aufruf angepasst werden muss:
//   • window.fetch wird umhüllt und injiziert den X-Session-Token-Header
//   • EventSource wird umhüllt und hängt das Token als ?token=… an (SSE)
//   • 401-Antworten lösen automatisch das Login-Overlay aus
// Das Token liegt in sessionStorage (wird beim Schließen des Tabs verworfen).
(function () {
  "use strict";

  const TOKEN_KEY = "gva_token";
  const ORIGIN = window.location.origin;

  const getToken = () => sessionStorage.getItem(TOKEN_KEY) || "";
  const setToken = (t) => sessionStorage.setItem(TOKEN_KEY, t);
  const clearToken = () => sessionStorage.removeItem(TOKEN_KEY);

  // Nur eigene API-Aufrufe bekommen das Token (keine fremden Origins/CDNs).
  function isSameOrigin(url) {
    try {
      const u = new URL(url, ORIGIN);
      return u.origin === ORIGIN && u.pathname.startsWith("/api/");
    } catch (_) {
      return typeof url === "string" && url.startsWith("/api/");
    }
  }

  // ── fetch() umhüllen ─────────────────────────────────────────────────────
  const _fetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    init = init || {};
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const token = getToken();

    if (token && isSameOrigin(url)) {
      const headers = new Headers(init.headers || (input && input.headers) || {});
      headers.set("X-Session-Token", token);
      init.headers = headers;
    }

    return _fetch(input, init).then((res) => {
      // Login-Routen selbst nicht abfangen
      if (res.status === 401 && isSameOrigin(url) && !url.includes("/api/login")) {
        clearToken();
        showLogin();
      }
      return res;
    });
  };

  // ── EventSource umhüllen (SSE kann keine Header setzen) ───────────────────
  const _EventSource = window.EventSource;
  if (_EventSource) {
    window.EventSource = function (url, config) {
      const token = getToken();
      if (token && isSameOrigin(url)) {
        url += (url.indexOf("?") === -1 ? "?" : "&") + "token=" + encodeURIComponent(token);
      }
      return new _EventSource(url, config);
    };
    window.EventSource.prototype = _EventSource.prototype;
    window.EventSource.CONNECTING = _EventSource.CONNECTING;
    window.EventSource.OPEN = _EventSource.OPEN;
    window.EventSource.CLOSED = _EventSource.CLOSED;
  }

  // ── Login-Overlay ────────────────────────────────────────────────────────
  function buildOverlay() {
    if (document.getElementById("gva-login-overlay")) return;
    const ov = document.createElement("div");
    ov.id = "gva-login-overlay";
    ov.style.cssText =
      "position:fixed;inset:0;z-index:99999;display:none;align-items:center;" +
      "justify-content:center;background:rgba(10,12,18,.92);backdrop-filter:blur(4px);";
    ov.innerHTML =
      '<form id="gva-login-form" style="background:#161b26;border:1px solid #2a3344;' +
      'border-radius:12px;padding:28px 26px;width:320px;font-family:system-ui,sans-serif;' +
      'color:#e6e9ef;box-shadow:0 10px 40px rgba(0,0,0,.5)">' +
      '<div style="font-size:20px;font-weight:700;margin-bottom:4px">👻 GhostVenumAI</div>' +
      '<div style="font-size:13px;color:#8b94a7;margin-bottom:18px">Anmeldung erforderlich</div>' +
      '<input id="gva-user" placeholder="Benutzername" autocomplete="username" ' +
      'style="width:100%;box-sizing:border-box;margin-bottom:10px;padding:10px;border-radius:8px;' +
      'border:1px solid #2a3344;background:#0e1219;color:#e6e9ef">' +
      '<input id="gva-pass" type="password" placeholder="Passwort" autocomplete="current-password" ' +
      'style="width:100%;box-sizing:border-box;margin-bottom:10px;padding:10px;border-radius:8px;' +
      'border:1px solid #2a3344;background:#0e1219;color:#e6e9ef">' +
      '<input id="gva-totp" placeholder="2FA-Code (falls aktiv)" inputmode="numeric" ' +
      'style="width:100%;box-sizing:border-box;margin-bottom:14px;padding:10px;border-radius:8px;' +
      'border:1px solid #2a3344;background:#0e1219;color:#e6e9ef">' +
      '<button type="submit" style="width:100%;padding:11px;border:0;border-radius:8px;' +
      'background:#7c3aed;color:#fff;font-weight:600;cursor:pointer">Anmelden</button>' +
      '<div id="gva-login-err" style="color:#ff6b6b;font-size:12px;margin-top:10px;min-height:16px"></div>' +
      "</form>";
    document.body.appendChild(ov);

    ov.querySelector("#gva-login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = ov.querySelector("#gva-login-err");
      err.textContent = "";
      const body = {
        username: ov.querySelector("#gva-user").value.trim(),
        password: ov.querySelector("#gva-pass").value,
        totp_code: ov.querySelector("#gva-totp").value.trim(),
      };
      try {
        const res = await _fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.token) {
          setToken(data.token);
          hideLogin();
          window.location.reload();
        } else {
          err.textContent = data.error || "Anmeldung fehlgeschlagen.";
        }
      } catch (_) {
        err.textContent = "Verbindungsfehler.";
      }
    });
  }

  function showLogin() {
    buildOverlay();
    const ov = document.getElementById("gva-login-overlay");
    if (ov) {
      ov.style.display = "flex";
      const u = document.getElementById("gva-user");
      if (u) u.focus();
    }
  }

  function hideLogin() {
    const ov = document.getElementById("gva-login-overlay");
    if (ov) ov.style.display = "none";
  }

  // Globaler Logout-Hook für die UI (optional in Buttons nutzbar)
  window.gvaLogout = async function () {
    try {
      await window.fetch("/api/logout", { method: "POST" });
    } catch (_) {}
    clearToken();
    showLogin();
  };

  // ── Beim Laden prüfen, ob eine gültige Session existiert ──────────────────
  document.addEventListener("DOMContentLoaded", async () => {
    buildOverlay();
    if (!getToken()) {
      showLogin();
      return;
    }
    try {
      const res = await _fetch("/api/whoami", {
        headers: { "X-Session-Token": getToken() },
      });
      if (!res.ok) {
        clearToken();
        showLogin();
      }
    } catch (_) {
      /* Backend nicht erreichbar — UI lädt, API-Aufrufe lösen ggf. Login aus */
    }
  });
})();
