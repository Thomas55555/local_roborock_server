"""Standalone admin/dashboard adapter routes."""

from __future__ import annotations

import io
import json
from textwrap import dedent
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .security import verify_password


def _admin_login_html() -> str:
    return dedent(
        """\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:420px;margin:12vh auto">
        <h1>Roborock Local Server</h1>
        <p>Sign in to manage the stack.</p>
        <input id="password" type="password" placeholder="Admin password" style="width:100%;padding:10px" />
        <button id="login" style="width:100%;padding:10px;margin-top:8px">Sign In</button>
        <pre id="result"></pre>
        <script>
        document.getElementById("login").addEventListener("click", async () => {
          const response = await fetch("/admin/api/login", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({password: document.getElementById("password").value})
          });
          const payload = await response.json().catch(() => ({error: "Invalid response"}));
          if (!response.ok) {
            document.getElementById("result").textContent = payload.error || "Sign-in failed";
            return;
          }
          window.location.reload();
        });
        </script></body></html>
        """
    )


def _admin_dashboard_html(project_support: dict[str, Any]) -> str:
    support_payload = json.dumps(project_support)
    return dedent(
        f"""\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:1100px;margin:20px auto;padding:0 12px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Roborock Local Server</h1>
          <div><span id="overall">Loading</span> <button id="logout">Sign Out</button></div>
        </div>
        <section><h2 id="supportTitle"></h2><p id="supportText"></p><div id="supportLinks" style="display:flex;gap:12px;flex-wrap:wrap"></div></section>
        <section><h2>Cloud Import</h2>
          <input id="email" placeholder="email@example.com" />
          <button id="sendCode">Send Code</button>
          <input id="code" placeholder="Email code" style="margin-top:8px" />
          <button id="fetchData">Fetch Data</button>
          <pre id="cloudResult">No cloud request yet.</pre>
        </section>
        <section><h2>Pair Device</h2>
          <button id="pairDevice">Pair Device</button>
          <div id="pairingMessage" style="margin-top:8px">No pairing session started.</div>
          <div id="pairingTarget" style="margin-top:8px;color:#555"></div>
          <div id="pairingSteps" style="display:grid;gap:6px;margin-top:12px"></div>
        </section>
        <section><h2>iPhone MITM Intercept</h2>
          <div id="mitmState">Unknown</div>
          <div id="mitmMeta" style="margin-top:8px;color:#555"></div>
          <div id="mitmLinks" style="display:flex;gap:12px;flex-wrap:wrap;margin-top:8px"></div>
          <div id="mitmQrWrap" style="display:none;margin-top:8px">
            <img
              id="mitmQrImage"
              alt="WireGuard QR"
              style="max-width:300px;width:100%;height:auto;border:1px solid #ddd;padding:6px;background:#fff"
            />
          </div>
          <pre id="mitmHints" style="margin-top:8px;white-space:pre-wrap"></pre>
          <pre id="mitmError" style="margin-top:8px"></pre>
        </section>
        <section><h2>Health</h2><pre id="health"></pre></section>
        <section><h2>Vacuums</h2><pre id="vacuums"></pre></section>
        <script>
        const support = {support_payload};
        let cloudSessionId = "";
        document.getElementById("supportTitle").textContent = support.title || "Support This Project";
        document.getElementById("supportText").textContent = support.text || "";
        const supportLinks = document.getElementById("supportLinks");
        for (const link of (support.links || [])) {{
          const anchor = document.createElement("a");
          anchor.href = link.url;
          anchor.target = "_blank";
          anchor.rel = "noreferrer";
          anchor.textContent = link.label || link.url;
          anchor.style.display = "inline-block";
          anchor.style.padding = "8px 12px";
          anchor.style.border = "1px solid #999";
          anchor.style.textDecoration = "none";
          anchor.style.color = "inherit";
          supportLinks.appendChild(anchor);
        }}
        async function fetchJson(url, options) {{
          const response = await fetch(url, options);
          const raw = await response.text();
          const payload = raw ? JSON.parse(raw) : {{}};
          if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
          return payload;
        }}
        function renderPairing(pairing) {{
          const payload = pairing || {{}};
          const steps = Array.isArray(payload.steps) ? payload.steps : [];
          const target = payload.target || {{}};
          document.getElementById("pairingMessage").textContent = payload.message || "No pairing session started.";
          const targetIdentity = target.name || target.did || target.duid || "";
          document.getElementById("pairingTarget").textContent = targetIdentity
            ? `Tracking: ${{targetIdentity}}`
            : "";
          const container = document.getElementById("pairingSteps");
          container.innerHTML = "";
          for (const step of steps) {{
            const row = document.createElement("div");
            const detail = step.detail ? ` ${{step.detail}}` : "";
            row.innerHTML = `${{step.checked ? "&#10003;" : "&#9633;"}} ${{step.label}}${{detail}}`;
            container.appendChild(row);
          }}
        }}
        function renderMitm(mitm) {{
          const payload = mitm || {{}};
          const running = Boolean(payload.running);
          const available = payload.available !== false;
          const stateSuffix = available ? "" : " (script missing)";
          document.getElementById("mitmState").textContent = `${{running ? "Running" : "Stopped"}}${{stateSuffix}}`;
          const meta = [];
          if (payload.pid) meta.push(`PID: ${{payload.pid}}`);
          if (payload.log_path) meta.push(`Log: ${{payload.log_path}}`);
          document.getElementById("mitmMeta").textContent = meta.join(" | ");
          const links = document.getElementById("mitmLinks");
          links.innerHTML = "";
          const addLink = (href, label) => {{
            if (!href) return;
            const anchor = document.createElement("a");
            anchor.href = href;
            anchor.target = "_blank";
            anchor.rel = "noreferrer";
            anchor.textContent = label;
            links.appendChild(anchor);
          }};
          const endpointHost = encodeURIComponent(window.location.hostname || "");
          const wireguardConfigHref = payload.wireguard_config_url
            ? `${{payload.wireguard_config_url}}?endpoint_host=${{endpointHost}}`
            : "";
          const wireguardQrHref = payload.wireguard_qr_url
            ? `${{payload.wireguard_qr_url}}?endpoint_host=${{endpointHost}}`
            : "";
          addLink(wireguardConfigHref, "Open WireGuard Config (Docker-safe)");
          addLink(wireguardQrHref, "Open WireGuard QR");
          addLink(payload.viewer_url || "", "Open mitmweb Logs");
          for (const url of (payload.detected_urls || [])) {{
            addLink(url, url);
          }}
          const qrWrap = document.getElementById("mitmQrWrap");
          const qrImage = document.getElementById("mitmQrImage");
          if (wireguardQrHref) {{
            qrWrap.style.display = "block";
            if ((qrImage.dataset.src || "") !== wireguardQrHref) {{
              qrImage.src = wireguardQrHref;
              qrImage.dataset.src = wireguardQrHref;
            }}
          }} else {{
            qrWrap.style.display = "none";
            qrImage.removeAttribute("src");
            qrImage.dataset.src = "";
          }}
          const hints = Array.isArray(payload.setup_hints) ? payload.setup_hints : [];
          document.getElementById("mitmHints").textContent = hints.length
            ? hints.join("\\n")
            : "MITM is managed outside this server. Open admin via server LAN IP/hostname (not localhost), then use the links above for logs and profiles.";
          document.getElementById("mitmError").textContent = payload.last_error || "";
        }}
        async function refresh() {{
          const status = await fetchJson("/admin/api/status");
          document.getElementById("overall").textContent = status.health.overall_ok ? "Healthy" : "Needs Attention";
          renderPairing(status.pairing);
          renderMitm(status.mitm_intercept);
          document.getElementById("health").textContent = JSON.stringify(status.health, null, 2);
          const vacuums = await fetchJson("/admin/api/vacuums");
          document.getElementById("vacuums").textContent = JSON.stringify(vacuums.vacuums, null, 2);
        }}
        document.getElementById("sendCode").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/cloud/request-code", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{email: document.getElementById("email").value}})
            }});
            cloudSessionId = payload.session_id || "";
            document.getElementById("cloudResult").textContent = JSON.stringify(payload, null, 2);
          }} catch (error) {{
            document.getElementById("cloudResult").textContent = error.message;
          }}
        }});
        document.getElementById("fetchData").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/cloud/submit-code", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{session_id: cloudSessionId, code: document.getElementById("code").value}})
            }});
            cloudSessionId = "";
            document.getElementById("cloudResult").textContent = JSON.stringify(payload, null, 2);
            await refresh();
          }} catch (error) {{
            document.getElementById("cloudResult").textContent = error.message;
          }}
        }});
        document.getElementById("pairDevice").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/pair-device", {{method:"POST"}});
            renderPairing(payload.pairing);
          }} catch (error) {{
            document.getElementById("pairingMessage").textContent = error.message;
          }}
        }});
        document.getElementById("logout").addEventListener("click", async () => {{
          await fetch("/admin/api/logout", {{method:"POST"}});
          window.location.reload();
        }});
        refresh().catch((error) => document.getElementById("overall").textContent = error.message);
        setInterval(() => refresh().catch(() => {{}}), 2000);
        </script></body></html>
        """
    )


def _admin_mitm_logs_html() -> str:
    return dedent(
        """\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:1100px;margin:20px auto;padding:0 12px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <h1 style="margin:0">MITM Logs</h1>
          <div style="display:flex;gap:8px;align-items:center">
            <label>Lines <input id="lines" type="number" value="400" min="50" max="1200" style="width:90px" /></label>
            <button id="refresh">Refresh</button>
            <a href="/admin">Back to Admin</a>
          </div>
        </div>
        <div id="summary" style="margin-top:10px;color:#555"></div>
        <pre id="hints" style="white-space:pre-wrap;border:1px solid #ddd;padding:10px;min-height:64px"></pre>
        <pre id="log" style="white-space:pre-wrap;border:1px solid #ddd;padding:10px;min-height:420px;max-height:70vh;overflow:auto"></pre>
        <script>
        async function fetchJson(url) {
          const response = await fetch(url);
          const raw = await response.text();
          const payload = raw ? JSON.parse(raw) : {};
          if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
          return payload;
        }
        async function refresh() {
          const lines = Math.max(50, Math.min(1200, Number(document.getElementById("lines").value) || 400));
          const payload = await fetchJson(`/admin/api/mitm/log-tail?lines=${lines}`);
          const hintLines = Array.isArray(payload.setup_hints) ? payload.setup_hints : [];
          const urls = Array.isArray(payload.detected_urls) ? payload.detected_urls : [];
          const logLines = Array.isArray(payload.lines) ? payload.lines : [];
          document.getElementById("summary").textContent =
            `Path: ${payload.path || "<unknown>"} | Lines shown: ${logLines.length}`;
          document.getElementById("hints").textContent =
            hintLines.length
              ? hintLines.join("\\n")
              : "No setup hints detected yet. Start MITM and wait for wireguard startup output.";
          document.getElementById("log").textContent = logLines.join("\\n");
          if (urls.length) {
            document.getElementById("summary").textContent += ` | URLs: ${urls.join(", ")}`;
          }
        }
        document.getElementById("refresh").addEventListener("click", () => refresh().catch((err) => {
          document.getElementById("summary").textContent = err.message;
        }));
        refresh().catch((err) => {
          document.getElementById("summary").textContent = err.message;
        });
        setInterval(() => refresh().catch(() => {}), 2000);
        </script></body></html>
        """
    )


def register_standalone_admin_routes(
    *,
    app: FastAPI,
    supervisor: Any,
    project_support: dict[str, Any],
) -> None:
    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request) -> HTMLResponse:
        if not supervisor._authenticated(request):
            return HTMLResponse(_admin_login_html())
        return HTMLResponse(_admin_dashboard_html(project_support))

    @app.get("/admin/mitm/logs", response_class=HTMLResponse)
    async def admin_mitm_logs_page(request: Request) -> HTMLResponse:
        supervisor._require_admin(request)
        return HTMLResponse(_admin_mitm_logs_html())

    @app.post("/admin/api/login")
    async def admin_login(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        password = str((body or {}).get("password") or "")
        if not verify_password(password, supervisor.config.admin.password_hash):
            return JSONResponse({"error": "Invalid password"}, status_code=401)
        response = JSONResponse({"ok": True})
        response.set_cookie(
            supervisor.session_manager.cookie_name,
            supervisor.session_manager.issue(),
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
            max_age=supervisor.config.admin.session_ttl_seconds,
            path="/",
        )
        return response

    @app.post("/admin/api/logout")
    async def admin_logout() -> JSONResponse:
        response = JSONResponse({"ok": True})
        response.delete_cookie(supervisor.session_manager.cookie_name, path="/")
        return response

    @app.get("/admin/api/status")
    async def admin_status(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._status_payload())

    @app.get("/admin/api/vacuums")
    async def admin_vacuums(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._vacuums_payload())

    @app.get("/admin/api/mitm/status")
    async def admin_mitm_status(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse({"ok": True, "mitm_intercept": supervisor.mitm_intercept.snapshot()})

    @app.get("/admin/api/mitm/log-tail")
    async def admin_mitm_log_tail(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        raw_lines = str(request.query_params.get("lines") or "").strip()
        try:
            lines = int(raw_lines) if raw_lines else 400
        except ValueError:
            lines = 400
        return JSONResponse({"ok": True, **supervisor.mitm_intercept.log_tail(lines=lines)})

    @app.get("/admin/api/mitm/wireguard-config")
    async def admin_mitm_wireguard_config(request: Request):
        supervisor._require_admin(request)
        requested_endpoint_host = str(request.query_params.get("endpoint_host") or "").strip()
        if not requested_endpoint_host:
            requested_endpoint_host = str(request.url.hostname or "").strip()
        payload = supervisor.mitm_intercept.wireguard_config(endpoint_host_override=requested_endpoint_host)
        if not payload.get("available"):
            error_message = str(payload.get("error") or "WireGuard client config not found yet.")
            return JSONResponse(
                {"ok": False, "error": error_message},
                status_code=404,
            )
        content = str(payload.get("content") or "")
        if not content.strip():
            return JSONResponse(
                {"ok": False, "error": "WireGuard client config is empty."},
                status_code=404,
            )
        response = PlainTextResponse(content)
        response.headers["Content-Disposition"] = 'inline; filename="wireguard.conf"'
        response.headers["X-WireGuard-Config-Path"] = str(payload.get("path") or "")
        return response

    @app.get("/admin/api/mitm/wireguard-qr")
    async def admin_mitm_wireguard_qr(request: Request):
        supervisor._require_admin(request)
        requested_endpoint_host = str(request.query_params.get("endpoint_host") or "").strip()
        if not requested_endpoint_host:
            requested_endpoint_host = str(request.url.hostname or "").strip()
        payload = supervisor.mitm_intercept.wireguard_config(endpoint_host_override=requested_endpoint_host)
        if not payload.get("available"):
            error_message = str(payload.get("error") or "WireGuard client config not found yet.")
            return JSONResponse(
                {"ok": False, "error": error_message},
                status_code=404,
            )
        content = str(payload.get("content") or "").strip()
        if not content:
            return JSONResponse(
                {"ok": False, "error": "WireGuard client config is empty."},
                status_code=404,
            )
        try:
            import qrcode
            from qrcode.image.svg import SvgImage
        except Exception:
            return JSONResponse(
                {"ok": False, "error": "QR generator unavailable. Install optional MITM dependencies."},
                status_code=500,
            )
        qr = qrcode.QRCode(border=2, box_size=8)
        qr.add_data(content)
        qr.make(fit=True)
        image = qr.make_image(image_factory=SvgImage)
        buffer = io.BytesIO()
        image.save(buffer)
        response = Response(content=buffer.getvalue(), media_type="image/svg+xml")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/admin/api/mitm/start")
    async def admin_mitm_start(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(
            {
                "ok": False,
                "error": "MITM lifecycle is managed externally. Start it outside roborock_local_server.",
                "mitm_intercept": supervisor.mitm_intercept.snapshot(),
            },
            status_code=410,
        )

    @app.post("/admin/api/mitm/stop")
    async def admin_mitm_stop(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(
            {
                "ok": False,
                "error": "MITM lifecycle is managed externally. Stop it outside roborock_local_server.",
                "mitm_intercept": supervisor.mitm_intercept.snapshot(),
            },
            status_code=410,
        )

    @app.post("/admin/api/pair-device")
    async def admin_pair_device(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        pairing = supervisor.runtime_state.start_pairing_session()
        return JSONResponse({"ok": True, "pairing": pairing})

    @app.post("/admin/api/cloud/request-code")
    async def admin_cloud_request_code(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        try:
            result = await supervisor.cloud_manager.request_code(
                email=str((body or {}).get("email") or ""),
                base_url=str((body or {}).get("base_url") or ""),
            )
        except Exception as exc:  # noqa: BLE001
            result = {"success": False, "step": "code_request_failed", "error": str(exc)}
        supervisor.runtime_state.record_cloud_request(result)
        return JSONResponse(result, status_code=200 if result.get("success") else 400)

    @app.post("/admin/api/cloud/submit-code")
    async def admin_cloud_submit_code(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        try:
            result = await supervisor.cloud_manager.submit_code(
                session_id=str((body or {}).get("session_id") or ""),
                code=str((body or {}).get("code") or ""),
            )
            supervisor.refresh_inventory_state()
        except Exception as exc:  # noqa: BLE001
            result = {"success": False, "step": "code_submit_failed", "error": str(exc)}
        supervisor.runtime_state.record_cloud_request(result)
        return JSONResponse(result, status_code=200 if result.get("success") else 400)
