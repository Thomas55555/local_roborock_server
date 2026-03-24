"""Config-driven release supervisor and admin/API server."""

from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
import secrets
import signal
import socket
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
import uvicorn

from .certs import CertificateManager
from .bundled_backend.shared.runtime_state import ONBOARDING_STEP_LABELS, REQUIRED_ONBOARDING_STEPS
from .cloud import CloudImportManager
from .config import AppConfig, AppPaths, load_config, resolve_paths
from .standalone_admin import register_standalone_admin_routes
from .backend import (
    MqttTlsProxy,
    MqttTopicBridge,
    RuntimeCredentialsStore,
    RuntimeState,
    ServerContext,
    _extract_inventory_vacuums,
    _load_inventory,
    _merge_vacuum_state,
    append_jsonl,
    classify_host,
    default_endpoint_rules,
    resolve_route,
    setup_file_logger,
    start_broker,
    strip_roborock_prefix,
)
from .security import AdminSessionManager


ALL_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
PROJECT_SUPPORT = {
    "title": "Support This Project",
    "text": (
        "If this project helps you keep your Roborock stack local, you can support ongoing research "
        "and maintenance here, or use the Roborock discount and affiliate links below:"
    ),
    "links": [
        {"label": "Buy Me a Coffee", "url": "https://buymeacoffee.com/lashl"},
        {"label": "PayPal", "url": "https://paypal.me/LLashley304"},
        {
            "label": "5% Off Roborock Store",
            "url": "https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D",
        },
        {"label": "Roborock Affiliate", "url": "https://roborock.pxf.io/B0VYV9"},
        {"label": "Amazon Affiliate", "url": "https://amzn.to/4bGfG6B"},
    ],
}

PLUGIN_PROXY_ALLOWED_HOSTS = {
    "files.roborock.com",
    "app-files.roborock.com",
    "rrpkg-us.roborock.com",
    "cdn.awsusor0.fds.api.mi-img.com",
}

LEGACY_CATEGORY_PLUGIN_SOURCES = {
    "robot_vacuum_cleaner": "https://files.roborock.com/iot/plugin/979bb22f91a24f10a8bafe232b4fb5ee.zip",
    "roborock_wetdryvac": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/10320c51139848e9ade1e6bd231e15c8.zip",
    "roborock_wm": "https://cdn.awsusor0.fds.api.mi-img.com/resources/iot/plugin/7f2a3e398aa54427afb48461f69a1a8c.zip",
}

PLUGIN_PROXY_MAX_BYTES = 32 * 1024 * 1024


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _request_query_params(request: Request) -> dict[str, list[str]]:
    return parse_qs(request.url.query, keep_blank_values=True)


def _request_body_params(raw_body: bytes) -> tuple[str, dict[str, list[str]]]:
    body_text = raw_body.decode("utf-8", errors="replace")
    if not body_text:
        return "", {}
    return body_text, parse_qs(body_text, keep_blank_values=True)


def _pick_first_header(headers: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = str(headers.get(key, "")).strip()
        if value:
            return value
    return ""


def _extract_explicit_pid(
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
) -> str:
    for key in ("pid", "m", "model"):
        for value in query_params.get(key, []) + body_params.get(key, []):
            candidate = str(value).strip()
            if candidate:
                return candidate
    return ""


def _connectivity_check(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=3):
        return


def _resolve_mitm_viewer_host(*, bind_host: str, stack_fqdn: str) -> str:
    host = bind_host.strip().strip("[]")
    if host and host not in {"0.0.0.0", "::"}:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
    fqdn = stack_fqdn.strip()
    if fqdn:
        try:
            resolved = socket.gethostbyname(fqdn)
        except OSError:
            resolved = ""
        if resolved:
            try:
                ipaddress.ip_address(resolved)
                return resolved
            except ValueError:
                pass
    return "127.0.0.1"


class MitmInterceptProcess:
    """Tracks external MITM state/logs for the admin UI."""

    _URL_RE = re.compile(r"https?://[^\s)]+")
    _CONF_PATH_RE = re.compile(r"((?:[A-Za-z]:[\\/]|/|~\/)[^\s\"']+\.conf)")
    _WG_ENDPOINT_RE = re.compile(r"^\s*Endpoint\s*=\s*(.+):(\d+)\s*$", re.IGNORECASE)

    def __init__(
        self,
        *,
        log_path: Path,
        web_port: int = 8081,
        viewer_host: str = "",
        wireguard_endpoint_host: str = "",
        conf_dir: Path | None = None,
    ) -> None:
        self._log_path = log_path
        self._web_port = max(1, int(web_port))
        self._viewer_host = viewer_host.strip()
        self._wireguard_endpoint_host = wireguard_endpoint_host.strip()
        self._conf_dir = conf_dir or (self._log_path.parent / ".mitmproxy")
        self._lock = threading.Lock()
        self._last_error = ""

    @staticmethod
    def _normalize_host(raw_host: str) -> str:
        host = raw_host.strip()
        if host.startswith(("http://", "https://")):
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].strip()
        host = host.strip("[]")
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        return host

    def _viewer_url(self) -> str:
        host = self._normalize_host(self._viewer_host or "127.0.0.1")
        return f"http://{host}:{self._web_port}/"

    def _wireguard_endpoint_host_value(self, endpoint_host_override: str = "") -> str:
        raw_host = endpoint_host_override or self._wireguard_endpoint_host or self._viewer_host
        return self._normalize_host(raw_host or "127.0.0.1")

    def _snapshot_locked(self) -> dict[str, Any]:
        log_tail = self._read_log_tail_locked(lines=240)
        hint_lines = self._extract_setup_hints_locked(log_tail)
        detected_urls = self._extract_urls_locked(log_tail)
        wireguard_path = self._resolve_wireguard_config_path_locked(log_tail)
        wireguard_available = bool(wireguard_path) or bool(self._extract_wireguard_client_config_locked(log_tail))
        return {
            "available": True,
            "running": False,
            "pid": None,
            "started_at": "",
            "log_path": str(self._log_path),
            "viewer_url": self._viewer_url(),
            "log_view_url": "/admin/mitm/logs",
            "log_tail_url": "/admin/api/mitm/log-tail",
            "setup_hints": hint_lines,
            "detected_urls": detected_urls,
            "wireguard_config_path": str(wireguard_path) if wireguard_path is not None else "",
            "wireguard_config_url": "/admin/api/mitm/wireguard-config" if wireguard_available else "",
            "wireguard_qr_url": "/admin/api/mitm/wireguard-qr" if wireguard_available else "",
            "last_error": self._last_error,
            "last_exit_code": None,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_locked()

    def log_tail(self, *, lines: int = 240) -> dict[str, Any]:
        with self._lock:
            normalized_lines = max(20, min(1200, int(lines)))
            tail_lines = self._read_log_tail_locked(lines=normalized_lines)
            return {
                "available": self._log_path.exists(),
                "path": str(self._log_path),
                "lines": tail_lines,
                "setup_hints": self._extract_setup_hints_locked(tail_lines),
                "detected_urls": self._extract_urls_locked(tail_lines),
            }

    def wireguard_config(self, endpoint_host_override: str = "") -> dict[str, Any]:
        with self._lock:
            log_tail = self._read_log_tail_locked(lines=300)
            config_from_logs = self._extract_wireguard_client_config_locked(log_tail)
            config_path = self._resolve_wireguard_config_path_locked(log_tail)
        if config_from_logs:
            return {
                "available": True,
                "path": str(self._log_path),
                "content": self._rewrite_wireguard_endpoint(config_from_logs, endpoint_host_override),
            }
        if config_path is None:
            return {
                "available": False,
                "path": "",
                "content": "",
                "error": "WireGuard client config not found yet.",
            }
        try:
            content = config_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {"available": False, "path": str(config_path), "content": ""}
        return {
            "available": True,
            "path": str(config_path),
            "content": self._rewrite_wireguard_endpoint(content, endpoint_host_override),
        }

    def _read_log_tail_locked(self, *, lines: int) -> list[str]:
        if not self._log_path.exists():
            return []
        max_bytes = 256 * 1024
        try:
            with self._log_path.open("rb") as handle:
                handle.seek(0, 2)
                size = handle.tell()
                if size <= 0:
                    return []
                handle.seek(max(0, size - max_bytes))
                chunk = handle.read().decode("utf-8", errors="replace")
        except OSError:
            return []
        all_lines = [line.rstrip("\r") for line in chunk.splitlines() if line.strip()]
        if not all_lines:
            return []
        return all_lines[-lines:]

    def _extract_setup_hints_locked(self, lines: list[str]) -> list[str]:
        keywords = (
            "wireguard",
            "scan",
            "qr",
            "config",
            "certificate",
            "proxy listening",
            "listening at",
            "mitm.it",
        )
        out: list[str] = []
        seen: set[str] = set()
        for line in lines:
            lowered = line.lower()
            if not any(keyword in lowered for keyword in keywords):
                continue
            normalized = line.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        return out[-12:]

    def _extract_urls_locked(self, lines: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for line in lines:
            for candidate in self._URL_RE.findall(line):
                normalized = candidate.rstrip(".,;)]}>")
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                out.append(normalized)
        return out[-12:]

    def _resolve_wireguard_config_path_locked(self, lines: list[str]) -> Path | None:
        candidates: list[Path] = []
        for line in lines:
            for raw_path in self._CONF_PATH_RE.findall(line):
                try:
                    expanded = Path(raw_path).expanduser()
                except Exception:
                    continue
                candidates.append(expanded)
        home = Path.home()
        candidates.extend(
            [
                self._conf_dir / "wireguard.conf",
                self._conf_dir / "wireguard-client.conf",
                self._conf_dir / "wireguard-client-profile.conf",
                home / ".mitmproxy" / "wireguard.conf",
                home / ".mitmproxy" / "wireguard-client.conf",
                home / ".mitmproxy" / "wireguard-client-profile.conf",
            ]
        )
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate
            except OSError:
                continue
        return None

    def _extract_wireguard_client_config_locked(self, lines: list[str]) -> str:
        start = -1
        for index in range(len(lines) - 1, -1, -1):
            if lines[index].strip() == "[Interface]":
                start = index
                break
        if start < 0:
            return ""
        block: list[str] = []
        for line in lines[start:]:
            stripped = line.strip()
            if stripped.startswith("---"):
                break
            if not stripped:
                continue
            block.append(stripped)
        if not block:
            return ""
        if "[Peer]" not in block:
            return ""
        return "\n".join(block) + "\n"

    def _rewrite_wireguard_endpoint(self, content: str, endpoint_host_override: str = "") -> str:
        lines = content.splitlines()
        endpoint_host = self._wireguard_endpoint_host_value(endpoint_host_override)
        if not endpoint_host:
            return content
        for index, line in enumerate(lines):
            match = self._WG_ENDPOINT_RE.match(line.strip())
            if not match:
                continue
            endpoint_port = match.group(2)
            lines[index] = f"Endpoint = {endpoint_host}:{endpoint_port}"
            return "\n".join(lines).strip() + "\n"
        return content


class ManagedFastApiServer:
    """Owns FastAPI/uvicorn lifecycle."""

    def __init__(
        self,
        *,
        app: FastAPI,
        bind_host: str,
        port: int,
        cert_file: Path,
        key_file: Path,
    ) -> None:
        self._app = app
        self._bind_host = bind_host
        self._port = port
        self._cert_file = cert_file
        self._key_file = key_file
        self._server: uvicorn.Server | None = None
        self._serve_task: asyncio.Task[bool] | None = None

    async def start(self) -> None:
        config = uvicorn.Config(
            app=self._app,
            host=self._bind_host,
            port=self._port,
            log_level="warning",
            access_log=False,
            ssl_certfile=str(self._cert_file),
            ssl_keyfile=str(self._key_file),
            ssl_ciphers="DEFAULT:@SECLEVEL=0",
        )
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve(), name="release-https-server")
        await self._wait_started()

    async def _wait_started(self) -> None:
        if self._server is None:
            raise RuntimeError("HTTP server was not initialized")
        for _ in range(120):
            if self._server.started:
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("Timed out waiting for HTTPS server startup")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._serve_task is not None:
            await self._serve_task


def _seed_runtime_vacuums_from_inventory(
    *,
    runtime_state: RuntimeState,
    runtime_credentials: RuntimeCredentialsStore,
    inventory_path: Path,
) -> int:
    try:
        parsed = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(parsed, dict):
        return 0

    seen: set[str] = set()
    seeded = 0
    for source_key in ("devices", "received_devices", "receivedDevices"):
        items = parsed.get(source_key)
        if not isinstance(items, list):
            continue
        for raw in items:
            if not isinstance(raw, dict):
                continue
            duid = str(raw.get("duid") or raw.get("did") or raw.get("device_id") or "").strip()
            if not duid or duid in seen:
                continue
            seen.add(duid)
            model = str(raw.get("model") or "").strip()
            runtime_state.upsert_vacuum(
                duid,
                name=str(raw.get("name") or raw.get("device_name") or "").strip() or None,
                local_key=runtime_credentials.resolve_device_localkey(
                    duid=duid,
                    model=model,
                    name=str(raw.get("name") or raw.get("device_name") or "").strip(),
                    product_id=str(raw.get("product_id") or raw.get("productId") or "").strip(),
                    source="inventory_seed",
                    assign_if_missing=True,
                )
                or None,
                source=source_key,
            )
            seeded += 1
    return seeded


def _seed_runtime_vacuums_from_credentials(
    *,
    runtime_state: RuntimeState,
    runtime_credentials: RuntimeCredentialsStore,
) -> int:
    seeded = 0
    for raw in runtime_credentials.devices():
        if not isinstance(raw, dict):
            continue
        did = str(raw.get("did") or "").strip()
        duid = str(raw.get("duid") or "").strip()
        identifier = duid or did
        if not identifier:
            continue
        runtime_state.upsert_vacuum(
            identifier,
            did=did or None,
            id_kind="duid" if duid else "did",
            name=str(raw.get("name") or "").strip() or None,
            local_key=str(raw.get("localkey") or "").strip() or None,
            source="runtime_credentials",
            last_mqtt_at=str(raw.get("last_mqtt_seen_at") or "").strip() or None,
            last_nc_at=str(raw.get("last_nc_at") or "").strip() or None,
            restored_activity=bool(str(raw.get("last_mqtt_seen_at") or "").strip()),
        )
        seeded += 1
    return seeded


class ReleaseSupervisor:
    """Owns the release stack lifecycle."""

    def __init__(
        self,
        *,
        config: AppConfig,
        paths: AppPaths,
        enable_standalone_admin: bool = True,
    ) -> None:
        self.config = config
        self.paths = paths
        self.enable_standalone_admin = bool(enable_standalone_admin)

        self.root_logger = logging.getLogger("roborock_local_server")
        self.root_logger.setLevel(logging.INFO)
        if not self.root_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            self.root_logger.addHandler(handler)

        self._broker: Any | None = None
        self._topic_bridge: MqttTopicBridge | None = None
        self._mqtt_proxy: MqttTlsProxy | None = None
        self._http_server: ManagedFastApiServer | None = None
        self._renew_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

        self.certificate_manager = CertificateManager(config=config, paths=paths)
        self.session_manager = AdminSessionManager(
            secret=config.admin.session_secret,
            ttl_seconds=config.admin.session_ttl_seconds,
        )
        self.cloud_manager = CloudImportManager(
            inventory_path=self.paths.inventory_path,
            snapshot_path=self.paths.cloud_snapshot_path,
        )

        self.loggers = self._setup_loggers()
        mitm_viewer_host = _resolve_mitm_viewer_host(
            bind_host=self.config.network.bind_host,
            stack_fqdn=self.config.network.stack_fqdn,
        )
        self.mitm_intercept = MitmInterceptProcess(
            log_path=self.paths.runtime_dir / "mitm_intercept.log",
            viewer_host=mitm_viewer_host,
            wireguard_endpoint_host=mitm_viewer_host,
            conf_dir=self.paths.runtime_dir / ".mitmproxy",
        )
        if not self.paths.device_key_state_path.exists():
            self.paths.device_key_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.paths.device_key_state_path.write_text('{"devices":{}}\n', encoding="utf-8")
        self.runtime_credentials = RuntimeCredentialsStore(
            self.paths.runtime_credentials_path,
            inventory_path=self.paths.inventory_path,
            key_state_file=self.paths.device_key_state_path,
        )
        self.runtime_state = RuntimeState(
            log_dir=self.paths.runtime_dir,
            key_state_file=self.paths.device_key_state_path,
        )
        self.runtime_state.set_service(
            "https_server",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.network.bind_host}:{self.config.network.https_port}",
        )
        self.runtime_state.set_service(
            "mqtt_tls_proxy",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.network.bind_host}:{self.config.network.mqtt_tls_port}",
        )
        self.runtime_state.set_service(
            "mqtt_backend_broker",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.broker.mode}:{self.config.broker.host}:{self.config.broker.port}",
        )
        self.runtime_state.set_service(
            "mqtt_topic_bridge",
            running=False,
            required=False,
            enabled=self.config.broker.enable_topic_bridge,
            detail="rr/m <-> rr/d",
        )

        self._bootstrap_credentials = self._derive_bootstrap_credentials()
        self.runtime_credentials.update_base(
            api_host=self.config.network.stack_fqdn,
            mqtt_host=self.config.network.stack_fqdn,
            wood_host=self.config.network.stack_fqdn,
            region=self.config.network.region,
            localkey=self._bootstrap_credentials["localkey"],
            duid=self._bootstrap_credentials["duid"],
            mqtt_usr=self._bootstrap_credentials["mqtt_usr"],
            mqtt_passwd=self._bootstrap_credentials["mqtt_passwd"],
            mqtt_clientid=self._bootstrap_credentials["mqtt_clientid"],
            https_port=self.config.network.https_port,
            mqtt_tls_port=self.config.network.mqtt_tls_port,
            mqtt_backend_port=self.config.broker.port,
        )
        self.runtime_credentials.sync_inventory()

        self.context = ServerContext(
            api_host=self.config.network.stack_fqdn,
            mqtt_host=self.config.network.stack_fqdn,
            wood_host=self.config.network.stack_fqdn,
            region=self.config.network.region,
            localkey=self._bootstrap_credentials["localkey"],
            duid=self._bootstrap_credentials["duid"],
            mqtt_usr=self._bootstrap_credentials["mqtt_usr"],
            mqtt_passwd=self._bootstrap_credentials["mqtt_passwd"],
            mqtt_clientid=self._bootstrap_credentials["mqtt_clientid"],
            mqtt_tls_port=self.config.network.mqtt_tls_port,
            http_jsonl=self.paths.http_jsonl_path,
            mqtt_jsonl=self.paths.mqtt_jsonl_path,
            loggers=self.loggers,
            key_state_file=self.paths.device_key_state_path,
            bootstrap_encryption_enabled=True,
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
        )
        self.endpoint_rules = default_endpoint_rules()
        self.app = self._create_app()

    def _setup_loggers(self) -> dict[str, logging.Logger]:
        self.paths.runtime_dir.mkdir(parents=True, exist_ok=True)
        return {
            "api": setup_file_logger("api", self.paths.runtime_dir / "api_server.log"),
            "iot": setup_file_logger("iot", self.paths.runtime_dir / "iot_server.log"),
            "wood": setup_file_logger("wood", self.paths.runtime_dir / "wood_server.log"),
            "https": setup_file_logger("https", self.paths.runtime_dir / "https_server.log"),
            "mqtt": setup_file_logger("mqtt", self.paths.runtime_dir / "mqtt_server.log"),
            "unknown": setup_file_logger("unknown", self.paths.runtime_dir / "unknown_server.log"),
        }

    def _derive_bootstrap_credentials(self) -> dict[str, str]:
        persisted_duid = str(self.runtime_credentials.bootstrap_value("duid", "") or "").strip()
        localkey = (
            self.config.network.localkey
            or str(self.runtime_credentials.bootstrap_value("localkey", "") or "").strip()
            or secrets.token_hex(8)
        )
        duid = self.config.network.duid or persisted_duid or f"rr_{secrets.token_hex(8)}"
        mqtt_usr = (
            self.config.network.mqtt_username
            or str(self.runtime_credentials.bootstrap_value("mqtt_usr", "") or "").strip()
            or hashlib.md5(duid.encode("utf-8")).hexdigest()[:16]
        )
        mqtt_passwd = (
            self.config.network.mqtt_password
            or str(self.runtime_credentials.bootstrap_value("mqtt_passwd", "") or "").strip()
            or secrets.token_hex(6)
        )
        mqtt_clientid = (
            self.config.network.mqtt_client_id
            or str(self.runtime_credentials.bootstrap_value("mqtt_clientid", "") or "").strip()
            or duid
        )
        return {
            "localkey": localkey,
            "duid": duid,
            "mqtt_usr": mqtt_usr,
            "mqtt_passwd": mqtt_passwd,
            "mqtt_clientid": mqtt_clientid,
        }

    def _authenticated(self, request: Request) -> bool:
        return self.session_manager.verify(request.cookies.get(self.session_manager.cookie_name)) is not None

    def _require_admin(self, request: Request) -> None:
        if not self._authenticated(request):
            raise HTTPException(status_code=401, detail="Authentication required")

    @staticmethod
    def _first_query_value(query_params: dict[str, list[str]], *keys: str) -> str:
        for key in keys:
            values = query_params.get(key) or []
            for value in values:
                candidate = str(value or "").strip()
                if candidate:
                    return candidate
        return ""

    @staticmethod
    def _is_allowed_plugin_source(source_url: str) -> bool:
        parsed = urlparse(source_url)
        if parsed.scheme.lower() != "https":
            return False
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return False
        if host in PLUGIN_PROXY_ALLOWED_HOSTS:
            return True
        return host.endswith(".fds.api.mi-img.com")

    def _plugin_source_from_request(self, clean_path: str, query_params: dict[str, list[str]]) -> str:
        path = clean_path.rstrip("/")
        if path.startswith("/plugin/proxy/") and path.endswith(".zip"):
            source = self._first_query_value(query_params, "src", "url")
            if source and self._is_allowed_plugin_source(source):
                return source
            return ""
        if path.startswith("/plugin/category/") and path.endswith(".zip"):
            slug = path.rsplit("/", 1)[-1].removesuffix(".zip").strip().lower()
            source = LEGACY_CATEGORY_PLUGIN_SOURCES.get(slug, "")
            if source and self._is_allowed_plugin_source(source):
                return source
        return ""

    def _plugin_cache_path(self, source_url: str) -> Path:
        digest = hashlib.sha256(source_url.encode("utf-8")).hexdigest()
        return self.paths.runtime_dir / "plugin_proxy_cache" / f"{digest}.zip"

    async def _download_plugin_zip(self, source_url: str) -> tuple[bytes, str]:
        timeout = aiohttp.ClientTimeout(total=45)
        headers = {"User-Agent": "roborock-local-server/0.1"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(source_url, allow_redirects=True) as response:
                status = int(response.status)
                if status != 200:
                    raise RuntimeError(f"upstream returned HTTP {status}")
                data = await response.read()
                if not data:
                    raise RuntimeError("upstream returned empty content")
                if len(data) > PLUGIN_PROXY_MAX_BYTES:
                    raise RuntimeError(
                        f"plugin too large: {len(data)} bytes exceeds {PLUGIN_PROXY_MAX_BYTES} byte limit"
                    )
                content_type = str(response.headers.get("Content-Type") or "application/zip").strip()
                return data, content_type

    async def _plugin_proxy_response(self, source_url: str) -> Response:
        cache_path = self._plugin_cache_path(source_url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        if cache_path.exists():
            payload = cache_path.read_bytes()
            return Response(
                content=payload,
                media_type="application/zip",
                headers={"Cache-Control": "public, max-age=86400", "X-RR-Plugin-Cache": "hit"},
            )

        payload, upstream_content_type = await self._download_plugin_zip(source_url)
        temp_path = cache_path.with_suffix(".tmp")
        temp_path.write_bytes(payload)
        temp_path.replace(cache_path)
        media_type = upstream_content_type if "zip" in upstream_content_type.lower() else "application/zip"
        return Response(
            content=payload,
            media_type=media_type,
            headers={"Cache-Control": "public, max-age=86400", "X-RR-Plugin-Cache": "miss"},
        )

    async def _handle_roborock_request(self, request: Request) -> Response:
        host = (request.headers.get("host") or "").strip()
        group = classify_host(host)
        logger = self.context.loggers.get(group, self.context.loggers["unknown"])
        raw_body = await request.body()
        clean_path = strip_roborock_prefix(request.url.path)
        query_params = _request_query_params(request)
        body_text, body_params = _request_body_params(raw_body)
        body_sha256 = hashlib.sha256(raw_body).hexdigest()

        if host:
            host_no_port = host.split(":", 1)[0].strip()
            if host_no_port:
                query_params = {key: list(values) for key, values in query_params.items()}
                query_params.setdefault("__host", [host_no_port])

        explicit_did = self.context.extract_explicit_did(query_params, body_params)
        explicit_pid = _extract_explicit_pid(query_params, body_params)
        key_cache = self.context.device_key_cache()

        query_sample_added = False
        header_sample_added = False
        if key_cache is not None and explicit_did:
            if request.url.query:
                try:
                    query_sample_added = key_cache.add_signed_query(explicit_did, request.url.query)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("key_cache add_signed_query failed did=%s: %s", explicit_did, exc)
            sign = _pick_first_header(
                dict(request.headers),
                ("sign", "x-sign", "x_roborock_sign", "x-roborock-sign"),
            )
            if sign:
                nonce = _pick_first_header(
                    dict(request.headers),
                    ("nonce", "x-nonce", "x_roborock_nonce", "x-roborock-nonce"),
                )
                ts = _pick_first_header(
                    dict(request.headers),
                    ("ts", "timestamp", "x-timestamp", "x_roborock_ts", "x-roborock-ts"),
                )
                try:
                    header_sample_added = key_cache.add_header_signature(
                        explicit_did,
                        method=request.method,
                        path=request.url.path,
                        query=request.url.query,
                        nonce=nonce,
                        ts=ts,
                        signature_b64=sign,
                        body_sha256=body_sha256,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("key_cache add_header_signature failed did=%s: %s", explicit_did, exc)

        raw_path = request.url.path
        if request.url.query:
            raw_path += f"?{request.url.query}"
        client_host = request.client.host if request.client else "-"
        client_port = request.client.port if request.client else 0
        entry: dict[str, object] = {
            "time": _utcnow_iso(),
            "server": group,
            "host": host,
            "method": request.method,
            "raw_path": raw_path,
            "clean_path": clean_path,
            "query": {key: value for key, value in query_params.items()},
            "headers": dict(request.headers),
            "body_len": len(raw_body),
            "body_sha256": body_sha256,
            "body_b64": base64.b64encode(raw_body).decode("ascii"),
            "remote": f"{client_host}:{client_port}",
        }
        if explicit_did:
            entry["did"] = explicit_did
        if explicit_pid:
            entry["pid"] = explicit_pid
        if body_text:
            entry["body_text"] = body_text
            try:
                entry["body_json"] = json.loads(body_text)
            except json.JSONDecodeError:
                pass
            if body_params:
                entry["body_form"] = {key: value for key, value in body_params.items()}
        if query_sample_added or header_sample_added:
            entry["key_state_capture"] = {
                "did": explicit_did,
                "query_sample_added": query_sample_added,
                "header_sample_added": header_sample_added,
            }

        plugin_source = self._plugin_source_from_request(clean_path, query_params)
        if plugin_source:
            route_name = "plugin_proxy"
            try:
                response = await self._plugin_proxy_response(plugin_source)
            except Exception as exc:  # noqa: BLE001
                error_payload = {
                    "success": False,
                    "code": 502,
                    "msg": "plugin_proxy_failed",
                    "data": {"source": plugin_source, "error": str(exc)},
                }
                entry["route"] = route_name
                entry["plugin_source"] = plugin_source
                entry["response_json"] = error_payload
                try:
                    self.runtime_state.record_http_event(
                        event_time=str(entry["time"]),
                        route_name=route_name,
                        clean_path=clean_path,
                        raw_path=raw_path,
                        method=request.method,
                        host=host,
                        remote=str(entry["remote"]),
                        did=explicit_did or None,
                        pid=explicit_pid or None,
                    )
                except Exception as record_exc:  # noqa: BLE001
                    logger.warning("runtime_state record_http_event failed: %s", record_exc)
                append_jsonl(self.context.http_jsonl, entry)
                logger.warning(
                    "%s %s host=%s route=%s plugin_source=%s error=%s",
                    request.method,
                    clean_path,
                    host or "-",
                    route_name,
                    plugin_source,
                    exc,
                )
                return JSONResponse(error_payload, status_code=502)

            entry["route"] = route_name
            entry["plugin_source"] = plugin_source
            entry["response_meta"] = {
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "cache": response.headers.get("X-RR-Plugin-Cache", ""),
            }
            try:
                self.runtime_state.record_http_event(
                    event_time=str(entry["time"]),
                    route_name=route_name,
                    clean_path=clean_path,
                    raw_path=raw_path,
                    method=request.method,
                    host=host,
                    remote=str(entry["remote"]),
                    did=explicit_did or None,
                    pid=explicit_pid or None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("runtime_state record_http_event failed: %s", exc)
            append_jsonl(self.context.http_jsonl, entry)
            logger.info(
                "%s %s host=%s route=%s plugin_source=%s cache=%s",
                request.method,
                clean_path,
                host or "-",
                route_name,
                plugin_source,
                response.headers.get("X-RR-Plugin-Cache", ""),
            )
            return response

        route_name, response_payload = resolve_route(
            rules=self.endpoint_rules,
            context=self.context,
            clean_path=clean_path,
            query_params=query_params,
            body_params=body_params,
            method=request.method,
        )
        entry["route"] = route_name
        entry["response_json"] = response_payload
        try:
            self.runtime_state.record_http_event(
                event_time=str(entry["time"]),
                route_name=route_name,
                clean_path=clean_path,
                raw_path=raw_path,
                method=request.method,
                host=host,
                remote=str(entry["remote"]),
                did=explicit_did or None,
                pid=explicit_pid or None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("runtime_state record_http_event failed: %s", exc)
        append_jsonl(self.context.http_jsonl, entry)
        if key_cache is not None and explicit_did:
            try:
                key_cache.maybe_recover_async(explicit_did)
            except Exception as exc:  # noqa: BLE001
                logger.warning("key_cache maybe_recover_async failed did=%s: %s", explicit_did, exc)

        logger.info(
            "%s %s host=%s route=%s body_sha256=%s",
            request.method,
            clean_path,
            host or "-",
            route_name,
            body_sha256[:16],
        )
        return JSONResponse(response_payload)

    def _status_payload(self) -> dict[str, Any]:
        health = self.runtime_state.health_snapshot()
        merged_vacuums = self._vacuums_payload()["vacuums"]
        health["all_vacuums"] = merged_vacuums
        health["connected_vacuums"] = [vac for vac in merged_vacuums if vac.get("connected")]
        return {
            "health": health,
            "pairing": self.runtime_state.pairing_snapshot(),
            "mitm_intercept": self.mitm_intercept.snapshot(),
            "support": PROJECT_SUPPORT,
            "inventory_path": str(self.paths.inventory_path),
            "cloud_snapshot_path": str(self.paths.cloud_snapshot_path),
        }

    def _vacuums_payload(self) -> dict[str, Any]:
        inventory = _load_inventory(self.paths.inventory_path)
        inventory_vacuums = _extract_inventory_vacuums(self.context, inventory)
        vacuums = _merge_vacuum_state(context=self.context, inventory_vacuums=inventory_vacuums)
        return {
            "inventory_path": str(self.paths.inventory_path),
            "vacuums": vacuums,
        }

    def _ui_health_payload(self) -> dict[str, Any]:
        runtime_state = self.runtime_state
        if runtime_state is None:
            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "overall_ok": False,
                "services": [],
                "connected_vacuums": [],
                "all_vacuums": [],
                "active_mqtt_connections": 0,
                "pending_onboarding_ips": [],
                "last_cloud_request": None,
                "note": "Runtime state tracking is disabled.",
            }
        return runtime_state.health_snapshot()

    def _ui_vacuums_payload(self) -> dict[str, Any]:
        payload = self._vacuums_payload()
        payload["required_onboarding_steps"] = list(REQUIRED_ONBOARDING_STEPS)
        payload["step_labels"] = dict(ONBOARDING_STEP_LABELS)
        return payload

    def refresh_inventory_state(self) -> None:
        self.runtime_credentials.sync_inventory()
        _seed_runtime_vacuums_from_inventory(
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
            inventory_path=self.paths.inventory_path,
        )
        _seed_runtime_vacuums_from_credentials(
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
        )

    @staticmethod
    def _is_standalone_route_path(path: str) -> bool:
        normalized = str(path or "").rstrip("/")
        return normalized == "/admin" or normalized.startswith("/admin/")

    def _register_protocol_routes(self, app: FastAPI) -> None:
        @app.get("/ui/api/health")
        async def ui_health() -> JSONResponse:
            return JSONResponse(self._ui_health_payload())

        @app.get("/ui/api/vacuums")
        async def ui_vacuums() -> JSONResponse:
            return JSONResponse(self._ui_vacuums_payload())

        @app.api_route("/", methods=list(ALL_HTTP_METHODS))
        async def root_handler(request: Request) -> Response:
            if not self.enable_standalone_admin and self._is_standalone_route_path(request.url.path):
                return JSONResponse({"error": "Not Found"}, status_code=404)
            return await self._handle_roborock_request(request)

        @app.api_route("/{full_path:path}", methods=list(ALL_HTTP_METHODS))
        async def catchall_handler(request: Request, full_path: str) -> Response:
            _ = full_path
            if not self.enable_standalone_admin and self._is_standalone_route_path(request.url.path):
                return JSONResponse({"error": "Not Found"}, status_code=404)
            return await self._handle_roborock_request(request)

    def _create_app(self) -> FastAPI:
        app = FastAPI(title="Roborock Local Server", docs_url=None, redoc_url=None, openapi_url=None)
        if self.enable_standalone_admin:
            register_standalone_admin_routes(
                app=app,
                supervisor=self,
                project_support=PROJECT_SUPPORT,
            )
        self._register_protocol_routes(app)
        return app

    async def _start_http_server(self) -> None:
        cert_paths = self.certificate_manager.certificate_paths
        self._http_server = ManagedFastApiServer(
            app=self.app,
            bind_host=self.config.network.bind_host,
            port=self.config.network.https_port,
            cert_file=cert_paths.cert_file,
            key_file=cert_paths.key_file,
        )
        await self._http_server.start()
        self.runtime_state.set_service("https_server", running=True, required=True, enabled=True)

    def _start_mqtt_proxy(self) -> None:
        cert_paths = self.certificate_manager.certificate_paths
        self._mqtt_proxy = MqttTlsProxy(
            cert_file=cert_paths.cert_file,
            key_file=cert_paths.key_file,
            listen_host=self.config.network.bind_host,
            listen_port=self.config.network.mqtt_tls_port,
            backend_host=self.config.broker.host,
            backend_port=self.config.broker.port,
            localkey=self.context.localkey,
            logger=self.loggers["mqtt"],
            decoded_jsonl=self.context.mqtt_jsonl,
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
        )
        self._mqtt_proxy.start()
        self.runtime_state.set_service("mqtt_tls_proxy", running=True, required=True, enabled=True)

    async def reload_tls_services(self) -> None:
        self.root_logger.info("Reloading TLS listeners after certificate update")
        if self._http_server is not None:
            self.runtime_state.set_service("https_server", running=False, required=True, enabled=True)
            await self._http_server.stop()
            self._http_server = None
        if self._mqtt_proxy is not None:
            self.runtime_state.set_service("mqtt_tls_proxy", running=False, required=True, enabled=True)
            self._mqtt_proxy.stop()
            self._mqtt_proxy = None
        await self._start_http_server()
        self._start_mqtt_proxy()

    async def _renew_loop(self) -> None:
        interval = max(3600, self.config.tls.renew_check_seconds)
        while not self._stop_event.is_set():
            await asyncio.sleep(interval)
            try:
                if self.certificate_manager.ensure_certificate():
                    await self.reload_tls_services()
            except Exception as exc:  # noqa: BLE001
                self.root_logger.warning("TLS renewal check failed: %s", exc)

    async def start(self) -> None:
        for path in (self.paths.data_dir, self.paths.runtime_dir, self.paths.state_dir, self.paths.certs_dir, self.paths.acme_dir):
            path.mkdir(parents=True, exist_ok=True)

        self.certificate_manager.ensure_certificate()
        self.refresh_inventory_state()

        if self.config.broker.mode == "embedded":
            self._broker = await start_broker(
                self.config.broker.port,
                state_dir=self.paths.state_dir / "mqtt_broker",
                mosquitto_binary=self.config.broker.mosquitto_binary,
                logger=self.loggers["mqtt"],
            )
            self.runtime_state.set_service("mqtt_backend_broker", running=True, required=True, enabled=True)
        else:
            _connectivity_check(self.config.broker.host, self.config.broker.port)
            self.runtime_state.set_service("mqtt_backend_broker", running=True, required=True, enabled=True)

        if self.config.broker.enable_topic_bridge:
            self._topic_bridge = MqttTopicBridge(
                host=self.config.broker.host,
                port=self.config.broker.port,
                logger=self.loggers["mqtt"],
                runtime_state=self.runtime_state,
                inventory_path=self.paths.inventory_path,
            )
            await self._topic_bridge.start()
            self.runtime_state.set_service("mqtt_topic_bridge", running=True, required=False, enabled=True)
        else:
            self.runtime_state.set_service("mqtt_topic_bridge", running=False, required=False, enabled=False)

        await self._start_http_server()
        self._start_mqtt_proxy()

        self.root_logger.info(
            "HTTPS server listening on %s:%d",
            self.config.network.bind_host,
            self.config.network.https_port,
        )
        self.root_logger.info(
            "MQTT TLS proxy listening on %s:%d",
            self.config.network.bind_host,
            self.config.network.mqtt_tls_port,
        )
        self.root_logger.info(
            "MQTT backend %s on %s:%d",
            self.config.broker.mode,
            self.config.broker.host,
            self.config.broker.port,
        )

        if self.config.tls.mode == "cloudflare_acme":
            self._renew_task = asyncio.create_task(self._renew_loop(), name="tls-renew-loop")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._renew_task is not None:
            self._renew_task.cancel()
            try:
                await self._renew_task
            except asyncio.CancelledError:
                pass
        if self._mqtt_proxy is not None:
            self.runtime_state.set_service("mqtt_tls_proxy", running=False, required=True, enabled=True)
            self._mqtt_proxy.stop()
            self._mqtt_proxy = None
        if self._topic_bridge is not None:
            self.runtime_state.set_service(
                "mqtt_topic_bridge",
                running=False,
                required=False,
                enabled=self.config.broker.enable_topic_bridge,
            )
            await self._topic_bridge.stop()
            self._topic_bridge = None
        if self._http_server is not None:
            self.runtime_state.set_service("https_server", running=False, required=True, enabled=True)
            await self._http_server.stop()
            self._http_server = None
        self.runtime_state.set_service("mqtt_backend_broker", running=False, required=True, enabled=True)
        if self._broker is not None:
            await self._broker.shutdown()
            self._broker = None

    async def serve_forever(self) -> int:
        await self.start()

        def request_shutdown() -> None:
            if not self._stop_event.is_set():
                self._stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_shutdown)
            except NotImplementedError:
                pass

        try:
            await self._stop_event.wait()
        finally:
            await self.stop()
        return 0


async def run_server(*, config_file: Path, enable_standalone_admin: bool = True) -> int:
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(
        config=config,
        paths=paths,
        enable_standalone_admin=enable_standalone_admin,
    )
    return await supervisor.serve_forever()


def repair_runtime_identities(*, config_file: Path, links: list[str]) -> int:
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    runtime_credentials = RuntimeCredentialsStore(
        paths.runtime_credentials_path,
        inventory_path=paths.inventory_path,
        key_state_file=paths.device_key_state_path,
    )
    runtime_credentials.sync_inventory()

    inventory = _load_inventory(paths.inventory_path)
    inventory_vacuums = _extract_inventory_vacuums(
        ServerContext(
            api_host=config.network.stack_fqdn,
            mqtt_host=config.network.stack_fqdn,
            wood_host=config.network.stack_fqdn,
            region=config.network.region,
            localkey=str(runtime_credentials.bootstrap_value("localkey", "") or ""),
            duid=str(runtime_credentials.bootstrap_value("duid", "") or ""),
            mqtt_usr=str(runtime_credentials.bootstrap_value("mqtt_usr", "") or ""),
            mqtt_passwd=str(runtime_credentials.bootstrap_value("mqtt_passwd", "") or ""),
            mqtt_clientid=str(runtime_credentials.bootstrap_value("mqtt_clientid", "") or ""),
            mqtt_tls_port=config.network.mqtt_tls_port,
            http_jsonl=paths.http_jsonl_path,
            mqtt_jsonl=paths.mqtt_jsonl_path,
            loggers={},
            key_state_file=paths.device_key_state_path,
            bootstrap_encryption_enabled=False,
            runtime_state=None,
            runtime_credentials=runtime_credentials,
        ),
        inventory,
    )
    inventory_by_duid = {str(item.get("duid") or "").strip(): item for item in inventory_vacuums}

    if not links:
        orphan_dids = [
            device
            for device in runtime_credentials.devices()
            if str(device.get("did") or "").strip() and not str(device.get("duid") or "").strip()
        ]
        unmapped_cloud = [
            item
            for item in inventory_vacuums
            if not str(item.get("did") or "").strip()
        ]
        print("Orphan runtime DIDs:")
        for device in orphan_dids:
            print(
                f"  did={device.get('did','')} mqtt_usr={device.get('device_mqtt_usr','')} "
                f"last_mqtt_seen_at={device.get('last_mqtt_seen_at','')}"
            )
        print("Cloud DUIDs without a DID:")
        for item in unmapped_cloud:
            print(f"  duid={item.get('duid','')} name={item.get('name','')} model={item.get('model','')}")
        return 0

    repaired: list[tuple[str, str, str]] = []
    for link in links:
        normalized = str(link or "").strip()
        if "=" not in normalized:
            raise SystemExit(f"Invalid --link '{normalized}'. Expected DID=DUID.")
        did, duid = (part.strip() for part in normalized.split("=", 1))
        if not did or not duid:
            raise SystemExit(f"Invalid --link '{normalized}'. Expected DID=DUID.")
        inventory_match = inventory_by_duid.get(duid)
        if inventory_match is None:
            raise SystemExit(f"DUID '{duid}' was not found in {paths.inventory_path}")
        merged = runtime_credentials.ensure_device(
            did=did,
            duid=duid,
            name=str(inventory_match.get("name") or ""),
            model=str(inventory_match.get("model") or ""),
            product_id=str(inventory_match.get("product_id") or ""),
            localkey=str(inventory_match.get("local_key") or ""),
            assign_localkey=False,
        )
        repaired.append((did, duid, str(merged.get("name") or duid)))

    print(f"Repaired {len(repaired)} device identity link(s) in {paths.runtime_credentials_path}")
    for did, duid, name in repaired:
        print(f"  did={did} -> duid={duid} ({name})")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Roborock local server release runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the release stack")
    serve.add_argument("--config", default="config.toml")
    serve.add_argument(
        "--core-only",
        action="store_true",
        help="Run protocol runtime without standalone admin/dashboard routes.",
    )

    hash_password = subparsers.add_parser("hash-password", help="Generate an admin password hash")
    hash_password.add_argument("--password", default="")

    generate_secret = subparsers.add_parser("generate-secret", help="Generate a random admin session secret")
    generate_secret.add_argument("--bytes", type=int, default=32)

    repair_identities = subparsers.add_parser(
        "repair-identities",
        help="Manually adopt existing runtime DIDs into known cloud DUIDs",
    )
    repair_identities.add_argument("--config", default="config.toml")
    repair_identities.add_argument(
        "--link",
        action="append",
        default=[],
        help="Explicit DID=DUID mapping to repair existing state; can be supplied multiple times",
    )
    return parser
