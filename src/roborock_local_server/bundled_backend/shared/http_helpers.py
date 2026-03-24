"""HTTP helper functions shared by the HTTPS server."""

from __future__ import annotations

from typing import Any


def classify_host(host: str) -> str:
    host = (host or "").split(":")[0].lower()
    if "wood-" in host:
        return "wood"
    if "iot." in host or host.startswith(("usiot", "euiot", "cniot", "ruiot")):
        return "iot"
    if host.startswith("api-") or ".api-" in host or "api-" in host:
        return "api"
    return "api" if host else "unknown"


def strip_roborock_prefix(path: str) -> str:
    prefixes = ("/.roborock.com", "/roborock.com", "/.roborock.com/")
    for prefix in prefixes:
        if path.startswith(prefix):
            remainder = path[len(prefix) :]
            if not remainder:
                return "/"
            return remainder if remainder.startswith("/") else "/" + remainder
    return path


def pick_first(values: list[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


def wrap_response(data: Any) -> dict[str, Any]:
    return {
        "success": True,
        "code": 200,
        "msg": "success",
        "data": data,
        "result": data,
    }
