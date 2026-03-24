"""I/O and logging helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


def append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True, separators=(",", ":")) + "\n")


def setup_file_logger(name: str, path: Path) -> logging.Logger:
    logger = logging.getLogger(f"real_stack.{name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


def payload_preview(payload: bytes, max_chars: int = 280) -> str:
    if not payload:
        return ""
    try:
        text = payload.decode("utf-8")
        if len(text) > max_chars:
            return text[:max_chars] + "...[truncated]"
        return text
    except UnicodeDecodeError:
        hex_data = payload.hex()
        if len(hex_data) > max_chars:
            return hex_data[:max_chars] + "...[truncated]"
        return hex_data
