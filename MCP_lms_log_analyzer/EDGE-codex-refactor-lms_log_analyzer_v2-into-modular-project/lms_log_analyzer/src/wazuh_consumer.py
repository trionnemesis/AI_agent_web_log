from __future__ import annotations
"""Read Wazuh alerts from a dedicated file or HTTP endpoint."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from .. import config

logger = logging.getLogger(__name__)

# Track last read position for file source
_FILE_OFFSET = 0

def _read_from_file() -> List[Dict[str, Any]]:
    """Read new alerts from configured file."""
    path_str = config.WAZUH_ALERTS_FILE
    if not path_str:
        return []
    path = Path(path_str)
    if not path.exists():
        return []
    global _FILE_OFFSET
    alerts = []
    with path.open("r", encoding="utf-8") as f:
        f.seek(_FILE_OFFSET)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                logger.error("Invalid JSON alert line: %s", line)
        _FILE_OFFSET = f.tell()
    return alerts

def _read_from_http() -> List[Dict[str, Any]]:
    """Fetch alerts from HTTP endpoint returning JSON list."""
    url = config.WAZUH_ALERTS_URL
    if not url:
        return []
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return data.get("alerts", [])
        return []
    except Exception as exc:  # pragma: no cover - optional network failure
        logger.error("Failed to fetch alerts from %s: %s", url, exc)
        return []

def get_alerts_for_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """Return alerts whose original log is among provided lines."""
    if not lines:
        return []
    alerts = []
    alerts.extend(_read_from_file())
    alerts.extend(_read_from_http())
    if not alerts:
        return []
    lines_set = set(lines)
    matched = []
    for alert in alerts:
        original = alert.get("full_log") or alert.get("original_log")
        if original and original in lines_set:
            matched.append({"line": original, "alert": alert})
    return matched
