from __future__ import annotations
"""從 OpenSearch 取得 Wazuh 告警"""


import logging
from typing import Any, Dict, List, Optional

from opensearchpy import OpenSearch

from .. import config

logger = logging.getLogger(__name__)

_CLIENT: Optional[OpenSearch] = None


def _get_client() -> Optional[OpenSearch]:
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    try:
        auth = None
        if config.OPENSEARCH_USER and config.OPENSEARCH_PASSWORD:
            auth = (config.OPENSEARCH_USER, config.OPENSEARCH_PASSWORD)
        _CLIENT = OpenSearch(
            hosts=[{"host": config.OPENSEARCH_HOST, "port": config.OPENSEARCH_PORT}],
            http_auth=auth,
            use_ssl=False,
            verify_certs=False,
        )
        return _CLIENT
    except Exception as exc:  # pragma: no cover - optional network failure
        logger.error("OpenSearch connection failed: %s", exc)
        _CLIENT = None
        return None

def get_alerts_for_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """依照 log 內容查詢 OpenSearch 中的 Wazuh 告警"""
    if not lines:
        return []
    client = _get_client()
    if client is None:
        return []
    try:
        query = {
            "size": len(lines),
            "query": {"bool": {"filter": {"terms": {"full_log.keyword": lines}}}},
        }
        resp = client.search(index=config.OS_ALERT_INDEX, body=query)
        hits = resp.get("hits", {}).get("hits", [])
        matched = []
        for h in hits:
            src = h.get("_source", {})
            line = src.get("full_log") or src.get("original_log")
            matched.append({"line": line, "alert": src})
        return matched
    except Exception as exc:  # pragma: no cover - optional network failure
        logger.error("OpenSearch query failed: %s", exc)
        return []
