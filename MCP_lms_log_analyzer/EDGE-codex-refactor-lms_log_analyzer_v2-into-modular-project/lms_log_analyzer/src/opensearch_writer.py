"""OpenSearch 輸出模組

This module indexes analysis results into an OpenSearch cluster. The
client is optional to keep local development lightweight.
"""

from typing import Mapping

try:
    from opensearchpy import OpenSearch
except Exception:  # pragma: no cover - optional
    OpenSearch = None  # type: ignore

from .. import config


class OpenSearchWriter:
    """Simple wrapper around the OpenSearch client."""

    def __init__(self, index_name: str) -> None:
        self.index_name = index_name
        if OpenSearch is None:
            self._client = None
        else:
            self._client = OpenSearch(hosts=[config.OPENSEARCH_URL])

    def index_result(self, doc: Mapping[str, object]) -> None:
        if not self._client:
            return
        self._client.index(index=self.index_name, body=dict(doc))
