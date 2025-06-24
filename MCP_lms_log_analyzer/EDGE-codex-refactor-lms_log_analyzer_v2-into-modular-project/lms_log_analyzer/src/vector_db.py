from __future__ import annotations
"""OpenSearch k-NN 向量索引介面"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from opensearchpy import OpenSearch, helpers

from .. import config

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_NAME_DEFAULT = 'paraphrase-multilingual-MiniLM-L12-v2'
    EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", EMBEDDING_MODEL_NAME_DEFAULT)
    SENTENCE_MODEL: Optional[SentenceTransformer] = SentenceTransformer(EMBEDDING_MODEL_NAME)
    if SENTENCE_MODEL:
        EMBED_DIM = SENTENCE_MODEL.get_sentence_embedding_dimension()
    else:
        EMBED_DIM = 384
except Exception:  # pragma: no cover - optional
    SENTENCE_MODEL = None
    EMBED_DIM = 384

logger = logging.getLogger(__name__)


def embed(text: str) -> List[float]:
    """取得文字向量表示"""
    if not SENTENCE_MODEL:
        raise RuntimeError("SentenceTransformer model not available")
    return SENTENCE_MODEL.encode(text, convert_to_numpy=True).tolist()


class VectorIndex:
    """OpenSearch k-NN 索引封裝"""

    def __init__(self, index_name: str, dimension: int) -> None:
        self.index_name = index_name
        self.dimension = dimension
        self.client: Optional[OpenSearch] = None
        self.index = None
        self._connect()

    def _connect(self) -> None:
        try:
            auth = None
            if config.OPENSEARCH_USER and config.OPENSEARCH_PASSWORD:
                auth = (config.OPENSEARCH_USER, config.OPENSEARCH_PASSWORD)
            self.client = OpenSearch(
                hosts=[{"host": config.OPENSEARCH_HOST, "port": config.OPENSEARCH_PORT}],
                http_auth=auth,
                use_ssl=False,
                verify_certs=False,
            )
            self.index = self.client
            self._ensure_index()
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error("OpenSearch connection failed: %s", exc)
            self.client = None
            self.index = None

    def _ensure_index(self) -> None:
        if not self.client:
            return
        try:
            if not self.client.indices.exists(self.index_name):
                body = {
                    "settings": {"index": {"knn": True}},
                    "mappings": {
                        "properties": {
                            "embedding": {"type": "knn_vector", "dimension": self.dimension},
                            "log": {"type": "text"},
                            "analysis": {"type": "object"},
                        }
                    },
                }
                self.client.indices.create(index=self.index_name, body=body)
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error("Failed creating OpenSearch index: %s", exc)

    def save(self) -> None:  # pragma: no cover - compatibility
        """與舊介面相容，OpenSearch 無需另存檔案"""
        return

    def search(self, vec: List[float], k: int = 5) -> Tuple[List[str], List[float]]:
        if not self.client:
            return [], []
        try:
            body = {"size": k, "query": {"knn": {"embedding": {"vector": vec, "k": k}}}}
            resp = self.client.search(index=self.index_name, body=body)
            hits = resp.get("hits", {}).get("hits", [])
            ids = [h["_id"] for h in hits]
            scores = [h["_score"] for h in hits]
            return ids, scores
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error("OpenSearch search failed: %s", exc)
            return [], []

    def add(self, vecs: List[List[float]], cases: List[Dict[str, Any]]) -> None:
        if not self.client:
            return
        actions = [
            {"_op_type": "index", "_index": self.index_name, "_source": {"embedding": v, **c}}
            for v, c in zip(vecs, cases)
        ]
        try:
            helpers.bulk(self.client, actions)
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error("OpenSearch add failed: %s", exc)

    def get_cases(self, ids: List[str]) -> List[Dict[str, Any]]:
        if not self.client or not ids:
            return []
        try:
            resp = self.client.mget(index=self.index_name, body={"ids": ids})
            cases = []
            for doc in resp.get("docs", []):
                if doc.get("found"):
                    src = doc.get("_source", {})
                    cases.append({"log": src.get("log"), "analysis": src.get("analysis")})
            return cases
        except Exception as exc:  # pragma: no cover - optional network failure
            logger.error("OpenSearch get_cases failed: %s", exc)
            return []


VECTOR_DB = VectorIndex(config.OS_VECTOR_INDEX, EMBED_DIM)
