"""OpenSearch 客戶端模組

這個模組取代原本的 vector_db.py，使用 OpenSearch 作為中央資料儲存與搜尋引擎。
支援傳統的全文檢索以及 k-NN 向量相似度搜尋。
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.helpers import bulk
import numpy as np

from .. import config

logger = logging.getLogger(__name__)

# OpenSearch 連線設定
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_SSL = os.getenv("OPENSEARCH_SSL", "true").lower() == "true"
OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"

# 索引名稱
LOGS_ALERTS_INDEX = os.getenv("OPENSEARCH_LOGS_INDEX", "logs-alerts")
ANALYSIS_CASES_INDEX = os.getenv("OPENSEARCH_CASES_INDEX", "analysis-cases")

# 向量搜尋設定
VECTOR_DIMENSION = 384  # 對應 paraphrase-multilingual-MiniLM-L12-v2 模型
KNN_ALGORITHM = "hnsw"
KNN_SPACE_TYPE = "l2"  # 使用 L2 距離

# 嵌入模型
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "paraphrase-multilingual-MiniLM-L12-v2")
    SENTENCE_MODEL = SentenceTransformer(EMBEDDING_MODEL_NAME)
except Exception as e:
    logger.warning(f"無法載入 SentenceTransformer: {e}")
    SENTENCE_MODEL = None


class OpenSearchClient:
    """OpenSearch 客戶端，提供日誌儲存、搜尋和向量相似度搜尋功能"""
    
    def __init__(self):
        """初始化 OpenSearch 客戶端連線"""
        self.client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
            use_ssl=OPENSEARCH_SSL,
            verify_certs=OPENSEARCH_VERIFY_CERTS,
            ssl_show_warn=False,
            connection_class=RequestsHttpConnection,
            timeout=30,
            max_retries=3
        )
        
        # 初始化索引
        self._init_indices()
    
    def _init_indices(self):
        """初始化必要的索引"""
        # logs-alerts 索引映射
        logs_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "raw_log": {"type": "text"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "log_level": {"type": "keyword"},
                    "log_source": {"type": "keyword"},
                    "fast_score": {"type": "float"},
                    "analysis": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "keyword"},
                            "attack_type": {"type": "keyword"},
                            "indicators": {"type": "text"},
                            "recommended_action": {"type": "text"},
                            "confidence": {"type": "float"}
                        }
                    },
                    "analyzed": {"type": "boolean"},
                    "alert_id": {"type": "keyword"},
                    "wazuh_rule_id": {"type": "keyword"}
                }
            }
        }
        
        # analysis-cases 索引映射（支援 k-NN）
        cases_mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "log": {"type": "text"},
                    "log_embedding": {
                        "type": "knn_vector",
                        "dimension": VECTOR_DIMENSION,
                        "method": {
                            "name": KNN_ALGORITHM,
                            "space_type": KNN_SPACE_TYPE,
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    },
                    "analysis": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "keyword"},
                            "attack_type": {"type": "keyword"},
                            "indicators": {"type": "text"},
                            "recommended_action": {"type": "text"},
                            "confidence": {"type": "float"}
                        }
                    },
                    "case_quality": {"type": "keyword"},  # high, medium, low
                    "reference_count": {"type": "integer"}
                }
            }
        }
        
        # 建立索引（如果不存在）
        if not self.client.indices.exists(LOGS_ALERTS_INDEX):
            self.client.indices.create(index=LOGS_ALERTS_INDEX, body=logs_mapping)
            logger.info(f"建立索引: {LOGS_ALERTS_INDEX}")
        
        if not self.client.indices.exists(ANALYSIS_CASES_INDEX):
            self.client.indices.create(index=ANALYSIS_CASES_INDEX, body=cases_mapping)
            logger.info(f"建立索引: {ANALYSIS_CASES_INDEX}")
    
    def embed_text(self, text: str) -> List[float]:
        """將文字轉換為向量"""
        if not SENTENCE_MODEL:
            raise RuntimeError("SentenceTransformer 模型未載入")
        return SENTENCE_MODEL.encode(text, convert_to_numpy=True).tolist()
    
    def index_log(self, log_data: Dict[str, Any]) -> str:
        """將日誌寫入 logs-alerts 索引"""
        log_data["timestamp"] = log_data.get("timestamp", datetime.utcnow().isoformat())
        log_data["analyzed"] = log_data.get("analyzed", False)
        
        response = self.client.index(
            index=LOGS_ALERTS_INDEX,
            body=log_data,
            refresh=True
        )
        return response["_id"]
    
    def bulk_index_logs(self, logs: List[Dict[str, Any]]) -> int:
        """批量寫入日誌"""
        actions = []
        for log in logs:
            log["timestamp"] = log.get("timestamp", datetime.utcnow().isoformat())
            log["analyzed"] = log.get("analyzed", False)
            actions.append({
                "_index": LOGS_ALERTS_INDEX,
                "_source": log
            })
        
        success, _ = bulk(self.client, actions, refresh=True)
        return success
    
    def index_case(self, case_data: Dict[str, Any]) -> str:
        """將分析案例寫入 analysis-cases 索引"""
        # 產生向量嵌入
        if "log" in case_data and "log_embedding" not in case_data:
            case_data["log_embedding"] = self.embed_text(case_data["log"])
        
        case_data["timestamp"] = case_data.get("timestamp", datetime.utcnow().isoformat())
        case_data["reference_count"] = case_data.get("reference_count", 0)
        
        response = self.client.index(
            index=ANALYSIS_CASES_INDEX,
            body=case_data,
            refresh=True
        )
        return response["_id"]
    
    def search_similar_cases(self, query_text: str, k: int = 5, 
                           min_score: float = 0.0) -> List[Dict[str, Any]]:
        """使用 k-NN 搜尋相似的分析案例"""
        if not SENTENCE_MODEL:
            logger.warning("向量模型未載入，返回空結果")
            return []
        
        # 將查詢文字轉換為向量
        query_vector = self.embed_text(query_text)
        
        # 構建 k-NN 查詢
        knn_query = {
            "size": k,
            "query": {
                "knn": {
                    "log_embedding": {
                        "vector": query_vector,
                        "k": k
                    }
                }
            },
            "_source": ["log", "analysis", "case_quality", "timestamp"]
        }
        
        try:
            response = self.client.search(
                index=ANALYSIS_CASES_INDEX,
                body=knn_query
            )
            
            results = []
            for hit in response["hits"]["hits"]:
                if hit["_score"] >= min_score:
                    result = hit["_source"]
                    result["_id"] = hit["_id"]
                    result["_score"] = hit["_score"]
                    results.append(result)
            
            # 更新參考計數
            for result in results:
                self.client.update(
                    index=ANALYSIS_CASES_INDEX,
                    id=result["_id"],
                    body={
                        "script": {
                            "source": "ctx._source.reference_count += 1",
                            "lang": "painless"
                        }
                    }
                )
            
            return results
            
        except Exception as e:
            logger.error(f"k-NN 搜尋失敗: {e}")
            return []
    
    def search_logs(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        """搜尋日誌（全文檢索）"""
        search_body = {
            "size": size,
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        
        response = self.client.search(
            index=LOGS_ALERTS_INDEX,
            body=search_body
        )
        
        results = []
        for hit in response["hits"]["hits"]:
            result = hit["_source"]
            result["_id"] = hit["_id"]
            results.append(result)
        
        return results
    
    def get_unanalyzed_logs(self, size: int = 100) -> List[Dict[str, Any]]:
        """取得尚未分析的日誌"""
        query = {
            "bool": {
                "must": [
                    {"term": {"analyzed": False}}
                ]
            }
        }
        return self.search_logs(query, size)
    
    def update_log_analysis(self, log_id: str, analysis: Dict[str, Any]):
        """更新日誌的分析結果"""
        self.client.update(
            index=LOGS_ALERTS_INDEX,
            id=log_id,
            body={
                "doc": {
                    "analysis": analysis,
                    "analyzed": True,
                    "analyzed_at": datetime.utcnow().isoformat()
                }
            },
            refresh=True
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """取得系統統計資訊"""
        logs_count = self.client.count(index=LOGS_ALERTS_INDEX)["count"]
        analyzed_count = self.client.count(
            index=LOGS_ALERTS_INDEX,
            body={"query": {"term": {"analyzed": True}}}
        )["count"]
        cases_count = self.client.count(index=ANALYSIS_CASES_INDEX)["count"]
        
        return {
            "total_logs": logs_count,
            "analyzed_logs": analyzed_count,
            "unanalyzed_logs": logs_count - analyzed_count,
            "total_cases": cases_count
        }
    
    def close(self):
        """關閉連線"""
        self.client.close()


# 全域實例
opensearch_client = None

def get_opensearch_client() -> OpenSearchClient:
    """取得 OpenSearch 客戶端實例"""
    global opensearch_client
    if opensearch_client is None:
        opensearch_client = OpenSearchClient()
    return opensearch_client 