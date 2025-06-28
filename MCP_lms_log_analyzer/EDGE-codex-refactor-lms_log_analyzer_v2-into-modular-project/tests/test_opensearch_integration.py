"""OpenSearch 整合測試

這個腳本用於測試 OpenSearch 的連線和基本功能
"""

import os
import sys
import json
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# 添加專案路徑
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lms_log_analyzer.src.opensearch_client import get_opensearch_client
from lms_log_analyzer import config


class TestOpenSearchIntegration:
    """OpenSearch 整合測試類別"""
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    def test_connection(self, mock_opensearch):
        """測試 OpenSearch 連線"""
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {
            'version': {'number': '2.11.0'}
        }
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        assert client is not None
        assert client.client is not None
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    def test_indices(self, mock_opensearch):
        """測試索引是否正確建立"""
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        mock_client_instance.indices.exists.side_effect = lambda index: index in [
            config.OPENSEARCH_LOGS_INDEX,
            config.OPENSEARCH_CASES_INDEX
        ]
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        
        # 檢查索引存在性的呼叫
        exists_calls = mock_client_instance.indices.exists.call_args_list
        assert any(call[0][0] == config.OPENSEARCH_LOGS_INDEX for call in exists_calls)
        assert any(call[0][0] == config.OPENSEARCH_CASES_INDEX for call in exists_calls)
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    @patch('lms_log_analyzer.src.opensearch_client.bulk')
    def test_log_operations(self, mock_bulk, mock_opensearch):
        """測試日誌操作"""
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        mock_client_instance.index.return_value = {"_id": "test-log-id"}
        mock_client_instance.search.return_value = {
            "hits": {
                "hits": [
                    {"_id": "test-id", "_source": {"raw_log": "test log"}}
                ]
            }
        }
        mock_client_instance.count.return_value = {"count": 10}
        mock_opensearch.return_value = mock_client_instance
        
        # 模擬 bulk 操作
        mock_bulk.return_value = (5, [])
        
        client = get_opensearch_client()
        
        # 測試寫入單筆日誌
        test_log = {
            "raw_log": "Test log: Failed login attempt from 192.168.1.100",
            "log_source": "test",
            "timestamp": datetime.utcnow().isoformat()
        }
        log_id = client.index_log(test_log)
        assert log_id == "test-log-id"
        
        # 測試批量寫入
        test_logs = [
            {"raw_log": f"Test log {i}: SQL injection attempt", "log_source": "test"}
            for i in range(5)
        ]
        success_count = client.bulk_index_logs(test_logs)
        assert success_count == 5
        
        # 測試搜尋未分析的日誌
        unanalyzed = client.get_unanalyzed_logs(size=10)
        assert len(unanalyzed) == 1
        
        # 測試更新分析結果
        test_analysis = {
            "severity": "high",
            "attack_type": "brute_force",
            "indicators": ["multiple failed login attempts"],
            "recommended_action": "block IP",
            "confidence": 0.85
        }
        client.update_log_analysis("test-id", test_analysis)
        assert mock_client_instance.update.called
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    @patch('lms_log_analyzer.src.opensearch_client.SENTENCE_MODEL')
    def test_vector_search(self, mock_sentence_model, mock_opensearch):
        """測試向量搜尋功能"""
        # 模擬句子嵌入模型
        mock_sentence_model.encode.return_value.tolist.return_value = [0.1] * 384
        
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        mock_client_instance.index.return_value = {"_id": "test-case-id"}
        mock_client_instance.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "similar-case-1",
                        "_score": 0.95,
                        "_source": {
                            "log": "Similar SQL injection",
                            "analysis": {"attack_type": "sql_injection"}
                        }
                    }
                ]
            }
        }
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        
        # 寫入測試案例
        test_case = {
            "log": "SQL injection attack detected: SELECT * FROM users WHERE id='1' OR '1'='1'",
            "analysis": {
                "severity": "critical",
                "attack_type": "sql_injection",
                "indicators": ["SQL keywords in input", "OR condition bypass"],
                "recommended_action": "block request and alert",
                "confidence": 0.95
            },
            "case_quality": "high"
        }
        case_id = client.index_case(test_case)
        assert case_id == "test-case-id"
        
        # 測試相似度搜尋
        similar_cases = client.search_similar_cases(
            "Database query with suspicious OR clause",
            k=3
        )
        assert len(similar_cases) == 1
        assert similar_cases[0]["_score"] == 0.95
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    def test_stats(self, mock_opensearch):
        """測試統計功能"""
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        mock_client_instance.count.side_effect = [
            {"count": 100},  # total_logs
            {"count": 60},   # analyzed_logs
            {"count": 20}    # total_cases
        ]
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        stats = client.get_stats()
        
        assert stats["total_logs"] == 100
        assert stats["analyzed_logs"] == 60
        assert stats["unanalyzed_logs"] == 40
        assert stats["total_cases"] == 20


def test_connection():
    """測試 OpenSearch 連線的簡單版本（用於向後相容）"""
    with patch('lms_log_analyzer.src.opensearch_client.OpenSearch') as mock_opensearch:
        mock_client_instance = MagicMock()
        mock_client_instance.info.return_value = {'version': {'number': '2.11.0'}}
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        assert client is not None


def test_indices():
    """測試索引的簡單版本（用於向後相容）"""
    with patch('lms_log_analyzer.src.opensearch_client.OpenSearch') as mock_opensearch:
        mock_client_instance = MagicMock()
        mock_client_instance.indices.exists.return_value = True
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        assert client is not None


def test_log_operations():
    """測試日誌操作的簡單版本（用於向後相容）"""
    with patch('lms_log_analyzer.src.opensearch_client.OpenSearch') as mock_opensearch:
        mock_client_instance = MagicMock()
        mock_client_instance.index.return_value = {"_id": "test-id"}
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        log_id = client.index_log({"raw_log": "test"})
        assert log_id == "test-id"


def test_vector_search():
    """測試向量搜尋的簡單版本（用於向後相容）"""
    with patch('lms_log_analyzer.src.opensearch_client.OpenSearch') as mock_opensearch:
        with patch('lms_log_analyzer.src.opensearch_client.SENTENCE_MODEL') as mock_model:
            mock_model.encode.return_value.tolist.return_value = [0.1] * 384
            
            mock_client_instance = MagicMock()
            mock_client_instance.search.return_value = {"hits": {"hits": []}}
            mock_opensearch.return_value = mock_client_instance
            
            client = get_opensearch_client()
            results = client.search_similar_cases("test", k=3)
            assert results == []


def test_stats():
    """測試統計功能的簡單版本（用於向後相容）"""
    with patch('lms_log_analyzer.src.opensearch_client.OpenSearch') as mock_opensearch:
        mock_client_instance = MagicMock()
        mock_client_instance.count.side_effect = [
            {"count": 100}, {"count": 60}, {"count": 20}
        ]
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        stats = client.get_stats()
        assert stats["total_logs"] == 100
        assert stats["analyzed_logs"] == 60


if __name__ == "__main__":
    # 保留原本的主程式介面，但使用 pytest
    pytest.main([__file__, "-v"]) 