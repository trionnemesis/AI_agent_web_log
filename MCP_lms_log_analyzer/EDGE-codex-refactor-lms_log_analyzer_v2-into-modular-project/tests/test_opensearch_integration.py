"""OpenSearch 整合測試

這個腳本用於測試 OpenSearch 的連線和基本功能
"""

import os
import sys
import json
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock, PropertyMock

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
        # 暫時移除 SKIP_OPENSEARCH_INIT 環境變數以測試索引建立
        original_env = os.environ.get("SKIP_OPENSEARCH_INIT")
        os.environ.pop("SKIP_OPENSEARCH_INIT", None)
        
        try:
            # 模擬 OpenSearch 客戶端
            mock_client_instance = MagicMock()
            mock_client_instance.indices.exists.side_effect = lambda index: False  # 模擬索引不存在
            mock_client_instance.indices.create.return_value = {"acknowledged": True}
            mock_opensearch.return_value = mock_client_instance
            
            client = get_opensearch_client()
            
            # 檢查索引存在性的呼叫
            exists_calls = mock_client_instance.indices.exists.call_args_list
            create_calls = mock_client_instance.indices.create.call_args_list
            
            # 應該檢查兩個索引是否存在
            assert len(exists_calls) >= 2
            # 應該建立兩個索引
            assert len(create_calls) >= 2
            
        finally:
            # 恢復環境變數
            if original_env is not None:
                os.environ["SKIP_OPENSEARCH_INIT"] = original_env
    
    @patch('lms_log_analyzer.src.opensearch_client.OpenSearch')
    @patch('lms_log_analyzer.src.opensearch_client.bulk')
    def test_log_operations(self, mock_bulk, mock_opensearch):
        """測試日誌操作"""
        # 模擬 OpenSearch 客戶端
        mock_client_instance = MagicMock()
        
        # 使用真實的字典作為返回值，避免 MagicMock 的 __getitem__ 問題
        index_response = {"_id": "test-log-id", "_index": "logs-alerts", "_version": 1}
        mock_client_instance.index = Mock(return_value=index_response)
        
        mock_client_instance.search.return_value = {
            "hits": {
                "hits": [
                    {"_id": "test-id", "_source": {"raw_log": "test log"}}
                ]
            }
        }
        
        count_response = {"count": 10}
        mock_client_instance.count = Mock(return_value=count_response)
        
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
        
        # 使用真實的字典作為返回值
        index_response = {"_id": "test-case-id", "_index": "analysis-cases", "_version": 1}
        mock_client_instance.index = Mock(return_value=index_response)
        
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
        
        # 使用 Mock 並設定 side_effect 返回真實的字典
        count_responses = [
            {"count": 100},  # total_logs
            {"count": 60},   # analyzed_logs
            {"count": 20}    # total_cases
        ]
        mock_client_instance.count = Mock(side_effect=count_responses)
        
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
        # 使用真實的字典
        index_response = {"_id": "test-id", "_index": "logs-alerts"}
        mock_client_instance.index = Mock(return_value=index_response)
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
        # 使用 Mock 並設定 side_effect
        count_responses = [
            {"count": 100}, {"count": 60}, {"count": 20}
        ]
        mock_client_instance.count = Mock(side_effect=count_responses)
        mock_opensearch.return_value = mock_client_instance
        
        client = get_opensearch_client()
        stats = client.get_stats()
        assert stats["total_logs"] == 100
        assert stats["analyzed_logs"] == 60


if __name__ == "__main__":
    # 保留原本的主程式介面，但使用 pytest
    pytest.main([__file__, "-v"]) 