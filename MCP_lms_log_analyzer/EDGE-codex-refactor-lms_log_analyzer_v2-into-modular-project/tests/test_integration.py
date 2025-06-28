import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

from lms_log_analyzer.src import log_processor

class MockOpenSearchClient:
    """模擬 OpenSearch 客戶端"""
    def __init__(self):
        self.logs = []
        self.cases = []
    
    def bulk_index_logs(self, logs):
        self.logs.extend(logs)
        return len(logs)
    
    def search_similar_cases(self, query_text, k=5, min_score=0.0):
        # 返回模擬的相似案例
        return [
            {
                "log": "Similar attack log",
                "analysis": {"is_attack": True, "confidence": 0.9},
                "_score": 0.95
            }
        ]
    
    def search_logs(self, query, size=100):
        # 返回模擬的搜尋結果
        return [{"_id": "test-id-123", "raw_log": query}]
    
    def update_log_analysis(self, log_id, analysis):
        pass
    
    def index_case(self, case_data):
        self.cases.append(case_data)
        return f"case-{len(self.cases)}"
    
    def get_unanalyzed_logs(self, size=100):
        return []

class IntegrationTest(TestCase):
    def test_process_logs_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test.log"
            lines = [
                "1.1.1.1 - - [01/Jan/2023:00:00:00 +0000] \"GET /etc/passwd HTTP/1.1\" 404 0 \"-\" \"nmap\" resp_time:2",
                "normal log"
            ]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            # Mock OpenSearch 客戶端
            mock_client = MockOpenSearchClient()
            
            with patch('lms_log_analyzer.src.log_processor.get_opensearch_client', return_value=mock_client), \
                 patch('lms_log_analyzer.src.log_processor.get_alerts_for_lines', 
                       return_value=[{'line': lines[0], 'alert': {'id': '123', 'rule': {'id': '456'}}}]), \
                 patch('lms_log_analyzer.src.log_processor.llm_analyse', 
                       return_value=[{'is_attack': True, 'confidence': 0.95}]) as mock_analyse, \
                 patch('lms_log_analyzer.src.log_processor.save_state'), \
                 patch('lms_log_analyzer.src.log_processor.STATE', {}), \
                 patch('lms_log_analyzer.src.log_processor.config.CASE_QUALITY_THRESHOLD', 0.8):
                
                results = log_processor.process_logs([log_path])
                
                # 驗證 LLM 分析被呼叫
                mock_analyse.assert_called_once()
                arg = mock_analyse.call_args.args[0][0]
                self.assertIn('alert', arg)
                self.assertIn('examples', arg)
                
                # 驗證日誌被寫入 OpenSearch
                self.assertEqual(len(mock_client.logs), 1)
                self.assertEqual(mock_client.logs[0]['raw_log'], lines[0])

        # 驗證結果
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]['analysis']['is_attack'])
        self.assertEqual(results[0]['analysis']['confidence'], 0.95)
    
    def test_process_opensearch_logs(self):
        """測試從 OpenSearch 處理日誌"""
        mock_client = MockOpenSearchClient()
        
        # 模擬未分析的日誌
        mock_client.get_unanalyzed_logs = MagicMock(return_value=[
            {
                "_id": "log-123",
                "raw_log": "SQL injection attempt: SELECT * FROM users",
                "alert_id": "alert-123",
                "wazuh_rule_id": "rule-456"
            }
        ])
        
        with patch('lms_log_analyzer.src.log_processor.get_opensearch_client', return_value=mock_client), \
             patch('lms_log_analyzer.src.log_processor.llm_analyse', 
                   return_value=[{'is_attack': True, 'confidence': 0.9, 'attack_type': 'sql_injection'}]), \
             patch('lms_log_analyzer.src.log_processor.config.CASE_QUALITY_THRESHOLD', 0.8), \
             patch('lms_log_analyzer.src.log_processor.config.SAMPLE_TOP_PERCENT', 100):
            
            results = log_processor.process_opensearch_logs()
            
            # 驗證結果
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]['analysis']['is_attack'])
            self.assertEqual(results[0]['analysis']['attack_type'], 'sql_injection')
            
            # 驗證案例被加入
            self.assertEqual(len(mock_client.cases), 1)
