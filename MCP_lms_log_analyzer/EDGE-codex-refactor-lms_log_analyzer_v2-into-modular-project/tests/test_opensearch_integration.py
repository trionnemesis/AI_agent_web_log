"""OpenSearch 整合測試

這個腳本用於測試 OpenSearch 的連線和基本功能
"""

import os
import sys
import json
from datetime import datetime

# 添加專案路徑
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lms_log_analyzer.src.opensearch_client import get_opensearch_client
from lms_log_analyzer import config


def test_connection():
    """測試 OpenSearch 連線"""
    print("測試 OpenSearch 連線...")
    try:
        client = get_opensearch_client()
        info = client.client.info()
        print(f"✓ 成功連線到 OpenSearch {info['version']['number']}")
        return True
    except Exception as e:
        print(f"✗ 連線失敗: {e}")
        return False


def test_indices():
    """測試索引是否正確建立"""
    print("\n測試索引...")
    try:
        client = get_opensearch_client()
        
        # 檢查 logs-alerts 索引
        if client.client.indices.exists(config.OPENSEARCH_LOGS_INDEX):
            print(f"✓ {config.OPENSEARCH_LOGS_INDEX} 索引存在")
        else:
            print(f"✗ {config.OPENSEARCH_LOGS_INDEX} 索引不存在")
        
        # 檢查 analysis-cases 索引
        if client.client.indices.exists(config.OPENSEARCH_CASES_INDEX):
            print(f"✓ {config.OPENSEARCH_CASES_INDEX} 索引存在")
        else:
            print(f"✗ {config.OPENSEARCH_CASES_INDEX} 索引不存在")
        
        return True
    except Exception as e:
        print(f"✗ 索引檢查失敗: {e}")
        return False


def test_log_operations():
    """測試日誌操作"""
    print("\n測試日誌操作...")
    try:
        client = get_opensearch_client()
        
        # 測試寫入單筆日誌
        test_log = {
            "raw_log": "Test log: Failed login attempt from 192.168.1.100",
            "log_source": "test",
            "timestamp": datetime.utcnow().isoformat()
        }
        log_id = client.index_log(test_log)
        print(f"✓ 成功寫入測試日誌，ID: {log_id}")
        
        # 測試批量寫入
        test_logs = [
            {"raw_log": f"Test log {i}: SQL injection attempt", "log_source": "test"}
            for i in range(5)
        ]
        success_count = client.bulk_index_logs(test_logs)
        print(f"✓ 成功批量寫入 {success_count} 筆日誌")
        
        # 測試搜尋未分析的日誌
        unanalyzed = client.get_unanalyzed_logs(size=10)
        print(f"✓ 找到 {len(unanalyzed)} 筆未分析的日誌")
        
        # 測試更新分析結果
        if unanalyzed:
            test_analysis = {
                "severity": "high",
                "attack_type": "brute_force",
                "indicators": ["multiple failed login attempts"],
                "recommended_action": "block IP",
                "confidence": 0.85
            }
            client.update_log_analysis(unanalyzed[0]["_id"], test_analysis)
            print(f"✓ 成功更新日誌分析結果")
        
        return True
    except Exception as e:
        print(f"✗ 日誌操作失敗: {e}")
        return False


def test_vector_search():
    """測試向量搜尋功能"""
    print("\n測試向量搜尋...")
    try:
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
        print(f"✓ 成功寫入測試案例，ID: {case_id}")
        
        # 測試相似度搜尋
        similar_cases = client.search_similar_cases(
            "Database query with suspicious OR clause",
            k=3
        )
        print(f"✓ 找到 {len(similar_cases)} 個相似案例")
        
        if similar_cases:
            print(f"  最相似案例分數: {similar_cases[0].get('_score', 'N/A')}")
        
        return True
    except Exception as e:
        print(f"✗ 向量搜尋失敗: {e}")
        return False


def test_stats():
    """測試統計功能"""
    print("\n測試統計功能...")
    try:
        client = get_opensearch_client()
        stats = client.get_stats()
        
        print("✓ 系統統計資訊:")
        print(f"  總日誌數: {stats['total_logs']}")
        print(f"  已分析: {stats['analyzed_logs']}")
        print(f"  未分析: {stats['unanalyzed_logs']}")
        print(f"  案例庫大小: {stats['total_cases']}")
        
        return True
    except Exception as e:
        print(f"✗ 統計功能失敗: {e}")
        return False


def main():
    """執行所有測試"""
    print("=== OpenSearch 整合測試 ===\n")
    
    tests = [
        test_connection,
        test_indices,
        test_log_operations,
        test_vector_search,
        test_stats
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
    
    print(f"\n=== 測試結果 ===")
    print(f"通過: {passed}")
    print(f"失敗: {failed}")
    
    if failed == 0:
        print("\n✓ 所有測試通過！")
    else:
        print(f"\n✗ {failed} 個測試失敗")
        sys.exit(1)


if __name__ == "__main__":
    main() 