from __future__ import annotations
"""日誌讀取與分析核心邏輯 - OpenSearch 版本"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import config
from . import log_parser
from .llm_handler import llm_analyse, COST_TRACKER
from .opensearch_client import get_opensearch_client
from .utils import tail_since, save_state, STATE
from .wazuh_consumer import get_alerts_for_lines

# 模組層級記錄器，供其他函式使用
logger = logging.getLogger(__name__)


def analyse_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """分析多行日誌並回傳結果"""
    
    if not lines:
        return []
    
    alerts = get_alerts_for_lines(lines)
    if not alerts:
        save_state(STATE)
        return []
    
    # 取得 OpenSearch 客戶端
    os_client = get_opensearch_client()
    
    # 先將原始日誌寫入 OpenSearch
    logs_to_index = []
    for alert in alerts:
        log_entry = {
            "raw_log": alert["line"],
            "log_source": alert.get("source", "unknown"),
            "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
            "alert_id": alert.get("alert", {}).get("id"),
            "wazuh_rule_id": alert.get("alert", {}).get("rule", {}).get("id"),
            "analyzed": False
        }
        logs_to_index.append(log_entry)
    
    # 批量寫入日誌
    if logs_to_index:
        os_client.bulk_index_logs(logs_to_index)
    
    # 評分並選擇要分析的日誌
    scored = [(log_parser.fast_score(a["line"]), a) for a in alerts]
    scored.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored) * config.SAMPLE_TOP_PERCENT / 100))
    top_scored = [sl for sl in scored if sl[0] > 0.0][:num_to_sample]
    
    if not top_scored:
        save_state(STATE)
        return []
    
    top_lines = [item["line"] for _, item in top_scored]
    top_alerts = [item["alert"] for _, item in top_scored]
    
    # 為每個日誌查詢相似案例
    contexts = []
    for line in top_lines:
        similar_cases = os_client.search_similar_cases(
            line, 
            k=config.VECTOR_SEARCH_K,
            min_score=config.VECTOR_MIN_SCORE
        )
        contexts.append(similar_cases)
    
    # 準備 LLM 分析輸入
    analysis_inputs = [
        {"alert": alert, "examples": ctx} 
        for alert, ctx in zip(top_alerts, contexts)
    ]
    
    # 執行 LLM 分析
    analysis_results = llm_analyse(analysis_inputs)
    
    # 處理分析結果
    exported: List[Dict[str, Any]] = []
    for (fast_s, item), analysis, line in zip(top_scored, analysis_results, top_lines):
        # 準備完整的日誌項目
        entry: Dict[str, Any] = {
            "log": item["line"],
            "fast_score": fast_s,
            "analysis": analysis,
            "timestamp": item.get("timestamp", datetime.utcnow().isoformat())
        }
        exported.append(entry)
        
        # 更新 logs-alerts 索引中的分析結果
        # 這裡需要找到對應的日誌 ID，可以透過查詢實現
        search_query = {
            "bool": {
                "must": [
                    {"match": {"raw_log": line}},
                    {"term": {"analyzed": False}}
                ]
            }
        }
        matching_logs = os_client.search_logs(search_query, size=1)
        if matching_logs:
            log_id = matching_logs[0]["_id"]
            os_client.update_log_analysis(log_id, analysis)
        
        # 如果分析結果品質高，加入案例庫
        if analysis.get("confidence", 0) >= config.CASE_QUALITY_THRESHOLD:
            case_data = {
                "log": line,
                "analysis": analysis,
                "case_quality": "high" if analysis.get("confidence", 0) >= 0.9 else "medium",
                "timestamp": datetime.utcnow().isoformat()
            }
            os_client.index_case(case_data)
    
    save_state(STATE)
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    logger.info(f"Analyzed {len(exported)} logs")
    
    return exported


def process_logs(log_paths: List[Path]) -> List[Dict[str, Any]]:
    """讀取指定的日誌檔並回傳可疑行的分析結果"""
    
    # 依序讀取所有待處理的檔案，只保留新增的部分
    all_new_lines: List[str] = []
    for p in log_paths:
        if not p.exists() or not p.is_file():
            continue
        # ``tail_since`` 只會取出自上次處理後的新行
        all_new_lines.extend(tail_since(p))
    
    return analyse_lines(all_new_lines)


def process_opensearch_logs() -> List[Dict[str, Any]]:
    """從 OpenSearch 處理未分析的日誌"""
    
    os_client = get_opensearch_client()
    
    # 取得未分析的日誌
    unanalyzed_logs = os_client.get_unanalyzed_logs(size=config.OPENSEARCH_BATCH_SIZE)
    
    if not unanalyzed_logs:
        logger.info("No unanalyzed logs found")
        return []
    
    logger.info(f"Found {len(unanalyzed_logs)} unanalyzed logs")
    
    # 評分並選擇要分析的日誌
    scored_logs = []
    for log in unanalyzed_logs:
        score = log_parser.fast_score(log["raw_log"])
        if score > 0.0:
            scored_logs.append((score, log))
    
    scored_logs.sort(key=lambda x: x[0], reverse=True)
    num_to_sample = max(1, int(len(scored_logs) * config.SAMPLE_TOP_PERCENT / 100))
    top_logs = scored_logs[:num_to_sample]
    
    if not top_logs:
        # 將所有日誌標記為已分析（但沒有結果）
        for log in unanalyzed_logs:
            os_client.update_log_analysis(log["_id"], {"analyzed": True, "skipped": True})
        return []
    
    # 為每個日誌查詢相似案例
    analysis_inputs = []
    for score, log in top_logs:
        similar_cases = os_client.search_similar_cases(
            log["raw_log"],
            k=config.VECTOR_SEARCH_K,
            min_score=config.VECTOR_MIN_SCORE
        )
        
        # 準備 alert 物件（相容舊格式）
        alert_obj = {
            "id": log.get("alert_id", ""),
            "rule": {"id": log.get("wazuh_rule_id", "")},
            "data": log.get("raw_log", "")
        }
        
        analysis_inputs.append({
            "alert": alert_obj,
            "examples": similar_cases
        })
    
    # 執行 LLM 分析
    analysis_results = llm_analyse(analysis_inputs)
    
    # 處理分析結果
    exported = []
    for (score, log), analysis in zip(top_logs, analysis_results):
        # 更新日誌的分析結果
        os_client.update_log_analysis(log["_id"], analysis)
        
        # 如果分析結果品質高，加入案例庫
        if analysis.get("confidence", 0) >= config.CASE_QUALITY_THRESHOLD:
            case_data = {
                "log": log["raw_log"],
                "analysis": analysis,
                "case_quality": "high" if analysis.get("confidence", 0) >= 0.9 else "medium"
            }
            os_client.index_case(case_data)
        
        exported.append({
            "log": log["raw_log"],
            "fast_score": score,
            "analysis": analysis,
            "timestamp": log.get("timestamp")
        })
    
    # 標記其餘未分析的日誌
    analyzed_ids = {log["_id"] for _, log in top_logs}
    for log in unanalyzed_logs:
        if log["_id"] not in analyzed_ids:
            os_client.update_log_analysis(log["_id"], {"analyzed": True, "skipped": True})
    
    logger.info(f"LLM stats: {COST_TRACKER.get_total_stats()}")
    logger.info(f"Analyzed {len(exported)} logs from OpenSearch")
    
    return exported


def continuous_process_loop():
    """持續從 OpenSearch 處理日誌的循環"""
    
    logger.info("Starting continuous OpenSearch log processing")
    
    while True:
        try:
            results = process_opensearch_logs()
            
            if results:
                # 可選：將結果寫入檔案或其他地方
                if config.LMS_ANALYSIS_OUTPUT_FILE:
                    with open(config.LMS_ANALYSIS_OUTPUT_FILE, "a", encoding="utf-8") as f:
                        for result in results:
                            f.write(json.dumps(result, ensure_ascii=False) + "\n")
            
            # 等待下一輪
            time.sleep(config.LOG_FETCH_INTERVAL)
            
        except KeyboardInterrupt:
            logger.info("Process interrupted by user")
            break
        except Exception as e:
            logger.error(f"Error in processing loop: {e}", exc_info=True)
            time.sleep(config.LOG_FETCH_INTERVAL)
