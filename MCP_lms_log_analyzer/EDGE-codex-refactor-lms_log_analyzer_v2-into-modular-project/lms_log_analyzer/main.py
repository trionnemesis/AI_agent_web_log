from __future__ import annotations
"""程式入口點

此腳本負責整合各模組：搜尋待分析的日誌檔、
呼叫處理流程並輸出結果，同時設定日誌系統讓
資訊能寫入檔案與終端機。"""

import logging
import json
from pathlib import Path
from typing import List

import requests

from . import config
from .src.utils import logger, save_state, STATE, tail_since, http_request_with_retry

# 先行設定 logging，讓所有模組共用同一組 handler。
# 預設輸出至終端機，若有權限則同時寫入檔案。
log_handlers: List[logging.Handler] = [logging.StreamHandler()]
try:
    file_handler = logging.FileHandler(config.LMS_OPERATIONAL_LOG_FILE, encoding="utf-8")
    log_handlers.append(file_handler)
except PermissionError:
    print(f"[CRITICAL] Cannot write to {config.LMS_OPERATIONAL_LOG_FILE}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    handlers=log_handlers,
)


def main():
    """
    掃描目標目錄取得最新日誌，並將新增行送至本機 API 分析。

    此函式不再直接處理分析邏輯，而是扮演 API 客戶端的角色，
    定期收集日誌後呼叫 ``/analyze/logs`` 取得分析結果。
    """
    log_paths: List[Path] = []
    if config.LMS_TARGET_LOG_DIR.exists() and config.LMS_TARGET_LOG_DIR.is_dir():
        # 收集目錄下所有支援的日誌檔，包含壓縮格式 (.gz、.bz2)。
        for p in config.LMS_TARGET_LOG_DIR.iterdir():
            if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]:
                log_paths.append(p)
    if not log_paths:
        logger.info(f"No log files found in {config.LMS_TARGET_LOG_DIR}")
        return

    # Collect new log lines
    new_lines: List[str] = []
    for p in log_paths:
        new_lines.extend(tail_since(p))

    if not new_lines:
        logger.info("No new log lines to analyze")
        save_state(STATE)
        return

    # 將收集到的新日誌行打包成 JSON 並送至本地 FastAPI 服務
    try:
        resp = http_request_with_retry(
            "post", "http://localhost:8000/analyze/logs", json={"logs": new_lines}
        )
        results = resp.json()
    except Exception as e:
        logger.error(f"Failed to contact API: {e}")
        results = []
    if results:
        # 有分析結果時將其輸出為 JSON 檔
        try:
            with open(config.LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        except PermissionError:
            logger.error(f"Cannot write analysis output to {config.LMS_ANALYSIS_OUTPUT_FILE}")

    # 每次執行完畢都要儲存狀態
    save_state(STATE)


if __name__ == "__main__":
    # 直接執行檔案時啟動主函式
    main()
