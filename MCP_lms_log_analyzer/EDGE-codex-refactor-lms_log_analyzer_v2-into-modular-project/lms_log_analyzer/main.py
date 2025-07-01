from __future__ import annotations
"""程式入口點

此腳本負責整合各模組：支援兩種運行模式
1. 傳統模式：搜尋待分析的日誌檔
2. OpenSearch 模式：從 OpenSearch 持續處理日誌"""

import argparse
import logging
import json
import sys
from pathlib import Path
from typing import List

# 檢測是否作為腳本直接執行
IS_SCRIPT = __name__ == "__main__" or not __package__

if IS_SCRIPT:
    # 當作為腳本執行時，添加當前目錄到 Python 路徑並使用絕對導入
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))
    
    import config
    from src.log_processor import process_logs, process_opensearch_logs, continuous_process_loop
    from src.utils import logger, save_state, STATE
else:
    # 當作為模組導入時使用相對導入
    from . import config
    from .src.log_processor import process_logs, process_opensearch_logs, continuous_process_loop
    from .src.utils import logger, save_state, STATE

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


def file_mode():
    """傳統檔案模式：尋找日誌檔並啟動處理流程"""
    log_paths: List[Path] = []
    if config.LMS_TARGET_LOG_DIR.exists() and config.LMS_TARGET_LOG_DIR.is_dir():
        # 收集目錄下所有支援的日誌檔，包含壓縮格式 (.gz、.bz2)。
        for p in config.LMS_TARGET_LOG_DIR.iterdir():
            if p.is_file() and p.suffix.lower() in [".log", ".gz", ".bz2"]:
                log_paths.append(p)
    if not log_paths:
        logger.info(f"No log files found in {config.LMS_TARGET_LOG_DIR}")
        return

    # 將實際處理交由 log_processor 模組
    results = process_logs(log_paths)
    if results:
        # 有分析結果時將其輸出為 JSON 檔
        try:
            with open(config.LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        except PermissionError:
            logger.error(f"Cannot write analysis output to {config.LMS_ANALYSIS_OUTPUT_FILE}")

    # 每次執行完畢都要儲存狀態
    save_state(STATE)


def opensearch_mode(continuous: bool = False):
    """OpenSearch 模式：從 OpenSearch 讀取並處理日誌"""
    if continuous:
        # 持續處理模式
        logger.info("Starting continuous OpenSearch processing mode")
        continuous_process_loop()
    else:
        # 單次處理模式
        logger.info("Starting single-run OpenSearch processing mode")
        results = process_opensearch_logs()
        
        if results:
            # 有分析結果時將其輸出為 JSON 檔
            try:
                with open(config.LMS_ANALYSIS_OUTPUT_FILE, "w", encoding="utf-8") as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                logger.info(f"Analysis results written to {config.LMS_ANALYSIS_OUTPUT_FILE}")
            except PermissionError:
                logger.error(f"Cannot write analysis output to {config.LMS_ANALYSIS_OUTPUT_FILE}")


def main():
    """主程式入口，解析命令列參數並執行對應模式"""
    parser = argparse.ArgumentParser(
        description="LMS Log Analyzer - 支援檔案模式與 OpenSearch 模式"
    )
    
    parser.add_argument(
        "--mode",
        choices=["file", "opensearch"],
        default="file",
        help="選擇運行模式：file（傳統檔案模式）或 opensearch（OpenSearch 模式）"
    )
    
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="在 OpenSearch 模式下持續處理（預設為單次執行）"
    )
    
    parser.add_argument(
        "--stats",
        action="store_true",
        help="顯示 OpenSearch 統計資訊"
    )
    
    args = parser.parse_args()
    
    # 如果要求顯示統計資訊
    if args.stats:
        try:
            # 根據執行模式選擇適當的導入方式
            if IS_SCRIPT:
                from src.opensearch_client import get_opensearch_client
            else:
                from .src.opensearch_client import get_opensearch_client
            client = get_opensearch_client()
            stats = client.get_stats()
            print("\n=== OpenSearch 統計資訊 ===")
            print(f"總日誌數: {stats['total_logs']}")
            print(f"已分析: {stats['analyzed_logs']}")
            print(f"未分析: {stats['unanalyzed_logs']}")
            print(f"案例庫大小: {stats['total_cases']}")
            print("========================\n")
        except Exception as e:
            logger.error(f"無法取得統計資訊: {e}")
        return
    
    # 根據模式執行
    if args.mode == "file":
        logger.info("Running in file mode")
        file_mode()
    elif args.mode == "opensearch":
        logger.info("Running in OpenSearch mode")
        opensearch_mode(continuous=args.continuous)


if __name__ == "__main__":
    # 直接執行檔案時啟動主函式
    main()
