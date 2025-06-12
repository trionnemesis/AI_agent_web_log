# 專案說明（繁體中文）

本專案提供自動化的 LMS 日誌分析與告警功能，核心程式位於
`MCP_lms_log_analyzer/EDGE-codex-refactor-lms_log_analyzer_v2-into-modular-project` 目錄下。

## 目錄結構與程式用途

- `lms_log_analyzer/`
  - `main.py`：程式入口，整合各模組執行日誌分析流程。
  - `config.py`：集中式設定檔，可透過環境變數覆寫。
  - `requirements.txt`：所需 Python 套件清單。
  - `src/`
    - `filebeat_server.py`：提供 HTTP 介面接收 Filebeat 傳送的日誌。
    - `llm_handler.py`：封裝 Gemini 與 LangChain，處理 LLM 互動與快取。
    - `log_parser.py`：解析日誌並進行啟發式快速評分。
    - `log_processor.py`：核心處理邏輯，呼叫解析、向量比對與 LLM 分析。
    - `utils.py`：狀態管理、檔案處理與通用工具函式。
    - `vector_db.py`：FAISS 向量資料庫封裝。
    - `wazuh_api.py`：與 Wazuh API 溝通的輔助函式。
    - `wazuh_consumer.py`：讀取 Wazuh 告警檔案或端點資料。
  - `data/`：存放向量索引與處理狀態等持久化資料。
  - `logs/`：執行時輸出的記錄檔。

- `tests/`
  - `test_*` 檔案：基本單元測試，驗證主要模組功能是否正常。
