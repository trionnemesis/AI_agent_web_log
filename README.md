# MS AI 日誌分析與告警系統 (基於 Gemini 與 LangChain)

## 概覽與介紹

本系統旨在自動化分析 `/var/log/LMS_LOG/` 目錄下的日誌檔案，利用啟發式規則、向量搜尋（模擬）以及 Google Gemini 大型語言模型（透過 LangChain 框架）來識別潛在的攻擊或異常行為，並在偵測到可疑活動時產生告警。

**核心技術：**

- **Python:** 主要程式語言。
- **LangChain:** 用於簡化與大型語言模型 (LLM) 的互動。
- **Google Gemini Pro (透過 API):** 用於對可疑日誌進行深度分析。腳本中使用 `gemini-2.0-flash` 作為模型範例。

---

## I. 系統架構 (概念流程)

1. **Filebeat 近即時輸入：** Filebeat 監控日誌並將新行透過 HTTP 傳送至 `filebeat_server.py`，立即觸發後續分析。
2. **FastAPI 服務：** 啟動 `api_server.py` 提供 `/analyze/logs` 與 `/investigate` 端點。
3. **批次日誌處理：** `main.py` 會讀取新行並呼叫前述 API 取得分析結果。
4. **Wazuh 告警比對：** 每行先送至 Wazuh `logtest` API，僅保留產生告警的項目並取得告警 JSON。
5. **啟發式評分與取樣：** 對告警行以 `fast_score()` 計算分數，挑選最高分的前 `SAMPLE_TOP_PERCENT`％ 作為候選。
6. **向量嵌入與歷史比對：** 將候選日誌嵌入向量並寫入 FAISS 索引，以便搜尋過往相似模式。
7. **LLM 深度分析：** 把 Wazuh 告警 JSON 傳入 `llm_analyse()` 由 Gemini 分析是否為攻擊行為並回傳結構化結果。
8. **結果輸出與成本控制：** 將分析結果寫入 `analysis_results.json`，同時更新向量索引、狀態檔並追蹤 LLM Token 成本。
9. **標註資料累積：** 分析完的向量與 `is_attack` 等欄位會被追加至 `labeled_dataset.jsonl` 作為訓練資料。
10. **互動式調查：** 透過 `/investigate` 端點輸入任一日誌，即可查詢歷史最相近的案例與當時的 LLM 分析結果。

---

## 專案目錄結構

```text
lms_log_analyzer/
├── main.py
├── config.py
├── requirements.txt
├── src/
│   ├── log_processor.py
│   ├── log_parser.py
│   ├── llm_handler.py
│   ├── vector_db.py
│   ├── utils.py
│   ├── wazuh_api.py
│   └── filebeat_server.py
├── data/
└── logs/
```

## II. 建議安裝環境

- **作業系統 (Operating System):**
    - 建議使用 Linux 發行版 (如 Ubuntu, CentOS, Debian)。因為腳本設計用來讀取類 Unix 系統常見的日誌路徑 (如 `/var/log/`)。
    - macOS 應該也可以運作。
    - Windows 可能需要調整路徑寫法及排程方式。
- **Python 版本:**
    - Python 3.8 或更高版本。
- **虛擬環境 (Virtual Environment - 強烈建議):**
    - 使用 `venv` 或 `conda` 建立獨立的 Python 環境，以避免套件版本衝突。
    - 例如：`python3 -m venv lms_ai_env`

---

## III. 安裝步驟與說明

1. **先決條件 (Prerequisites):**
    - **Python 與 Pip:** 確保您的系統已安裝 Python 3.8+ 及 Pip。
        
        ```bash
        python3 --version
        pip3 --version
        
        ```
        
    - **日誌目錄存取權限:** 執行腳本的使用者需要有權限讀取您設定的 `LOG_DIRECTORY` (預設為 `/var/log/LMS_LOG/`) 及其中的檔案。如果腳本需要在該目錄下創建模擬日誌檔 (當目錄為空時)，則還需要寫入權限。
    - **Google AI Studio API Key:**
        - 您需要前往 [Google AI Studio](https://aistudio.google.com/) 取得 Gemini API 金鑰。
        - 此金鑰將用於讓腳本透過 LangChain 與 Gemini 模型進行通訊。
2. **設定虛擬環境 (建議):**
    - 開啟終端機，進入您想放置專案的目錄。
    - 建立虛擬環境 (假設名稱為 `lms_ai_env`):
        
        ```bash
        python3 -m venv lms_ai_env
        
        ```
        
    - 啟動虛擬環境:
    
    啟動後，您的終端機提示符前應會出現 `(lms_ai_env)`。
        - Linux/macOS:
            
            ```bash
            source lms_ai_env/bin/activate
            
            ```
            
        - Windows:
            
            ```bash
            lms_ai_env\\Scripts\\activate
            
            ```
            
3. **安裝 Python 套件:**
    - 在已啟動的虛擬環境中，執行以下指令安裝必要的 Python 函式庫：
        
        ```bash
        pip install -r lms_log_analyzer/requirements.txt
        ```
        
    - **套件說明:**
        - `langchain`: LangChain 核心函式庫，提供與 LLM 互動的框架。
        - `langchain-google-genai`: LangChain 專用於整合 Google Generative AI (包括 Gemini 模型) 的套件。
        - `google-api-python-client`: Google API 的 Python 客戶端函式庫，`langchain-google-genai` 可能會依賴它。
4. **取得並設定程式:**
    - 下載或 clone 此專案，確保 `lms_log_analyzer` 目錄與上方目錄結構相符。
    - **設定 API 金鑰:**
        - 建議在環境變數 `GEMINI_API_KEY` 中指定，避免將金鑰寫死在程式碼中。
    - **調整設定值:**
        - 所有設定集中於 `lms_log_analyzer/config.py`，也可透過對應環境變數覆寫，如 `LMS_TARGET_LOG_DIR` 等。
5. **目錄與檔案權限 (Directory & File Permissions):**
    - **讀取日誌:** 執行腳本的使用者必須擁有對 `LOG_DIRECTORY` 及其內部日誌檔案的**讀取**權限。
        
        ```bash
        # 範例：檢查目錄權限
        ls -ld /var/log/LMS_LOG/
        # 範例：檢查檔案權限 (假設有個 access.log)
        ls -l /var/log/LMS_LOG/access.log
        
        ```
        
    - **寫入輸出檔案:** 執行腳本的使用者需能寫入 `LMS_ANALYSIS_OUTPUT_FILE` 及 `data/` 目錄，程式才能儲存分析結果與狀態檔。

---

## IV. 執行腳本

1. **啟動虛擬環境** (如果尚未啟動):
    
    ```bash
    source lms_ai_env/bin/activate
    
    ```
    
2. **執行程式:**

    ```bash
    python lms_log_analyzer/main.py

    ```

    若要以近即時方式搭配 Filebeat，啟動以下伺服器：

    ```bash
    python -m lms_log_analyzer.src.filebeat_server
    ```
    
3. **腳本運作流程簡述:**
    - 腳本啟動並載入 `config.py` 設定。
    - 掃描 `LMS_TARGET_LOG_DIR` 取得最新的 `.log` 檔案。
    - 從 `data/file_state.json` 取得先前處理的偏移量，只讀取新增的日誌行。
    - 透過 Wazuh 檢查告警、計算啟發式分數並建立向量索引。
    - 將產生告警的日誌交由 Gemini 分析，取得結構化結果並統計 Token 成本。
    - 儲存分析輸出與最新偏移量，以便下次執行接續處理。
4. **預期輸出檔案位置 (預設):**
    - 分析結果: `/var/log/analyzer_results.json`

5. **Filebeat 範例設定:** 以下是一個簡易的 Filebeat `output.http` 範例，會將日誌傳送至本程式的伺服器：

    ```yaml
    filebeat.inputs:
      - type: log
        paths: ["/var/log/LMS_LOG/*.log"]

    output.http:
      url: "http://localhost:9000/"
      method: POST
      headers:
        Content-Type: application/json
      format: json
      batch_publish: true
    ```

---

## V. 腳本設定詳解 (Configurable Settings)

所有可自訂的參數都集中在 `lms_log_analyzer/config.py` 中，也可透過環境變數覆寫。
常見的設定包含：

- `LMS_TARGET_LOG_DIR`：要掃描的日誌目錄。
- `LMS_ANALYSIS_OUTPUT_FILE`：分析結果輸出的 JSON 路徑。
- `LABELED_DATA_FILE`：累積已標註向量與分析結果的資料集路徑。
- `CACHE_SIZE`、`SAMPLE_TOP_PERCENT`：控制快取大小與取樣比例。
- `MAX_HOURLY_COST_USD`：每小時允許的 LLM 費用上限。
- `GEMINI_API_KEY`：Gemini API 金鑰，可透過環境變數提供。

---

## VI. 系統功能與未來方向 (System Capabilities & Future Roadmap)
為了更清晰地呈現專案的成熟度，我們將原有的「未來可改進建議」拆分為「現已整合的核心功能」與「未來可行的擴充方向」。

1.現已整合的核心功能 (Core Features Already Integrated)
本專案已經從概念驗證發展為一個功能較為完善的系統，許多初期的改進建議已被實作：

2.真實向量搜尋與嵌入 (Advanced Vector Search):

3.系統已整合 FAISS (faiss-cpu) 進行高效的相似性搜尋，並使用 Sentence Transformers 模型將日誌轉換為高維度向量，實現了比對攻擊與正常模式的語義搜尋能力。
LLM 成本優化與批次處理 (LLM Cost Optimization & Batching):

4.透過 LRU 快取機制避免重複分析相同的日誌。
內建成本追蹤器與每小時費用上限，有效控管 API 支出。
採用批次處理 (Batch Processing) 將多個請求一次性發送給 LLM，提升處理效率。
日誌處理與狀態管理 (Log Handling & State Management):

5.原生支援壓縮日誌 (.gz, .bz2) 的讀取與即時解壓縮。
具備日誌輪替感知 (Log Rotation Awareness) 功能，透過追蹤檔案的 inode 和位元組偏移 (offset) 來確保日誌處理的連續性，避免資料遺漏或重複處理。
架構與部署 (Architecture & Deployment):

6.已實現設定外部化，所有參數皆可透過環境變數在 config.py 中覆寫，無需修改程式碼。
整合 Filebeat，提供 filebeat_server.py 以接收日誌串流，達成近即時處理。
包含單元測試與整合測試，確保程式碼品質與可靠性。
未來可行的擴充方向 (Potential Future Extensions)


基於穩固的現有功能，未來可以朝以下方向進行擴充：

1.增強型日誌解析 (Enhanced Log Parsing):

2.針對格式更複雜或多樣的日誌，可引入 python-grok 等函式庫，取代現有的自訂解析邏輯，以更結構化、更可靠的方式提取日誌欄位。
進階告警與整合 (Advanced Alerting & Integration):

3.將分析結果對接到專業的告警平台，如 Slack, PagerDuty, 或 Microsoft Teams，以便告警能更即時、有效地觸達維運團隊。
安全性強化 (Security Hardening):

4.在生產環境中，將 API 金鑰等敏感資訊從環境變數移至更安全的儲存體，例如 HashiCorp Vault, Google Cloud Secret Manager, 或 AWS Secrets Manager。

5.Web UI/儀表板 (Web UI/Dashboard) 暫時定案是opensearch:
基於現有的 FastAPI 後端，開發一個簡單的 Web 介面，用於視覺化呈現告警趨勢、查詢歷史分析結果、查看 Token 使用統計等，提升系統的易用性。
## VIII. 持續整合與測試 (CI)

本專案已加入 GitHub Actions 工作流程 `.github/workflows/python.yml`，
在推送或提出 Pull Request 時會自動安裝依賴並執行 `pytest`。

若要在本地端手動測試，可於專案根目錄下執行：

```bash
cd MCP_lms_log_analyzer/EDGE-codex-refactor-lms_log_analyzer_v2-into-modular-project
pip install -r lms_log_analyzer/requirements.txt
pytest -q tests
```

建立回饋迴圈與自適應模型 (Feedback Loop & Adaptive Models):

將 LLM 的分析結果作為標籤，建立一個持續增長的已標註資料集。利用此資料集定期微調（Fine-tune）嵌入模型或訓練一個輕量級的本地端分類器，讓系統能夠自我學習，變得更懂特定環境的攻擊模式。
多源日誌關聯分析 (Multi-source Log Correlation):

擴充系統以接收多種日誌來源（如：防火牆、資料庫、應用程式），並在偵測到可疑活動時，自動關聯分析來自不同來源但在同一時間窗口內的相關日誌，以拼湊出完整的攻擊鏈。

---

## VII. 常見問題排解 (Troubleshooting Common Issues)

- **`ModuleNotFoundError: No module named 'some_package'`**
    - **原因:** Python 環境中缺少必要的套件。
    - **解決:** 啟動正確的虛擬環境，然後使用 `pip install some_package` 安裝。
- **權限錯誤 (Permission Denied / Errno 13)**
    - **原因:** 腳本執行使用者沒有讀取日誌目錄/檔案或寫入輸出目錄/檔案的權限。
    - **解決:**
        - 檢查並修正相關目錄和檔案的權限 (`ls -l`, `chmod`, `chown`)。
        - 確保以擁有正確權限的使用者執行腳本。
        - 將 `LMS_ANALYSIS_OUTPUT_FILE` 與 `data/` 目錄等輸出路徑設置到使用者具寫入權限的位置 (如 `/tmp/` 或家目錄下的子目錄)。
- **`[Errno 21] Is a directory`**
    - **原因:** 腳本試圖將一個目錄當作檔案來開啟。通常是因為 `LOG_DIRECTORY` 被錯誤地當作完整檔案路徑傳遞給了 `open()` 函數。
    - **解決:** 確保腳本中的路徑變數 (尤其是傳給 `open()` 的) 指向的是檔案而不是目錄。在此腳本的最新版本中，應檢查 `get_latest_log_file` 是否正確返回檔案路徑。
- **API 金鑰問題 (認證失敗、401/403 錯誤)**
    - **原因:** `GEMINI_API_KEY` 未設定、設定錯誤或金鑰本身無效/權限不足。
    - **解決:**
        - 確認 `GEMINI_API_KEY` 已正確設定 (透過環境變數或腳本內提示)。
        - 驗證 API 金鑰是否有效，以及是否已為您的專案啟用 Gemini API。
        - 或者是使用openai key也可以但腳本需要對應的修改
        
- **日誌時間戳解析錯誤**
    - **原因:** 日誌檔案中的時間戳格式與腳本中 `read_incremental_logs` 函數預期的 `strptime` 格式不符。
    - **解決:** 修改 `read_incremental_logs` 中 `datetime.datetime.strptime(timestamp_str, "...")` 的格式字串，使其與您的實際日誌時間戳格式匹配。

---

架構圖
┌────────────┐
│ Log Source │   ← 來自 LMS 系統的 .log/.gz/.bz2 檔案
└────┬───────┘
     │
     ▼
┌──────────────┐
│  Filebeat    │ ← 監控日誌並透過 HTTP 送出
└────┬─────────┘
     │
     ▼
┌────────────┐
│  main.py   │ ← 收集新行並 POST 至 API
└────┬───────┘
     │ HTTP
     ▼
┌──────────────┐
│ FastAPI      │ ← `/analyze/logs` / `/investigate`
│ api_server.py│
└────┬─────────┘
     │
     ▼
┌────────────┐
│  Parser    │ ← 逐行讀取新日誌、解壓縮、處理編碼
│ tail_since │
└────┬───────┘
     │
     ▼
┌──────────────┐
│ Wazuh Filter │ ← 調用 Wazuh logtest 檢查告警
│ filter_logs()│
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ Fast Scorer  │ ← 啟發式快速評分
│ fast_score() │
└────┬─────────┘
     │top X%
     ▼
┌────────────────────┐
│ Vector Embedder     │ ← 用 sentence-transformers 或 SHA256 偽向量
│ embed()             │
└────┬────────────────┘
│                ┌────────────────────┐
│                │ FAISS Vector Index │ ← 搜尋歷史相似模式
│───────────────▶│ search(), add()    │
└────────────────────┘
     ▼
┌────────────────────┐
│ Gemini LLM (Langchain) │ ← 分析是否為攻擊行為
│ llm_analyse()          │
└────────┬──────────────┘
         │
         ▼
┌────────────────────┐
│ Cache / Token Cost │ ← 避免重複分析 + 成本控制
│ LRUCache / Tracker │
└────────┬────────────┘
         ▼
┌────────────────────┐
│ Exporter            │ ← 將分析結果輸出為 JSON
│ JSON / Log Report   │
└────────────────────┘
