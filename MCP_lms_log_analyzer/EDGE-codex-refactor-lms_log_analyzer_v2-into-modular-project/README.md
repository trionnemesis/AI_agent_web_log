# LMS Log Analyzer

AI 驅動的日誌分析系統，整合 OpenSearch 與 Gemini LLM。

## 架構

```
數據流向：
日誌來源 → OpenSearch → AI分析 → 分析結果儲存

核心組件：
- OpenSearch：中央資料儲存（logs-alerts、analysis-cases 索引）
- Log Processor：日誌處理引擎
- LLM Handler：Gemini API 整合
- Vector Search：k-NN 相似案例搜尋
```

## 專案結構

```
lms_log_analyzer/
├── src/
│   ├── opensearch_client.py   # OpenSearch 整合
│   ├── log_processor.py       # 核心處理邏輯
│   ├── llm_handler.py         # LLM 分析
│   ├── log_parser.py          # 日誌解析
│   ├── wazuh_consumer.py      # Wazuh 整合
│   ├── filebeat_server.py     # Filebeat 接收器
│   └── utils.py               # 工具函數
├── config.py                  # 配置管理
└── main.py                    # 程式入口
```

## 快速開始

### 1. 部署 OpenSearch

```bash
docker-compose up -d
```

### 2. 安裝依賴

```bash
cd lms_log_analyzer
pip install -r requirements.txt
```

### 3. 設定環境變數

```bash
cp env.example .env
# 編輯 .env，填入 GEMINI_API_KEY
```

### 4. 執行

```bash
# 檔案模式（向後相容）
python -m lms_log_analyzer.main --mode file

# OpenSearch 模式（推薦）
python -m lms_log_analyzer.main --mode opensearch

# 持續處理模式
python -m lms_log_analyzer.main --mode opensearch --continuous

# 查看統計
python -m lms_log_analyzer.main --stats
```

## 核心功能

### OpenSearch 整合

- **logs-alerts 索引**：儲存原始日誌與分析結果
- **analysis-cases 索引**：k-NN 向量搜尋，儲存高品質案例

### AI 分析流程

1. 從 OpenSearch 讀取未分析日誌
2. 執行快速評分篩選
3. 向量相似度搜尋歷史案例
4. 調用 Gemini API 分析
5. 儲存結果並更新案例庫

### API 使用

```python
from lms_log_analyzer.src.opensearch_client import get_opensearch_client

client = get_opensearch_client()

# 寫入日誌
log_id = client.index_log({
    "raw_log": "Failed SSH login from 192.168.1.100",
    "log_source": "sshd"
})

# 搜尋相似案例
cases = client.search_similar_cases("SQL injection attempt", k=5)

# 取得統計
stats = client.get_stats()
```

## 環境變數

必要：
- `GEMINI_API_KEY`：Google AI API 金鑰
- `OPENSEARCH_HOST`：OpenSearch 主機（預設：localhost）
- `OPENSEARCH_PORT`：OpenSearch 埠號（預設：9200）

可選：
- `VECTOR_SEARCH_K`：相似案例數量（預設：5）
- `CASE_QUALITY_THRESHOLD`：案例品質門檻（預設：0.8）
- `LOG_FETCH_INTERVAL`：處理間隔秒數（預設：60）

完整列表見 `env.example`。

## 測試

```bash
# 單元測試
pytest tests/

# OpenSearch 整合測試
python tests/test_opensearch_integration.py
```

## 監控

OpenSearch Dashboards：http://localhost:5601

可視化：
- 攻擊趨勢
- 分析成本
- 效能指標
- 地理分佈

## 故障排除

### OpenSearch 連線失敗

```bash
curl -X GET "localhost:9200/_cluster/health?pretty"
```

### 索引問題

```bash
# 重建索引
curl -X DELETE "localhost:9200/logs-alerts"
curl -X DELETE "localhost:9200/analysis-cases"
python -m lms_log_analyzer.main --mode opensearch
```

## Logstash 整合

日誌注入管道配置見 `logstash/pipeline/logstash.conf`。

支援來源：
- Filebeat (5044)
- HTTP (8080)
- Syslog (5514)
- Wazuh alerts

## 授權

MIT 