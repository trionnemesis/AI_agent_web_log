from __future__ import annotations
import json
import logging
import time
from typing import Any, Dict, List, Optional
import hashlib

"""LLM 互動工具

此模組封裝 Gemini 模型與 LangChain 的整合，負責快取回應、
追蹤 Token 使用成本，並提供 ``llm_analyse`` 供 :mod:`log_processor`
 呼叫。"""

from .. import config
from .utils import CACHE, retry_with_backoff

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import Runnable
    from langchain_core.messages import AIMessage
except ImportError:  # pragma: no cover - optional
    ChatGoogleGenerativeAI = None
    PromptTemplate = None
    Runnable = None
    AIMessage = None

# 模組記錄器，提供除錯與成本追蹤資訊
logger = logging.getLogger(__name__)

LLM_CHAIN: Optional[Runnable] = None

if config.GEMINI_API_KEY and ChatGoogleGenerativeAI and PromptTemplate:
    try:
        llm = ChatGoogleGenerativeAI(
            model=config.LLM_MODEL_NAME,
            google_api_key=config.GEMINI_API_KEY,
            temperature=0.3,
            convert_system_message_to_human=True,
        )
        PROMPT_TEMPLATE_STR = """
System: 你是一位經驗豐富的 SOC 資安分析師。你將收到一份 Wazuh 告警 (僅保留關鍵欄位)，以及若干歷史案例的精簡摘要。請依下列思考流程進行判斷：
1. 研讀告警中的 IP、Port、Rule 描述與原始日誌，推論可能的威脅情境。
2. 與歷史案例比對相似度，參考其攻擊類型與推論理由。
3. 綜合 (1)(2) 給出是否屬於攻擊、攻擊類型、嚴重度，並以簡潔中文說明判斷依據。

注意事項：
- 務必依照 JSON Schema 回傳，不要加入多餘文字。
- 若無足夠證據，請謹慎標記 is_attack = false，並在 reason 中說明疑慮。
- severity 嚴重度建議：Critical | High | Medium | Low | None。

歷史案例摘要 (最多 5 筆，每行一例)：
{examples_summary}

Wazuh Alert (精簡)：
{alert_json}

請僅輸出以下 JSON (不要加上 markdown 標記)：
- "is_attack": boolean
- "attack_type": string
- "reason": string (≤120 字，內含你的簡要思考過程)
- "severity": string
"""
        PROMPT = PromptTemplate(
            input_variables=["alert_json", "examples_summary"],
            template=PROMPT_TEMPLATE_STR
        )
        LLM_CHAIN = PROMPT | llm  # type: ignore
        logger.info(f"LLM ({config.LLM_MODEL_NAME}) initialized")
    except Exception as e:  # pragma: no cover - optional
        logger.error(f"Failed initializing LLM: {e}")
        LLM_CHAIN = None
else:
    if not config.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set; LLM disabled")
    LLM_CHAIN = None


class LLMCostTracker:
    """追蹤 LLM Token 使用量與費用的輔助類別"""

    def __init__(self) -> None:
        # 以小時計算與累積總量，便於限制費用並觀察長期趨勢
        self.in_tokens_hourly = 0
        self.out_tokens_hourly = 0
        self.cost_hourly = 0.0
        self.total_in_tokens = 0
        self.total_out_tokens = 0
        self.total_cost = 0.0
        # 紀錄目前小時段起始時間
        self.hour_start_ts = time.time()

    def _maybe_reset_hour(self) -> None:
        """若已跨過一小時則重置統計"""
        if time.time() - self.hour_start_ts >= 3600:
            self.in_tokens_hourly = 0
            self.out_tokens_hourly = 0
            self.cost_hourly = 0.0
            self.hour_start_ts = time.time()

    def add_usage(self, in_tok: int, out_tok: int) -> None:
        """記錄一次呼叫的 Token 數量"""
        self._maybe_reset_hour()

        self.in_tokens_hourly += in_tok
        self.out_tokens_hourly += out_tok
        current_cost = (
            in_tok / 1000 * config.PRICE_IN_PER_1K_TOKENS
            + out_tok / 1000 * config.PRICE_OUT_PER_1K_TOKENS
        )
        self.cost_hourly += current_cost
        self.total_in_tokens += in_tok
        self.total_out_tokens += out_tok
        self.total_cost += current_cost

    def get_hourly_cost(self) -> float:
        """取得本小時累積費用"""
        self._maybe_reset_hour()
        return self.cost_hourly

    def get_current_hour_stats(self) -> Dict[str, Any]:
        """取得當前小時統計資料"""
        self._maybe_reset_hour()
        return {
            "hour_start": self.hour_start_ts,
            "input_tokens": self.in_tokens_hourly,
            "output_tokens": self.out_tokens_hourly,
            "cost_usd": self.cost_hourly,
        }

    def get_total_stats(self) -> Dict[str, Any]:
        """回傳跨執行期間的總體使用統計"""
        return {
            "total_input_tokens": self.total_in_tokens,
            "total_output_tokens": self.total_out_tokens,
            "total_cost_usd": self.total_cost,
        }


COST_TRACKER = LLMCostTracker()


def _trim_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """將告警資料縮減至最關鍵欄位，以節省 Token

    保留：
    - rule.id / rule.description / rule.level
    - srcip, dstip, srcport, dstport
    - original_log (折疊多餘空白並截斷過長內容)
    """
    rule = alert.get("rule", {})
    trimmed: Dict[str, Any] = {
        "rule": {
            "id": rule.get("id"),
            "description": rule.get("description"),
            "level": rule.get("level"),
        }
    }

    # IP 與 Port 資訊
    data = alert.get("data", {})
    ip_port = {k: v for k, v in (
        ("srcip", data.get("srcip")),
        ("dstip", data.get("dstip")),
        ("srcport", data.get("srcport")),
        ("dstport", data.get("dstport")),
    ) if v}
    if ip_port:
        trimmed["data"] = ip_port

    # 原始日誌 (移除多餘空白並限制長度)
    original = alert.get("full_log") or alert.get("original_log")
    if original:
        compact = " ".join(str(original).split())
        if len(compact) > 300:
            compact = compact[:300] + "..."
        trimmed["original_log"] = compact

    return trimmed


def _summarize_examples(examples: List[Dict[str, Any]], *, max_examples: int = 5, max_reason_len: int = 80) -> str:
    """將歷史案例摘要為高資訊密度的一行文字，最多 `max_examples` 筆。

    每行格式：
    歷史攻擊: {attack_type} | 嚴重度: {severity} | 理由: {reason}
    """
    if not examples:
        return "無歷史案例"

    parts: List[str] = []
    for ex in examples[:max_examples]:
        analysis = ex.get("analysis", {})
        attack_type = analysis.get("attack_type", "未知")
        severity = analysis.get("severity", "")
        reason = analysis.get("reason", "")
        if len(reason) > max_reason_len:
            reason = reason[:max_reason_len] + "..."
        summary = f"歷史攻擊: {attack_type}"
        if severity:
            summary += f" | 嚴重度: {severity}"
        summary += f" | 理由: {reason}"
        parts.append(summary)

    return "\n".join(parts) if parts else "無有效歷史案例"


def _count_tokens_estimate(text: str) -> int:
    """估算文字的 Token 數量（簡化版本）"""
    # 簡化的 token 計算，實際應使用對應模型的 tokenizer
    return len(text.split())


def _generate_cache_key(alert: Dict[str, Any], examples: List[Dict[str, Any]]) -> str:
    """生成快取鍵值，包含告警和歷史案例的內容"""
    # 將告警和歷史案例合併為一個字典來生成快取鍵
def llm_analyse(alerts: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]:
    """使用 LLM 分析告警並回傳 JSON 結果

    若同一筆資料先前已分析過，將從快取取得結果以節省費用；
    當 LLM 停用或超過本小時預算時，會回傳預設結果而不呼叫 API。
    """
    if not LLM_CHAIN:
        logger.warning("LLM disabled")
        return [None] * len(alerts)

    # 預先建立結果陣列與要查詢的索引
    results: List[Optional[Dict[str, Any]]] = [None] * len(alerts)
    indices_to_query: List[int] = []
    batch_inputs: List[Dict[str, str]] = []

    for idx, item in enumerate(alerts):
        alert = item.get("alert", item)
        trimmed = _trim_alert(alert)
        alert_json = json.dumps(trimmed, ensure_ascii=False, sort_keys=True)
        cache_key = hashlib.sha256(alert_json.encode("utf-8", "replace")).hexdigest()
        cached = CACHE.get(cache_key)
        
        if cached is not None:
            # 若已在快取中，直接使用
            results[idx] = cached
            continue

        examples_summary = _summarize_examples(item.get("examples", []))
        indices_to_query.append(idx)
        batch_inputs.append({
            "alert_json": alert_json, 
            "examples_summary": examples_summary
        })

    if not batch_inputs:
        # 全部都有快取，不需再呼叫 LLM
        logger.info("All alerts found in cache, no LLM calls needed")
        return results

    if COST_TRACKER.get_hourly_cost() >= config.MAX_HOURLY_COST_USD:
        # 目前累積費用已達上限，不再呼叫 LLM
        logger.warning("LLM cost limit reached; skipping analysis")
        for i in indices_to_query:
            results[i] = {
                "is_attack": False,
                "attack_type": "N/A",
                "reason": "Budget limit reached",
                "severity": "None",
            }
        return results

    try:
        total_in = 0
        total_out = 0
        
        for start in range(0, len(batch_inputs), config.BATCH_SIZE):
            chunk = batch_inputs[start : start + config.BATCH_SIZE]
            chunk_indices = indices_to_query[start : start + config.BATCH_SIZE]
            
            responses = retry_with_backoff(
                LLM_CHAIN.batch,
                chunk,
                config={"max_concurrency": 5},
            )  # type: ignore
            
            for i, resp in enumerate(responses):
                orig_idx = chunk_indices[i]
                
                # 處理不同類型的回應
                if hasattr(resp, 'content'):
                    text = resp.content
                elif isinstance(resp, str):
                    text = resp
                else:
                    text = str(resp)
                
                item = alerts[orig_idx]
                alert = item.get("alert", item)
                trimmed = _trim_alert(alert)
                alert_json = json.dumps(trimmed, ensure_ascii=False, sort_keys=True)
                cache_key = hashlib.sha256(alert_json.encode("utf-8", "replace")).hexdigest()
                examples_summary = _summarize_examples(item.get("examples", []))
                
                try:
                    # 清理回應文字，移除可能的前後綴
                    clean_text = text.strip()
                    if clean_text.startswith('```json'):
                        clean_text = clean_text[7:]
                    if clean_text.endswith('```'):
                        clean_text = clean_text[:-3]
                    clean_text = clean_text.strip()
                    
                    parsed = json.loads(clean_text)
                    
                    # 驗證必要欄位
                    required_fields = ["is_attack", "attack_type", "reason", "severity"]
                    if not all(field in parsed for field in required_fields):
                        raise ValueError(f"Missing required fields in LLM response")
                    
                    # 成功解析則寫入結果並更新快取
                    results[orig_idx] = parsed
                    CACHE.put(cache_key, parsed)
                    
                    # 估算 token 使用量
                    prompt_text = PROMPT.format(
                        alert_json=alert_json,
                        examples_summary=examples_summary
                    )  # type: ignore
                    total_in += _count_tokens_estimate(prompt_text)
                    total_out += _count_tokens_estimate(text)
                    
                except (json.JSONDecodeError, ValueError) as e:
                    logger.error(f"Failed parsing LLM response: {e}")
                    logger.debug(f"Raw response: {text}")
                    results[orig_idx] = {
                        "is_attack": True,
                        "attack_type": "LLM Parse Error",
                        "reason": f"Response parsing failed: {str(e)}",
                        "severity": "Medium",
                    }
        
        # 紀錄本次批次的 Token 使用量
        if total_in > 0 or total_out > 0:
            COST_TRACKER.add_usage(total_in, total_out)
            logger.info(f"LLM usage: {total_in} input tokens, {total_out} output tokens")
            
    except Exception as e:  # pragma: no cover - optional
        # API 呼叫失敗，回傳錯誤資訊
        logger.error(f"LLM batch call failed: {e}")
        for i in indices_to_query:
            results[i] = {
                "is_attack": True,
                "attack_type": "LLM API Error",
                "reason": f"API call failed: {str(e)}",
                "severity": "High",
            }
    
    return results