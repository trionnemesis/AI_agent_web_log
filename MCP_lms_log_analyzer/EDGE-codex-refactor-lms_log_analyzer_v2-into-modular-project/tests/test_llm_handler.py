import json
import unittest
from unittest.mock import MagicMock, patch

from lms_log_analyzer.src import llm_handler
from lms_log_analyzer.src.utils import LRUCache


class DummyPrompt:
    def format(self, **kwargs):
        return "dummy"


class LLMHandlerTest(unittest.TestCase):
    def setUp(self):
        self.orig_chain = llm_handler.LLM_CHAIN
        self.orig_prompt = getattr(llm_handler, "PROMPT", None)
        self.orig_cost = llm_handler.COST_TRACKER.get_hourly_cost
        llm_handler.LLM_CHAIN = MagicMock()
        # 修正：提供完整的 LLM 回應格式，包含所有必要欄位
        llm_handler.LLM_CHAIN.batch.return_value = [
            json.dumps({
                "is_attack": False,
                "attack_type": "N/A",
                "reason": "Test response",
                "severity": "None"
            })
        ]
        llm_handler.PROMPT = DummyPrompt()
        llm_handler.CACHE = LRUCache(10)

    def tearDown(self):
        llm_handler.LLM_CHAIN = self.orig_chain
        if self.orig_prompt is not None:
            llm_handler.PROMPT = self.orig_prompt
        llm_handler.COST_TRACKER.get_hourly_cost = self.orig_cost

    def test_summarize_examples_format(self):
        examples = [
            {"log": "line1\n", "analysis": {"attack_type": "phish", "reason": "x"}},
            {"log": "line2", "analysis": {"attack_type": "mal", "reason": "y"}},
        ]

        summary = llm_handler._summarize_examples(examples)
        self.assertNotIn("line1", summary)
        self.assertIn("歷史攻擊: phish | 理由: x", summary)
        self.assertIn("歷史攻擊: mal | 理由: y", summary)

    def test_llm_analyse_caches_and_summarizes(self):
        example = {
            "log": "bad log",
            "analysis": {"attack_type": "sql", "reason": "r"},
        }
        alerts = [{"alert": {"rule": {"id": 1}}, "examples": [example]}]

        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result1 = llm_handler.llm_analyse(alerts)

        llm_handler.LLM_CHAIN.batch.assert_called_once()
        sent = llm_handler.LLM_CHAIN.batch.call_args.args[0][0]["examples_summary"]
        self.assertNotIn("bad log", sent)
        self.assertIn("sql", sent)
        self.assertIn("r", sent)
        alert_json = llm_handler.LLM_CHAIN.batch.call_args.args[0][0]["alert_json"]
        self.assertIn("\"id\": 1", alert_json)

        llm_handler.LLM_CHAIN.batch.reset_mock()
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result2 = llm_handler.llm_analyse(alerts)

        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result1, result2)

    def test_llm_analyse_budget_limit(self):
        llm_handler.COST_TRACKER.get_hourly_cost = MagicMock(return_value=llm_handler.config.MAX_HOURLY_COST_USD)

        alerts = [{"alert": {"rule": {"id": 1}}, "examples": []}]
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f,*a,**k: f(*a, **k)):
            result = llm_handler.llm_analyse(alerts)
        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result[0]["reason"], "Budget limit reached")

    def test_llm_analyse_disabled(self):
        llm_handler.LLM_CHAIN = None

        alerts = [{"alert": {"rule": {"id": 1}}, "examples": []}]
        result = llm_handler.llm_analyse(alerts)
        self.assertEqual(result, [None])

    def test_llm_analyse_invalid_response(self):
        """測試 LLM 回應格式不正確時的處理"""
        # 模擬 LLM 回傳格式不正確的 JSON
        llm_handler.LLM_CHAIN.batch.return_value = [
            json.dumps({"is_attack": False})  # 缺少必要欄位
        ]
        
        alerts = [{"alert": {"rule": {"id": 1}}, "examples": []}]
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = llm_handler.llm_analyse(alerts)
        
        # 應該回傳預設值或 None，而不是拋出例外
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)

    def test_llm_analyse_malformed_json(self):
        """測試 LLM 回傳非 JSON 格式時的處理"""
        # 模擬 LLM 回傳非 JSON 格式
        llm_handler.LLM_CHAIN.batch.return_value = ["invalid json response"]
        
        alerts = [{"alert": {"rule": {"id": 1}}, "examples": []}]
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result = llm_handler.llm_analyse(alerts)
        
        # 應該優雅地處理錯誤，回傳預設值
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
