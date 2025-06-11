import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from lms_log_analyzer.src import llm_handler
from lms_log_analyzer import config

class TestLLMHandler(unittest.TestCase):
    def setUp(self):
        self.orig_chain = llm_handler.LLM_CHAIN
        self.orig_prompt = getattr(llm_handler, "PROMPT", None)
        llm_handler.LLM_CHAIN = Mock()
        llm_handler.PROMPT = SimpleNamespace(format=lambda **kw: "prompt")
        llm_handler.CACHE.clear()
        llm_handler.COST_TRACKER.cost_hourly = 0.0
        llm_handler.COST_TRACKER.in_tokens_hourly = 0
        llm_handler.COST_TRACKER.out_tokens_hourly = 0
        llm_handler.COST_TRACKER.total_in_tokens = 0
        llm_handler.COST_TRACKER.total_out_tokens = 0
        llm_handler.COST_TRACKER.total_cost = 0.0

    def tearDown(self):
        llm_handler.LLM_CHAIN = self.orig_chain
        if self.orig_prompt is None:
            delattr(llm_handler, "PROMPT")
        else:
            llm_handler.PROMPT = self.orig_prompt
        llm_handler.CACHE.clear()
        llm_handler.COST_TRACKER.cost_hourly = 0.0
        llm_handler.COST_TRACKER.in_tokens_hourly = 0
        llm_handler.COST_TRACKER.out_tokens_hourly = 0
        llm_handler.COST_TRACKER.total_in_tokens = 0
        llm_handler.COST_TRACKER.total_out_tokens = 0
        llm_handler.COST_TRACKER.total_cost = 0.0

    def test_cache_hit(self):
        alert = {"a": 1}
        ex = []
        key = json.dumps(alert, sort_keys=True, ensure_ascii=False) + "|" + json.dumps(ex, sort_keys=True, ensure_ascii=False)
        llm_handler.CACHE.put(key, {"cached": True})
        res = llm_handler.llm_analyse([{"alert": alert, "examples": ex}])
        self.assertEqual(res, [{"cached": True}])
        llm_handler.LLM_CHAIN.batch.assert_not_called()

    def test_budget_limit(self):
        llm_handler.COST_TRACKER.cost_hourly = config.MAX_HOURLY_COST_USD
        res = llm_handler.llm_analyse([{"alert": {"x": 1}, "examples": []}])
        self.assertEqual(res[0]["reason"], "Budget limit reached")
        llm_handler.LLM_CHAIN.batch.assert_not_called()

    def test_success_and_error(self):
        llm_handler.LLM_CHAIN.batch.side_effect = [
            ["{\"is_attack\": false}"]
        ]
        res = llm_handler.llm_analyse([{"alert": {"x": 1}, "examples": []}])
        self.assertFalse(res[0]["is_attack"])
        llm_handler.LLM_CHAIN.batch.assert_called_once()

        llm_handler.LLM_CHAIN.batch.reset_mock(side_effect=True)
        llm_handler.LLM_CHAIN.batch.side_effect = Exception("boom")
        res = llm_handler.llm_analyse([{"alert": {"y": 2}, "examples": []}])
        self.assertEqual(res[0]["attack_type"], "LLM API Error")
        llm_handler.LLM_CHAIN.batch.assert_called_once()
