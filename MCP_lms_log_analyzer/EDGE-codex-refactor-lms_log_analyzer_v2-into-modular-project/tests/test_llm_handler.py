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
        llm_handler.LLM_CHAIN.batch.return_value = [json.dumps({"is_attack": False})]
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
        self.assertIn("line1  | phish | x", summary)
        self.assertIn("line2 | mal | y", summary)

    def test_trim_alert(self):
        alert = {
            "rule": {"id": 1, "description": "desc", "level": 3, "unused": True},
            "full_log": "foo",
            "agent": {"name": "a", "other": 1},
            "data": {"srcip": "1.1.1.1", "foo": "bar"},
        }
        trimmed = llm_handler._trim_alert(alert)
        self.assertEqual(trimmed["rule"], {"id": 1, "description": "desc", "level": 3})
        self.assertEqual(trimmed["original_log"], "foo")
        self.assertEqual(trimmed["agent"], {"name": "a"})
        self.assertEqual(trimmed["data"], {"srcip": "1.1.1.1"})

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
        self.assertIn("bad log", sent)
        alert_json = llm_handler.LLM_CHAIN.batch.call_args.args[0][0]["alert_json"]
        self.assertIn("\"id\": 1", alert_json)

        llm_handler.LLM_CHAIN.batch.reset_mock()
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result2 = llm_handler.llm_analyse(alerts)

        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result1, result2)

    def test_llm_analyse_budget_limit(self):
        llm_handler.COST_TRACKER.get_hourly_cost = MagicMock(return_value=llm_handler.config.MAX_HOURLY_COST_USD)
        alerts = [{"alert": {"rule": {"id": 2}}, "examples": []}]
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f,*a,**k: f(*a, **k)):
            result = llm_handler.llm_analyse(alerts)
        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result[0]["reason"], "Budget limit reached")

    def test_llm_analyse_disabled(self):
        llm_handler.LLM_CHAIN = None
        alerts = [{"alert": {"rule": {"id": 3}}, "examples": []}]
        result = llm_handler.llm_analyse(alerts)
        self.assertEqual(result, [None])


if __name__ == "__main__":
    unittest.main()
