import unittest
from unittest.mock import patch

from lms_log_analyzer.src import llm_handler
from lms_log_analyzer.src.utils import LRUCache

class DummyResp:
    def __init__(self, content="{\"is_attack\": false}"):
        self.content = content

class DummyChain:
    def __init__(self):
        self.calls = []
    def batch(self, inputs, config=None):
        self.calls.append(inputs)
        return [DummyResp() for _ in inputs]

class DummyPrompt:
    def format(self, **kwargs):
        return "dummy"

class DummyTracker:
    def get_hourly_cost(self):
        return 0.0
    def add_usage(self, in_tok, out_tok):
        pass

class TestLLMHandlerBatching(unittest.TestCase):
    def test_batching_respects_config_size(self):
        dummy_chain = DummyChain()
        with patch.object(llm_handler, "LLM_CHAIN", dummy_chain), \
             patch.object(llm_handler, "PROMPT", DummyPrompt(), create=True), \
             patch("lms_log_analyzer.config.BATCH_SIZE", 2), \
             patch.object(llm_handler, "CACHE", LRUCache(10)), \
             patch.object(llm_handler, "COST_TRACKER", DummyTracker()):
            alerts = [{"alert": {"id": i}, "examples": []} for i in range(5)]
            results = llm_handler.llm_analyse(alerts)
            self.assertEqual(len(results), 5)
            self.assertEqual(len(dummy_chain.calls), 3)
            self.assertEqual([len(c) for c in dummy_chain.calls], [2, 2, 1])

if __name__ == "__main__":
    unittest.main()
