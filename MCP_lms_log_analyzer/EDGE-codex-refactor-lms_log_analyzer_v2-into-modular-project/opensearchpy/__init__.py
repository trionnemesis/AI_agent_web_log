class DummyIndices:
    def exists(self, name):
        return True
    def create(self, index=None, body=None):
        pass

class OpenSearch:
    def __init__(self, *args, **kwargs):
        self.indices = DummyIndices()
    def search(self, index=None, body=None):
        return {"hits": {"hits": []}}
    def mget(self, index=None, body=None):
        return {"docs": []}

class Helpers:
    @staticmethod
    def bulk(client, actions):
        pass

helpers = Helpers()
