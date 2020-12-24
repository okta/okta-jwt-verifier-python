"""Module contains tools to perform http requests."""
import requests
from cachecontrol import CacheControl


class RequestExecutor:
    def __init__(self):
        # setup cached session
        sess = requests.session()
        self.cached_sess = CacheControl(sess)

    def execute(self, request):
        pass

    def get(self, uri, **params):
        return self.cached_sess.get(uri, headers=params.get('headers'))

    def clear_cache(self):
        """Remove all cached data from all adapters in cached session."""
        for _, adapter in self.cached_sess.adapters.items():
            adapter.cache.data = {}
