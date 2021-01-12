"""Module contains tools to perform http requests."""
import requests
import time

from cachecontrol import CacheControl
from retry.api import retry_call

from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT


class RequestExecutor:
    """Wrapper around HTTP API requests."""
    def __init__(self,
                 max_retries=MAX_RETRIES,
                 max_requests=MAX_REQUESTS,
                 request_timeout=REQUEST_TIMEOUT,
                 cache_controller=CacheControl):
        # setup cached session
        sess = requests.session()
        self.cached_sess = cache_controller(sess)
        self.max_retries = max_retries
        self.max_requests = max_requests
        self.request_timeout = request_timeout
        self.requests_count = 0

    def get(self, uri, **params):
        """Perform http(s) GET request.

        Return response in json-format.
        """
        while self.requests_count >= self.max_requests:
            time.sleep(0.1)
        self.requests_count += 1
        resp = retry_call(self.cached_sess.get,
                          fargs=(uri,),
                          fkwargs={'headers': params.get('headers')},
                          tries=self.max_retries)
        self.requests_count -= 1
        return resp.json()

    def clear_cache(self):
        """Remove all cached data from all adapters in cached session."""
        for _, adapter in self.cached_sess.adapters.items():
            adapter.cache.data = {}
