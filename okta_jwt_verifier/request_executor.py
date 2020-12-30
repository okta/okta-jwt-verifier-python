"""Module contains tools to perform http requests."""
import requests
import time

from cachecontrol import CacheControl
from retry.api import retry_call

from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT


class RequestExecutor:
    def __init__(self,
                 max_retries=MAX_RETRIES,
                 max_requests=MAX_REQUESTS,
                 request_timeout=REQUEST_TIMEOUT):
        # setup cached session
        sess = requests.session()
        self.cached_sess = CacheControl(sess)
        self.max_retries = max_retries
        self.max_requests = max_requests
        # TODO: use timeout when lib is migrated from requests to aiohttp
        self.request_timeout = request_timeout
        self.requests_count = 0

    def get(self, uri, **params):
        """Perform http(s) GET request."""
        while self.requests_count >= self.max_requests:
            time.sleep(0.1)
        self.requests_count += 1
        resp = retry_call(self.cached_sess.get,
                          fargs=(uri,),
                          fkwargs={'headers': params.get('headers')},
                          tries=self.max_retries)
        self.requests_count -= 1
        return resp

    def clear_cache(self):
        """Remove all cached data from all adapters in cached session."""
        for _, adapter in self.cached_sess.adapters.items():
            adapter.cache.data = {}
