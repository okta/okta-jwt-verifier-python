"""Module contains tools to perform http requests."""
import time

import requests as requests_lib
from acachecontrol import AsyncCacheControl
from acachecontrol.cache import AsyncCache
from retry.api import retry_call

from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT


class RequestExecutor:
    """Wrapper around HTTP API requests."""
    def __init__(self,
                 max_retries=MAX_RETRIES,
                 max_requests=MAX_REQUESTS,
                 request_timeout=REQUEST_TIMEOUT,
                 cache_controller=AsyncCache(),
                 proxy=None):
        self.cache = cache_controller
        self.max_retries = max_retries
        self.max_requests = max_requests
        self.request_timeout = request_timeout
        self.requests_count = 0
        self.proxy = proxy
        self._sync_cache = {}

    async def fire_request(self, uri, **params):
        """Perform async http(s) request within AsyncCacheControl session.

        Return:
            dict: response in JSON format.
        """
        async with AsyncCacheControl(cache=self.cache) as cached_sess:
            async with cached_sess.get(uri, **params) as resp:
                resp_json = await resp.json()
        return resp_json

    def fire_request_sync(self, uri, **params):
        """Perform synchronous http(s) request using requests library.

        Return:
            dict: response in JSON format.
        """
        request_headers = params.get('headers')
        timeout = params.get('timeout', self.request_timeout)
        proxies = None
        if params.get('proxy'):
            proxies = {'https': params['proxy'], 'http': params['proxy']}

        # Check sync cache
        if uri in self._sync_cache:
            return self._sync_cache[uri]

        resp = requests_lib.get(uri, headers=request_headers,
                                timeout=timeout, proxies=proxies)
        resp.raise_for_status()
        resp_json = resp.json()
        self._sync_cache[uri] = resp_json
        return resp_json

    def _build_request_params(self, **params):
        """Build common request parameters dict.

        Return:
            dict: request parameters including headers, timeout, and proxy.
        """
        request_params = {'headers': params.get('headers'),
                          'timeout': self.request_timeout}
        if self.proxy:
            request_params['proxy'] = self.proxy
        return request_params

    def _throttled_call(self, func, uri, request_params):
        """Execute a request function with throttling and retry logic.

        Args:
            func: callable, the request function to execute.
            uri: str, the target URI.
            request_params: dict, parameters to pass to the request function.

        Return:
            dict: response in JSON format.
        """
        while self.requests_count >= self.max_requests:
            time.sleep(0.1)
        self.requests_count += 1
        try:
            response = retry_call(func,
                                  fargs=(uri,),
                                  fkwargs=request_params,
                                  tries=self.max_retries)
        finally:
            self.requests_count -= 1
        return response

    def get(self, uri, **params):
        """Perform async http(s) GET request with retry and throttling.

        Return:
            coroutine: awaitable response in JSON format.
        """
        request_params = self._build_request_params(**params)
        return self._throttled_call(self.fire_request, uri, request_params)

    def get_sync(self, uri, **params):
        """Perform synchronous http(s) GET request with retry and throttling.

        Return:
            dict: response in JSON format.
        """
        request_params = self._build_request_params(**params)
        return self._throttled_call(self.fire_request_sync, uri, request_params)

    def clear_cache(self):
        """Remove all cached data from async and sync caches."""
        self.cache.clear_cache()
        self._sync_cache.clear()
