"""
Copyright 2021 - Present Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import time

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

    async def fire_request(self, uri, **params):
        """Perform http(s) request within AsyncCacheControl session.

        Return response in json-format.
        """
        async with AsyncCacheControl(cache=self.cache) as cached_sess:
            async with cached_sess.get(uri, **params) as resp:
                resp_json = await resp.json()
        return resp_json

    def get(self, uri, **params):
        """Perform http(s) GET request with retry.

        Return response in json-format.
        """
        request_params = {'headers': params.get('headers'),
                          'timeout': self.request_timeout}
        if self.proxy:
            request_params['proxy'] = self.proxy

        while self.requests_count >= self.max_requests:
            time.sleep(0.1)
        self.requests_count += 1
        response = retry_call(self.fire_request,
                              fargs=(uri,),
                              fkwargs=request_params,
                              tries=self.max_retries)
        self.requests_count -= 1
        return response

    def clear_cache(self):
        """Remove all cached data from all adapters in cached session."""
        self.cache.clear_cache()
