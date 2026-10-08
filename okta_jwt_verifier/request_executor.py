"""Module contains tools to perform http requests."""
import asyncio
import functools
import time

import requests as requests_lib
from retry.api import retry_call

from .async_cache import AsyncCache
from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT


# WHY THE ASYNC PATH RUNS `requests` IN A THREAD INSTEAD OF USING AN ASYNC
# HTTP CLIENT.
#
# The async path previously used acachecontrol, which hard-requires aiohttp.
# On a FIPS build aiohttp cannot be imported at all: client_reqrep.py does
# ``from hashlib import md5`` at module scope — only to populate a lookup
# table whose single use *rejects* md5 as a TLS fingerprint digest. A FIPS
# interpreter either does not expose that attribute or rejects the call;
# ``from hashlib import md5`` fails on the former. Because the reference is
# evaluated at import, the failure propagated up to
# ``import okta_jwt_verifier`` and took the synchronous API down with it too.
#
# httpx is not a safe alternative either: ``httpx/_auth.py`` builds
# ``{"MD5": hashlib.md5, ...}`` in the ``DigestAuth`` class body — the same
# import-scope md5 reference, for an HTTP Digest feature a JWKS fetch never
# uses. It survives on builds that keep the attribute and only reject the
# call (verified on 0.23.3, 0.27.2 and 0.28.1), but breaks on builds that
# remove it. Swapping in httpx would trade a certain failure for a
# conditional one.
#
# `requests` is immune for one specific reason worth recording, so nobody
# "simplifies" it later: it does not reference md5 at module scope. Its digest
# auth calls ``hashlib.md5(x, usedforsecurity=False)`` inside a nested
# function, evaluated only if digest auth is actually used. The
# ``usedforsecurity=False`` flag is what makes even that call legal under
# FIPS (psf/requests#6810).
#
# So the async path reuses the sync client on a worker thread. It is not
# native async I/O, but it is correct, adds no dependency — `requests` is
# already required — and keeps the event loop free, which is what callers
# actually observe. The alternative was taking on a far less common async
# client on an authentication path.
def _run_in_thread(func, *args, **kwargs):
    """Await a blocking callable on the default executor.

    Keeps the event loop responsive while the synchronous HTTP client works.
    """
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, functools.partial(func, *args, **kwargs))


class RequestExecutor:
    """Wrapper around HTTP API requests."""
    def __init__(self,
                 max_retries=MAX_RETRIES,
                 max_requests=MAX_REQUESTS,
                 request_timeout=REQUEST_TIMEOUT,
                 cache_controller=None,
                 proxy=None):
        # Deliberately NOT `cache_controller=AsyncCache()` in the signature. A
        # mutable default is evaluated once at import and then shared by every
        # RequestExecutor that does not pass one, so independently configured
        # verifiers silently shared one JWKS cache.
        self.cache = (cache_controller if cache_controller is not None
                      else AsyncCache())
        self.max_retries = max_retries
        self.max_requests = max_requests
        self.request_timeout = request_timeout
        self.requests_count = 0
        self.proxy = proxy
        self._sync_cache = {}
        # Bounds in-flight async requests. Created lazily and per running
        # loop, because a Semaphore binds to the loop that first awaits it:
        # one built in __init__ (possibly with no loop running, or on a
        # different loop) raises "got Future attached to a different loop"
        # when awaited elsewhere. Verifiers are commonly module-level
        # singletons reused across asyncio.run() calls and across threads
        # with their own loops, so the loop is resolved at acquire time.
        self._async_semaphores = {}

    def _get_async_semaphore(self):
        """Return the concurrency semaphore for the running event loop.

        Keyed by loop so a long-lived executor can be reused across separate
        asyncio.run() calls and across threads that each own a loop. Entries
        for dead loops are dropped on access rather than tracked, which keeps
        this free of weak-reference bookkeeping for what is normally a single
        entry.
        """
        loop = asyncio.get_running_loop()
        semaphore = self._async_semaphores.get(loop)
        if semaphore is None:
            # max_requests arrives from an env var, so it may be a string.
            semaphore = asyncio.Semaphore(int(self.max_requests))
            self._async_semaphores = {
                stored_loop: stored
                for stored_loop, stored in self._async_semaphores.items()
                if not stored_loop.is_closed()
            }
            self._async_semaphores[loop] = semaphore
        return semaphore

    async def _throttled_call_async(self, func, uri, request_params):
        """Await func with concurrency limiting and retries.

        The async counterpart of _throttled_call. Both the throttle and the
        retry loop previously ran synchronously around a coroutine, which did
        not work:

        * ``time.sleep`` in the throttle blocked the whole event loop, so one
          verification stalled every other task in the process.
        * ``retry_call`` received a coroutine *function*, so calling it merely
          produced a coroutine object. That looked like success, the retry loop
          returned immediately, and the request had not run yet — async callers
          effectively had no retries at all.
        * The ``requests_count`` check-then-increment was not atomic across
          awaits, so the limit was never enforced. Measured before this change:
          ``max_requests=2`` admitted 10 concurrent requests.

        A semaphore fixes all three. It yields instead of sleeping, is acquired
        and released around the actual await, and makes the limit real.
        """
        tries = int(self.max_retries)
        async with self._get_async_semaphore():
            # requests_count is kept in step for subclasses and callers that
            # read it; the semaphore is what actually bounds concurrency.
            self.requests_count += 1
            try:
                for attempt in range(1, tries + 1):
                    try:
                        return await func(uri, **request_params)
                    except Exception:
                        # Mirrors retry_call's contract: `tries` total
                        # attempts, no delay between them, and the final
                        # exception propagates unchanged.
                        if attempt >= tries:
                            raise
            finally:
                self.requests_count -= 1

    async def fire_request(self, uri, **params):
        """Perform an async GET, serving from and populating the cache.

        Mirrors what acachecontrol did, minus aiohttp:

        1. Claim the key, so concurrent callers with a cold cache wait instead
           of each firing their own JWKS request (cache stampede).
        2. Serve a live cached entry if there is one.
        3. Otherwise fetch, store under the response's Cache-Control, and
           release the key.

        The key is released on every exit path — including failure — or the
        next caller would block until its registration timeout.

        Return:
            dict: response in JSON format.
        """
        key = ('GET', uri)
        timeout = params.get('timeout', self.request_timeout)

        await self.cache.register_new_key(key, timeout)
        try:
            if self.cache.has_valid_entry(key):
                return self.cache.get(key)

            # The blocking GET runs on a worker thread; see the module comment
            # for why this is `requests` rather than an async client.
            response = await _run_in_thread(self._http_get, uri, **params)
            resp_json = response.json()

            # add() releases the key itself, and does so whether or not the
            # response turned out to be cacheable.
            self.cache.add(key, resp_json, response.headers)
            return resp_json
        except BaseException:
            # Covers CancelledError as well as ordinary failures: a cancelled
            # or failed fetch must not leave the key claimed, or the next
            # caller blocks until its registration timeout.
            self.cache.release_new_key(key)
            raise

    def _http_get(self, uri, **params):
        """Perform one blocking GET and return the raw response.

        Shared by the sync and async paths so both honour the same timeout,
        proxy and redirect handling, and so a change to one cannot silently
        diverge from the other.
        """
        proxies = None
        if params.get('proxy'):
            proxies = {'https': params['proxy'], 'http': params['proxy']}
        response = requests_lib.get(
            uri,
            headers=params.get('headers'),
            timeout=params.get('timeout', self.request_timeout),
            proxies=proxies,
            allow_redirects=params.get('allow_redirects', True))
        response.raise_for_status()
        return response

    def fire_request_sync(self, uri, **params):
        """Perform synchronous http(s) request using requests library.

        Return:
            dict: response in JSON format.
        """
        # Check sync cache
        if uri in self._sync_cache:
            return self._sync_cache[uri]

        # Shares _http_get with the async path so the two cannot drift on
        # timeout, proxy or redirect handling.
        resp_json = self._http_get(uri, **params).json()
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

        Still a plain def returning an awaitable, so existing callers that do
        ``await executor.get(...)`` are unaffected. The difference is that the
        throttling and retries now happen inside that awaitable instead of
        synchronously before it is returned — nothing blocks the event loop,
        and the retry loop actually sees the request's outcome.

        Return:
            coroutine: awaitable response in JSON format.
        """
        request_params = self._build_request_params(**params)
        return self._throttled_call_async(self.fire_request, uri,
                                          request_params)

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
