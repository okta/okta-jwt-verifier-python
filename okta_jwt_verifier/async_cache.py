"""In-process response cache for the asynchronous JWKS fetch.

Replaces the `acachecontrol` dependency, which pulled in `aiohttp`. aiohttp's
client_reqrep does ``from hashlib import md5`` — only to reject md5 as a TLS
fingerprint digest — so on a FIPS build that removes the md5 attribute the
whole import chain raises ImportError and the async path cannot run at all.

This keeps `acachecontrol.cache.AsyncCache`'s observable behaviour, because
`JWTVerifier` reaches into it directly (`release_new_key`) and subclasses may
supply their own `cache_controller`:

* ``register_new_key`` / ``release_new_key`` — dog-pile prevention. The first
  caller for a key registers it; concurrent callers wait until it is released
  rather than stampeding the JWKS endpoint.
* ``has_valid_entry`` / ``get`` / ``add`` / ``delete`` / ``clear_cache``
* ``parse_cache_control_header`` — ``max-age`` honoured, ``no-cache`` and
  ``no-store`` respected
* LRU eviction at a fixed capacity, and the same 120s default max-age

Two deliberate differences from acachecontrol:

1. It caches the PARSED JSON BODY, not the HTTP response object. acachecontrol
   stored the aiohttp response and called ``.json()`` on it again on a cache
   hit — after the session that produced it had been closed, since a new
   session was opened per request. Caching the decoded body removes that
   lifetime coupling entirely.
2. ``register_new_key`` raises ``CacheRegistrationTimeout`` instead of
   acachecontrol's ``TimeoutException``, since that class is not importable
   without the dependency. Both derive from ``Exception``; callers that wrap
   the fetch broadly are unaffected.
"""
import asyncio
import logging
import time
from collections import OrderedDict

logger = logging.getLogger('okta-jwt-verifier')

DEFAULT_MAX_AGE = 120
DEFAULT_SLEEP_TIME = 0.1
DEFAULT_WAIT_TIMEOUT = 30
DEFAULT_CACHE_CAPACITY = 100
CACHEABLE_METHODS = ('HEAD', 'GET')


class CacheException(Exception):
    """Raised when a cache entry cannot be read."""


class CacheRegistrationTimeout(Exception):
    """Raised when waiting for another caller's in-flight request times out."""


class AsyncCache:
    """LRU response cache with Cache-Control support and dog-pile prevention.

    Keys are ``(method, url)`` tuples, matching the previous implementation so
    that ``JWTVerifier``'s direct ``release_new_key(('GET', jwks_uri))`` call
    keeps working unchanged.
    """

    def __init__(self, config=None, cache_backend=None):
        self.cache = (
            cache_backend if cache_backend is not None else OrderedDict()
        )
        config = config or {}
        self._wait_until_completed = set()
        self.default_max_age = config.get('max_age', DEFAULT_MAX_AGE)
        self.sleep_time = config.get('sleep_time', DEFAULT_SLEEP_TIME)
        self.cacheable_methods = config.get(
            'cacheable_methods', CACHEABLE_METHODS)
        self.capacity = config.get('capacity', DEFAULT_CACHE_CAPACITY)

    @staticmethod
    def parse_cache_control_header(headers):
        """Parse a Cache-Control header into a dict.

        ``max-age=604800`` becomes ``{'max-age': 604800}``; valueless
        directives such as ``no-store`` map to ``None``. Unparseable max-age
        values are dropped rather than raising, so a malformed header falls
        back to the default max-age instead of failing the request.
        """
        parsed = {}
        raw = ''
        if headers:
            raw = headers.get('Cache-Control') or headers.get(
                'cache-control') or ''
        for directive in raw.split(','):
            directive = directive.strip()
            if not directive:
                continue
            name, _, value = directive.partition('=')
            name = name.strip().lower()
            if not value:
                parsed[name] = None
                continue
            if name == 'max-age':
                try:
                    parsed[name] = int(value.strip())
                except ValueError:
                    logger.debug('Ignoring unparseable max-age: %r', value)
            else:
                parsed[name] = value.strip()
        return parsed

    def _is_response_cacheable(self, method, cc_header):
        """Whether a response may be stored."""
        if method not in self.cacheable_methods:
            return False
        # no-cache technically permits storage with revalidation, but there is
        # no revalidation here, so treat it as uncacheable — same choice the
        # previous implementation made.
        if 'no-cache' in cc_header or 'no-store' in cc_header:
            return False
        return True

    def add(self, key, value, headers):
        """Store a value, honouring Cache-Control, then release the key.

        The release happens whether or not the response was cacheable, so a
        no-store response cannot leave waiters stuck behind a key that is
        never populated.
        """
        cc_header = self.parse_cache_control_header(headers)
        if self._is_response_cacheable(key[0], cc_header):
            max_age = cc_header.get('max-age')
            if max_age is None:
                max_age = self.default_max_age
            self.cache[key] = {
                'created_at': time.time(),
                'max-age': max_age,
                'value': value,
            }
            self._move_to_end(key)
            if len(self.cache) > self.capacity:
                self._evict_oldest()
        self.release_new_key(key)
        logger.debug('Added a new entry to cache for %s key', key)

    def get(self, key):
        """Return a cached value, or raise CacheException if absent."""
        cache_entry = self.cache.get(key)
        if not cache_entry:
            raise CacheException(f'No cache entry for {key} key')
        self._move_to_end(key)
        logger.debug('Get entry from cache for %s key', key)
        return cache_entry['value']

    def has_valid_entry(self, key):
        """Whether a live entry exists. Expired entries are deleted here."""
        if key in self.cache:
            if not self.is_cache_entry_expired(key):
                return True
            logger.debug('Cache entry is expired for %s key', key)
            self.delete(key)
        return False

    def is_cache_entry_expired(self, key):
        """Whether the entry for key is past its max-age."""
        entry = self.cache[key]
        return entry['created_at'] + entry['max-age'] < time.time()

    async def register_new_key(self, key, timeout=DEFAULT_WAIT_TIMEOUT):
        """Claim a key before fetching, so concurrent callers wait.

        Without this, N concurrent verifications with a cold cache would each
        issue their own JWKS request — a cache stampede against the issuer.
        The first caller claims the key; the rest wait for it to be released
        and then find the populated entry.

        Raises:
            CacheRegistrationTimeout: if the holder does not release in time.
        """
        total_wait_time = 0.0
        while key in self._wait_until_completed:
            await asyncio.sleep(self.sleep_time)
            total_wait_time += self.sleep_time
            if total_wait_time >= timeout:
                raise CacheRegistrationTimeout(
                    f'Timeout exceeded for {key}')
        if key not in self.cache:
            self._wait_until_completed.add(key)

    def release_new_key(self, key):
        """Release a claimed key. A no-op if it was not claimed."""
        self._wait_until_completed.discard(key)

    def delete(self, key):
        """Remove one entry."""
        logger.debug('Delete entry from cache for %s key', key)
        self.cache.pop(key, None)

    def clear_cache(self):
        """Remove every entry."""
        self.cache.clear()

    def _move_to_end(self, key):
        """Mark key as most recently used, when the backend supports it."""
        move_to_end = getattr(self.cache, 'move_to_end', None)
        if move_to_end is not None:
            move_to_end(key)

    def _evict_oldest(self):
        """Drop the least recently used entry."""
        popitem = getattr(self.cache, 'popitem', None)
        if popitem is None:
            return
        try:
            popitem(last=False)
        except TypeError:
            # A dict-like backend without OrderedDict's `last` keyword.
            popitem()
