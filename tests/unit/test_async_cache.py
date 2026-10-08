import asyncio
import time

import pytest
from okta_jwt_verifier.async_cache import (AsyncCache, CacheException,
                                           CacheRegistrationTimeout,
                                           DEFAULT_MAX_AGE)

KEY = ('GET', 'https://issuer/oauth2/v1/keys')


def test_add_and_get_roundtrip():
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=600'})
    assert cache.get(KEY) == {'keys': []}
    assert cache.has_valid_entry(KEY)


def test_get_missing_key_raises():
    with pytest.raises(CacheException):
        AsyncCache().get(KEY)


def test_expired_entry_is_invalid_and_deleted():
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=0'})
    # max-age=0 means the entry is stale the moment the clock advances.
    time.sleep(0.01)
    assert cache.has_valid_entry(KEY) is False
    assert KEY not in cache.cache, 'expired entries should be purged on check'


def test_default_max_age_applies_without_header():
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {})
    assert cache.cache[KEY]['max-age'] == DEFAULT_MAX_AGE


@pytest.mark.parametrize('header', ['no-store', 'no-cache',
                                    'max-age=600, no-store'])
def test_uncacheable_responses_are_not_stored(header):
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': header})
    assert KEY not in cache.cache


def test_uncacheable_response_still_releases_the_key():
    """Otherwise a no-store response leaves waiters stuck forever."""
    cache = AsyncCache()
    cache._wait_until_completed.add(KEY)
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'no-store'})
    assert KEY not in cache._wait_until_completed


def test_non_cacheable_method_is_not_stored():
    cache = AsyncCache()
    post_key = ('POST', 'https://issuer/oauth2/v1/keys')
    cache.add(post_key, {'x': 1}, {'Cache-Control': 'max-age=600'})
    assert post_key not in cache.cache


@pytest.mark.parametrize('raw,expected', [
    ('max-age=604800', {'max-age': 604800}),
    ('no-store', {'no-store': None}),
    ('max-age=60, no-transform', {'max-age': 60, 'no-transform': None}),
    ('', {}),
    ('max-age=not-a-number', {}),
])
def test_parse_cache_control_header(raw, expected):
    assert AsyncCache.parse_cache_control_header(
        {'Cache-Control': raw}) == expected


def test_parse_cache_control_header_is_case_insensitive():
    assert AsyncCache.parse_cache_control_header(
        {'cache-control': 'max-age=5'}) == {'max-age': 5}


def test_malformed_max_age_falls_back_to_default():
    """A bad header must not fail the request — it just loses its max-age."""
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=abc'})
    assert cache.cache[KEY]['max-age'] == DEFAULT_MAX_AGE


def test_lru_eviction_at_capacity():
    cache = AsyncCache(config={'capacity': 2})
    for n in range(3):
        cache.add(('GET', f'https://issuer/{n}'), n,
                  {'Cache-Control': 'max-age=600'})
    assert len(cache.cache) == 2
    assert ('GET', 'https://issuer/0') not in cache.cache, 'oldest evicted'


def test_get_refreshes_lru_position():
    cache = AsyncCache(config={'capacity': 2})
    first = ('GET', 'https://issuer/0')
    cache.add(first, 0, {'Cache-Control': 'max-age=600'})
    cache.add(('GET', 'https://issuer/1'), 1, {'Cache-Control': 'max-age=600'})
    cache.get(first)                      # first is now most-recently-used
    cache.add(('GET', 'https://issuer/2'), 2, {'Cache-Control': 'max-age=600'})
    assert first in cache.cache, 'recently read entry should survive eviction'


def test_clear_and_delete():
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=600'})
    cache.delete(KEY)
    assert KEY not in cache.cache
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=600'})
    cache.clear_cache()
    assert cache.cache == {}


def test_release_unregistered_key_is_a_noop():
    AsyncCache().release_new_key(KEY)      # must not raise


@pytest.mark.asyncio
async def test_register_new_key_waits_for_release():
    """A second caller waits until the first releases the key."""
    cache = AsyncCache(config={'sleep_time': 0.01})
    await cache.register_new_key(KEY)
    order = []

    async def waiter():
        await cache.register_new_key(KEY, timeout=5)
        order.append('waiter-proceeded')

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.05)
    assert order == [], 'waiter should still be blocked'
    order.append('released')
    cache.release_new_key(KEY)
    await asyncio.wait_for(task, timeout=2)
    assert order == ['released', 'waiter-proceeded']


@pytest.mark.asyncio
async def test_register_new_key_times_out():
    cache = AsyncCache(config={'sleep_time': 0.01})
    await cache.register_new_key(KEY)
    with pytest.raises(CacheRegistrationTimeout):
        await cache.register_new_key(KEY, timeout=0.05)


@pytest.mark.asyncio
async def test_register_does_not_claim_an_already_cached_key():
    """A warm key needs no claim — callers read straight through."""
    cache = AsyncCache()
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=600'})
    await cache.register_new_key(KEY)
    assert KEY not in cache._wait_until_completed


@pytest.mark.asyncio
async def test_register_does_not_block_the_event_loop():
    """Waiting for a claimed key must yield, not sleep."""
    cache = AsyncCache(config={'sleep_time': 0.01})
    await cache.register_new_key(KEY)
    loop = asyncio.get_running_loop()
    ticks = []

    async def heartbeat():
        for _ in range(8):
            ticks.append(loop.time())
            await asyncio.sleep(0.02)

    async def releaser():
        await asyncio.sleep(0.1)
        cache.release_new_key(KEY)

    beat = asyncio.create_task(heartbeat())
    asyncio.create_task(releaser())
    await cache.register_new_key(KEY, timeout=5)
    await beat

    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert max(gaps) < 0.05, f'event loop was blocked for {max(gaps):.3f}s'


def test_custom_backend_without_move_to_end():
    """A plain-dict backend must still work, just without LRU ordering."""
    cache = AsyncCache(cache_backend={})
    cache.add(KEY, {'keys': []}, {'Cache-Control': 'max-age=600'})
    assert cache.get(KEY) == {'keys': []}
