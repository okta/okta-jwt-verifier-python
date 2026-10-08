import asyncio
import threading
import time

import pytest
from okta_jwt_verifier import BaseJWTVerifier, __version__ as version
from okta_jwt_verifier.constants import REQUEST_TIMEOUT
from okta_jwt_verifier.request_executor import RequestExecutor


@pytest.mark.asyncio
async def test_proxy(mocker):
    class AsyncMock(mocker.MagicMock):
        async def __call__(self, *args, **kwargs):
            return super().__call__(self, *args, **kwargs)

    issuer = 'https://test_issuer.com'
    jwt_verifier = BaseJWTVerifier(issuer)

    mock_fire_request = AsyncMock()
    jwt_verifier.request_executor.fire_request = mock_fire_request
    await jwt_verifier.get_jwks()

    mock_fire_request.assert_called_with(mock_fire_request,
                                         f'{issuer}/oauth2/v1/keys',
                                         headers={'User-Agent': f'okta-jwt-verifier-python/{version}',
                                                  'Content-Type': 'application/json'},
                                         timeout=REQUEST_TIMEOUT)

    jwt_verifier = BaseJWTVerifier(issuer, proxy='http://test_proxy.com')
    jwt_verifier.request_executor.fire_request = mock_fire_request
    await jwt_verifier.get_jwks()

    mock_fire_request.assert_called_with(mock_fire_request,
                                         f'{issuer}/oauth2/v1/keys',
                                         headers={'User-Agent': f'okta-jwt-verifier-python/{version}',
                                                  'Content-Type': 'application/json'},
                                         timeout=REQUEST_TIMEOUT,
                                         proxy='http://test_proxy.com')


def test_cache_is_not_shared_between_instances():
    """Each RequestExecutor gets its own cache.

    `cache_controller=AsyncCache()` was a mutable default argument, evaluated
    once at import, so every executor that did not pass one shared a single
    JWKS cache.
    """
    first, second = RequestExecutor(), RequestExecutor()
    assert first.cache is not second.cache


def test_explicit_cache_controller_is_respected():
    sentinel = object()
    assert RequestExecutor(cache_controller=sentinel).cache is sentinel


def test_cache_is_settable():
    """Assignment to `cache` must keep working for callers that swap it."""
    executor = RequestExecutor()
    sentinel = object()
    executor.cache = sentinel
    assert executor.cache is sentinel


@pytest.mark.asyncio
async def test_async_throttle_bounds_concurrency():
    """max_requests must actually limit in-flight async requests.

    The old throttle did a non-atomic check-then-increment around a coroutine,
    so it never bounded anything: measured before this change, max_requests=2
    admitted 10 concurrent requests.
    """
    executor = RequestExecutor(max_requests=2)
    peak = inflight = 0

    async def fake_fire(uri, **params):
        nonlocal peak, inflight
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0.02)
        inflight -= 1
        return {'ok': True}

    executor.fire_request = fake_fire
    await asyncio.gather(*[executor.get(f'https://issuer/{n}') for n in range(10)])

    assert peak <= 2
    assert executor.requests_count == 0


@pytest.mark.asyncio
async def test_async_throttle_does_not_block_the_event_loop():
    """Waiting for a throttle slot must not block the event loop.

    This is a forward-looking guard rather than a reproduction of the old
    behaviour, and the distinction is worth recording: the old throttle used
    `time.sleep`, but its `requests_count` was incremented and decremented
    around a coroutine that had not been awaited, so the counter was back to
    zero before anything ran and the sleeping branch was effectively
    unreachable for async callers. The real defects were the dead retry loop
    and the unenforced limit, covered by the tests above.

    Now that the semaphore makes the limit real, waiting genuinely happens —
    so this asserts that waiting yields. It would fail against any future
    change that reintroduced a blocking wait.
    """
    executor = RequestExecutor(max_requests=1)
    loop = asyncio.get_running_loop()
    ticks = []
    released = loop.create_future()

    async def heartbeat():
        for _ in range(10):
            ticks.append(loop.time())
            await asyncio.sleep(0.02)

    async def gated_fire(uri, **params):
        # Holds the single slot until the heartbeat has had time to tick.
        await released
        return {}

    async def releaser():
        await asyncio.sleep(0.15)
        released.set_result(None)

    executor.fire_request = gated_fire
    beat = asyncio.create_task(heartbeat())
    gate = asyncio.create_task(releaser())
    await asyncio.sleep(0)

    # Two requests, one slot: the second must wait for the first, and that
    # waiting must not stop the heartbeat.
    await asyncio.wait_for(
        asyncio.gather(executor.get('https://issuer/a'),
                       executor.get('https://issuer/b')),
        timeout=5.0)
    await gate
    await beat

    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert max(gaps) < 0.05, f'event loop was blocked for {max(gaps):.3f}s'


@pytest.mark.asyncio
async def test_async_retries_actually_retry():
    """Async retries must observe the request outcome.

    retry_call was handed a coroutine *function*; calling it returned a
    coroutine object, which looked like success. The retry loop returned before
    the request had run, so async callers had no retries at all.
    """
    executor = RequestExecutor(max_retries=3)
    attempts = 0

    async def flaky(uri, **params):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError('transient')
        return {'ok': True}

    executor.fire_request = flaky
    assert await executor.get('https://issuer/keys') == {'ok': True}
    assert attempts == 3


@pytest.mark.asyncio
async def test_async_retries_exhaust_and_reraise():
    """`tries` total attempts, then the final exception propagates unchanged."""
    executor = RequestExecutor(max_retries=2)
    attempts = 0

    async def always_fails(uri, **params):
        nonlocal attempts
        attempts += 1
        raise RuntimeError('down')

    executor.fire_request = always_fails
    with pytest.raises(RuntimeError, match='down'):
        await executor.get('https://issuer/keys')

    assert attempts == 2
    assert executor.requests_count == 0


@pytest.mark.asyncio
async def test_async_retries_are_sequential():
    """Retries must not overlap.

    Overlapping attempts could race each other against the shared JWKS cache.
    """
    executor = RequestExecutor(max_retries=4)
    order = []
    attempts = 0

    async def flaky(uri, **params):
        nonlocal attempts
        attempts += 1
        mine = attempts
        order.append(f'start{mine}')
        await asyncio.sleep(0.01)
        order.append(f'end{mine}')
        if mine < 3:
            raise RuntimeError('transient')
        return {}

    executor.fire_request = flaky
    await executor.get('https://issuer/keys')

    assert order == ['start1', 'end1', 'start2', 'end2', 'start3', 'end3']


@pytest.mark.asyncio
async def test_cancellation_releases_the_semaphore():
    """A cancelled request must not hold its slot, or the executor deadlocks."""
    executor = RequestExecutor(max_requests=1)

    async def hang(uri, **params):
        await asyncio.sleep(10)

    executor.fire_request = hang
    task = asyncio.create_task(executor.get('https://issuer/keys'))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert executor.requests_count == 0

    async def quick(uri, **params):
        return {'ok': True}

    executor.fire_request = quick
    assert await asyncio.wait_for(
        executor.get('https://issuer/keys'), timeout=1.0) == {'ok': True}


@pytest.mark.asyncio
async def test_cancellation_is_not_retried():
    """CancelledError must propagate on the first attempt.

    It derives from BaseException on supported Pythons, so the retry loop's
    `except Exception` does not catch it — asserted here so a later widening
    of that clause cannot silently turn a cancel into a retry storm.
    """
    executor = RequestExecutor(max_retries=5)
    attempts = 0

    async def cancelling(uri, **params):
        nonlocal attempts
        attempts += 1
        raise asyncio.CancelledError()

    executor.fire_request = cancelling
    with pytest.raises(asyncio.CancelledError):
        await executor.get('https://issuer/keys')

    assert attempts == 1


def test_executor_is_reusable_across_event_loops():
    """One executor must survive separate asyncio.run() calls.

    A Semaphore binds to the loop that first awaits it, so one created in
    __init__ raises "got Future attached to a different loop" on the second
    run. Verifiers are commonly module-level singletons, which is exactly how
    that would be hit.
    """
    executor = RequestExecutor(max_requests=2)

    async def once(tag):
        async def fake(uri, **params):
            await asyncio.sleep(0.01)
            return {'tag': tag}
        executor.fire_request = fake
        return await executor.get('https://issuer/keys')

    assert asyncio.run(once('first'))['tag'] == 'first'
    assert asyncio.run(once('second'))['tag'] == 'second'
    # Closed loops must not accumulate.
    assert len(executor._async_semaphores) == 1


def test_executor_is_safe_across_threads_with_their_own_loops():
    """Independent loops in separate threads each get their own semaphore."""
    executor = RequestExecutor(max_requests=2)
    results = []
    errors = []

    def worker(tag):
        async def run():
            async def fake(uri, **params):
                await asyncio.sleep(0.02)
                return {'tag': tag}
            executor.fire_request = fake
            return await executor.get('https://issuer/keys')
        try:
            results.append(asyncio.run(run()))
        except Exception as exc:                      # pragma: no cover
            errors.append(f'{type(exc).__name__}: {exc}')

    threads = [threading.Thread(target=worker, args=(f't{n}',)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 4


def test_sync_path_retries_are_unchanged():
    """The synchronous path keeps its blocking throttle and retry_call."""
    executor = RequestExecutor(max_requests=2, max_retries=3)
    attempts = 0

    def flaky(uri, **params):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError('transient')
        return {'ok': True}

    executor.fire_request_sync = flaky
    result = executor.get_sync('https://issuer/keys')

    assert result == {'ok': True}
    assert attempts == 3
    assert executor.requests_count == 0


# ---------------------------------------------------------------------------
# Async fetch (requests on a worker thread) and the first-party cache
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Stands in for a requests.Response."""

    def __init__(self, payload, headers=None):
        self._payload = payload
        self.headers = headers or {'Cache-Control': 'max-age=600'}

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_async_fetch_is_cached_and_reused(mocker):
    """A second fetch within max-age is served from the cache, not the network."""
    executor = RequestExecutor()
    calls = []

    def fake_get(self, uri, **params):
        calls.append(uri)
        return _FakeResponse({'keys': [{'kid': 'K'}]})

    mocker.patch.object(RequestExecutor, '_http_get', fake_get)

    first = await executor.fire_request('https://issuer/keys')
    second = await executor.fire_request('https://issuer/keys')

    assert first == second == {'keys': [{'kid': 'K'}]}
    assert calls == ['https://issuer/keys'], 'second call should hit the cache'


@pytest.mark.asyncio
async def test_async_fetch_does_not_block_the_event_loop(mocker):
    """The blocking GET must run off the loop.

    This is the property that makes reusing the synchronous client acceptable:
    callers observe async behaviour even though the client itself blocks.
    """
    executor = RequestExecutor()
    loop = asyncio.get_running_loop()
    ticks = []

    def slow_get(self, uri, **params):
        time.sleep(0.15)
        return _FakeResponse({'keys': []})

    mocker.patch.object(RequestExecutor, '_http_get', slow_get)

    async def heartbeat():
        for _ in range(10):
            ticks.append(loop.time())
            await asyncio.sleep(0.02)

    beat = asyncio.create_task(heartbeat())
    await executor.fire_request('https://issuer/keys')
    await beat

    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert max(gaps) < 0.05, f'event loop was blocked for {max(gaps):.3f}s'


@pytest.mark.asyncio
async def test_async_fetch_releases_key_on_failure(mocker):
    """A failed fetch must release its claim, or the next caller hangs."""
    executor = RequestExecutor()

    def failing_get(self, uri, **params):
        raise RuntimeError('network down')

    mocker.patch.object(RequestExecutor, '_http_get', failing_get)

    with pytest.raises(RuntimeError, match='network down'):
        await executor.fire_request('https://issuer/keys')

    assert ('GET', 'https://issuer/keys') not in executor.cache._wait_until_completed
    with pytest.raises(RuntimeError):
        await asyncio.wait_for(
            executor.fire_request('https://issuer/keys'), timeout=2.0)


@pytest.mark.asyncio
async def test_concurrent_cold_fetches_do_not_stampede(mocker):
    """Dog-pile prevention: N concurrent cold callers cause one request.

    Without register_new_key, every concurrent verification with a cold cache
    would issue its own JWKS request against the issuer.
    """
    executor = RequestExecutor(max_requests=10)
    calls = []

    def slow_get(self, uri, **params):
        calls.append(uri)
        time.sleep(0.05)
        return _FakeResponse({'keys': []})

    mocker.patch.object(RequestExecutor, '_http_get', slow_get)

    results = await asyncio.gather(
        *[executor.fire_request('https://issuer/keys') for _ in range(8)])

    assert all(r == {'keys': []} for r in results)
    assert len(calls) == 1, f'expected a single upstream request, got {len(calls)}'


@pytest.mark.asyncio
async def test_sync_and_async_share_one_http_helper(mocker):
    """Both paths go through _http_get, so they cannot drift apart."""
    executor = RequestExecutor()
    seen = []

    def record(self, uri, **params):
        seen.append(params.get('timeout'))
        return _FakeResponse({'keys': []})

    mocker.patch.object(RequestExecutor, '_http_get', record)

    await executor.fire_request('https://issuer/keys', timeout=7)
    executor.fire_request_sync('https://issuer/other', timeout=7)

    assert seen == [7, 7]
