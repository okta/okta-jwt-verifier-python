import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from okta_jwt_verifier import BaseJWTVerifier, __version__ as version
from okta_jwt_verifier.request_executor import RequestExecutor


@pytest.mark.asyncio
async def test_proxy():
    """Test that proxy parameter is passed to requests."""
    issuer = 'https://test.okta.com'

    # Without proxy
    verifier = BaseJWTVerifier(issuer)
    verifier.request_executor.fire_request = AsyncMock(return_value={'keys': []})
    await verifier.get_jwks()

    verifier.request_executor.fire_request.assert_called_with(
        f'{issuer}/oauth2/v1/keys',
        headers={'User-Agent': f'okta-jwt-verifier-python/{version}',
                 'Content-Type': 'application/json'},
        timeout=30
    )

    # With proxy
    verifier = BaseJWTVerifier(issuer, proxy='http://proxy:8080')
    verifier.request_executor.fire_request = AsyncMock(return_value={'keys': []})
    await verifier.get_jwks()

    verifier.request_executor.fire_request.assert_called_with(
        f'{issuer}/oauth2/v1/keys',
        headers={'User-Agent': f'okta-jwt-verifier-python/{version}',
                 'Content-Type': 'application/json'},
        timeout=30,
        proxy='http://proxy:8080'
    )


@pytest.mark.asyncio
async def test_retry_success():
    """Test that transient failures are retried."""
    executor = RequestExecutor(max_retries=3)
    executor.fire_request = AsyncMock(side_effect=[
        Exception('fail'),
        Exception('fail'),
        {'keys': []}
    ])

    result = await executor.get('https://test.com/keys')

    assert result == {'keys': []}
    assert executor.fire_request.call_count == 3


@pytest.mark.asyncio
async def test_retry_exhausted():
    """Test that exception is raised when retries exhausted."""
    executor = RequestExecutor(max_retries=2)
    executor.fire_request = AsyncMock(side_effect=Exception('network error'))

    with pytest.raises(Exception):
        await executor.get('https://test.com/keys')

    assert executor.fire_request.call_count == 2


@pytest.mark.asyncio
async def test_clear_cache():
    """Test that clear_cache calls underlying cache."""
    executor = RequestExecutor()
    executor.cache.clear_cache = MagicMock()

    executor.clear_cache()

    executor.cache.clear_cache.assert_called_once()
