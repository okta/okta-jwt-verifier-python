import os
import pytest

from acachecontrol.cache import AsyncCache

from okta_jwt_verifier import JWTVerifier
from okta_jwt_verifier.request_executor import RequestExecutor

from tests.conftest import is_env_set


@pytest.mark.skipif(not is_env_set(),
                    reason='Set env variables for integration tests')
@pytest.mark.asyncio
async def test_verify_token():
    issuer = os.environ.get('ISSUER')
    client_id = os.environ.get('CLIENT_ID')
    token = os.environ.get('OKTA_JWT')
    jwt_verifier = JWTVerifier(issuer, client_id)
    assert await jwt_verifier.verify_token(token)


@pytest.mark.skipif(not is_env_set(),
                    reason='Set env variables for integration tests')
@pytest.mark.asyncio
async def test_clear_requests_cache():
    cache_controller = AsyncCache()

    class MockRequestExecutor(RequestExecutor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, cache_controller=cache_controller, **kwargs)

    issuer = os.environ.get('ISSUER')
    client_id = os.environ.get('CLIENT_ID')
    jwt_verifier = JWTVerifier(issuer, client_id,
                               request_executor=MockRequestExecutor)
    await jwt_verifier.get_jwks()

    # verify cache_data is not empty
    assert cache_controller.cache

    jwt_verifier._clear_requests_cache()

    # verify cache_data is empty
    assert not cache_controller.cache
