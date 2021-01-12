import os
import pytest

from cachecontrol import CacheControl

from okta_jwt_verifier import JWTVerifier
from okta_jwt_verifier.request_executor import RequestExecutor

from tests.conftest import is_env_set


class CacheControlObserver():

    instance = None

    def __new__(cls, *args, **kwargs):
        sess = CacheControl(*args, **kwargs)
        cls.instance = sess
        return sess

    @classmethod
    def get_cache_data(cls):
        cache_data = []
        for _, adapter in cls.instance.adapters.items():
            if adapter.cache.data:
                cache_data.append(adapter.cache.data)
        return cache_data


class MockRequestExecutor(RequestExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, cache_controller=CacheControlObserver, **kwargs)


@pytest.mark.skipif(not is_env_set(),
                    reason='Set env variables for integration tests')
def test_verify_token():
    issuer = os.environ.get('ISSUER')
    client_id = os.environ.get('CLIENT_ID')
    token = os.environ.get('OKTA_JWT')
    jwt_verifier = JWTVerifier(issuer, client_id)
    assert jwt_verifier.verify_token(token)


@pytest.mark.skipif(not is_env_set(),
                    reason='Set env variables for integration tests')
def test_clear_requests_cache():
    issuer = os.environ.get('ISSUER')
    client_id = os.environ.get('CLIENT_ID')
    jwt_verifier = JWTVerifier(issuer, client_id,
                               request_executor=MockRequestExecutor)
    jwt_verifier.get_jwks()

    # verify cache_data is not empty
    cache_data = CacheControlObserver.get_cache_data()
    assert cache_data

    jwt_verifier._clear_requests_cache()

    # verify cache_data is empty
    cache_data = CacheControlObserver.get_cache_data()
    assert not cache_data
