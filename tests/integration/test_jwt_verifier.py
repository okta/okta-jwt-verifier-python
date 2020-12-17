import os
import pytest

from okta_jwt_verifier import JWTVerifier

from tests.conftest import is_env_set


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
    jwt_verifier = JWTVerifier(issuer, client_id)
    jwt_verifier.get_jwks()

    cache_data = []
    for _, adapter in jwt_verifier.cached_sess.adapters.items():
        if adapter.cache.data:
            cache_data.append(adapter.cache.data)

    # verify cache_data is not empty
    assert cache_data

    jwt_verifier._clear_requests_cache()

    cache_data = []
    for _, adapter in jwt_verifier.cached_sess.adapters.items():
        if adapter.cache.data:
            cache_data.append(adapter.cache.data)

    # verify cache_data is empty
    assert not cache_data
