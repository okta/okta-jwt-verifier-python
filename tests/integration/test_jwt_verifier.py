import os
import pytest

from okta_jwt_verifier import JWTVerifier

from conftest import is_env_set


@pytest.mark.skipif(not is_env_set(),
                    reason='Set env variables for integration tests')
def test_verify_token():
    issuer = os.environ.get('ISSUER')
    client_id = os.environ.get('CLIENT_ID')
    token = os.environ.get('OKTA_JWT')
    jwt_verifier = JWTVerifier(issuer, client_id)
    assert jwt_verifier.verify_token(token)
