import pytest
import time

from okta_jwt_verifier.jwt_utils import JWTUtils
from okta_jwt_verifier.exceptions import JWTValidationException


def test_verify_expiration(mocker):
    # verify token is not expired
    headers = {'alg': 'RS256', 'kid': 'test_kid'}
    issuer = 'https://test_issuer.com'
    iss_time = time.time()
    claims = {'ver': 1,
              'jti': 'test_jti_str',
              'iss': issuer,
              'iat': iss_time,
              'exp': iss_time+300,
              'uid': 'test_uid',
              'scp': ['openid'],
              'sub': 'test_jwt@okta.com'}
    signing_input = 'test_signing_input'
    signature = 'test_signature'

    mock_parse_token = lambda token: (headers, claims, signing_input, signature)
    mocker.patch('okta_jwt_verifier.jwt_utils.JWTUtils.parse_token', mock_parse_token)

    JWTUtils.verify_expiration('test_token')

    # verify token is expired
    claims = {'ver': 1,
              'jti': 'test_jti_str',
              'iss': issuer,
              'iat': iss_time,
              'exp': iss_time-300,
              'uid': 'test_uid',
              'scp': ['openid'],
              'sub': 'test_jwt@okta.com'}
    with pytest.raises(JWTValidationException):
        JWTUtils.verify_expiration('test_token')
