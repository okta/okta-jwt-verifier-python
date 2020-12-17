import pytest

from okta_jwt_verifier import JWTVerifier
from okta_jwt_verifier.exceptions import JWKException


def test_construct_jwks_uri():
    # issuer without '/' at the end
    jwt_verifier = JWTVerifier('https://test_issuer.com', 'test_client_id')
    actual = jwt_verifier._construct_jwks_uri()
    expected = 'https://test_issuer.com/oauth2/v1/keys'
    assert actual == expected

    # issuer with '/' at the end
    jwt_verifier = JWTVerifier('https://test_issuer.com/', 'test_client_id')
    actual = jwt_verifier._construct_jwks_uri()
    expected = 'https://test_issuer.com/oauth2/v1/keys'
    assert actual == expected

    # issuer with /oauth2/ in URI
    jwt_verifier = JWTVerifier('https://test_issuer.com/oauth2/',
                               'test_client_id')
    actual = jwt_verifier._construct_jwks_uri()
    expected = 'https://test_issuer.com/oauth2/v1/keys'
    assert actual == expected


def test_get_jwk(mocker):
    jwt_verifier = JWTVerifier('https://test_issuer.com', 'test_client_id')

    class MockJWKSResp():
        def __init__(self, resp):
            self.resp = resp

        def json(self):
            return self.resp

    # check success flow
    jwks_resp = {'keys': [{'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                           'use': 'sig', 'e': 'AQAB', 'n': 'test_n'},
                          {'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid2',
                           'use': 'sig', 'e': 'AQAB', 'n': 'test_n2'}]}
    jwt_verifier.cached_sess = mocker.Mock()
    jwt_verifier.cached_sess.get = lambda *args, **kw: MockJWKSResp(jwks_resp)
    expected = {'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                'use': 'sig', 'e': 'AQAB', 'n': 'test_n'}
    actual = jwt_verifier.get_jwk('test_kid')
    assert actual == expected

    # check if exception raised in case no matching key
    jwt_verifier._clear_requests_cache = mocker.Mock()
    with pytest.raises(JWKException):
        actual = jwt_verifier.get_jwk('test_kid_no_match')


def test_get_jwks(mocker):
    jwt_verifier = JWTVerifier('https://test_issuer.com', 'test_client_id')

    class MockJWKSResp():
        def __init__(self, resp):
            self.resp = resp

        def json(self):
            return self.resp

    jwks_resp = {'keys': [{'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                           'use': 'sig', 'e': 'AQAB', 'n': 'test_n'}]}
    jwt_verifier.cached_sess = mocker.Mock()
    jwt_verifier.cached_sess.get = lambda *args, **kw: MockJWKSResp(jwks_resp)
    actual = jwt_verifier.get_jwks()
    assert actual == jwks_resp


def test_get_jwk_by_kid():
    jwt_verifier = JWTVerifier('https://test_issuer.com', 'test_client_id')
    jwks_resp = {'keys': [{'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                           'use': 'sig', 'e': 'AQAB', 'n': 'test_n'},
                          {'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid2',
                           'use': 'sig', 'e': 'AQAB', 'n': 'test_n2'}]}
    expected = {'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                'use': 'sig', 'e': 'AQAB', 'n': 'test_n'}
    actual = jwt_verifier._get_jwk_by_kid(jwks_resp, 'test_kid')
    assert actual == expected
    actual = jwt_verifier._get_jwk_by_kid(jwks_resp, 'test_kid_no_match')
    expected = None
    assert actual == expected


def test_verify_signature(mocker):
    jwt_verifier = JWTVerifier('https://test_issuer.com', 'test_client_id')

    jwks = {'keys': [{'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid',
                      'use': 'sig', 'e': 'AQAB', 'n': 'test_n'},
                     {'kty': 'RSA', 'alg': 'RS256', 'kid': 'test_kid_2',
                      'use': 'sig', 'e': 'AQAB', 'n': 'test_n'}]}

    jwt_verifier.get_jwks = lambda *args: jwks
    mock_sign_verifier = mocker.Mock()
    mocker.patch('okta_jwt_verifier.jwt_verifier.jws.verify',
                 mock_sign_verifier)

    token = 'test_token'
    jwt_verifier.verify_signature(token, 'test_kid_2')
    mock_sign_verifier.assert_called_with(token,
                                          jwks['keys'][1],
                                          algorithms=['RS256'])
