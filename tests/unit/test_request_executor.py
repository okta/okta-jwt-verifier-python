import pytest
from okta_jwt_verifier import JWTVerifier


@pytest.mark.asyncio
async def test_proxy(mocker):
    class AsyncMock(mocker.MagicMock):
        async def __call__(self, *args, **kwargs):
            return super().__call__(self, *args, **kwargs)

    issuer = 'https://test_issuer.com'
    jwt_verifier = JWTVerifier(issuer)

    mock_fire_request = AsyncMock()
    jwt_verifier.request_executor.fire_request = mock_fire_request
    await jwt_verifier.get_jwks()

    mock_fire_request.assert_called_with(mock_fire_request,
                                         f'{issuer}/oauth2/v1/keys',
                                         headers={'User-Agent': 'okta-jwt-verifier-python/0.1.0',
                                                  'Content-Type': 'application/json'})

    jwt_verifier = JWTVerifier(issuer, proxy='http://test_proxy.com')
    jwt_verifier.request_executor.fire_request = mock_fire_request
    await jwt_verifier.get_jwks()

    mock_fire_request.assert_called_with(mock_fire_request,
                                         f'{issuer}/oauth2/v1/keys',
                                         headers={'User-Agent': 'okta-jwt-verifier-python/0.1.0',
                                                  'Content-Type': 'application/json'},
                                         proxy='http://test_proxy.com')
