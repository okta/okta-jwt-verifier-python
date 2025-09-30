"""
Copyright 2021 - Present Okta, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import warnings

from urllib.parse import urljoin

from . import __version__ as version
from .config_validator import ConfigValidator
from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT, LEEWAY
from .exceptions import JWKException, JWTValidationException
from .jwt_utils import JWTUtils
from .request_executor import RequestExecutor


class BaseJWTVerifier():

    def __init__(self,
                 issuer=None,
                 client_id='client_id_stub',
                 audience='api://default',
                 request_executor=RequestExecutor,
                 max_retries=MAX_RETRIES,
                 request_timeout=REQUEST_TIMEOUT,
                 max_requests=MAX_REQUESTS,
                 leeway=LEEWAY,
                 cache_jwks=True,
                 proxy=None):
        """
        Args:
            issuer: string, full URI of the token issuer, required
            client_id: string, expected client_id, required
            audience: string, expected audience, optional
            request_executor: RequestExecutor class or its subclass, optional
            max_retries: int, number of times to retry a failed network request, optional
            request_timeout: int, max request timeout, optional
            max_requests: int, max number of concurrent requests
            leeway: int, amount of time to expand the window for token expiration (to work around clock skew)
            cache_jwks: bool, optional
        """
        # validate input data before any processing
        config = {'issuer': issuer,
                  'client_id': client_id,
                  'audience': audience,
                  'max_retries': max_retries,
                  'request_timeout': request_timeout,
                  'max_requests': max_requests,
                  'leeway': leeway,
                  'cache_jwks': cache_jwks}
        ConfigValidator(config).validate_config()

        self.issuer = issuer
        self.client_id = client_id
        self.audience = audience
        self.request_executor = request_executor(max_retries=max_retries,
                                                 max_requests=max_requests,
                                                 request_timeout=request_timeout,
                                                 proxy=proxy)
        self.max_retries = max_retries
        self.request_timeout = request_timeout
        self.max_requests = max_requests
        self.leeway = leeway
        self.cache_jwks = cache_jwks

    def parse_token(self, token):
        """Parse JWT token, get headers, claims and signature.

        Return:
            tuple (headers, claims, signing_input, signature)
        """
        return JWTUtils.parse_token(token)

    async def verify_access_token(self, token, claims_to_verify=('iss', 'aud', 'exp')):
        """Verify acess token.

        Algorithm:
        1. Retrieve and parse your Okta JSON Web Keys (JWK),
           which should be checked periodically and cached by your application.
        2. Decode the access token, which is in JSON Web Token format
        3. Verify the signature used to sign the access token
        4. Verify the claims found inside the access token

        Default claims to verify for access token:
        'exp' Expiration - The time after which the token is invalid.
        'iss' Issuer     - The principal that issued the JWT.
        'aud' Audience   - The recipient that the JWT is intended for.

        Raise an Exception if any validation is failed, return None otherwise.
        """
        try:
            headers, claims, signing_input, signature = self.parse_token(token)
            if headers.get('alg') != 'RS256':
                raise JWTValidationException('Header claim "alg" is invalid.')

            self.verify_claims(claims,
                               claims_to_verify=claims_to_verify,
                               leeway=self.leeway)

            okta_jwk = await self.get_jwk(headers['kid'])
            self.verify_signature(token, okta_jwk)
        except JWTValidationException:
            raise
        except Exception as err:
            raise JWTValidationException(str(err))

    async def verify_id_token(self, token, claims_to_verify=('iss', 'exp'), nonce=None):
        """Verify id token.

        Algorithm:
        1. Retrieve and parse your Okta JSON Web Keys (JWK),
           which should be checked periodically and cached by your application.
        2. Decode the access token, which is in JSON Web Token format.
        3. Verify the signature used to sign the access token.
        4. Verify the claims found inside the access token.
        5. Verify claim "cid" matches provided client_id.
        6. If claim "nonce" was provided for token generation, it should be validated too.

        Default claims to verify for id token:
        'exp' Expiration - The time after which the token is invalid.
        'iss' Issuer     - The principal that issued the JWT.
        'aud' Audience   - The recipient that the JWT is intended for.
                           For ID token 'aud' should match Client ID

        Raise an Exception if any validation is failed, return None otherwise.
        """
        try:
            headers, claims, signing_input, signature = self.parse_token(token)
            if headers.get('alg') != 'RS256':
                raise JWTValidationException('Header claim "alg" is invalid.')

            self.verify_claims(claims,
                               claims_to_verify=claims_to_verify,
                               leeway=self.leeway)

            okta_jwk = await self.get_jwk(headers['kid'])
            self.verify_signature(token, okta_jwk)

            # verify client_id and nonce
            self.verify_client_id(claims['aud'])
            if 'nonce' in claims and claims['nonce'] != nonce:
                raise JWTValidationException('Claim "nonce" is invalid.')
        except JWTValidationException:
            raise
        except Exception as err:
            raise JWTValidationException(str(err))

    def verify_client_id(self, aud):
        """Verify client_id match aud or one of its elements."""
        if isinstance(aud, str):
            if aud != self.client_id:
                raise JWTValidationException('Claim "aud" does not match Client ID.')
        elif isinstance(aud, list):
            for elem in aud:
                if elem == self.client_id:
                    return
            raise JWTValidationException('Claim "aud" does not contain Client ID.')
        else:
            raise JWTValidationException('Claim "aud" has unsupported format.')

    def verify_signature(self, token, okta_jwk):
        """Verify token signature using received jwk."""
        JWTUtils.verify_signature(token, okta_jwk)

    def verify_claims(self, claims, claims_to_verify, leeway=LEEWAY):
        """Verify claims are present and valid."""
        JWTUtils.verify_claims(claims,
                               claims_to_verify,
                               self.audience,
                               self.issuer,
                               leeway)

    def verify_expiration(self, token, leeway=LEEWAY):
        """Verify if token is not expired."""
        JWTUtils.verify_expiration(token, leeway)

    def _get_jwk_by_kid(self, jwks, kid):
        """Loop through given jwks and find jwk which matches by kid.

        Return:
            str if jwk match found, None - otherwise
        """
        okta_jwk = None
        for key in jwks['keys']:
            if key['kid'] == kid:
                okta_jwk = key
        return okta_jwk

    async def get_jwk(self, kid):
        """Get JWK by kid.

        If key not found, clear cache and retry again to support keys rollover.

        Return:
            str - represents JWK
        Raise JWKException if key not found after retry.
        """
        jwks = await self.get_jwks()
        okta_jwk = self._get_jwk_by_kid(jwks, kid)

        if not okta_jwk:
            # retry logic
            self._clear_requests_cache()
            jwks = await self.get_jwks()
            okta_jwk = self._get_jwk_by_kid(jwks, kid)
        if not okta_jwk:
            raise JWKException('No matching JWK.')
        return okta_jwk

    async def get_jwks(self):
        """Get jwks_uri from claims and download jwks.

        version from okta_jwt_verifier.__init__.py
        """
        jwks_uri = self._construct_jwks_uri()
        headers = {'User-Agent': f'okta-jwt-verifier-python/{version}',
                   'Content-Type': 'application/json'}
        jwks = await self.request_executor.get(jwks_uri, headers=headers)
        if not self.cache_jwks:
            self._clear_requests_cache()
        return jwks

    def _construct_jwks_uri(self):
        """Construct URI for JWKs download.

        Issuer URL should end with '/', automatic add '/' otherwise.
        If the issuer URL does not contain /oauth2/, then:
        jwks_uri_base = {issuer}/oauth2.
        Otherwise: jwks_uri_base = {issuer}.
        Final JWKS URI: {jwks_uri_base}/v1/keys
        """
        jwks_uri_base = self.issuer
        if not jwks_uri_base.endswith('/'):
            jwks_uri_base = jwks_uri_base + '/'
        if '/oauth2/' not in jwks_uri_base:
            jwks_uri_base = urljoin(jwks_uri_base, 'oauth2/')
        return urljoin(jwks_uri_base, 'v1/keys')

    def _clear_requests_cache(self):
        """Clear whole cache."""
        self.request_executor.clear_cache()


class JWTVerifier(BaseJWTVerifier):

    def __init__(self,
                 issuer=None,
                 client_id='client_id_stub',
                 audience='api://default',
                 request_executor=RequestExecutor,
                 max_retries=MAX_RETRIES,
                 request_timeout=REQUEST_TIMEOUT,
                 max_requests=MAX_REQUESTS,
                 leeway=LEEWAY,
                 cache_jwks=True,
                 proxy=None):
        """
        Args:
            issuer: string, full URI of the token issuer, required
            client_id: string, expected client_id, required
            audience: string, expected audience, optional
            request_executor: RequestExecutor class or its subclass, optional
            max_retries: int, number of times to retry a failed network request, optional
            request_timeout: int, max request timeout, optional
            max_requests: int, max number of concurrent requests
            leeway: int, amount of time to expand the window for token expiration (to work around clock skew)
            cache_jwks: bool, optional
        """
        warnings.simplefilter('module')
        warnings.warn('JWTVerifier will be deprecated soon. '
                      'For token verification use IDTokenVerifier or AccessTokenVerifier. '
                      'For different jwt utils use JWTUtils.', DeprecationWarning)
        super().__init__(issuer=issuer,
                         client_id=client_id,
                         audience=audience,
                         request_executor=request_executor,
                         max_retries=max_retries,
                         request_timeout=request_timeout,
                         max_requests=max_requests,
                         leeway=leeway,
                         cache_jwks=cache_jwks,
                         proxy=proxy)


class AccessTokenVerifier():
    def __init__(self,
                 issuer=None,
                 audience='api://default',
                 request_executor=RequestExecutor,
                 max_retries=MAX_RETRIES,
                 request_timeout=REQUEST_TIMEOUT,
                 max_requests=MAX_REQUESTS,
                 leeway=LEEWAY,
                 cache_jwks=True,
                 proxy=None):
        """
        Args:
            issuer: string, full URI of the token issuer, required
            audience: string, expected audience, optional
            request_executor: RequestExecutor class or its subclass, optional
            max_retries: int, number of times to retry a failed network request, optional
            request_timeout: int, max request timeout, optional
            max_requests: int, max number of concurrent requests
            leeway: int, amount of time to expand the window for token expiration (to work around clock skew)
            cache_jwks: bool, optional
        """
        self._jwt_verifier = BaseJWTVerifier(issuer=issuer,
                                             client_id='client_id_stub',
                                             audience=audience,
                                             request_executor=request_executor,
                                             max_retries=max_retries,
                                             request_timeout=request_timeout,
                                             max_requests=max_requests,
                                             leeway=leeway,
                                             cache_jwks=cache_jwks,
                                             proxy=proxy)

    async def verify(self, token, claims_to_verify=('iss', 'aud', 'exp')):
        await self._jwt_verifier.verify_access_token(token, claims_to_verify)


class IDTokenVerifier():
    def __init__(self,
                 issuer=None,
                 client_id='client_id_stub',
                 audience='api://default',
                 request_executor=RequestExecutor,
                 max_retries=MAX_RETRIES,
                 request_timeout=REQUEST_TIMEOUT,
                 max_requests=MAX_REQUESTS,
                 leeway=LEEWAY,
                 cache_jwks=True,
                 proxy=None):
        """
        Args:
            issuer: string, full URI of the token issuer, required
            client_id: string, expected client_id, required
            audience: string, expected audience, optional
            request_executor: RequestExecutor class or its subclass, optional
            max_retries: int, number of times to retry a failed network request, optional
            request_timeout: int, max request timeout, optional
            max_requests: int, max number of concurrent requests
            leeway: int, amount of time to expand the window for token expiration (to work around clock skew)
            cache_jwks: bool, optional
        """
        self._jwt_verifier = BaseJWTVerifier(issuer,
                                             client_id,
                                             audience,
                                             request_executor,
                                             max_retries,
                                             request_timeout,
                                             max_requests,
                                             leeway,
                                             cache_jwks,
                                             proxy)

    async def verify(self, token, claims_to_verify=('iss', 'exp'), nonce=None):
        await self._jwt_verifier.verify_id_token(token, claims_to_verify, nonce)
