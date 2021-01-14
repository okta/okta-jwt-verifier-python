import json

from urllib.parse import urljoin
from jose import jwt, jws

from . import __version__ as version
from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT, LEEWAY
from .exceptions import JWKException, JWTValidationException
from .request_executor import RequestExecutor


class JWTVerifier():

    def __init__(self,
                 issuer,
                 client_id,
                 audience='api://default',
                 request_executor=RequestExecutor,
                 max_retries=MAX_RETRIES,
                 request_timeout=REQUEST_TIMEOUT,
                 max_requests=MAX_REQUESTS,
                 leeway=LEEWAY,
                 cache_jwks=True):
        """
        Args:
            issuer: string, full URI of the token issuer, required
            client_id: string, expected client_id, required
            audience: string, expected audience, optional
            request_executor: RequestExecutor class or its subclass, optional
            max_retries: int, number of times to retry a failed network request, optional
            request_timemout: int, max request timeout, optional
            max_requests: int, max number of concurrent requests
            leeway: int, amount of time to expand the window for token expiration (to work around clock skew)
            cache_jwks: bool, optional
        """
        self.issuer = issuer
        self.client_id = client_id
        self.audience = audience
        self.request_executor = request_executor(max_retries=max_retries,
                                                 max_requests=max_requests,
                                                 request_timeout=request_timeout)
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
        headers, payload, signing_input, signature = jws._load(token)
        claims = json.loads(payload.decode('utf-8'))
        return (headers, claims, signing_input, signature)

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

            okta_jwk = await self.get_jwk(headers['kid'])
            self.verify_signature(token, okta_jwk)

            self.verify_claims(claims,
                               claims_to_verify=claims_to_verify,
                               leeway=self.leeway)
        except JWTValidationException:
            raise
        except Exception as err:
            raise JWTValidationException(str(err))

    def verify_signature(self, token, okta_jwk):
        """Verify token signature using received jwk."""
        headers, claims, signing_input, signature = self.parse_token(token)
        jws._verify_signature(signing_input=signing_input,
                              header=headers,
                              signature=signature,
                              key=okta_jwk,
                              algorithms=['RS256'])

    def verify_claims(self, claims, claims_to_verify, leeway=LEEWAY):
        # Overwrite defaults in python-jose library
        options = {'verify_aud': 'aud' in claims_to_verify,
                   'verify_iat': 'iat' in claims_to_verify,
                   'verify_exp': 'exp' in claims_to_verify,
                   'verify_nbf': 'nbf' in claims_to_verify,
                   'verify_iss': 'iss' in claims_to_verify,
                   'verify_sub': 'sub' in claims_to_verify,
                   'verify_jti': 'jti' in claims_to_verify,
                   'leeway': leeway}
        jwt._validate_claims(claims,
                             audience=self.audience,
                             issuer=self.issuer,
                             options=options)

    def verify_expiration(self, token, leeway=LEEWAY):
        """Verify if token is not expired."""
        headers, claims, signing_input, signature = self.parse_token(token)
        self.verify_claims(claims, claims_to_verify=('exp'), leeway=LEEWAY)

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
