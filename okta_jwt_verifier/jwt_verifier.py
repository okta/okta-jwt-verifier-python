from urllib.parse import urljoin
from jose import jwt, jws

from . import __version__ as version
from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT, LEEWAY
from .exceptions import JWKException
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

    def verify_token(self, token):
        """
        Algorithm:
        1. Retrieve and parse your Okta JSON Web Keys (JWK),
           which should be checked periodically and cached by your application.
        2. Decode the access token, which is in JSON Web Token format
        3. Verify the signature used to sign the access token
        4. Verify the claims found inside the access token

        Claims:
        'exp' Expiration - The time after which the token is invalid.
        'nbf' Not Before - The time before which the token is invalid.
        'iss' Issuer     - The principal that issued the JWT.
        'aud' Audience   - The recipient that the JWT is intended for.
        # should not be validated according to technical design:
        https://github.com/okta/oss-technical-designs/blob/master/technical_designs/jwt-validation-libraries.md
        'iat' Issued At  - The time at which the JWT was issued.
        """
        headers = jwt.get_unverified_headers(token)
        okta_jwk = self.get_jwk(headers['kid'])
        self.verify_signature(token, okta_jwk)
        # method decode_token includes claims validation and token expiration
        decoded_token = self.decode_token(token, okta_jwk)
        return True

    def verify_signature(self, token, okta_jwk):
        """Verify token signature using received jwk."""
        # Will raise an error if verification is failed
        return jws.verify(token, okta_jwk, algorithms=['RS256'])

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

    def get_jwk(self, kid):
        """Get JWK by kid.

        If key not found, clear cache and retry again to support keys rollover.

        Return:
            str - represents JWK
        Raise JWKException if key not found after retry.
        """
        jwks = self.get_jwks()
        okta_jwk = self._get_jwk_by_kid(jwks, kid)

        if not okta_jwk:
            # retry logic
            self._clear_requests_cache()
            jwks = self.get_jwks()
            okta_jwk = self._get_jwk_by_kid(jwks, kid)
        if not okta_jwk:
            raise JWKException('No matching JWK.')
        return okta_jwk

    def get_jwks(self):
        """Get jwks_uri from claims and download jwks.

        version from okta_jwt_verifier.__init__.py
        """
        jwks_uri = self._construct_jwks_uri()
        headers = {'User-Agent': f'okta-jwt-verifier-python/{version}',
                   'Content-Type': 'application/json'}
        jwks = self.request_executor.get(jwks_uri, headers=headers)
        if not self.cache_jwks:
            self._clear_requests_cache()
        return jwks

    def decode_token(self, token, okta_jwk):
        """Method decode from python-jose automatically verify claims."""
        return jwt.decode(token, okta_jwk, algorithms=['RS256'],
                          audience=self.audience, issuer=self.issuer,
                          options={'leeway': self.leeway})

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
