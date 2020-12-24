from urllib.parse import urljoin
from jose import jwt, jws

from . import __version__ as version
from .exceptions import JWKException
from .request_executor import RequestExecutor


class JWTVerifier():

    def __init__(self, issuer, client_id, audience='api://default',
                 request_executor=RequestExecutor()):
        self.issuer = issuer
        self.client_id = client_id
        self.audience = audience
        self.request_executor = request_executor

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

        # TODO: implement all needed methods, check out for correct algorithm
        headers = jwt.get_unverified_headers(token)
        okta_jwk = self.get_jwk(headers['kid'])
        self.verify_signature(token, okta_jwk)
        decoded_token = self.decode_token(token, okta_jwk)
        # TODO: investigate if we need to verify claims after decode,
        # which inludes auto-verification
        self.verify_claims(decoded_token)
        return True

    def verify_claims(self, decode_token):
        pass

    def verify_signature(self, token, okta_jwk):
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
        response = self.request_executor.get(jwks_uri, headers=headers)
        jwks = response.json()
        # TODO: make some jwks validation here?
        return jwks

    def decode_token(self, token, okta_jwk):
        """Method decode from python-jose automatically verify claims."""
        return jwt.decode(token, okta_jwk, algorithms=['RS256'],
                          audience=self.audience, issuer=self.issuer)

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
