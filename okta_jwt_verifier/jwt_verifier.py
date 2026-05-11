import warnings

from urllib.parse import urljoin

from . import __version__ as version
from .config_validator import ConfigValidator
from .constants import MAX_RETRIES, MAX_REQUESTS, REQUEST_TIMEOUT, LEEWAY
from .exceptions import JWKException, JWTValidationException
from .jwt_utils import JWTUtils
from .request_executor import RequestExecutor


class BaseJWTVerifier:

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
            tuple: (headers, claims, signing_input, signature)
        """
        return JWTUtils.parse_token(token)

    def _verify_token_common(self, token, claims_to_verify):
        """Shared validation logic for both access and ID token verification.

        Validates algorithm header, claims, and returns parsed components
        needed for signature verification.

        Args:
            token: str, the JWT token string.
            claims_to_verify: tuple, claim names to validate.

        Return:
            tuple: (headers, claims) after validation passes.

        Raises:
            JWTValidationException: if algorithm or claims validation fails.
        """
        headers, claims, _, _ = self.parse_token(token)
        if headers.get('alg') != 'RS256':
            raise JWTValidationException('Header claim "alg" is invalid.')

        self.verify_claims(claims,
                           claims_to_verify=claims_to_verify,
                           leeway=self.leeway)
        return headers, claims

    async def verify_access_token(self, token, claims_to_verify=('iss', 'aud', 'exp')):
        """Verify access token (async).

        Algorithm per Okta guidelines (RFC 7519, RFC 7515):
        1. Parse and decode the JWT token.
        2. Verify the 'alg' header is RS256.
        3. Verify required claims (iss, aud, exp by default).
        4. Retrieve the matching JWK from Okta's JWKS endpoint.
        5. Verify the token signature using the JWK public key.

        Args:
            token: str, the encoded JWT access token.
            claims_to_verify: tuple, claim names to validate
                (default: 'iss', 'aud', 'exp').

        Raises:
            JWTValidationException: if any validation step fails.
        """
        try:
            headers, claims = self._verify_token_common(token, claims_to_verify)
            okta_jwk = await self.get_jwk(headers['kid'])
            self.verify_signature(token, okta_jwk)
        except JWTValidationException:
            raise
        except Exception as err:
            raise JWTValidationException(str(err))

    def verify_access_token_sync(self, token, claims_to_verify=('iss', 'aud', 'exp')):
        """Verify access token (synchronous).

        Same verification logic as verify_access_token but uses synchronous
        HTTP requests to fetch JWKs. Suitable for non-async applications
        (e.g. Django, Flask).

        Args:
            token: str, the encoded JWT access token.
            claims_to_verify: tuple, claim names to validate
                (default: 'iss', 'aud', 'exp').

        Raises:
            JWTValidationException: if any validation step fails.
        """
        try:
            headers, claims = self._verify_token_common(token, claims_to_verify)
            okta_jwk = self.get_jwk_sync(headers['kid'])
            self.verify_signature(token, okta_jwk)
        except JWTValidationException:
            raise
        except Exception as err:
            raise JWTValidationException(str(err))

    async def verify_id_token(self, token, claims_to_verify=('iss', 'exp'), nonce=None):
        """Verify ID token (async).

        Algorithm per Okta guidelines (RFC 7519, RFC 7515):
        1. Parse and decode the JWT token.
        2. Verify the 'alg' header is RS256.
        3. Verify required claims (iss, exp by default).
        4. Retrieve the matching JWK from Okta's JWKS endpoint.
        5. Verify the token signature using the JWK public key.
        6. Verify the 'aud' claim matches the configured client_id.
        7. If 'nonce' claim is present, verify it matches the expected value.

        Args:
            token: str, the encoded JWT ID token.
            claims_to_verify: tuple, claim names to validate
                (default: 'iss', 'exp').
            nonce: str or None, expected nonce value (optional).

        Raises:
            JWTValidationException: if any validation step fails.
        """
        try:
            headers, claims = self._verify_token_common(token, claims_to_verify)
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

    def verify_id_token_sync(self, token, claims_to_verify=('iss', 'exp'), nonce=None):
        """Verify ID token (synchronous).

        Same verification logic as verify_id_token but uses synchronous
        HTTP requests to fetch JWKs. Suitable for non-async applications
        (e.g. Django, Flask).

        Args:
            token: str, the encoded JWT ID token.
            claims_to_verify: tuple, claim names to validate
                (default: 'iss', 'exp').
            nonce: str or None, expected nonce value (optional).

        Raises:
            JWTValidationException: if any validation step fails.
        """
        try:
            headers, claims = self._verify_token_common(token, claims_to_verify)
            okta_jwk = self.get_jwk_sync(headers['kid'])
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
        """Verify client_id matches aud claim or one of its elements.

        Args:
            aud: str or list, the audience claim value from the token.

        Raises:
            JWTValidationException: if aud does not match client_id.
        """
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
        """Verify token signature using received JWK.

        Args:
            token: str, the encoded JWT token.
            okta_jwk: dict, the JSON Web Key to verify against.
        """
        JWTUtils.verify_signature(token, okta_jwk)

    def verify_claims(self, claims, claims_to_verify, leeway=LEEWAY):
        """Verify claims are present and valid.

        Args:
            claims: dict, the token claims payload.
            claims_to_verify: tuple, claim names to validate.
            leeway: int, clock skew tolerance in seconds.
        """
        JWTUtils.verify_claims(claims,
                               claims_to_verify,
                               self.audience,
                               self.issuer,
                               leeway)

    def verify_expiration(self, token, leeway=LEEWAY):
        """Verify if token is not expired.

        Args:
            token: str, the encoded JWT token.
            leeway: int, clock skew tolerance in seconds.
        """
        JWTUtils.verify_expiration(token, leeway)

    def _get_jwk_by_kid(self, jwks, kid):
        """Find JWK matching the given key ID.

        Args:
            jwks: dict, the JWKS response containing a 'keys' list.
            kid: str, the key ID to match.

        Return:
            dict or None: matching JWK if found, None otherwise.
        """
        for key in jwks['keys']:
            if key['kid'] == kid:
                return key
        return None

    async def get_jwk(self, kid):
        """Get JWK by key ID (async).

        Fetches JWKS from Okta. If the key is not found, clears cache and
        retries once to support key rotation (RFC 7517 §5).

        Args:
            kid: str, the key ID from the token header.

        Return:
            dict: the matching JSON Web Key.

        Raises:
            JWKException: if no matching key is found after retry.
        """
        jwks = await self.get_jwks()
        okta_jwk = self._get_jwk_by_kid(jwks, kid)

        if not okta_jwk:
            # retry to support key rotation
            self._clear_requests_cache()
            jwks = await self.get_jwks()
            okta_jwk = self._get_jwk_by_kid(jwks, kid)
        if not okta_jwk:
            raise JWKException('No matching JWK.')
        return okta_jwk

    def get_jwk_sync(self, kid):
        """Get JWK by key ID (synchronous).

        Synchronous version of get_jwk. Fetches JWKS using blocking HTTP.
        If the key is not found, clears cache and retries once to support
        key rotation (RFC 7517 §5).

        Args:
            kid: str, the key ID from the token header.

        Return:
            dict: the matching JSON Web Key.

        Raises:
            JWKException: if no matching key is found after retry.
        """
        jwks = self.get_jwks_sync()
        okta_jwk = self._get_jwk_by_kid(jwks, kid)

        if not okta_jwk:
            # retry to support key rotation
            self._clear_requests_cache()
            jwks = self.get_jwks_sync()
            okta_jwk = self._get_jwk_by_kid(jwks, kid)
        if not okta_jwk:
            raise JWKException('No matching JWK.')
        return okta_jwk

    async def get_jwks(self):
        """Download JWKS from the issuer's keys endpoint (async).

        Constructs the JWKS URI from the issuer and fetches the key set.

        Return:
            dict: the JWKS response containing signing keys.
        """
        jwks_uri = self._construct_jwks_uri()
        headers = {'User-Agent': f'okta-jwt-verifier-python/{version}',
                   'Content-Type': 'application/json'}
        try:
            jwks = await self.request_executor.get(jwks_uri, headers=headers)
        except Exception:
            self.request_executor.cache.release_new_key(('GET', jwks_uri))
            self._clear_requests_cache()
            raise

        if not self.cache_jwks:
            self._clear_requests_cache()
        return jwks

    def get_jwks_sync(self):
        """Download JWKS from the issuer's keys endpoint (synchronous).

        Constructs the JWKS URI from the issuer and fetches the key set
        using blocking HTTP requests.

        Return:
            dict: the JWKS response containing signing keys.
        """
        jwks_uri = self._construct_jwks_uri()
        headers = {'User-Agent': f'okta-jwt-verifier-python/{version}',
                   'Content-Type': 'application/json'}
        try:
            jwks = self.request_executor.get_sync(jwks_uri, headers=headers)
        except Exception:
            self._clear_requests_cache()
            raise

        if not self.cache_jwks:
            self._clear_requests_cache()
        return jwks

    def _construct_jwks_uri(self):
        """Construct the JWKS URI from the issuer URL.

        If the issuer URL does not contain '/oauth2/', it is added.
        Final URI format: {issuer_base}/v1/keys

        Return:
            str: the full JWKS endpoint URI.
        """
        jwks_uri_base = self.issuer
        if not jwks_uri_base.endswith('/'):
            jwks_uri_base = jwks_uri_base + '/'
        if '/oauth2/' not in jwks_uri_base:
            jwks_uri_base = urljoin(jwks_uri_base, 'oauth2/')
        return urljoin(jwks_uri_base, 'v1/keys')

    def _clear_requests_cache(self):
        """Clear all cached JWKS data (both async and sync caches)."""
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
        """Deprecated: use AccessTokenVerifier or IDTokenVerifier instead."""
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


class AccessTokenVerifier:
    """Verifier for Okta OAuth 2.0 access tokens."""

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
            issuer: str, full URI of the token issuer, required.
            audience: str, expected audience claim (default: 'api://default').
            request_executor: RequestExecutor class or subclass, optional.
            max_retries: int, network request retry count, optional.
            request_timeout: int, max request timeout in seconds, optional.
            max_requests: int, max concurrent requests, optional.
            leeway: int, clock skew tolerance in seconds, optional.
            cache_jwks: bool, enable JWK caching, optional.
            proxy: str, proxy URL, optional.
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
        """Verify access token asynchronously.

        Args:
            token: str, the encoded JWT access token.
            claims_to_verify: tuple, claim names to validate.

        Raises:
            JWTValidationException: if verification fails.
        """
        await self._jwt_verifier.verify_access_token(token, claims_to_verify)

    def verify_sync(self, token, claims_to_verify=('iss', 'aud', 'exp')):
        """Verify access token synchronously.

        Uses blocking HTTP requests to fetch JWKs. Suitable for
        non-async applications (e.g. Django, Flask).

        Args:
            token: str, the encoded JWT access token.
            claims_to_verify: tuple, claim names to validate.

        Raises:
            JWTValidationException: if verification fails.
        """
        self._jwt_verifier.verify_access_token_sync(token, claims_to_verify)


class IDTokenVerifier:
    """Verifier for Okta OIDC ID tokens."""

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
            issuer: str, full URI of the token issuer, required.
            client_id: str, expected client_id for aud verification, required.
            audience: str, expected audience claim (default: 'api://default').
            request_executor: RequestExecutor class or subclass, optional.
            max_retries: int, network request retry count, optional.
            request_timeout: int, max request timeout in seconds, optional.
            max_requests: int, max concurrent requests, optional.
            leeway: int, clock skew tolerance in seconds, optional.
            cache_jwks: bool, enable JWK caching, optional.
            proxy: str, proxy URL, optional.
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
        """Verify ID token asynchronously.

        Args:
            token: str, the encoded JWT ID token.
            claims_to_verify: tuple, claim names to validate.
            nonce: str or None, expected nonce value.

        Raises:
            JWTValidationException: if verification fails.
        """
        await self._jwt_verifier.verify_id_token(token, claims_to_verify, nonce)

    def verify_sync(self, token, claims_to_verify=('iss', 'exp'), nonce=None):
        """Verify ID token synchronously.

        Uses blocking HTTP requests to fetch JWKs. Suitable for
        non-async applications (e.g. Django, Flask).

        Args:
            token: str, the encoded JWT ID token.
            claims_to_verify: tuple, claim names to validate.
            nonce: str or None, expected nonce value.

        Raises:
            JWTValidationException: if verification fails.
        """
        self._jwt_verifier.verify_id_token_sync(token, claims_to_verify, nonce)
