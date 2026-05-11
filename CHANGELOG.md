# OKTA JWT Verifier Changelog

## v0.5.0
_New features:_
- Add synchronous `verify_sync()` method to `AccessTokenVerifier` and `IDTokenVerifier` for non-async applications (e.g. Django, Flask)
- Add sync verification methods to `BaseJWTVerifier`: `verify_access_token_sync()`, `verify_id_token_sync()`, `get_jwk_sync()`, `get_jwks_sync()`
- Add sync HTTP support in `RequestExecutor`: `fire_request_sync()`, `get_sync()` using the `requests` library

_Improvements:_
- Extract shared validation logic into `_verify_token_common()` to reduce code duplication across verify methods
- Simplify `_get_jwk_by_kid()` with early return pattern
- Fix `get_jwks()` silently swallowing exceptions on HTTP failure (now re-raises after cleanup)
- Ensure `clear_cache()` clears both async and sync caches
- Add `try/finally` to request throttling to guarantee counter cleanup on exceptions

_Code quality:_
- Fix docstring typo: `"acess"` → `"access"`
- Fix incorrect return type documentation: `str` → `dict` for JWK methods
- Add RFC 7519, 7515, 7517 references to docstrings
- Remove empty parentheses on classes with no base class (PEP 8)

_Backward compatible:_ All existing async APIs remain unchanged. No breaking changes.

## v0.4.0
- Added support to clear cache if http client fails

## v0.3.0
- Updated version of aiohttp to 3.12.14

## v0.2.9
- Updated version of setuptools to 78.1.1

## v0.2.8
- Updated version of setuptools to 70.0.0

## v0.2.3
- Verify claims before signature, issue #34

## v0.2.2
- Remove deprecation warning from IDTokenVerifier, add missing fix in v0.2.1

## v0.2.1
- Fix passing timeout parameter to cached session, issue #22
- Fix verify_expiration method, issue #24
- Remove deprecation warning from IDTokenVerifier and AccessTokenVerifier classes by separating JWTVerifier class

## v0.2.0
- Add classes IDTokenVerifier and AccessTokenVerifier
- Mark JWTVerifier class as deprecated. This class will be removed in the next major version.
- Add proxy support
- Update README
- Few codebase improvements

_New features:_
- Separate classes for verifying ID Tokens and Access Tokens
- Add proxy support

## v0.1.0
- Initial release
