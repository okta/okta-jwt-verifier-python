# OKTA JWT Verifier Changelog

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
