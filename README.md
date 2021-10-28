[<img src="https://aws1.discourse-cdn.com/standard14/uploads/oktadev/original/1X/0c6402653dfb70edc661d4976a43a46f33e5e919.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)](https://devforum.okta.com/)
[![PyPI](https://img.shields.io/pypi/v/okta-jwt-verifier)](https://pypi.org/project/okta-jwt-verifier/)
[![Code Style](https://img.shields.io/badge/Code%20Style-flake8-informational.svg)](https://flake8.pycqa.org)

# Okta JWT Verifier for Python

- [Release Status](#release-status)
- [Need help?](#need-help)
- [Getting Started](#getting-started)
- [Usage Guide](#usage-guide)
- [Exceptions](#exceptions)
- [Contributing](#contributing)

This library helps you verify tokens that have been issued by Okta. To learn more about verification cases and Okta's tokens please read [Working With OAuth 2.0 Tokens](https://developer.okta.com/authentication-guide/tokens/)

> Requires Python version 3.6.0 or higher.

## Release status

This library uses semantic versioning and follows Okta's [Library Version Policy][okta-library-versioning].

| Version | Status                           |
| ------- | -------------------------------- |
| 0.x     | :heavy_check_mark: Beta Release  |

The latest release can always be found on the [releases page][github-releases].

## Need help?

If you run into problems using the SDK, you can

- Ask questions on the [Okta Developer Forums][devforum]
- Post [issues on GitHub][github-issues] (for code errors)

## Getting started

To install Okta JWT Verifier Python:

```sh
pip install okta-jwt-verifier
```

This library was built to keep configuration to a minimum. To get it running at its most basic form, all you need to provide is the the following information:

- **Issuer** - This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is a combination of your Org URL (found in the upper right of the console home page) and `/oauth2/default`. For example, `https://dev-1234.oktapreview.com/oauth2/default`.
- **Client ID** - These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.
- **Audience** - By default `api://default`, can be found on Authorization Servers tab.

Following example will raise an JWTValidationException if Access Token is invalid:

```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier(issuer='{ISSUER}', audience='api://default')
    await jwt_verifier.verify_access_token('{JWT}')
    print('Token validated successfully.')


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

## Usage guide

These examples will help you understand how to use this library.

Verify ID Token:
```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier(issuer='{ISSUER}', client_id='{CLIENT_ID}', audience='api://default')
    await jwt_verifier.verify_id_token('{JWT}', nonce='{NONCE}')
    print('Token validated successfully.')


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```
> Note: parameter `nonce` is optional and required only if token was generated with nonce.

Another option - use class dedicated to ID tokens verification:
```py
import asyncio

from okta_jwt_verifier import IDTokenVerifier


async def main():
    jwt_verifier = IDTokenVerifier(issuer='{ISSUER}', client_id='{CLIENT_ID}', audience='api://default')
    await jwt_verifier.verify('{JWT}', nonce='{NONCE}')
    print('Token validated successfully.')


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

Verify Access Token
```py
import asyncio

from okta_jwt_verifier import AccessTokenVerifier


async def main():
    jwt_verifier = AccessTokenVerifier(issuer='{ISSUER}', audience='api://default')
    await jwt_verifier.verify('{JWT}')
    print('Token validated successfully.')


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

It is possible to verify signature if JWK is provided (no async requests):
```py
from okta_jwt_verifier import BaseJWTVerifier


def main():
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    jwt_verifier.verify_signature('{JWT}', {JWK})


main()
```

The following example shows how to receive JWK using async http request:
```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    headers, claims, signing_input, signature = jwt_verifier.parse_token({JWT})
    okta_jwk = await self.get_jwk(headers['kid'])

    # Then it can be used to verify_signature as in example above.
    jwt_verifier.verify_signature('{JWT}', okta_jwk)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```


It is possible to verify only given list of claims (no async requests):

```py
from okta_jwt_verifier import BaseJWTVerifier


def main():
    claims_to_verify = ['aud', 'iss']
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    headers, claims, signing_input, signature = jwt_verifier.parse_token({JWT})
    jwt_verifier.verify_claims(claims, claims_to_verify)


main()
```

or token expiration only (no async requests):

```py
from okta_jwt_verifier import BaseJWTVerifier


def main():
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    jwt_verifier.verify_expiration('{JWT}', leeway=0)


main()
```

v 0.2.0 allows to work via proxy:
```py
# BaseJWTVerifier will be deprecated soon
jwt_verifier = BaseJWTVerifier(issuer='{ISSUER}', proxy='{PROXY}')

# The same for AccessTokenVerifier
jwt_verifier = AccessTokenVerifier(issuer='{ISSUER}', proxy='{PROXY}')

# or IDTokenVerifier
jwt_verifier = IDTokenVerifier(issuer='{ISSUER}', proxy='{PROXY}')
```

## Exceptions

If token is invalid (malformed, expired, etc.), verifier will raise an exception `JWTValidationException`:

```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    await jwt_verifier.verify_access_token(access_token)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```
Output (part of traceback removed for simplicity):
```sh
Traceback (most recent call last):
...
okta_jwt_verifier.exceptions.JWTValidationException: Signature has expired.
```

If configuration provided is invalid, verifier will raise an exception `JWTInvalidConfigException`:
```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier('malformed_issuer.com', '{CLIENT_ID}', 'api://default')
    await jwt_verifier.verify_access_token(access_token)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```
Output (part of traceback removed for simplicity):
```sh
Traceback (most recent call last):
...
okta_jwt_verifier.exceptions.JWTInvalidConfigException: Your Okta URL must start with 'https'.
```

If JWK is invalid, verifier will raise an exception `JWKException`:
```py
import asyncio

from okta_jwt_verifier import BaseJWTVerifier


async def main():
    jwt_verifier = BaseJWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    await jwt_verifier.verify_access_token(access_token)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```
Output (part of traceback removed for simplicity):
```sh
Traceback (most recent call last):
...
okta_jwt_verifier.exceptions.JWKException: No matching JWK.
```

## Contributing

We're happy to accept contributions and PRs! Please see the [Contribution Guide](CONTRIBUTING.md) to understand how to structure a contribution.

[devforum]: https://devforum.okta.com/
[github-issues]: https://github.com/okta/okta-jwt-verifier-python/issues
[github-releases]: https://github.com/okta/okta-jwt-verifier-python/releases
[okta developer forum]: https://devforum.okta.com/
[lang-landing-page]: https://developer.okta.com/code/python/
[okta-library-versioning]: https://developer.okta.com/code/library-versions/
[dev-okta-signup]: https://developer.okta.com/signup
[python-docs]: https://docs.python.org/3/library/asyncio.html
