[<img src="https://aws1.discourse-cdn.com/standard14/uploads/oktadev/original/1X/0c6402653dfb70edc661d4976a43a46f33e5e919.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)](https://devforum.okta.com/)
[![Code Style](https://img.shields.io/badge/Code%20Style-flake8-informational.svg)](https://flake8.pycqa.org)

# Okta JWT Verifier for Python

This library helps you verify tokens that have been issued by Okta. To learn more about verification cases and Okta's tokens please read [Working With OAuth 2.0 Tokens](https://developer.okta.com/authentication-guide/tokens/)

> Requires Python version 3.6.0 or higher.

## Installation
```sh
pip install okta-jwt-verifier
```

> Note: currently, there is nothing to install, library is under development

## Usage

This library was built to keep configuration to a minimum. To get it running at its most basic form, all you need to provide is the the following information:

- **Issuer** - This is the URL of the authorization server that will perform authentication.  All Developer Accounts have a "default" authorization server.  The issuer is a combination of your Org URL (found in the upper right of the console home page) and `/oauth2/default`. For example, `https://dev-1234.oktapreview.com/oauth2/default`.
- **Client ID** - These can be found on the "General" tab of the Web application that you created earlier in the Okta Developer Console.
- **Audience** - By default `api://default`, can be found on Authorization Servers tab.

Following example will raise an JWTValidationException is JWT is invalid:

```py
import asyncio

from okta_jwt_verifier import JWTVerifier


async def main():
    jwt_verifier = JWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    await jwt_verifier.verify_access_token({JWT})
    print('Token validated successfully.')


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

It is possible to verify signature if JWK is provided (no async requests):
```py
from okta_jwt_verifier import JWTVerifier


def main():
    jwt_verifier = JWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    jwt_verifier.verify_signature({JWT}, {JWK})


main()
```

The following example shows how to receive JWK using async http request:
```py
import asyncio

from okta_jwt_verifier import JWTVerifier


async def main():
    jwt_verifier = JWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    headers, claims, signing_input, signature = jwt_verifier.parse_token({JWT})
    okta_jwk = await self.get_jwk(headers['kid'])

    # Then it can be used to verify_signature as in example above.
    jwt_verifier.verify_signature({JWT}, okta_jwk)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```


It is possible to verify only given list of claims (no async requests):

```py
from okta_jwt_verifier import JWTVerifier


def main():
    claims_to_verify = ['aud', 'cid']
    jwt_verifier = JWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    headers, claims, signing_input, signature = jwt_verifier.parse_token({JWT})
    result = jwt_verifier.verify_claims(claims, claims_to_verify)
    print(result)


main()
```

or token expiration only (no async requests):

```py
from okta_jwt_verifier import JWTVerifier


def main():
    jwt_verifier = JWTVerifier('{ISSUER}', '{CLIENT_ID}', 'api://default')
    result = jwt_verifier.verify_expiration({JWT}, leeway=0)
    print(result)


main()
```
