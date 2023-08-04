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

import json

from jose import jwt, jws
from jose.exceptions import ExpiredSignatureError

from .constants import LEEWAY
from .exceptions import JWTValidationException


class JWTUtils:
    """Contains different utils and common methods for jwt verification."""

    @staticmethod
    def parse_token(token):
        """Parse JWT token, get headers, claims and signature.

        Return:
            tuple (headers, claims, signing_input, signature)
        """
        headers, payload, signing_input, signature = jws._load(token)
        claims = json.loads(payload.decode('utf-8'))
        return (headers, claims, signing_input, signature)

    @staticmethod
    def verify_claims(claims,
                      claims_to_verify,
                      audience,
                      issuer,
                      leeway=LEEWAY):
        """Verify claims are present and valid."""
        # Check if required claims are present, because library "jose" doesn't raise an exception
        for claim in claims_to_verify:
            if claim not in claims:
                raise JWTValidationException(f'Required claim "{claim}" is not present.')

        # Overwrite defaults in python-jose library
        options = {'verify_aud': 'aud' in claims_to_verify,
                   'verify_iat': 'iat' in claims_to_verify,
                   'verify_exp': 'exp' in claims_to_verify,
                   'verify_nbf': 'nbf' in claims_to_verify,
                   'verify_iss': 'iss' in claims_to_verify,
                   'verify_sub': 'sub' in claims_to_verify,
                   'verify_jti': 'jti' in claims_to_verify,
                   'leeway': leeway}
        # Validate claims
        jwt._validate_claims(claims,
                             audience=audience,
                             issuer=issuer,
                             options=options)

    @staticmethod
    def verify_signature(token, okta_jwk):
        """Verify token signature using received jwk."""
        headers, claims, signing_input, signature = JWTUtils.parse_token(token)
        jws._verify_signature(signing_input=signing_input,
                              header=headers,
                              signature=signature,
                              key=okta_jwk,
                              algorithms=['RS256'])

    @staticmethod
    def verify_expiration(token, leeway=LEEWAY):
        """Verify if token is not expired."""
        headers, claims, signing_input, signature = JWTUtils.parse_token(token)
        try:
            JWTUtils.verify_claims(claims,
                                   claims_to_verify=('exp',),
                                   audience=None,
                                   issuer=None,
                                   leeway=LEEWAY)
        except ExpiredSignatureError:
            raise JWTValidationException('Signature has expired.')
