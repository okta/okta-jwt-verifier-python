import json

import jwt
from jwt.exceptions import ExpiredSignatureError


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
        jws_api = jwt.api_jws.PyJWS()
        payload, signing_input, headers, signature = jws_api._load(token)
        claims = json.loads(payload.decode('utf-8'))
        return (headers, claims, signing_input, signature)

    @staticmethod
    def verify_claims(claims,
                      claims_to_verify,
                      audience,
                      issuer,
                      leeway=LEEWAY):
        """Verify claims are present and valid."""
        # Check if required claims are present
        # This may not be required with the `pyjwt` implementation.
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
                   'require': claims_to_verify,
                   'leeway': leeway,
                   'verify_signature': False,}
        # Validate claims
        jwt_api = jwt.api_jwt.PyJWT()
        jwt_api._validate_claims(payload=claims, options=options, audience=audience, issuer=issuer, leeway=leeway)

    @staticmethod
    def verify_signature(token, okta_jwk):
        """Verify token signature using received jwk."""
        headers, claims, signing_input, signature = JWTUtils.parse_token(token)
        parsed_jwk = jwt.PyJWK(okta_jwk)
        jws_api = jwt.api_jws.PyJWS()
        jws_api._verify_signature(signing_input=signing_input,
                              header=headers,
                              signature=signature,
                              key=parsed_jwk.key,
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
