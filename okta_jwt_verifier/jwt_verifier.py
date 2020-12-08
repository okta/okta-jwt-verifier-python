from jose import jwt


class JWTVerifier():

    def __init__(self, issuer, client_id, audience):
        self.issuer = issuer
        self.client_id = client_id
        self.audience = audience

    def verify_access_token(self, token):
        """
        Algorithm:
        1. Retrieve and parse your Okta JSON Web Keys (JWK),
           which should be checked periodically and cached by your application.
        2. Decode the access token, which is in JSON Web Token format
        3. Verify the signature used to sign the access token
        4. Verify the claims found inside the access token

        Claims:
        ‘exp’ Expiration - The time after which the token is invalid.
        ‘nbf’ Not Before - The time before which the token is invalid.
        ‘iss’ Issuer     - The principal that issued the JWT.
        ‘aud’ Audience   - The recipient that the JWT is intended for.
        ‘iat’ Issued At  - The time at which the JWT was issued.
        """

        # TODO: implement all needed methods, check out for correct algorithm
        # headers = jwt.get_unverified_headers(token)
        claims = jwt.get_unverified_claims(token)
        okta_jwk = self.get_jwk(claims)
        self.decode_token(token, okta_jwk)

    def verify_claims(self):
        pass

    def verify_signature(self):
        pass

    def verify_expiration(self):
        pass

    def get_jwk(self, claims):
        """
        Get jwks_uri from claims and download jwk.
        """
        pass

    def decode_token(self, token, okta_jwk):
        pass
