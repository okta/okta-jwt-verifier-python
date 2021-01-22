class OktaJWTBaseException(Exception):
    pass


class JWKException(OktaJWTBaseException):
    pass


class JWTValidationException(OktaJWTBaseException):
    pass


class JWTInvalidConfigException(OktaJWTBaseException):
    pass
