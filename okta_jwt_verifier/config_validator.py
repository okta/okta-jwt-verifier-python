from .constants import ADMIN_DOMAINS
from .error_messages import (ERROR_MESSAGE_ORG_URL_MISSING,
                             ERROR_MESSAGE_ORG_URL_NOT_HTTPS,
                             ERROR_MESSAGE_ORG_URL_YOUROKTADOMAIN,
                             ERROR_MESSAGE_ORG_URL_ADMIN,
                             ERROR_MESSAGE_ORG_URL_TYPO,
                             ERROR_MESSAGE_ORG_URL_WRONG_TYPE,
                             ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE,
                             ERROR_MESSAGE_CLIENT_ID_MISSING,
                             ERROR_MESSAGE_CLIENT_ID_DEFAULT,
                             ERROR_MESSAGE_AUDIENCE_MISSING)
from .exceptions import JWTInvalidConfigException


class ConfigValidator():

    """Class designed for JWT Verifier config validation."""

    def __init__(self, config):
        self.config = config

    def validate_config(self):
        """Main method, validates whole config."""
        self.validate_issuer(self.config.get('issuer'))
        self.validate_client_id(self.config.get('client_id'))
        self.validate_audience(self.config.get('audience'))
        numbers = ('max_retries', 'max_requests', 'request_timeout', 'leeway')
        for number_variable in numbers:
            self.validate_number(self.config.get(number_variable), number_variable)

    def validate_issuer(self, issuer, https_check=True):
        if not issuer:
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_MISSING)
        if not isinstance(issuer, str):
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_WRONG_TYPE)
        if https_check and not issuer.startswith('https://'):
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_NOT_HTTPS)
        if '{yourOktaDomain}' in issuer:
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_YOUROKTADOMAIN)
        if any(domain in issuer for domain in ADMIN_DOMAINS):
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_ADMIN)
        if '.com.com' in issuer:
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_TYPO)
        if issuer.count('://') > 1:
            raise JWTInvalidConfigException(ERROR_MESSAGE_ORG_URL_TYPO)

    def validate_client_id(self, client_id):
        if not client_id:
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_MISSING)
        if not isinstance(client_id, str):
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE)
        if '{clientId}' in client_id:
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_DEFAULT)

    def validate_audience(self, audience):
        if not audience:
            raise JWTInvalidConfigException(ERROR_MESSAGE_AUDIENCE_MISSING)

    def validate_number(self, number, variable_name):
        if not isinstance(number, int):
            raise JWTInvalidConfigException(f'{variable_name} should be type of int.')
        if number < 0:
            raise JWTInvalidConfigException(f'Value of {variable_name} should be 0 or greater.')
