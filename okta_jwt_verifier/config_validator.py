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
        self.validate_issuer()
        self.validate_client_id()
        self.validate_audience()
        self.validate_numbers()

    def validate_issuer(self, issuer=None, https_check=True):
        """Validates issuer."""
        issuer = issuer or self.config.get('issuer')
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

    def validate_client_id(self, client_id=None):
        """Validates client_id."""
        client_id = client_id or self.config.get('client_id')
        if not client_id:
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_MISSING)
        if not isinstance(client_id, str):
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE)
        if '{clientId}' in client_id:
            raise JWTInvalidConfigException(ERROR_MESSAGE_CLIENT_ID_DEFAULT)

    def validate_audience(self, audience=None):
        """Validates audience."""
        audience = audience or self.config.get('audience')
        if not audience:
            raise JWTInvalidConfigException(ERROR_MESSAGE_AUDIENCE_MISSING)

    def _validate_number(self, number, variable_name):
        """Validates param which should be represented as integer and >= 0"""
        if not isinstance(number, int):
            raise JWTInvalidConfigException(f'{variable_name} should be type of int.')
        if number < 0:
            raise JWTInvalidConfigException(f'Value of {variable_name} should be 0 or greater.')

    def validate_numbers(self, numbers=('max_retries',
                                        'max_requests',
                                        'request_timeout',
                                        'leeway')):
        """Validates all number parameters."""
        for number_variable in numbers:
            self._validate_number(self.config.get(number_variable), number_variable)
