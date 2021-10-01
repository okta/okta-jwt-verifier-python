import copy
import pytest

from okta_jwt_verifier import BaseJWTVerifier
from okta_jwt_verifier.config_validator import ConfigValidator
from okta_jwt_verifier.exceptions import JWTInvalidConfigException
from okta_jwt_verifier.error_messages import (ERROR_MESSAGE_ORG_URL_MISSING,
                                              ERROR_MESSAGE_ORG_URL_NOT_HTTPS,
                                              ERROR_MESSAGE_ORG_URL_YOUROKTADOMAIN,
                                              ERROR_MESSAGE_ORG_URL_ADMIN,
                                              ERROR_MESSAGE_ORG_URL_TYPO,
                                              ERROR_MESSAGE_ORG_URL_WRONG_TYPE,
                                              ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE,
                                              ERROR_MESSAGE_CLIENT_ID_MISSING,
                                              ERROR_MESSAGE_CLIENT_ID_DEFAULT,
                                              ERROR_MESSAGE_AUDIENCE_MISSING)


BASIC_CONFIG = {'issuer': 'https://test_issuer.com',
                'client_id': 'test_client_id',
                'audience': 'api://default',
                'max_retries': 1,
                'request_timeout': 300,
                'max_requests': 10,
                'leeway': 120,
                'cache_jwks': True}


def test_jwt_verifier_init():
    # should not raise an error
    BaseJWTVerifier('https://test_issuer.com', 'test_client_id')

    # should raise an error
    with pytest.raises(JWTInvalidConfigException):
        BaseJWTVerifier('test_issuer.com', 'test_client_id')


def test_validate_issuer():
    config = copy.deepcopy(BASIC_CONFIG)
    ConfigValidator(config).validate_config()

    config['issuer'] = None
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_MISSING)

    config['issuer'] = ('https://test_issuer.com',)
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_WRONG_TYPE)

    config['issuer'] = 'test_issuer.com'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_NOT_HTTPS)

    config['issuer'] = 'https://{yourOktaDomain}.okta.com'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_YOUROKTADOMAIN)

    config['issuer'] = 'https://test_issuer-admin.okta.com'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_ADMIN)

    config['issuer'] = 'https://://test_issuer.com'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_TYPO)

    config['issuer'] = 'https://test_issuer.com.com'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_ORG_URL_TYPO)


def test_validate_client_id():
    config = copy.deepcopy(BASIC_CONFIG)
    ConfigValidator(config).validate_config()

    config['client_id'] = None
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_CLIENT_ID_MISSING)

    config['client_id'] = ('test_client_id',)
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE)

    config['client_id'] = '{clientId}'
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_CLIENT_ID_DEFAULT)


def test_validate_audience():
    config = copy.deepcopy(BASIC_CONFIG)
    ConfigValidator(config).validate_config()

    config['audience'] = None
    with pytest.raises(JWTInvalidConfigException) as exc_info:
        ConfigValidator(config).validate_config()
    exc_info.match(ERROR_MESSAGE_AUDIENCE_MISSING)


def test_validate_numbers():
    config = copy.deepcopy(BASIC_CONFIG)
    ConfigValidator(config).validate_config()

    config['max_retries'] = '1'
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config['max_retries'] = -1
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config = copy.deepcopy(BASIC_CONFIG)
    config['max_requests'] = '1'
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config['max_requests'] = -1
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config = copy.deepcopy(BASIC_CONFIG)
    config['request_timeout'] = '1'
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config['request_timeout'] = -1
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config = copy.deepcopy(BASIC_CONFIG)
    config['leeway'] = '1'
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()

    config['leeway'] = -1
    with pytest.raises(JWTInvalidConfigException):
        ConfigValidator(config).validate_config()
