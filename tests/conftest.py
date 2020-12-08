import os


def is_env_set():
    """Verify if all needed env variables set for integration tests."""
    variables = ('ISSUER', 'CLIENT_ID', 'OKTA_JWT')
    for var in variables:
        if not os.environ.get(var):
            return False
    return True
