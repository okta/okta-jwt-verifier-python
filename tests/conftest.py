import os


def is_env_set():
    """Verify if all needed env variables set for integration tests."""
    variables = ('ISSUER', 'CLIENT_ID', 'OKTA_ACCESS_TOKEN', 'OKTA_ID_TOKEN')
    for var in variables:
        if not os.environ.get(var):
            return False
    return True
