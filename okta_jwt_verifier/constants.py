import os

# Default values described in technical design

MAX_RETRIES = os.environ.get('JWT_VERIFIER_MAX_RETRIES', 1)
MAX_REQUESTS = os.environ.get('JWT_VERIFIER_MAX_REQUESTS', 10)
REQUEST_TIMEOUT = os.environ.get('JWT_VERIFIER_REQUEST_TIMEOUT', 30)
