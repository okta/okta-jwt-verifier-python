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

import os


# Default values described in technical design

MAX_RETRIES = os.environ.get('JWT_VERIFIER_MAX_RETRIES', 1)
MAX_REQUESTS = os.environ.get('JWT_VERIFIER_MAX_REQUESTS', 10)
REQUEST_TIMEOUT = os.environ.get('JWT_VERIFIER_REQUEST_TIMEOUT', 30)
LEEWAY = os.environ.get('LEEWAY', 120)


# Constant URLs used in error messages

DEV_OKTA = "https://developer.okta.com"
FINDING_OKTA_DOMAIN = (f"{DEV_OKTA}"
                       "/docs/guides/find-your-domain/overview")
GET_OKTA_API_TOKEN = (f"{DEV_OKTA}"
                      "/docs/guides/create-an-api-token/overview")
FINDING_OKTA_APP_CRED = (f"{DEV_OKTA}"
                         "/docs/guides/find-your-app-credentials/overview")


# Misc
ADMIN_DOMAINS = ('-admin.okta.com', '-admin.oktapreview.com', '-admin.okta-emea.com')
