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

from .constants import FINDING_OKTA_APP_CRED, FINDING_OKTA_DOMAIN

ERROR_MESSAGE_ORG_URL_WRONG_TYPE = ("Your Okta URL should be type of str.")

ERROR_MESSAGE_ORG_URL_MISSING = (
    "Your Okta URL is missing. You can copy "
    "your domain from the Okta Developer "
    "Console. Follow these instructions to"
    f" find it: {FINDING_OKTA_DOMAIN}"
)
ERROR_MESSAGE_ORG_URL_NOT_HTTPS = (
    "Your Okta URL must start with 'https'."
)
ERROR_MESSAGE_AUTH_MODE_INVALID = (
    "The AuthorizationMode configuration "
    "option must be one of: "
    "[SSWS, PrivateKey]. "
    "You provided the SDK with "
)
ERROR_MESSAGE_ORG_URL_YOUROKTADOMAIN = (
    "Replace {{yourOktaDomain}} with your Okta domain. "
    "You can copy your domain from the Okta Developer Console. "
    "Follow these instructions to find it: "
    f"{FINDING_OKTA_DOMAIN}"
)

ERROR_MESSAGE_ORG_URL_ADMIN = (
    "Your Okta domain should not contain -admin. "
)

ERROR_MESSAGE_ORG_URL_TYPO = (
    "It looks like there's a typo in your Okta domain."
)

ERROR_MESSAGE_CLIENT_ID_WRONG_TYPE = ("Your client ID should be type of str.")

ERROR_MESSAGE_CLIENT_ID_MISSING = (
    "Your client ID is missing. You can copy it from the "
    "Okta Developer Console in the details for the Application "
    "you created. Follow these instructions to find it: "
    f"{FINDING_OKTA_APP_CRED}"
)

ERROR_MESSAGE_CLIENT_ID_DEFAULT = (
    "Replace {{clientId}} with the client ID of your Application. "
    "You can copy it from the Okta Developer Console in the "
    "details for the Application you created. Follow these "
    f"instructions to find it: {FINDING_OKTA_APP_CRED}"
)

ERROR_MESSAGE_AUDIENCE_MISSING = ("Audience is missing.")
