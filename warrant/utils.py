from enum import Enum

import requests.auth
import requests

from . import Cognito


class SrpRequestsHTTPAuth(requests.auth.AuthBase):
    """
    A Requests Auth Plugin to automatically populate Authorization header
    with a Cognito token.

    """

    class token_type(str, Enum):
        ID_TOKEN = 'id_token'
        ACCESS_TOKEN = 'access_token'

    def __init__(self,
                 username: str = None,
                 password: str = None,
                 user_pool_id: str = None,
                 user_pool_region: str = None,
                 client_id: str = None,
                 cognito: Cognito = None,
                 http_header: str = 'Authorization',
                 http_header_prefix: str = 'Bearer ',
                 auth_token_type: token_type = token_type.ID_TOKEN
                 ) -> object:

        if cognito:
            self.cognito_client = cognito
        else:
            self.cognito_client = Cognito(
                user_pool_id=user_pool_id,
                client_id=client_id,
                user_pool_region=user_pool_region,
                username=username,
            )

        self.username = username
        self.__password = password
        self.http_header = http_header
        self.http_header_prefix = http_header_prefix
        self.token_type = auth_token_type

    def __call__(self, r: requests.Request):
        # If this is the first time in, we'll need to auth
        if not self.cognito_client.access_token:
            self.cognito_client.authenticate(password=self.__password)

        # Checks if token is expired and fetches a new token if available
        self.cognito_client.check_token(renew=True)

        token = getattr(self.cognito_client, self.token_type.value)

        r.headers[self.http_header] = self.http_header_prefix + token

        return r