"""
pycognito — Python wrapper for AWS Cognito User Pools.

The Cognito class is assembled via mixins so each concern lives in its own
module and maps directly to the corresponding test file:

    objects.py    ← test_objects.py   (UserObj, GroupObj)
    tokens.py     ← test_auth.py      (verify_token, check_token)
    auth.py       ← test_auth.py      (authenticate, register, passwords…)
    utils.py      ← test_utils.py     (helper functions, RequestsSrpAuth)
    user_pool.py  ← test_user_pool.py (users, groups, clients, IdPs)
    mfa.py                             (TOTP / SMS MFA)

Public surface — everything importable directly from `pycognito`:
    Cognito, UserObj, GroupObj,
    cognito_to_dict, dict_to_cognito, is_cognito_attr_list,
    camel_to_snake, snake_to_camel,
    TokenVerificationException
"""

import boto3

from .auth import AuthMixin
from .exceptions import MFAChallengeException, TokenVerificationException
from .mfa import MFAMixin
from .objects import GroupObj, UserObj
from .tokens import TokensMixin
from .user_pool import UserPoolMixin
from .utils import (
    camel_to_snake,
    cognito_to_dict,
    dict_to_cognito,
    is_cognito_attr_list,
    snake_to_camel,
)


class Cognito(TokensMixin, AuthMixin, UserPoolMixin, MFAMixin):
    """
    High-level client for AWS Cognito User Pools.

    Inherits all operations from focused mixins:
      - TokensMixin  : JWT verification and expiry checking
      - AuthMixin    : registration, authentication, password management
      - UserPoolMixin: user, group, pool-client, and identity-provider ops
      - MFAMixin     : TOTP / SMS MFA setup and challenge responses
    """

    user_class = UserObj
    group_class = GroupObj

    def __init__(
        self,
        user_pool_id,
        client_id=None,
        user_pool_region=None,
        username=None,
        id_token=None,
        refresh_token=None,
        access_token=None,
        client_secret=None,
        access_key=None,
        secret_key=None,
        session=None,
        botocore_config=None,
        boto3_client_kwargs=None,
        device_key=None,
        device_group_key=None,
        device_password=None,
        device_name=None,
    ):
        """
        :param user_pool_id: Cognito User Pool ID
        :param client_id: Cognito User Pool Application client ID
        :param user_pool_region: AWS region (inferred from user_pool_id if omitted)
        :param username: User Pool username
        :param id_token: ID Token returned by authentication
        :param refresh_token: Refresh Token returned by authentication
        :param access_token: Access Token returned by authentication
        :param client_secret: App client secret (when the client has one)
        :param access_key: AWS IAM access key
        :param secret_key: AWS IAM secret key
        :param session: Existing boto3 Session to use
        :param botocore_config: Botocore Config object for the boto3 client
        :param boto3_client_kwargs: Extra keyword args forwarded to boto3.client()
        :param device_key: Device Key for the user
        :param device_group_key: Device Group Key for the user
        :param device_password: Device Password for the user
        :param device_name: Device Name for the user
        """
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.user_pool_region = (
            user_pool_region if user_pool_region else self.user_pool_id.split("_")[0]
        )
        self.username = username
        self.id_token = id_token
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.client_secret = client_secret
        self.token_type = None
        self.id_claims = None
        self.access_claims = None
        self.custom_attributes = None
        self.base_attributes = None
        self.pool_jwk = None
        self.mfa_tokens = None
        self.device_key = device_key
        self.device_group_key = device_group_key
        self.device_password = device_password
        self.device_name = device_name

        if not boto3_client_kwargs:
            boto3_client_kwargs = {}
        if access_key and secret_key:
            boto3_client_kwargs["aws_access_key_id"] = access_key
            boto3_client_kwargs["aws_secret_access_key"] = secret_key
        self.pool_domain_url = boto3_client_kwargs.get("endpoint_url", None)

        if self.user_pool_region:
            boto3_client_kwargs["region_name"] = self.user_pool_region
        if botocore_config:
            boto3_client_kwargs["config"] = botocore_config

        if session:
            self.client = session.client("cognito-idp", **boto3_client_kwargs)
        else:
            self.client = boto3.client("cognito-idp", **boto3_client_kwargs)

        self._users_pagination_next_token = None
        self._groups_pagination_next_token = None
        self._clients_pagination_next_token = None
        self._group_users_pagination_next_token = None
        self._devices_pagination_next_token = None

    @property
    def user_pool_url(self):
        if self.pool_domain_url:
            return f"{self.pool_domain_url}/{self.user_pool_id}"
        return (
            f"https://cognito-idp.{self.user_pool_region}.amazonaws.com"
            f"/{self.user_pool_id}"
        )


__all__ = [
    "Cognito",
    "UserObj",
    "GroupObj",
    "cognito_to_dict",
    "dict_to_cognito",
    "is_cognito_attr_list",
    "camel_to_snake",
    "snake_to_camel",
    "TokenVerificationException",
    "MFAChallengeException",
]
