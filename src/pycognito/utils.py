"""
Stateless helper functions for converting between Python dicts and the
Cognito attribute-list format, plus case-conversion utilities.

Also contains RequestsSrpAuth — the requests auth plugin backed by SRP.
"""

import ast
import re
from typing import Optional

import requests
from requests.auth import AuthBase

# ---------------------------------------------------------------------------
# Attribute conversion
# ---------------------------------------------------------------------------


def cognito_to_dict(attr_list, attr_map=None):
    """Convert a Cognito attribute list to a plain dict."""
    if attr_map is None:
        attr_map = {}
    attr_dict = {}
    for attr in attr_list:
        name = attr.get("Name")
        value = attr.get("Value")
        if value in ["true", "false"]:
            value = ast.literal_eval(value.capitalize())
        name = attr_map.get(name, name)
        attr_dict[name] = value
    return attr_dict


def is_cognito_attr_list(attr_list):
    """
    :param attr_list: List of User Pool attribute dicts
    :return: bool indicating whether the list contains valid User Pool attribute dicts
    """
    if not isinstance(attr_list, list):
        return False
    for attr_dict in attr_list:
        if not isinstance(attr_dict, dict):
            return False
        if not attr_dict.keys() <= {"Name", "Value"}:
            return False
    return True


def dict_to_cognito(attributes, attr_map=None):
    """
    :param attributes: Dictionary of User Pool attribute names/values
    :param attr_map: Optional mapping from local names to Cognito attribute names
    :return: list of User Pool attribute formatted dicts: {'Name': <attr_name>, 'Value': <attr_value>}
    """
    if attr_map is None:
        attr_map = {}
    for key, value in attr_map.items():
        if value in attributes.keys():
            attributes[key] = attributes.pop(value)

    def normalize(val):
        if isinstance(val, bool):
            return "true" if val else "false"
        return val

    return [
        {"Name": key, "Value": normalize(value)} for key, value in attributes.items()
    ]


# ---------------------------------------------------------------------------
# Case conversion
# ---------------------------------------------------------------------------


def camel_to_snake(camel_str):
    """
    :param camel_str: string
    :return: string converted from CamelCase to snake_case
    """
    return re.sub(
        "([a-z0-9])([A-Z])", r"\1_\2", re.sub("(.)([A-Z][a-z]+)", r"\1_\2", camel_str)
    ).lower()


def snake_to_camel(snake_str):
    """
    :param snake_str: string
    :return: string converted from snake_case to camelCase
    """
    components = snake_str.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


# ---------------------------------------------------------------------------
# Requests auth plugin
# ---------------------------------------------------------------------------


class RequestsSrpAuth(AuthBase):
    """
    Requests authentication plugin that transparently authenticates via
    Cognito SRP and refreshes the access token when it expires.
    """

    def __init__(
        self,
        username: str,
        password: str,
        user_pool_id: str,
        client_id: str,
        user_pool_region: Optional[str] = None,
        client_secret: Optional[str] = None,
        boto3_client_kwargs=None,
        device_key: str = None,
        device_group_key: str = None,
        device_password: str = None,
        device_name: str = None,
    ):
        # Import here to avoid a circular import — Cognito lives in __init__
        from . import Cognito  # noqa

        self.cognito_client = Cognito(
            user_pool_id=user_pool_id,
            client_id=client_id,
            user_pool_region=user_pool_region,
            username=username,
            client_secret=client_secret,
            boto3_client_kwargs=boto3_client_kwargs,
            device_key=device_key,
            device_group_key=device_group_key,
            device_password=device_password,
            device_name=device_name,
        )
        self.cognito_client.authenticate(password=password)

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        if self.cognito_client.check_token():
            # check_token already called renew_access_token internally
            pass
        r.headers["Authorization"] = self.cognito_client.access_token
        return r
