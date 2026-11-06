"""
Shared test utilities used across multiple test modules.
"""

from src.pycognito import TokenVerificationException

# Reused by every @moto.mock_aws test class that creates a user pool client.
TOKEN_VALIDITY_PARAMS = {
    "RefreshTokenValidity": 1,
    "AccessTokenValidity": 1,
    "IdTokenValidity": 1,
    "TokenValidityUnits": {
        "AccessToken": "hours",
        "IdToken": "hours",
        "RefreshToken": "days",
    },
}


def mock_authenticate_user(_, client=None, client_metadata=None):
    return {
        "AuthenticationResult": {
            "TokenType": "admin",
            "IdToken": "dummy_token",
            "AccessToken": "dummy_token",
            "RefreshToken": "dummy_token",
        }
    }


def mock_authenticate_user_device_metadata(_, client=None, client_metadata=None):
    return {
        "AuthenticationResult": {
            "TokenType": "admin",
            "IdToken": "dummy_token",
            "AccessToken": "dummy_token",
            "RefreshToken": "dummy_token",
            "NewDeviceMetadata": {
                "DeviceKey": "us-east-1_de20abce",
                "DeviceGroupKey": "device_group_key",
            },
        }
    }


def mock_get_params(_):
    return {"USERNAME": "bob", "SRP_A": "srp"}


def mock_verify_tokens(self, token, id_name, token_use):
    if "wrong" in token:
        raise TokenVerificationException
    setattr(self, id_name, token)
