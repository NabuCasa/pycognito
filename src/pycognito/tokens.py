"""
TokensMixin — JWT verification and expiry checking.

Covers everything directly related to reading, verifying, and checking
the lifetime of Cognito-issued JWTs.  All methods here are tested by
the token-related cases in test_auth.py.
"""

from __future__ import annotations

import base64
import json
from os import environ

import jwt
import pendulum
import requests

from ._base import CognotoBase
from .exceptions import TokenVerificationException


class TokensMixin(CognotoBase):
    """Mixin providing JWT verification and token-expiry management."""

    # ------------------------------------------------------------------
    # JWKS retrieval
    # ------------------------------------------------------------------

    def get_keys(self):
        if self.pool_jwk:
            return self.pool_jwk

        pool_jwk_env = environ.get("COGNITO_JWKS") or {}
        if pool_jwk_env:
            self.pool_jwk = json.loads(pool_jwk_env)
        else:
            self.pool_jwk = requests.get(
                f"{self.user_pool_url}/.well-known/jwks.json", timeout=15
            ).json()
        return self.pool_jwk

    def get_key(self, kid):
        keys = self.get_keys().get("keys")
        key = list(filter(lambda x: x.get("kid") == kid, keys))
        if not key:
            raise jwt.PyJWTError(f"key with ID {kid} not found")
        return key[0]

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_tokens(self):
        """
        Verify the current id_token and access_token.  An exception will be
        thrown if they do not pass verification.  Useful after constructing a
        Cognito instance from externally-stored tokens.
        """
        self.verify_token(self.id_token, "id_token", "id")
        self.verify_token(self.access_token, "access_token", "access")

    def verify_token(self, token, id_name, token_use):
        # https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            hmac_key = jwt.api_jwk.PyJWK(self.get_key(kid)).key
            required_claims = (["aud"] if token_use != "access" else []) + [
                "iss",
                "exp",
            ]
            decoded = jwt.api_jwt.decode_complete(
                token,
                hmac_key,
                algorithms=["RS256"],
                audience=self.client_id if token_use != "access" else None,
                issuer=self.user_pool_url,
                options={
                    "require": required_claims,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as err:
            raise TokenVerificationException(
                f"Your {id_name!r} token could not be verified ({err})."
            ) from None

        verified, header = decoded["payload"], decoded["header"]

        token_use_verified = verified.get("token_use") == token_use
        if not token_use_verified:
            raise TokenVerificationException(
                f"Your {id_name!r} token use ({token_use!r}) could not be verified."
            )

        if (iat := verified.get("iat")) is not None:
            try:
                int(iat)
            except ValueError as exception:
                raise TokenVerificationException(
                    f"Your {id_name!r} token's iat claim is not a valid integer."
                ) from exception

        # Compute and verify at_hash (formerly done by python-jose)
        if "at_hash" in verified:
            alg_obj = jwt.get_algorithm_by_name(header["alg"])
            digest = alg_obj.compute_hash_digest(self.access_token)
            at_hash = (
                base64.urlsafe_b64encode(digest[: (len(digest) // 2)])
                .rstrip(b"=")
                .decode("utf-8")
            )
            if at_hash != verified["at_hash"]:
                raise TokenVerificationException(
                    "at_hash claim does not match access_token."
                )

        setattr(self, id_name, token)
        setattr(self, f"{token_use}_claims", verified)
        return verified

    # ------------------------------------------------------------------
    # Expiry check
    # ------------------------------------------------------------------

    def check_token(self, renew=True):
        """
        Checks the exp attribute of the access_token and either refreshes
        the tokens by calling renew_access_token or does nothing.
        :param renew: bool indicating whether to refresh on expiration
        :return: bool indicating whether access_token has expired
        """
        if not self.access_token:
            raise AttributeError("Access Token Required to Check Token")
        now = pendulum.now("UTC")
        dec_access_token = jwt.decode(
            self.access_token, options={"verify_signature": False}
        )
        if now > pendulum.from_timestamp(dec_access_token["exp"], tz="UTC"):
            expired = True
            if renew:
                self.renew_access_token()
        else:
            expired = False
        return expired

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def revoke_token(self, token=None):
        """
        Revoke a refresh token, invalidating all access tokens issued from it.
        Calls cognito-idp RevokeToken.  When the revoked token is this object's
        own refresh token, id_token, refresh_token, access_token, and token_type
        are cleared locally.  Revoking any other token leaves them untouched.
        :param token: Refresh token to revoke. Defaults to self.refresh_token.
        :raises AttributeError: if there is no token to revoke
        """
        if token is None:
            token = self.refresh_token
        if not token:
            raise AttributeError("Refresh Token Required to Revoke Token")
        params = {"Token": token, "ClientId": self.client_id}
        if self.client_secret is not None:
            params["ClientSecret"] = self.client_secret
        self.client.revoke_token(**params)
        if token == self.refresh_token:
            self.id_token = None
            self.refresh_token = None
            self.access_token = None
            self.token_type = None

    def admin_user_global_sign_out(self, username=None):
        """
        Admin-privilege global sign-out — invalidates all tokens for the
        specified user regardless of which client they used.
        Calls cognito-idp AdminUserGlobalSignOut.
        :param username: Username to sign out. Defaults to self.username.
        """
        if username is None:
            username = self.username
        self.client.admin_user_global_sign_out(
            UserPoolId=self.user_pool_id,
            Username=username,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _set_tokens(self, tokens):
        """
        Verify and set token attributes from a Cognito AuthenticationResult dict.
        """
        self.verify_token(
            tokens["AuthenticationResult"]["AccessToken"], "access_token", "access"
        )
        self.verify_token(tokens["AuthenticationResult"]["IdToken"], "id_token", "id")
        if "RefreshToken" in tokens["AuthenticationResult"]:
            self.refresh_token = tokens["AuthenticationResult"]["RefreshToken"]
        self.token_type = tokens["AuthenticationResult"]["TokenType"]

        if "NewDeviceMetadata" in tokens["AuthenticationResult"]:
            device_metadata = tokens["AuthenticationResult"]["NewDeviceMetadata"]
            self.device_key = device_metadata.get("DeviceKey")
            self.device_group_key = device_metadata.get("DeviceGroupKey")
