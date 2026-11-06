"""
AuthMixin — registration, authentication, password management, and sign-out.

All methods here are exercised by CognitoAuthTestCase and AWSSRPTestCase
in test_auth.py.
"""

from __future__ import annotations

from ._base import CognotoBase
from .aws_srp import AWSSRP
from .exceptions import MFAChallengeException
from .utils import dict_to_cognito


class AuthMixin(CognotoBase):
    """Mixin providing user registration, authentication, and password operations."""

    # ------------------------------------------------------------------
    # Attribute staging (called before register/admin_create_user)
    # ------------------------------------------------------------------

    def set_base_attributes(self, **kwargs):
        self.base_attributes = kwargs

    def add_custom_attributes(self, **kwargs):
        custom_key = "custom"
        custom_attributes = {}
        for old_key, value in kwargs.items():
            new_key = custom_key + ":" + old_key
            custom_attributes[new_key] = value
        self.custom_attributes = custom_attributes

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, username, password, attr_map=None, client_metadata=None):
        """
        Register the user. Standard Cognito base attributes include: address,
        birthdate, email, family_name, gender, given_name, locale, middle_name,
        name, nickname, phone_number, picture, preferred_username, profile,
        zoneinfo, updated_at, website.

        :param username: User Pool username
        :param password: User Pool password
        :param attr_map: Attribute map to Cognito's attributes
        :param client_metadata: Metadata forwarded to ClientMetadata in the request
        :return response: Cognito sign_up response (ResponseMetadata stripped)
        """
        if self.base_attributes is None:
            attributes = {}
        else:
            attributes = self.base_attributes.copy()
        if self.custom_attributes:
            attributes.update(self.custom_attributes)

        cognito_attributes = dict_to_cognito(attributes, attr_map)
        params = {
            "ClientId": self.client_id,
            "Username": username,
            "Password": password,
            "UserAttributes": cognito_attributes,
        }
        if client_metadata is not None:
            params["ClientMetadata"] = client_metadata
        self._add_secret_hash(params, "SecretHash", username)
        response = self.client.sign_up(**params)

        attributes.update(username=username, password=password)
        self._set_attributes(response, attributes)

        response.pop("ResponseMetadata")
        return response

    def admin_confirm_sign_up(self, username=None):
        """
        Confirm user registration as an admin without a confirmation code.
        :param username: User's username (defaults to self.username)
        """
        if not username:
            username = self.username
        self.client.admin_confirm_sign_up(
            UserPoolId=self.user_pool_id,
            Username=username,
        )

    def confirm_sign_up(self, confirmation_code, username=None):
        """
        Confirm sign-up using the code sent via email or SMS.
        :param confirmation_code: Confirmation code sent via text or email
        :param username: User's username (defaults to self.username)
        """
        if not username:
            username = self.username
        params = {
            "ClientId": self.client_id,
            "Username": username,
            "ConfirmationCode": confirmation_code,
        }
        self._add_secret_hash(params, "SecretHash", username)
        self.client.confirm_sign_up(**params)

    def resend_confirmation_code(self, username):
        """
        Trigger resending the confirmation code message.
        :param username: User's username
        """
        params = {
            "ClientId": self.client_id,
            "Username": username,
        }
        self._add_secret_hash(params, "SecretHash", username)
        self.client.resend_confirmation_code(**params)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def admin_authenticate(self, password):
        """
        Authenticate using admin super privileges (ADMIN_USER_PASSWORD_AUTH flow).
        The app client must allow ALLOW_ADMIN_USER_PASSWORD_AUTH.
        :param password: User's password
        """
        auth_params = {"USERNAME": self.username, "PASSWORD": password}
        self._add_secret_hash(auth_params, "SECRET_HASH")
        tokens = self.client.admin_initiate_auth(
            UserPoolId=self.user_pool_id,
            ClientId=self.client_id,
            # AuthFlow takes an AuthFlowType (ADMIN_USER_PASSWORD_AUTH), not
            # one of the client's ExplicitAuthFlows (ALLOW_ADMIN_USER_PASSWORD_AUTH)
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters=auth_params,
        )
        self._set_tokens(tokens)

    def authenticate(self, password, client_metadata=None):
        """
        Authenticate using the SRP protocol.
        :param password: The user's password
        :param client_metadata: Metadata for custom RespondToAuthChallenge workflows
        """
        aws = AWSSRP(
            username=self.username,
            password=password,
            pool_id=self.user_pool_id,
            client_id=self.client_id,
            client=self.client,
            client_secret=self.client_secret,
            device_key=self.device_key,
            device_group_key=self.device_group_key,
            device_password=self.device_password,
            device_name=self.device_name,
        )
        try:
            tokens = aws.authenticate_user(client_metadata=client_metadata)
        except MFAChallengeException as mfa_challenge:
            self.mfa_tokens = mfa_challenge.get_tokens()
            raise mfa_challenge

        self._set_tokens(tokens)

        # Only confirm the device when NewDeviceMetadata is present in the response.
        # If device_key was already provided by the caller (a previously confirmed device)
        # and the response does not include NewDeviceMetadata, no confirmation is needed.
        if (
            self.device_key is not None
            and "NewDeviceMetadata" in tokens["AuthenticationResult"]
        ):
            _, self.device_password = aws.confirm_device(
                tokens=tokens, device_name=self.device_name
            )

    def new_password_challenge(self, password, new_password):
        """
        Respond to a NEW_PASSWORD_REQUIRED challenge using the SRP protocol.
        :param password: The user's current password
        :param new_password: The user's desired new password
        """
        aws = AWSSRP(
            username=self.username,
            password=password,
            pool_id=self.user_pool_id,
            client_id=self.client_id,
            client=self.client,
            client_secret=self.client_secret,
            device_key=self.device_key,
        )
        tokens = aws.set_new_password_challenge(new_password)
        self._set_tokens(tokens)

    # ------------------------------------------------------------------
    # Token refresh and sign-out
    # ------------------------------------------------------------------

    def logout(self):
        """
        Global sign-out: invalidates all issued tokens for this user.
        Clears id_token, refresh_token, access_token, and token_type locally.
        """
        self.client.global_sign_out(AccessToken=self.access_token)
        self.id_token = None
        self.refresh_token = None
        self.access_token = None
        self.token_type = None

    def renew_access_token(self):
        """
        Sets a new access token using the cached refresh token.
        """
        auth_params = {"REFRESH_TOKEN": self.refresh_token}
        self._add_secret_hash(auth_params, "SECRET_HASH")

        if self.device_key is not None:
            auth_params["DEVICE_KEY"] = self.device_key

        refresh_response = self.client.initiate_auth(
            ClientId=self.client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=auth_params,
        )
        self._set_tokens(refresh_response)

    # ------------------------------------------------------------------
    # Password management
    # ------------------------------------------------------------------

    def initiate_forgot_password(self):
        """Send a verification code to the user to reset their password."""
        params = {"ClientId": self.client_id, "Username": self.username}
        self._add_secret_hash(params, "SecretHash")
        self.client.forgot_password(**params)

    def confirm_forgot_password(self, confirmation_code, password):
        """
        Submit a verification code and choose a new password.
        :param confirmation_code: The code sent by initiate_forgot_password
        :param password: New password
        """
        params = {
            "ClientId": self.client_id,
            "Username": self.username,
            "ConfirmationCode": confirmation_code,
            "Password": password,
        }
        self._add_secret_hash(params, "SecretHash")
        response = self.client.confirm_forgot_password(**params)
        self._set_attributes(response, {"password": password})

    def change_password(self, previous_password, proposed_password):
        """Change the authenticated user's password."""
        self.check_token()
        response = self.client.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=self.access_token,
        )
        self._set_attributes(response, {"password": proposed_password})

    def admin_reset_password(self, username, client_metadata=None):
        """
        Trigger an admin-initiated password reset for the specified user.
        :param username: The user to reset
        :param client_metadata: Optional metadata forwarded to Lambda triggers
        """
        if client_metadata is None:
            client_metadata = {}
        self.client.admin_reset_user_password(
            UserPoolId=self.user_pool_id,
            Username=username,
            ClientMetadata=client_metadata,
        )

    # ------------------------------------------------------------------
    # Attribute verification
    # ------------------------------------------------------------------

    def send_verification(self, attribute="email"):
        """
        Send a verification code for the specified user attribute.
        :param attribute: Attribute name to verify (default: "email")
        """
        self.check_token()
        self.client.get_user_attribute_verification_code(
            AccessToken=self.access_token, AttributeName=attribute
        )

    def validate_verification(self, confirmation_code, attribute="email"):
        """
        Verify a user attribute using a confirmation code.
        :param confirmation_code: Code sent by send_verification
        :param attribute: Attribute name to verify (default: "email")
        """
        self.check_token()
        return self.client.verify_user_attribute(
            AccessToken=self.access_token,
            AttributeName=attribute,
            Code=confirmation_code,
        )

    # ------------------------------------------------------------------
    # User deletion
    # ------------------------------------------------------------------

    def delete_user(self):
        """Delete the currently authenticated user."""
        self.client.delete_user(AccessToken=self.access_token)

    def admin_delete_user(self):
        """Delete the user using admin super privileges."""
        self.client.admin_delete_user(
            UserPoolId=self.user_pool_id, Username=self.username
        )

    # ------------------------------------------------------------------
    # Admin token refresh
    # ------------------------------------------------------------------

    def admin_renew_access_token(self):
        """
        Admin-privilege equivalent of renew_access_token.
        Uses admin_initiate_auth with REFRESH_TOKEN_AUTH flow so that
        server-side auth can refresh tokens without user interaction.
        Requires the instance to already hold a valid refresh_token.
        """
        auth_params = {"REFRESH_TOKEN": self.refresh_token}
        self._add_secret_hash(auth_params, "SECRET_HASH")
        refresh_response = self.client.admin_initiate_auth(
            UserPoolId=self.user_pool_id,
            ClientId=self.client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=auth_params,
        )
        self._set_tokens(refresh_response)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_secret_hash(self, parameters, key, username=None):
        """
        Compute SecretHash and add it to a parameters dict at the given key.
        No-op when client_secret is not configured.
        :param username: Username the request is for (defaults to self.username).
            The hash must be computed from the same username sent to Cognito.
        """
        if self.client_secret is not None:
            secret_hash = AWSSRP.get_secret_hash(
                username or self.username, self.client_id, self.client_secret
            )
            parameters[key] = secret_hash

    def _set_attributes(self, response, attribute_dict):
        """
        Set instance attributes from a dict when the HTTP response was 200.
        :param response: boto3 response dict (must contain ResponseMetadata)
        :param attribute_dict: {attr_name: value} pairs to set on self
        """
        status_code = response.get(
            "HTTPStatusCode", response["ResponseMetadata"]["HTTPStatusCode"]
        )
        if status_code == 200:
            for key, value in attribute_dict.items():
                setattr(self, key, value)
