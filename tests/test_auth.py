import base64
import json
import os
import unittest
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError, ParamValidationError
from botocore.stub import Stubber
import moto
import pendulum

from src.pycognito import Cognito, TokenVerificationException
from src.pycognito.aws_srp import AWSSRP

from .helpers import (
    TOKEN_VALIDITY_PARAMS,
    mock_authenticate_user,
    mock_authenticate_user_device_metadata,
    mock_get_params,
    mock_verify_tokens,
)


class CognitoAuthTestCase(unittest.TestCase):
    def setUp(self):
        if os.environ.get("USE_CLIENT_SECRET") == "True":
            self.app_id = os.environ.get("COGNITO_APP_WITH_SECRET_ID", "app")
            self.client_secret = os.environ.get("COGNITO_CLIENT_SECRET")
        else:
            self.app_id = os.environ.get("COGNITO_APP_ID", "app")
            self.client_secret = None
        self.cognito_user_pool_id = os.environ.get(
            "COGNITO_USER_POOL_ID", "us-east-1_123456789"
        )
        self.username = os.environ.get("COGNITO_TEST_USERNAME", "bob")
        self.password = os.environ.get("COGNITO_TEST_PASSWORD", "bobpassword")
        self.user = Cognito(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username,
            client_secret=self.client_secret,
        )

    @patch("src.pycognito.aws_srp.AWSSRP.authenticate_user", mock_authenticate_user)
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_authenticate(self):
        self.user.authenticate(self.password)
        self.assertNotEqual(self.user.access_token, None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)

    @patch("src.pycognito.aws_srp.AWSSRP.authenticate_user", mock_authenticate_user)
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_verify_token(self):
        self.user.authenticate(self.password)
        bad_access_token = "{}wrong".format(self.user.access_token)
        with self.assertRaises(TokenVerificationException):
            self.user.verify_token(bad_access_token, "access_token", "access")

    def test_verify_token_unknown_kid(self):
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "kid": "missing-kid"}).encode()
        ).rstrip(b"=")
        token = header.decode() + ".e30.c2ln"
        self.user.pool_jwk = {"keys": [{"kid": "some-other-kid"}]}
        with self.assertRaisesRegex(
            TokenVerificationException, "key with ID missing-kid not found"
        ):
            self.user.verify_token(token, "access_token", "access")

    @patch("src.pycognito.Cognito", autospec=True)
    def test_register(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id, self.app_id, username=self.username
        )
        base_attr = dict(
            given_name="Brian",
            family_name="Jones",
            name="Brian Jones",
            email="bjones39@capless.io",
            phone_number="+19194894555",
            gender="Male",
            preferred_username="billyocean",
        )
        user.set_base_attributes(**base_attr)
        user.register("sampleuser", "sample4#Password")

    @patch("src.pycognito.aws_srp.AWSSRP.authenticate_user", mock_authenticate_user)
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    @patch("src.pycognito.Cognito._add_secret_hash", return_value=None)
    def test_renew_tokens(self, _):
        stub = Stubber(self.user.client)
        stub.add_response(
            method="initiate_auth",
            service_response={
                "AuthenticationResult": {
                    "TokenType": "admin",
                    "IdToken": "dummy_token",
                    "AccessToken": "dummy_token",
                    "RefreshToken": "dummy_token",
                },
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
            expected_params={
                "ClientId": self.app_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": "dummy_token"},
            },
        )
        with stub:
            self.user.authenticate(self.password)
            self.user.renew_access_token()
            stub.assert_no_pending_responses()

    @patch("src.pycognito.Cognito", autospec=True)
    def test_update_profile(self, cognito_user):
        user = cognito_user(
            self.cognito_user_pool_id, self.app_id, username=self.username
        )
        user.authenticate(self.password)
        user.update_profile({"given_name": "Jenkins"})

    def test_admin_get_user(self):
        stub = Stubber(self.user.client)
        stub.add_response(
            method="admin_get_user",
            service_response={
                "Enabled": True,
                "UserStatus": "CONFIRMED",
                "Username": self.username,
                "UserAttributes": [],
            },
            expected_params={
                "UserPoolId": self.cognito_user_pool_id,
                "Username": self.username,
            },
        )
        with stub:
            u = self.user.admin_get_user()
            self.assertEqual(u.username, self.username)
            stub.assert_no_pending_responses()

    def test_check_token(self):
        self.user.access_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG"
            "9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjMyNTAzNjgwMDAwfQ.C-1gPxrhUsiWeCvMvaZuuQYarkDNAc"
            "pEGJPIqu_SrKQ"
        )
        try:
            valid = self.user.check_token()
        except OverflowError:
            self.skipTest("This test requires 64-bit time_t")
        else:
            self.assertFalse(valid)

    def test_check_token_uses_utc(self):
        """
        Regression: check_token must compare against UTC, not local time.
        """

        def _b64(data):
            return (
                base64.urlsafe_b64encode(json.dumps(data).encode())
                .rstrip(b"=")
                .decode()
            )

        exp_ts = int(pendulum.datetime(2024, 6, 1, 12, 0, 0, tz="UTC").timestamp())
        token = (
            f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}"
            f".{_b64({'exp': exp_ts, 'sub': 'test'})}"
            f".fakesig"
        )
        self.user.access_token = token

        one_before = pendulum.datetime(2024, 6, 1, 11, 59, 59, tz="UTC")
        with patch("pendulum.now", return_value=one_before):
            self.assertFalse(self.user.check_token(renew=False))

        one_after = pendulum.datetime(2024, 6, 1, 12, 0, 1, tz="UTC")
        with patch("pendulum.now", return_value=one_after):
            self.assertTrue(self.user.check_token(renew=False))

    @patch("src.pycognito.Cognito", autospec=True)
    def test_validate_verification(self, cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id, username=self.username)
        u.validate_verification("4321")

    @patch("src.pycognito.Cognito", autospec=True)
    def test_confirm_forgot_password(self, cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id, username=self.username)
        u.confirm_forgot_password("4553", "samplepassword")
        with self.assertRaises(TypeError):
            u.confirm_forgot_password(self.password)

    @patch("src.pycognito.aws_srp.AWSSRP.authenticate_user", mock_authenticate_user)
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    @patch("src.pycognito.Cognito.check_token", return_value=True)
    def test_change_password(self, _):
        self.user.authenticate(self.password)
        stub = Stubber(self.user.client)
        stub.add_response(
            method="change_password",
            service_response={"ResponseMetadata": {"HTTPStatusCode": 200}},
            expected_params={
                "PreviousPassword": self.password,
                "ProposedPassword": "crazypassword$45DOG",
                "AccessToken": self.user.access_token,
            },
        )
        with stub:
            self.user.change_password(self.password, "crazypassword$45DOG")
            stub.assert_no_pending_responses()

        with self.assertRaises(ParamValidationError):
            self.user.change_password(self.password, None)

    def test_set_attributes(self):
        user = Cognito(self.cognito_user_pool_id, self.app_id)
        user._set_attributes(
            {"ResponseMetadata": {"HTTPStatusCode": 200}}, {"somerandom": "attribute"}
        )
        self.assertEqual(user.somerandom, "attribute")

    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_admin_authenticate(self):
        """admin_authenticate must use ALLOW_ADMIN_USER_PASSWORD_AUTH."""
        stub = Stubber(self.user.client)
        stub.add_response(
            method="admin_initiate_auth",
            service_response={
                "AuthenticationResult": {
                    "TokenType": "admin",
                    "IdToken": "dummy_token",
                    "AccessToken": "dummy_token",
                    "RefreshToken": "dummy_token",
                }
            },
            expected_params={
                "UserPoolId": self.cognito_user_pool_id,
                "ClientId": self.app_id,
                "AuthFlow": "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                "AuthParameters": {
                    "USERNAME": self.username,
                    "PASSWORD": self.password,
                },
            },
        )
        with stub:
            self.user.admin_authenticate(self.password)
            self.assertNotEqual(self.user.access_token, None)
            self.assertNotEqual(self.user.id_token, None)
            self.assertNotEqual(self.user.refresh_token, None)
            stub.assert_no_pending_responses()


# ---------------------------------------------------------------------------
# Device authentication — PR #306
# ---------------------------------------------------------------------------


class CognitoAuthWithDeviceTestCase(CognitoAuthTestCase):
    """
    Extends CognitoAuthTestCase with device metadata pre-seeded on the
    Cognito instance, verifying that device values flow correctly through
    the authenticate / renew_access_token paths.
    """

    def setUp(self):
        super().setUp()
        self.user.device_key = "us-east-1_de20abce"
        self.user.device_group_key = "device_group_key"
        self.user.device_password = "device_password"
        self.user.device_name = "device_name"

    @patch(
        "src.pycognito.aws_srp.AWSSRP.authenticate_user",
        mock_authenticate_user_device_metadata,
    )
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_authenticate_sets_device_metadata_from_response(self):
        """
        When NewDeviceMetadata is returned, device_key and device_group_key
        must be updated on the Cognito instance from the response values.
        confirm_device is also called; we stub it to avoid the raw HTTP call.
        """
        with patch(
            "src.pycognito.aws_srp.AWSSRP.confirm_device",
            return_value=(None, "new_device_password"),
        ):
            self.user.authenticate(self.password)

        self.assertNotEqual(self.user.access_token, None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)
        self.assertEqual(self.user.device_key, "us-east-1_de20abce")
        self.assertEqual(self.user.device_group_key, "device_group_key")

    @patch(
        "src.pycognito.aws_srp.AWSSRP.authenticate_user",
        mock_authenticate_user_device_metadata,
    )
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_authenticate_calls_confirm_device_when_new_metadata_present(self):
        """confirm_device must be called when NewDeviceMetadata is in the response."""
        with patch(
            "src.pycognito.aws_srp.AWSSRP.confirm_device",
            return_value=(None, "new_device_password"),
        ) as mock_confirm:
            self.user.authenticate(self.password)

        mock_confirm.assert_called_once()

    @patch("src.pycognito.aws_srp.AWSSRP.authenticate_user", mock_authenticate_user)
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_authenticate_skips_confirm_device_when_no_new_metadata(self):
        """confirm_device must NOT be called when NewDeviceMetadata is absent."""
        with patch("src.pycognito.aws_srp.AWSSRP.confirm_device") as mock_confirm:
            self.user.authenticate(self.password)

        mock_confirm.assert_not_called()

    @patch(
        "src.pycognito.aws_srp.AWSSRP.authenticate_user",
        mock_authenticate_user_device_metadata,
    )
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    @patch("src.pycognito.Cognito._add_secret_hash", return_value=None)
    def test_renew_tokens(self, _):
        """Override: parent stub must include DEVICE_KEY since device_key is set."""
        stub = Stubber(self.user.client)
        stub.add_response(
            method="initiate_auth",
            service_response={
                "AuthenticationResult": {
                    "TokenType": "admin",
                    "IdToken": "dummy_token",
                    "AccessToken": "dummy_token",
                    "RefreshToken": "dummy_token",
                    "NewDeviceMetadata": {
                        "DeviceKey": "us-east-1_de20abce",
                        "DeviceGroupKey": "device_group_key",
                    },
                },
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
            expected_params={
                "ClientId": self.app_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {
                    "REFRESH_TOKEN": "dummy_token",
                    "DEVICE_KEY": self.user.device_key,
                },
            },
        )
        with (
            stub,
            patch(
                "src.pycognito.aws_srp.AWSSRP.confirm_device",
                return_value=(None, "new_device_password"),
            ),
        ):
            self.user.authenticate(self.password)
            self.user.renew_access_token()
            stub.assert_no_pending_responses()


class AWSSRPTestCase(unittest.TestCase):
    def setUp(self):
        if os.environ.get("USE_CLIENT_SECRET") == "True":
            self.client_secret = os.environ.get("COGNITO_CLIENT_SECRET")
            self.app_id = os.environ.get("COGNITO_APP_WITH_SECRET_ID", "app")
        else:
            self.app_id = os.environ.get("COGNITO_APP_ID", "app")
            self.client_secret = None
        self.cognito_user_pool_id = os.environ.get(
            "COGNITO_USER_POOL_ID", "us-east-1_123456789"
        )
        self.username = os.environ.get("COGNITO_TEST_USERNAME")
        self.password = os.environ.get("COGNITO_TEST_PASSWORD")
        self.aws = AWSSRP(
            username=self.username,
            password=self.password,
            pool_region="us-east-1",
            pool_id=self.cognito_user_pool_id,
            client_id=self.app_id,
            client_secret=self.client_secret,
        )

    def tearDown(self):
        del self.aws

    @patch("src.pycognito.aws_srp.AWSSRP.get_auth_params", mock_get_params)
    @patch("src.pycognito.aws_srp.AWSSRP.process_challenge", return_value={})
    def test_authenticate_user(self, _):
        stub = Stubber(self.aws.client)
        stub.add_response(
            method="initiate_auth",
            service_response={
                "ChallengeName": "PASSWORD_VERIFIER",
                "ChallengeParameters": {},
            },
            expected_params={
                "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": mock_get_params(None),
                "ClientId": self.app_id,
            },
        )
        stub.add_response(
            method="respond_to_auth_challenge",
            service_response={
                "AuthenticationResult": {
                    "IdToken": "dummy_token",
                    "AccessToken": "dummy_token",
                    "RefreshToken": "dummy_token",
                }
            },
            expected_params={
                "ClientId": self.app_id,
                "ChallengeName": "PASSWORD_VERIFIER",
                "ChallengeResponses": {},
            },
        )
        with stub:
            tokens = self.aws.authenticate_user()
            self.assertTrue("IdToken" in tokens["AuthenticationResult"])
            self.assertTrue("AccessToken" in tokens["AuthenticationResult"])
            self.assertTrue("RefreshToken" in tokens["AuthenticationResult"])
            stub.assert_no_pending_responses()

    def test_cognito_formatted_timestamp(self):
        cases = [
            (
                pendulum.datetime(2022, 1, 1, 0, 0, 0, tz="UTC"),
                "Sat Jan 1 00:00:00 UTC 2022",
            ),
            (
                pendulum.datetime(2022, 1, 2, 12, 0, 0, tz="UTC"),
                "Sun Jan 2 12:00:00 UTC 2022",
            ),
            (
                pendulum.datetime(2022, 1, 3, 9, 0, 0, tz="UTC"),
                "Mon Jan 3 09:00:00 UTC 2022",
            ),
            (
                pendulum.datetime(2022, 12, 31, 23, 59, 59, tz="UTC"),
                "Sat Dec 31 23:59:59 UTC 2022",
            ),
        ]
        for dt, expected in cases:
            with self.subTest(dt=dt):
                self.assertEqual(self.aws.get_cognito_formatted_timestamp(dt), expected)

    def test_cognito_formatted_timestamp_no_leading_zero(self):
        result = self.aws.get_cognito_formatted_timestamp(
            pendulum.datetime(2022, 3, 5, 8, 0, 0, tz="UTC")
        )
        self.assertEqual(result, "Sat Mar 5 08:00:00 UTC 2022")
        self.assertNotIn(" 05 ", result)

    def test_process_challenge_timestamp_is_utc(self):
        frozen_moment = pendulum.datetime(2024, 3, 7, 15, 30, 0, tz="UTC")
        challenge_parameters = {
            "USERNAME": self.username or "testuser",
            "USER_ID_FOR_SRP": self.username or "testuser",
            "SALT": "00" * 16,
            "SRP_B": "00" * 16,
            "SECRET_BLOCK": "",
        }
        with (
            patch("pendulum.now", return_value=frozen_moment),
            patch.object(
                self.aws,
                "get_password_authentication_key",
                return_value=b"\x00" * 16,
            ),
            patch("src.pycognito.aws_srp.base64.standard_b64decode", return_value=b""),
            patch("src.pycognito.aws_srp.hmac.new") as mock_hmac,
        ):
            mock_hmac.return_value.digest.return_value = b"\x00" * 32
            response = self.aws.process_challenge(
                challenge_parameters, {"USERNAME": "testuser"}
            )

        self.assertIn("UTC", response["TIMESTAMP"])
        self.assertEqual(response["TIMESTAMP"], "Thu Mar 7 15:30:00 UTC 2024")


# ---------------------------------------------------------------------------
# admin_renew_access_token
# ---------------------------------------------------------------------------


@moto.mock_aws
class AdminRenewAccessTokenTestCase(unittest.TestCase):
    """Tests for auth.py: admin_renew_access_token."""

    username = "user@test.com"
    password = "Testing123!"

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        pool = idp.create_user_pool(
            PoolName="pycognito-test-pool",
        )
        self.user_pool_id = pool["UserPool"]["Id"]
        client_app = idp.create_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientName="test-client",
            **TOKEN_VALIDITY_PARAMS,
        )
        self.client_id = client_app["UserPoolClient"]["ClientId"]
        idp.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            TemporaryPassword=self.password,
            MessageAction="SUPPRESS",
        )
        idp.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            Password=self.password,
            Permanent=True,
        )

    def _cognito(self):
        return Cognito(
            user_pool_id=self.user_pool_id,
            client_id=self.client_id,
            username=self.username,
            boto3_client_kwargs=json.loads(os.environ.get("BOTO3_CLIENT_EXTRAS", "{}")),
        )

    def test_admin_renew_access_token_refreshes_tokens(self):
        """After a successful refresh the access_token is still set."""
        cognito = self._cognito()
        cognito.authenticate(self.password)
        self.assertIsNotNone(cognito.access_token)
        self.assertIsNotNone(cognito.refresh_token)

        cognito.admin_renew_access_token()

        self.assertIsNotNone(cognito.access_token)
        self.assertIsNotNone(cognito.id_token)

    def test_admin_renew_access_token_uses_admin_initiate_auth(self):
        """admin_renew_access_token uses admin_initiate_auth, not initiate_auth."""
        cognito = self._cognito()
        cognito.authenticate(self.password)
        refresh_token = cognito.refresh_token

        # Wrap the boto3 client to spy on calls
        original_admin_initiate_auth = cognito.client.admin_initiate_auth
        calls = []

        def spy(*args, **kwargs):
            calls.append(kwargs)
            return original_admin_initiate_auth(*args, **kwargs)

        cognito.client.admin_initiate_auth = spy
        cognito.admin_renew_access_token()

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["AuthFlow"], "REFRESH_TOKEN_AUTH")
        self.assertEqual(calls[0]["AuthParameters"]["REFRESH_TOKEN"], refresh_token)

    def test_admin_renew_access_token_requires_refresh_token(self):
        """Calling without a valid refresh token should raise an exception.
        Moto raises KeyError for an unrecognised refresh token rather than
        a ClientError, so we assert on the broader Exception base class."""
        cognito = self._cognito()
        cognito.refresh_token = "invalid_token"
        with self.assertRaises(Exception):
            cognito.admin_renew_access_token()


# ---------------------------------------------------------------------------
# admin_user_global_sign_out
# ---------------------------------------------------------------------------


@moto.mock_aws
class AdminUserGlobalSignOutTestCase(unittest.TestCase):
    """Tests for tokens.py: admin_user_global_sign_out."""

    username = "user@test.com"
    password = "Testing123!"

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        pool = idp.create_user_pool(
            PoolName="pycognito-test-pool",
        )
        self.user_pool_id = pool["UserPool"]["Id"]
        client_app = idp.create_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientName="test-client",
            **TOKEN_VALIDITY_PARAMS,
        )
        self.client_id = client_app["UserPoolClient"]["ClientId"]
        idp.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            TemporaryPassword=self.password,
            MessageAction="SUPPRESS",
        )
        idp.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            Password=self.password,
            Permanent=True,
        )

    def _cognito(self):
        return Cognito(
            user_pool_id=self.user_pool_id,
            client_id=self.client_id,
            username=self.username,
            boto3_client_kwargs=json.loads(os.environ.get("BOTO3_CLIENT_EXTRAS", "{}")),
        )

    def test_admin_user_global_sign_out_self(self):
        """Signs out self.username when no explicit username is given."""
        cognito = self._cognito()
        cognito.authenticate(self.password)
        cognito.admin_user_global_sign_out()

    def test_admin_user_global_sign_out_explicit_username(self):
        """Signs out an explicitly specified username."""
        cognito = self._cognito()
        cognito.admin_user_global_sign_out(username=self.username)

    def test_admin_user_global_sign_out_defaults_to_self_username(self):
        """Without an argument the method uses self.username."""
        cognito = self._cognito()
        calls = []
        original = cognito.client.admin_user_global_sign_out

        def spy(**kwargs):
            calls.append(kwargs)
            return original(**kwargs)

        cognito.client.admin_user_global_sign_out = spy
        cognito.admin_user_global_sign_out()

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["Username"], self.username)
        self.assertEqual(calls[0]["UserPoolId"], self.user_pool_id)


# ---------------------------------------------------------------------------
# revoke_token (no moto support, so the client is stubbed)
# ---------------------------------------------------------------------------


class RevokeTokenTestCase(unittest.TestCase):
    """Tests for tokens.py: revoke_token."""

    client_id = "testclientid"
    # botocore validates ClientSecret as 24 to 64 characters
    client_secret = "s" * 32

    def _cognito(self, client_secret=None):
        cognito = Cognito(
            user_pool_id="us-east-1_123456789",
            client_id=self.client_id,
            username="testuser",
            client_secret=client_secret,
            id_token="stored_id_token",
            access_token="stored_access_token",
            refresh_token="stored_refresh_token",
        )
        cognito.token_type = "Bearer"
        return cognito

    def _assert_tokens_cleared(self, cognito):
        self.assertIsNone(cognito.id_token)
        self.assertIsNone(cognito.refresh_token)
        self.assertIsNone(cognito.access_token)
        self.assertIsNone(cognito.token_type)

    def _assert_tokens_kept(self, cognito):
        self.assertEqual(cognito.id_token, "stored_id_token")
        self.assertEqual(cognito.refresh_token, "stored_refresh_token")
        self.assertEqual(cognito.access_token, "stored_access_token")
        self.assertEqual(cognito.token_type, "Bearer")

    def _revoke(self, cognito, expected_params, **kwargs):
        with Stubber(cognito.client) as stub:
            stub.add_response("revoke_token", {}, expected_params)
            cognito.revoke_token(**kwargs)
            stub.assert_no_pending_responses()

    def test_defaults_to_own_refresh_token_and_clears_tokens(self):
        cognito = self._cognito()
        self._revoke(
            cognito,
            {"Token": "stored_refresh_token", "ClientId": self.client_id},
        )
        self._assert_tokens_cleared(cognito)

    def test_explicit_other_token_keeps_tokens(self):
        cognito = self._cognito()
        self._revoke(
            cognito,
            {"Token": "other_refresh_token", "ClientId": self.client_id},
            token="other_refresh_token",
        )
        self._assert_tokens_kept(cognito)

    def test_explicit_own_token_clears_tokens(self):
        cognito = self._cognito()
        self._revoke(
            cognito,
            {"Token": "stored_refresh_token", "ClientId": self.client_id},
            token="stored_refresh_token",
        )
        self._assert_tokens_cleared(cognito)

    def test_default_token_with_client_secret(self):
        cognito = self._cognito(client_secret=self.client_secret)
        self._revoke(
            cognito,
            {
                "Token": "stored_refresh_token",
                "ClientId": self.client_id,
                "ClientSecret": self.client_secret,
            },
        )
        self._assert_tokens_cleared(cognito)

    def test_explicit_token_with_client_secret(self):
        cognito = self._cognito(client_secret=self.client_secret)
        self._revoke(
            cognito,
            {
                "Token": "other_refresh_token",
                "ClientId": self.client_id,
                "ClientSecret": self.client_secret,
            },
            token="other_refresh_token",
        )
        self._assert_tokens_kept(cognito)

    def test_failed_revoke_keeps_tokens(self):
        cognito = self._cognito()
        with Stubber(cognito.client) as stub:
            stub.add_client_error("revoke_token", "UnauthorizedException")
            with self.assertRaises(ClientError):
                cognito.revoke_token()
        self._assert_tokens_kept(cognito)

    def test_no_token_raises_without_calling_cognito(self):
        cognito = self._cognito()
        cognito.refresh_token = None
        # Stubber fails any call that has no queued response
        with Stubber(cognito.client), self.assertRaises(AttributeError):
            cognito.revoke_token()


if __name__ == "__main__":
    unittest.main()
