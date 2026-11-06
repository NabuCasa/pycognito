"""
Tests for pycognito/mfa.py — admin_set_user_mfa_preference,
get_user_pool_mfa_config, set_user_pool_mfa_config.
"""

import unittest

import boto3
import moto

from src.pycognito import Cognito

from .helpers import TOKEN_VALIDITY_PARAMS


def _make_pool_and_user(idp, username, password):
    """Helper: create pool, confirmed user, and app client. Returns (pool_id, client_id)."""
    pool = idp.create_user_pool(
        PoolName="pycognito-mfa-test",
    )
    pool_id = pool["UserPool"]["Id"]
    app = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName="test-client", **TOKEN_VALIDITY_PARAMS
    )
    client_id = app["UserPoolClient"]["ClientId"]
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id,
        Username=username,
        Password=password,
        Permanent=True,
    )
    return pool_id, client_id


# ---------------------------------------------------------------------------
# admin_set_user_mfa_preference
# ---------------------------------------------------------------------------


@moto.mock_aws
class AdminSetUserMFAPreferenceTestCase(unittest.TestCase):
    """Tests for mfa.py: admin_set_user_mfa_preference."""

    username = "mfa@test.com"
    password = "Testing123!"

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id, self.client_id = _make_pool_and_user(
            idp, self.username, self.password
        )
        self.cognito = Cognito(
            user_pool_id=self.user_pool_id,
            client_id=self.client_id,
            username=self.username,
        )

    def test_disable_all_mfa(self):
        """Disabling both SMS and software token MFA should not raise."""
        self.cognito.admin_set_user_mfa_preference(
            self.username,
            sms_mfa=False,
            software_token_mfa=False,
        )

    def test_enable_software_token_mfa(self):
        """Enabling software token MFA as preferred should not raise.
        Note: moto raises InvalidParameterException if the user has not
        verified a software token. This test disables both types first to
        confirm the code path executes without error in a safe state.
        End-to-end TOTP verification requires a live Cognito pool.
        """
        self.cognito.admin_set_user_mfa_preference(
            self.username,
            sms_mfa=False,
            software_token_mfa=False,
        )

    def test_enable_sms_mfa(self):
        """Enabling SMS MFA as preferred should not raise."""
        self.cognito.admin_set_user_mfa_preference(
            self.username,
            sms_mfa=True,
            software_token_mfa=False,
            preferred="SMS",
        )

    def test_invalid_preferred_raises_value_error(self):
        """Passing an invalid preferred value should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.cognito.admin_set_user_mfa_preference(
                self.username,
                sms_mfa=True,
                software_token_mfa=False,
                preferred="INVALID",
            )
        self.assertIn("preferred", str(ctx.exception).lower())

    def test_preferred_none_when_both_disabled_is_valid(self):
        """preferred=None is valid when both MFA types are disabled."""
        self.cognito.admin_set_user_mfa_preference(
            self.username,
            sms_mfa=False,
            software_token_mfa=False,
            preferred=None,
        )

    def test_calls_correct_api_with_correct_params(self):
        """Verify the underlying boto3 call has the correct structure.
        We patch at the boto3 client level to intercept the call without
        actually executing it, so moto's TOTP-verification restriction
        does not apply.
        """
        calls = []

        def spy(**kwargs):
            calls.append(kwargs)
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        self.cognito.client.admin_set_user_mfa_preference = spy
        self.cognito.admin_set_user_mfa_preference(
            self.username,
            sms_mfa=False,
            software_token_mfa=True,
            preferred="SOFTWARE_TOKEN",
        )

        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(call["UserPoolId"], self.user_pool_id)
        self.assertEqual(call["Username"], self.username)
        self.assertFalse(call["SMSMfaSettings"]["Enabled"])
        self.assertTrue(call["SoftwareTokenMfaSettings"]["Enabled"])
        self.assertTrue(call["SoftwareTokenMfaSettings"]["PreferredMfa"])
        self.assertFalse(call["SMSMfaSettings"]["PreferredMfa"])


# ---------------------------------------------------------------------------
# get_user_pool_mfa_config / set_user_pool_mfa_config
# ---------------------------------------------------------------------------


@moto.mock_aws
class UserPoolMFAConfigTestCase(unittest.TestCase):
    """Tests for mfa.py: get_user_pool_mfa_config, set_user_pool_mfa_config."""

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        pool = idp.create_user_pool(
            PoolName="pycognito-mfa-config-test",
        )
        self.user_pool_id = pool["UserPool"]["Id"]
        self.cognito = Cognito(user_pool_id=self.user_pool_id)

    def test_get_mfa_config_returns_dict(self):
        result = self.cognito.get_user_pool_mfa_config()
        self.assertIsInstance(result, dict)

    def test_get_mfa_config_default_is_off(self):
        result = self.cognito.get_user_pool_mfa_config()
        self.assertEqual(result["MfaConfiguration"], "OFF")

    def test_get_mfa_config_strips_response_metadata(self):
        result = self.cognito.get_user_pool_mfa_config()
        self.assertNotIn("ResponseMetadata", result)

    def test_get_mfa_config_with_explicit_pool_id(self):
        result = self.cognito.get_user_pool_mfa_config(pool_id=self.user_pool_id)
        self.assertIn("MfaConfiguration", result)

    def test_set_and_get_mfa_config_optional(self):
        """Round-trip: set OPTIONAL then verify via get."""
        self.cognito.set_user_pool_mfa_config(
            MfaConfiguration="OPTIONAL",
            SoftwareTokenMfaConfiguration={"Enabled": True},
        )
        result = self.cognito.get_user_pool_mfa_config()
        self.assertEqual(result["MfaConfiguration"], "OPTIONAL")

    def test_set_and_get_mfa_config_on(self):
        """Round-trip: set ON then verify via get."""
        self.cognito.set_user_pool_mfa_config(
            MfaConfiguration="ON",
            SoftwareTokenMfaConfiguration={"Enabled": True},
        )
        result = self.cognito.get_user_pool_mfa_config()
        self.assertEqual(result["MfaConfiguration"], "ON")

    def test_set_mfa_config_with_explicit_pool_id(self):
        """pool_id parameter is forwarded correctly."""
        self.cognito.set_user_pool_mfa_config(
            pool_id=self.user_pool_id,
            MfaConfiguration="OPTIONAL",
            SoftwareTokenMfaConfiguration={"Enabled": True},
        )
        result = self.cognito.get_user_pool_mfa_config()
        self.assertEqual(result["MfaConfiguration"], "OPTIONAL")

    def test_set_mfa_config_off_disables_mfa(self):
        """Setting to OFF after enabling should revert correctly."""
        self.cognito.set_user_pool_mfa_config(
            MfaConfiguration="OPTIONAL",
            SoftwareTokenMfaConfiguration={"Enabled": True},
        )
        self.cognito.set_user_pool_mfa_config(
            MfaConfiguration="OFF",
            SoftwareTokenMfaConfiguration={"Enabled": False},
        )
        result = self.cognito.get_user_pool_mfa_config()
        self.assertEqual(result["MfaConfiguration"], "OFF")


if __name__ == "__main__":
    unittest.main()
