"""
Request-shape tests for thin boto3 wrappers, using botocore's Stubber.

Stubber validates every request against the cognito-idp service model, so
these tests catch wrong operation names, parameter names, and missing
required parameters, as well as checking the values each method sends.
"""

import unittest
from unittest.mock import patch

from botocore.stub import Stubber

from src.pycognito import Cognito, GroupObj, UserObj
from src.pycognito.aws_srp import AWSSRP
from src.pycognito.exceptions import SoftwareTokenMFAChallengeException

from .helpers import mock_verify_tokens

POOL_ID = "us-east-1_123456789"
CLIENT_ID = "testclientid"
CLIENT_SECRET = "testclientsecret"
USERNAME = "bob"
ACCESS_TOKEN = "access-token"
DEVICE_KEY = "us-east-1_device_abc123"
SESSION_1 = "session-one-" + "x" * 20
SESSION_2 = "session-two-" + "x" * 20

AUTH_RESULT = {
    "AuthenticationResult": {
        "AccessToken": "new-access-token",
        "IdToken": "new-id-token",
        "RefreshToken": "new-refresh-token",
        "TokenType": "Bearer",
    }
}


class _StubbedCase(unittest.TestCase):
    client_secret = None

    def setUp(self):
        self.cognito = Cognito(
            POOL_ID,
            CLIENT_ID,
            username=USERNAME,
            access_token=ACCESS_TOKEN,
            refresh_token="refresh-token",
            id_token="id-token",
            client_secret=self.client_secret,
        )
        self.stub = Stubber(self.cognito.client)
        self.stub.activate()

    def tearDown(self):
        self.stub.assert_no_pending_responses()
        self.stub.deactivate()

    def expect(self, operation, expected_params, response=None):
        self.stub.add_response(operation, response or {}, expected_params)


# ---------------------------------------------------------------------------
# AuthMixin
# ---------------------------------------------------------------------------


class RegistrationTestCase(_StubbedCase):
    def test_register_with_base_custom_attrs_attr_map_and_metadata(self):
        self.cognito.set_base_attributes(email="bob@example.com", first="Bob")
        self.cognito.add_custom_attributes(state="virginia")
        self.expect(
            "sign_up",
            {
                "ClientId": CLIENT_ID,
                "Username": "newuser",
                "Password": "pw",
                "UserAttributes": [
                    {"Name": "email", "Value": "bob@example.com"},
                    {"Name": "custom:state", "Value": "virginia"},
                    {"Name": "given_name", "Value": "Bob"},
                ],
                "ClientMetadata": {"source": "test"},
            },
            {
                "UserConfirmed": False,
                "UserSub": "sub-123",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )
        response = self.cognito.register(
            "newuser",
            "pw",
            attr_map={"given_name": "first"},
            client_metadata={"source": "test"},
        )
        self.assertEqual(response, {"UserConfirmed": False, "UserSub": "sub-123"})
        self.assertEqual(self.cognito.custom_attributes, {"custom:state": "virginia"})

    def test_register_without_attributes(self):
        self.expect(
            "sign_up",
            {
                "ClientId": CLIENT_ID,
                "Username": "newuser",
                "Password": "pw",
                "UserAttributes": [],
            },
            {
                "UserConfirmed": True,
                "UserSub": "sub-123",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )
        self.cognito.register("newuser", "pw")

    def test_admin_confirm_sign_up_defaults_to_self_username(self):
        self.expect(
            "admin_confirm_sign_up", {"UserPoolId": POOL_ID, "Username": USERNAME}
        )
        self.cognito.admin_confirm_sign_up()

    def test_admin_confirm_sign_up_explicit_username(self):
        self.expect(
            "admin_confirm_sign_up", {"UserPoolId": POOL_ID, "Username": "alice"}
        )
        self.cognito.admin_confirm_sign_up(username="alice")

    def test_confirm_sign_up(self):
        self.expect(
            "confirm_sign_up",
            {"ClientId": CLIENT_ID, "Username": USERNAME, "ConfirmationCode": "123"},
        )
        self.cognito.confirm_sign_up("123")

    def test_confirm_sign_up_explicit_username(self):
        self.expect(
            "confirm_sign_up",
            {"ClientId": CLIENT_ID, "Username": "alice", "ConfirmationCode": "123"},
        )
        self.cognito.confirm_sign_up("123", username="alice")

    def test_resend_confirmation_code(self):
        self.expect(
            "resend_confirmation_code", {"ClientId": CLIENT_ID, "Username": "alice"}
        )
        self.cognito.resend_confirmation_code("alice")


class SecretHashUsernameTestCase(_StubbedCase):
    """The SecretHash must be computed from the username sent to Cognito."""

    client_secret = CLIENT_SECRET

    def _hash(self, username):
        return AWSSRP.get_secret_hash(username, CLIENT_ID, CLIENT_SECRET)

    def test_register_hashes_registered_username(self):
        self.expect(
            "sign_up",
            {
                "ClientId": CLIENT_ID,
                "Username": "newuser",
                "Password": "pw",
                "UserAttributes": [],
                "SecretHash": self._hash("newuser"),
            },
            {
                "UserConfirmed": False,
                "UserSub": "sub-123",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )
        self.cognito.register("newuser", "pw")

    def test_confirm_sign_up_hashes_explicit_username(self):
        self.expect(
            "confirm_sign_up",
            {
                "ClientId": CLIENT_ID,
                "Username": "alice",
                "ConfirmationCode": "123",
                "SecretHash": self._hash("alice"),
            },
        )
        self.cognito.confirm_sign_up("123", username="alice")

    def test_resend_confirmation_code_hashes_explicit_username(self):
        self.expect(
            "resend_confirmation_code",
            {
                "ClientId": CLIENT_ID,
                "Username": "alice",
                "SecretHash": self._hash("alice"),
            },
        )
        self.cognito.resend_confirmation_code("alice")

    def test_initiate_forgot_password_hashes_self_username(self):
        self.expect(
            "forgot_password",
            {
                "ClientId": CLIENT_ID,
                "Username": USERNAME,
                "SecretHash": self._hash(USERNAME),
            },
        )
        self.cognito.initiate_forgot_password()


class PasswordAndVerificationTestCase(_StubbedCase):
    def test_confirm_forgot_password_sets_password(self):
        self.expect(
            "confirm_forgot_password",
            {
                "ClientId": CLIENT_ID,
                "Username": USERNAME,
                "ConfirmationCode": "123",
                "Password": "new-pw",
            },
            {"ResponseMetadata": {"HTTPStatusCode": 200}},
        )
        self.cognito.confirm_forgot_password("123", "new-pw")
        self.assertEqual(self.cognito.password, "new-pw")

    def test_initiate_forgot_password(self):
        self.expect("forgot_password", {"ClientId": CLIENT_ID, "Username": USERNAME})
        self.cognito.initiate_forgot_password()

    def test_admin_reset_password_default_metadata(self):
        self.expect(
            "admin_reset_user_password",
            {"UserPoolId": POOL_ID, "Username": "alice", "ClientMetadata": {}},
        )
        self.cognito.admin_reset_password("alice")

    def test_admin_reset_password_with_metadata(self):
        self.expect(
            "admin_reset_user_password",
            {
                "UserPoolId": POOL_ID,
                "Username": "alice",
                "ClientMetadata": {"reason": "lost"},
            },
        )
        self.cognito.admin_reset_password("alice", client_metadata={"reason": "lost"})

    @patch("src.pycognito.Cognito.check_token", return_value=False)
    def test_send_verification_default_attribute(self, _):
        self.expect(
            "get_user_attribute_verification_code",
            {"AccessToken": ACCESS_TOKEN, "AttributeName": "email"},
        )
        self.cognito.send_verification()

    @patch("src.pycognito.Cognito.check_token", return_value=False)
    def test_send_verification_phone(self, _):
        self.expect(
            "get_user_attribute_verification_code",
            {"AccessToken": ACCESS_TOKEN, "AttributeName": "phone_number"},
        )
        self.cognito.send_verification(attribute="phone_number")

    @patch("src.pycognito.Cognito.check_token", return_value=False)
    def test_validate_verification(self, _):
        self.expect(
            "verify_user_attribute",
            {"AccessToken": ACCESS_TOKEN, "AttributeName": "phone_number", "Code": "1"},
        )
        self.cognito.validate_verification("1", attribute="phone_number")


class SignOutAndDeleteTestCase(_StubbedCase):
    def test_logout_calls_global_sign_out_and_clears_tokens(self):
        self.expect("global_sign_out", {"AccessToken": ACCESS_TOKEN})
        self.cognito.token_type = "Bearer"
        self.cognito.logout()
        self.assertIsNone(self.cognito.access_token)
        self.assertIsNone(self.cognito.id_token)
        self.assertIsNone(self.cognito.refresh_token)
        self.assertIsNone(self.cognito.token_type)

    def test_delete_user(self):
        self.expect("delete_user", {"AccessToken": ACCESS_TOKEN})
        self.cognito.delete_user()

    def test_admin_delete_user(self):
        self.expect("admin_delete_user", {"UserPoolId": POOL_ID, "Username": USERNAME})
        self.cognito.admin_delete_user()


class AuthenticateTestCase(_StubbedCase):
    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_new_password_challenge_sets_tokens(self):
        with patch.object(
            AWSSRP, "set_new_password_challenge", return_value=AUTH_RESULT
        ) as challenge:
            self.cognito.new_password_challenge("old", "new")
        challenge.assert_called_once_with("new")
        self.assertEqual(self.cognito.access_token, "new-access-token")
        self.assertEqual(self.cognito.refresh_token, "new-refresh-token")

    def test_authenticate_stores_mfa_tokens_on_challenge(self):
        challenge = {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "s"}
        with patch.object(
            AWSSRP,
            "authenticate_user",
            side_effect=SoftwareTokenMFAChallengeException("mfa", challenge),
        ):
            with self.assertRaises(SoftwareTokenMFAChallengeException):
                self.cognito.authenticate("pw")
        self.assertEqual(self.cognito.mfa_tokens, challenge)


# ---------------------------------------------------------------------------
# MFAMixin
# ---------------------------------------------------------------------------


class MFATestCase(_StubbedCase):
    def test_associate_software_token(self):
        self.expect(
            "associate_software_token",
            {"AccessToken": ACCESS_TOKEN},
            {"SecretCode": "S" * 16},
        )
        self.assertEqual(self.cognito.associate_software_token(), "S" * 16)

    def test_verify_software_token_success(self):
        self.expect(
            "verify_software_token",
            {
                "AccessToken": ACCESS_TOKEN,
                "UserCode": "123456",
                "FriendlyDeviceName": "phone",
            },
            {"Status": "SUCCESS"},
        )
        self.assertTrue(self.cognito.verify_software_token("123456", "phone"))

    def test_verify_software_token_failure(self):
        self.expect(
            "verify_software_token",
            {
                "AccessToken": ACCESS_TOKEN,
                "UserCode": "000000",
                "FriendlyDeviceName": "",
            },
            {"Status": "ERROR"},
        )
        self.assertFalse(self.cognito.verify_software_token("000000"))

    def _expect_preference(self, sms, sms_pref, totp, totp_pref):
        self.expect(
            "set_user_mfa_preference",
            {
                "SMSMfaSettings": {"Enabled": sms, "PreferredMfa": sms_pref},
                "SoftwareTokenMfaSettings": {
                    "Enabled": totp,
                    "PreferredMfa": totp_pref,
                },
                "AccessToken": ACCESS_TOKEN,
            },
        )

    def test_set_user_mfa_preference_sms(self):
        self._expect_preference(True, True, False, False)
        self.cognito.set_user_mfa_preference(True, False, "SMS")

    def test_set_user_mfa_preference_software_token(self):
        self._expect_preference(True, False, True, True)
        self.cognito.set_user_mfa_preference(True, True, "SOFTWARE_TOKEN")

    def test_set_user_mfa_preference_disable_all(self):
        self._expect_preference(False, False, False, False)
        self.cognito.set_user_mfa_preference(False, False)

    def test_set_user_mfa_preference_invalid_preferred(self):
        with self.assertRaises(ValueError):
            self.cognito.set_user_mfa_preference(True, False, None)

    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_respond_to_software_token_challenge_explicit_tokens(self):
        self.expect(
            "respond_to_auth_challenge",
            {
                "ClientId": CLIENT_ID,
                "Session": SESSION_1,
                "ChallengeName": "SOFTWARE_TOKEN_MFA",
                "ChallengeResponses": {
                    "USERNAME": USERNAME,
                    "SOFTWARE_TOKEN_MFA_CODE": "123456",
                },
            },
            AUTH_RESULT,
        )
        self.cognito.respond_to_software_token_mfa_challenge(
            123456, mfa_tokens={"Session": SESSION_1}
        )
        self.assertEqual(self.cognito.access_token, "new-access-token")

    @patch("src.pycognito.Cognito.verify_token", mock_verify_tokens)
    def test_respond_to_sms_challenge_uses_stored_tokens(self):
        self.cognito.mfa_tokens = {"Session": SESSION_2}
        self.expect(
            "respond_to_auth_challenge",
            {
                "ClientId": CLIENT_ID,
                "Session": SESSION_2,
                "ChallengeName": "SMS_MFA",
                "ChallengeResponses": {"USERNAME": USERNAME, "SMS_MFA_CODE": "654321"},
            },
            AUTH_RESULT,
        )
        self.cognito.respond_to_sms_mfa_challenge("654321")
        self.assertEqual(self.cognito.id_token, "new-id-token")


# ---------------------------------------------------------------------------
# UserPoolMixin — users
# ---------------------------------------------------------------------------


class UserManagementTestCase(_StubbedCase):
    def test_get_user(self):
        self.expect(
            "get_user",
            {"AccessToken": ACCESS_TOKEN},
            {
                "Username": USERNAME,
                "UserAttributes": [
                    {"Name": "sub", "Value": "sub-1"},
                    {"Name": "given_name", "Value": "Bob"},
                ],
            },
        )
        user = self.cognito.get_user(attr_map={"given_name": "first_name"})
        self.assertIsInstance(user, UserObj)
        self.assertEqual(user.first_name, "Bob")
        self.assertEqual(user.sub, "sub-1")
        self.assertEqual(user.access_token, ACCESS_TOKEN)

    def test_admin_create_user_with_temporary_password_and_extra_kwargs(self):
        self.expect(
            "admin_create_user",
            {
                "UserPoolId": POOL_ID,
                "Username": "alice",
                "UserAttributes": [{"Name": "email", "Value": "a@example.com"}],
                "TemporaryPassword": "Temp1234!",
                "MessageAction": "SUPPRESS",
            },
            {
                "User": {"Username": "alice"},
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )
        response = self.cognito.admin_create_user(
            "alice",
            temporary_password="Temp1234!",
            additional_kwargs={"MessageAction": "SUPPRESS"},
            email="a@example.com",
        )
        self.assertEqual(response, {"User": {"Username": "alice"}})

    def test_admin_create_user_attr_map(self):
        self.expect(
            "admin_create_user",
            {
                "UserPoolId": POOL_ID,
                "Username": "alice",
                "UserAttributes": [{"Name": "given_name", "Value": "Alice"}],
            },
            {
                "User": {"Username": "alice"},
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )
        self.cognito.admin_create_user(
            "alice", attr_map={"given_name": "first_name"}, first_name="Alice"
        )

    def test_admin_set_user_password_default_temporary(self):
        self.expect(
            "admin_set_user_password",
            {
                "UserPoolId": POOL_ID,
                "Username": "alice",
                "Password": "pw",
                "Permanent": False,
            },
        )
        self.cognito.admin_set_user_password("alice", "pw")

    def test_admin_set_user_password_permanent(self):
        self.expect(
            "admin_set_user_password",
            {
                "UserPoolId": POOL_ID,
                "Username": "alice",
                "Password": "pw",
                "Permanent": True,
            },
        )
        self.cognito.admin_set_user_password("alice", "pw", permanent=True)

    def test_update_profile_with_attr_map(self):
        self.expect(
            "update_user_attributes",
            {
                "UserAttributes": [{"Name": "given_name", "Value": "Robert"}],
                "AccessToken": ACCESS_TOKEN,
            },
        )
        self.cognito.update_profile(
            {"first_name": "Robert"}, attr_map={"given_name": "first_name"}
        )

    def test_admin_update_profile_with_cognito_list_and_username(self):
        attrs = [{"Name": "email", "Value": "new@example.com"}]
        self.expect(
            "admin_update_user_attributes",
            {"UserPoolId": POOL_ID, "Username": "alice", "UserAttributes": attrs},
        )
        self.cognito.admin_update_profile(attrs, username="alice")

    def test_admin_enable_user(self):
        self.expect("admin_enable_user", {"UserPoolId": POOL_ID, "Username": "alice"})
        self.cognito.admin_enable_user("alice")

    def test_admin_disable_user(self):
        self.expect("admin_disable_user", {"UserPoolId": POOL_ID, "Username": "alice"})
        self.cognito.admin_disable_user("alice")

    def test_get_users_page_limit_and_token(self):
        self.expect(
            "list_users",
            {"UserPoolId": POOL_ID, "Limit": 1, "PaginationToken": "t1"},
            {
                "Users": [{"Username": "alice", "Attributes": []}],
                "PaginationToken": "t2",
            },
        )
        users = self.cognito.get_users(page_limit=1, page_token="t1")
        self.assertEqual([u.username for u in users], ["alice"])
        self.assertEqual(self.cognito.get_users_pagination_token(), "t2")

    def test_get_users_follows_pagination(self):
        self.expect(
            "list_users",
            {"UserPoolId": POOL_ID},
            {"Users": [{"Username": "a", "Attributes": []}], "PaginationToken": "t1"},
        )
        self.expect(
            "list_users",
            {"UserPoolId": POOL_ID, "PaginationToken": "t1"},
            {"Users": [{"Username": "b", "Attributes": []}]},
        )
        users = self.cognito.get_users()
        self.assertEqual([u.username for u in users], ["a", "b"])
        self.assertEqual(repr(users[0]), "<UserObj: a>")

    def test_get_user_obj_username_from_metadata(self):
        self.cognito.username = None
        user = self.cognito.get_user_obj(
            attribute_list=[], metadata={"username": "from-metadata"}
        )
        self.assertEqual(user.username, "from-metadata")


# ---------------------------------------------------------------------------
# UserPoolMixin — groups
# ---------------------------------------------------------------------------


class GroupManagementTestCase(_StubbedCase):
    def test_get_group(self):
        self.expect(
            "get_group",
            {"GroupName": "admins", "UserPoolId": POOL_ID},
            {"Group": {"GroupName": "admins", "Description": "Admins"}},
        )
        group = self.cognito.get_group("admins")
        self.assertIsInstance(group, GroupObj)
        self.assertEqual(repr(group), "<GroupObj: admins>")
        self.assertEqual(group.description, "Admins")

    def test_get_groups_follows_pagination(self):
        self.expect(
            "list_groups",
            {"UserPoolId": POOL_ID},
            {"Groups": [{"GroupName": "a"}], "NextToken": "n1"},
        )
        self.expect(
            "list_groups",
            {"UserPoolId": POOL_ID, "NextToken": "n1"},
            {"Groups": [{"GroupName": "b"}]},
        )
        groups = self.cognito.get_groups()
        self.assertEqual([g.group_name for g in groups], ["a", "b"])

    def test_get_groups_page_limit_and_token(self):
        self.expect(
            "list_groups",
            {"UserPoolId": "other-pool", "Limit": 1, "NextToken": "n1"},
            {"Groups": [{"GroupName": "a"}], "NextToken": "n2"},
        )
        self.cognito.get_groups(pool_id="other-pool", page_limit=1, page_token="n1")
        self.assertEqual(self.cognito.get_groups_pagination_token(), "n2")

    def test_admin_add_user_to_group(self):
        self.expect(
            "admin_add_user_to_group",
            {"UserPoolId": POOL_ID, "Username": "alice", "GroupName": "admins"},
        )
        self.cognito.admin_add_user_to_group("alice", "admins")

    def test_admin_remove_user_from_group(self):
        self.expect(
            "admin_remove_user_from_group",
            {"UserPoolId": POOL_ID, "Username": "alice", "GroupName": "admins"},
        )
        self.cognito.admin_remove_user_from_group("alice", "admins")

    def test_admin_list_groups_for_user_follows_pagination(self):
        self.expect(
            "admin_list_groups_for_user",
            {"Username": "alice", "UserPoolId": POOL_ID, "Limit": 60},
            {"Groups": [{"GroupName": "admins"}], "NextToken": "n1"},
        )
        self.expect(
            "admin_list_groups_for_user",
            {
                "Username": "alice",
                "UserPoolId": POOL_ID,
                "Limit": 60,
                "NextToken": "n1",
            },
            {"Groups": [{"GroupName": "editors"}]},
        )
        self.assertEqual(
            self.cognito.admin_list_groups_for_user("alice"), ["admins", "editors"]
        )

    def test_create_group_with_role_arn(self):
        role = "arn:aws:iam::123456789012:role/test-role"
        self.expect(
            "create_group",
            {"GroupName": "g", "UserPoolId": POOL_ID, "RoleArn": role},
            {"Group": {"GroupName": "g", "RoleArn": role}},
        )
        self.assertEqual(self.cognito.create_group("g", role_arn=role).role_arn, role)

    def test_update_group_role_arn(self):
        role = "arn:aws:iam::123456789012:role/test-role"
        self.expect(
            "update_group",
            {"GroupName": "g", "UserPoolId": POOL_ID, "RoleArn": role},
            {"Group": {"GroupName": "g"}},
        )
        self.cognito.update_group("g", role_arn=role)

    def test_list_users_in_group_follows_pagination(self):
        self.expect(
            "list_users_in_group",
            {"GroupName": "g", "UserPoolId": POOL_ID},
            {"Users": [{"Username": "a", "Attributes": []}], "NextToken": "n1"},
        )
        self.expect(
            "list_users_in_group",
            {"GroupName": "g", "UserPoolId": POOL_ID, "NextToken": "n1"},
            {"Users": [{"Username": "b", "Attributes": []}]},
        )
        users = self.cognito.list_users_in_group("g")
        self.assertEqual([u.username for u in users], ["a", "b"])


# ---------------------------------------------------------------------------
# UserPoolMixin — pool clients and identity providers
# ---------------------------------------------------------------------------


class ClientAndProviderTestCase(_StubbedCase):
    def test_list_user_pool_clients_follows_pagination(self):
        self.expect(
            "list_user_pool_clients",
            {"UserPoolId": POOL_ID},
            {"UserPoolClients": [{"ClientId": "c1"}], "NextToken": "n1"},
        )
        self.expect(
            "list_user_pool_clients",
            {"UserPoolId": POOL_ID, "NextToken": "n1"},
            {"UserPoolClients": [{"ClientId": "c2"}]},
        )
        clients = self.cognito.list_user_pool_clients()
        self.assertEqual([c["ClientId"] for c in clients], ["c1", "c2"])

    def test_list_user_pool_clients_page_limit_and_token(self):
        self.expect(
            "list_user_pool_clients",
            {"UserPoolId": POOL_ID, "MaxResults": 1, "NextToken": "n1"},
            {"UserPoolClients": [{"ClientId": "c1"}], "NextToken": "n2"},
        )
        self.cognito.list_user_pool_clients(page_limit=1, page_token="n1")
        self.assertEqual(self.cognito.get_clients_pagination_token(), "n2")

    def test_delete_user_pool_client_defaults(self):
        self.expect(
            "delete_user_pool_client", {"UserPoolId": POOL_ID, "ClientId": CLIENT_ID}
        )
        self.cognito.delete_user_pool_client()

    def test_delete_user_pool_client_explicit(self):
        self.expect(
            "delete_user_pool_client", {"UserPoolId": "other-pool", "ClientId": "c9"}
        )
        self.cognito.delete_user_pool_client(pool_id="other-pool", client_id="c9")

    def test_admin_update_user_pool_client(self):
        self.expect(
            "update_user_pool_client",
            {"UserPoolId": POOL_ID, "ClientId": "c1", "ClientName": "renamed"},
            {"UserPoolClient": {"ClientId": "c1"}},
        )
        self.cognito.admin_update_user_pool_client(POOL_ID, "c1", ClientName="renamed")

    def test_admin_create_identity_provider(self):
        details = {"client_id": "x", "client_secret": "y", "authorize_scopes": "email"}
        self.expect(
            "create_identity_provider",
            {
                "UserPoolId": POOL_ID,
                "ProviderName": "Google",
                "ProviderType": "Google",
                "ProviderDetails": details,
                "AttributeMapping": {"email": "email"},
            },
            {
                "IdentityProvider": {
                    "ProviderName": "Google",
                    "ProviderType": "Google",
                }
            },
        )
        self.cognito.admin_create_identity_provider(
            POOL_ID, "Google", "Google", details, AttributeMapping={"email": "email"}
        )

    def test_admin_describe_identity_provider(self):
        self.expect(
            "describe_identity_provider",
            {"UserPoolId": POOL_ID, "ProviderName": "Google"},
            {"IdentityProvider": {"ProviderName": "Google"}},
        )
        response = self.cognito.admin_describe_identity_provider(POOL_ID, "Google")
        self.assertEqual(response["IdentityProvider"]["ProviderName"], "Google")

    def test_admin_update_identity_provider(self):
        self.expect(
            "update_identity_provider",
            {
                "UserPoolId": POOL_ID,
                "ProviderName": "Google",
                "AttributeMapping": {"email": "email"},
            },
            {"IdentityProvider": {"ProviderName": "Google"}},
        )
        self.cognito.admin_update_identity_provider(
            POOL_ID, "Google", AttributeMapping={"email": "email"}
        )

    def test_admin_link_provider_for_user(self):
        self.expect(
            "admin_link_provider_for_user",
            {
                "UserPoolId": POOL_ID,
                "DestinationUser": {
                    "ProviderName": "Cognito",
                    "ProviderAttributeValue": "bob",
                },
                "SourceUser": {
                    "ProviderName": "Google",
                    "ProviderAttributeName": "Cognito_Subject",
                    "ProviderAttributeValue": "google-123",
                },
            },
        )
        self.cognito.admin_link_provider_for_user(
            "bob", "Google", "Cognito_Subject", "google-123"
        )

    def test_admin_disable_provider_for_user_default_attribute_name(self):
        self.expect(
            "admin_disable_provider_for_user",
            {
                "UserPoolId": POOL_ID,
                "User": {
                    "ProviderName": "Google",
                    "ProviderAttributeName": "Cognito_Subject",
                    "ProviderAttributeValue": "google-123",
                },
            },
        )
        self.cognito.admin_disable_provider_for_user("Google", "google-123")

    def test_admin_disable_provider_for_user_custom_attribute_name(self):
        self.expect(
            "admin_disable_provider_for_user",
            {
                "UserPoolId": POOL_ID,
                "User": {
                    "ProviderName": "MySAML",
                    "ProviderAttributeName": "email",
                    "ProviderAttributeValue": "bob@example.com",
                },
            },
        )
        self.cognito.admin_disable_provider_for_user(
            "MySAML", "bob@example.com", provider_attribute_name="email"
        )


# ---------------------------------------------------------------------------
# UserPoolMixin — devices
# ---------------------------------------------------------------------------


class DeviceManagementTestCase(_StubbedCase):
    DEVICE = {"DeviceKey": DEVICE_KEY, "DeviceAttributes": []}

    def test_admin_list_devices_defaults_to_self_username(self):
        self.expect(
            "admin_list_devices",
            {"UserPoolId": POOL_ID, "Username": USERNAME},
            {"Devices": []},
        )
        self.assertEqual(self.cognito.admin_list_devices(), [])

    def test_get_device(self):
        self.expect(
            "get_device",
            {"DeviceKey": DEVICE_KEY, "AccessToken": ACCESS_TOKEN},
            {"Device": self.DEVICE},
        )
        self.assertEqual(self.cognito.get_device(DEVICE_KEY), self.DEVICE)

    def test_admin_get_device(self):
        self.expect(
            "admin_get_device",
            {"DeviceKey": DEVICE_KEY, "UserPoolId": POOL_ID, "Username": USERNAME},
            {"Device": self.DEVICE},
        )
        self.assertEqual(self.cognito.admin_get_device(DEVICE_KEY), self.DEVICE)

    def test_admin_forget_device_explicit_username(self):
        self.expect(
            "admin_forget_device",
            {"UserPoolId": POOL_ID, "Username": "alice", "DeviceKey": DEVICE_KEY},
        )
        self.cognito.admin_forget_device(DEVICE_KEY, username="alice")


# ---------------------------------------------------------------------------
# UserObj delegation
# ---------------------------------------------------------------------------


class PaginationTestCase(_StubbedCase):
    """
    Every paginated method must:
    - follow all pages when page_limit is not set, leaving no stale token
    - return one page and store the next token when page_limit is set
    - support the manual loop shown in the README until the token is None
    """

    # name: (call, operation, base params, limit key, token key, items key,
    #        item factory, item id, token getter)
    SPECS = {
        "get_users": (
            lambda c, **kw: c.get_users(**kw),
            "list_users",
            {"UserPoolId": POOL_ID},
            "Limit",
            "PaginationToken",
            "Users",
            lambda i: {"Username": f"u{i}", "Attributes": []},
            lambda item: item.username,
            "get_users_pagination_token",
        ),
        "get_groups": (
            lambda c, **kw: c.get_groups(**kw),
            "list_groups",
            {"UserPoolId": POOL_ID},
            "Limit",
            "NextToken",
            "Groups",
            lambda i: {"GroupName": f"g{i}"},
            lambda item: item.group_name,
            "get_groups_pagination_token",
        ),
        "list_user_pool_clients": (
            lambda c, **kw: c.list_user_pool_clients(**kw),
            "list_user_pool_clients",
            {"UserPoolId": POOL_ID},
            "MaxResults",
            "NextToken",
            "UserPoolClients",
            lambda i: {"ClientId": f"c{i}"},
            lambda item: item["ClientId"],
            "get_clients_pagination_token",
        ),
        "list_users_in_group": (
            lambda c, **kw: c.list_users_in_group("g", **kw),
            "list_users_in_group",
            {"GroupName": "g", "UserPoolId": POOL_ID},
            "Limit",
            "NextToken",
            "Users",
            lambda i: {"Username": f"u{i}", "Attributes": []},
            lambda item: item.username,
            "get_group_users_pagination_token",
        ),
        "list_devices": (
            lambda c, **kw: c.list_devices(**kw),
            "list_devices",
            {"AccessToken": ACCESS_TOKEN},
            "Limit",
            "PaginationToken",
            "Devices",
            lambda i: {"DeviceKey": f"us-east-1_d{i}"},
            lambda item: item["DeviceKey"],
            "get_devices_pagination_token",
        ),
        "admin_list_devices": (
            lambda c, **kw: c.admin_list_devices(username="alice", **kw),
            "admin_list_devices",
            {"UserPoolId": POOL_ID, "Username": "alice"},
            "Limit",
            "PaginationToken",
            "Devices",
            lambda i: {"DeviceKey": f"us-east-1_d{i}"},
            lambda item: item["DeviceKey"],
            "get_devices_pagination_token",
        ),
    }

    def _page(self, spec, start, count, next_token):
        _, _, _, _, token_key, items_key, factory, _, _ = spec
        page = {items_key: [factory(i) for i in range(start, start + count)]}
        if next_token:
            page[token_key] = next_token
        return page

    def _expect_page(self, spec, page, limit=None, token=None):
        _, operation, base, limit_key, token_key, *_ = spec
        params = dict(base)
        if limit is not None:
            params[limit_key] = limit
        if token is not None:
            params[token_key] = token
        self.expect(operation, params, page)

    def _ids(self, spec, items):
        return [spec[7](item) for item in items]

    def _token(self, spec):
        return getattr(self.cognito, spec[8])()

    def test_without_page_limit_follows_every_page(self):
        for name, spec in self.SPECS.items():
            with self.subTest(name):
                self._expect_page(spec, self._page(spec, 0, 2, "t1"))
                self._expect_page(spec, self._page(spec, 2, 2, "t2"), token="t1")
                self._expect_page(spec, self._page(spec, 4, 1, None), token="t2")
                items = spec[0](self.cognito)
                self.assertEqual(len(self._ids(spec, items)), 5)
                self.assertIsNone(self._token(spec))

    def test_without_page_limit_starts_from_page_token(self):
        for name, spec in self.SPECS.items():
            with self.subTest(name):
                self._expect_page(spec, self._page(spec, 2, 2, "t2"), token="t1")
                self._expect_page(spec, self._page(spec, 4, 1, None), token="t2")
                items = spec[0](self.cognito, page_token="t1")
                self.assertEqual(len(items), 3)

    def test_page_limit_returns_one_page_and_stores_token(self):
        for name, spec in self.SPECS.items():
            with self.subTest(name):
                self._expect_page(spec, self._page(spec, 0, 2, "t1"), limit=2)
                items = spec[0](self.cognito, page_limit=2)
                self.assertEqual(len(items), 2)
                self.assertEqual(self._token(spec), "t1")

    def test_manual_loop_collects_every_page(self):
        for name, spec in self.SPECS.items():
            with self.subTest(name):
                self._expect_page(spec, self._page(spec, 0, 2, "t1"), limit=2)
                self._expect_page(spec, self._page(spec, 2, 2, "t2"), 2, "t1")
                self._expect_page(spec, self._page(spec, 4, 1, None), 2, "t2")

                items = spec[0](self.cognito, page_limit=2)
                token = self._token(spec)
                while token:
                    items += spec[0](self.cognito, page_limit=2, page_token=token)
                    token = self._token(spec)
                self.assertEqual(len(set(self._ids(spec, items))), 5)
                self.assertIsNone(token)

    def test_full_fetch_clears_token_from_earlier_page(self):
        for name, spec in self.SPECS.items():
            with self.subTest(name):
                self._expect_page(spec, self._page(spec, 0, 2, "t1"), limit=2)
                self._expect_page(spec, self._page(spec, 0, 1, None))
                spec[0](self.cognito, page_limit=2)
                self.assertEqual(self._token(spec), "t1")
                spec[0](self.cognito)
                self.assertIsNone(self._token(spec))


class UserObjDelegationTestCase(_StubbedCase):
    def _user(self):
        return UserObj(
            "alice",
            [{"Name": "given_name", "Value": "Alice"}],
            self.cognito,
            metadata={"user_status": "CONFIRMED"},
        )

    def test_save_updates_own_profile(self):
        self.expect(
            "update_user_attributes",
            {
                "UserAttributes": [{"Name": "given_name", "Value": "Alicia"}],
                "AccessToken": ACCESS_TOKEN,
            },
        )
        user = self._user()
        user.given_name = "Alicia"
        user.save()

    def test_save_admin_updates_profile(self):
        self.expect(
            "admin_update_user_attributes",
            {
                "UserPoolId": POOL_ID,
                "Username": USERNAME,
                "UserAttributes": [{"Name": "given_name", "Value": "Alice"}],
            },
        )
        self._user().save(admin=True)

    def test_delete(self):
        self.expect("delete_user", {"AccessToken": ACCESS_TOKEN})
        self._user().delete()

    def test_delete_admin(self):
        self.expect("admin_delete_user", {"UserPoolId": POOL_ID, "Username": USERNAME})
        self._user().delete(admin=True)

    def test_metadata_and_missing_attribute_access(self):
        user = self._user()
        self.assertEqual(user.user_status, "CONFIRMED")
        with self.assertRaises(AttributeError):
            _ = user.does_not_exist


class SwitchSessionTestCase(unittest.TestCase):
    def test_switch_session_replaces_client(self):
        cognito = Cognito(POOL_ID, CLIENT_ID)
        with patch("boto3.session.Session") as session_cls:
            session = session_cls.return_value
            cognito.switch_session(session)
        session.client.assert_called_once_with("cognito-idp")
        self.assertIs(cognito.client, session.client.return_value)


if __name__ == "__main__":
    unittest.main()
