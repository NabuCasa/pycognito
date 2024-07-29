import datetime
import unittest
import os.path
from unittest.mock import patch
import uuid

import freezegun
import moto
import moto.cognitoidp
import boto3
from botocore.exceptions import ParamValidationError
from botocore.stub import Stubber
from envs import env
import requests
import requests_mock

from pycognito import (
    is_cognito_attr_list,
    Cognito,
    UserObj,
    GroupObj,
    TokenVerificationException,
)
from pycognito.aws_srp import AWSSRP
from pycognito.utils import RequestsSrpAuth


def _mock_authenticate_user(_, client=None, client_metadata=None):
    return {
        "AuthenticationResult": {
            "TokenType": "admin",
            "IdToken": "dummy_token",
            "AccessToken": "dummy_token",
            "RefreshToken": "dummy_token",
        }
    }


def _mock_get_params(_):
    return {"USERNAME": "bob", "SRP_A": "srp"}


def _mock_verify_tokens(self, token, id_name, token_use):
    if "wrong" in token:
        raise TokenVerificationException
    setattr(self, id_name, token)


class UserObjTestCase(unittest.TestCase):
    def setUp(self):
        if env("USE_CLIENT_SECRET", "False") == "True":
            self.app_id = env("COGNITO_APP_WITH_SECRET_ID")
        else:
            self.app_id = env("COGNITO_APP_ID")
        self.cognito_user_pool_id = env("COGNITO_USER_POOL_ID", "us-east-1_123456789")
        self.username = env("COGNITO_TEST_USERNAME")

        self.user = Cognito(
            user_pool_id=self.cognito_user_pool_id,
            client_id=self.app_id,
            username=self.username,
        )

        self.user_metadata = {
            "user_status": "CONFIRMED",
            "username": "bjones",
        }
        self.user_info = [
            {"Name": "name", "Value": "Brian Jones"},
            {"Name": "given_name", "Value": "Brian"},
            {"Name": "birthdate", "Value": "12/7/1980"},
        ]

    def test_init(self):
        user = UserObj("bjones", self.user_info, self.user, self.user_metadata)
        self.assertEqual(user.username, self.user_metadata.get("username"))
        self.assertEqual(user.name, self.user_info[0].get("Value"))
        self.assertEqual(user.user_status, self.user_metadata.get("user_status"))


class GroupObjTestCase(unittest.TestCase):
    def setUp(self):
        if env("USE_CLIENT_SECRET", "False") == "True":
            self.app_id = env("COGNITO_APP_WITH_SECRET_ID")
        else:
            self.app_id = env("COGNITO_APP_ID")
        self.cognito_user_pool_id = env("COGNITO_USER_POOL_ID", "us-east-1_123456789")
        self.group_data = {"GroupName": "test_group", "Precedence": 1}
        self.cognito_obj = Cognito(
            user_pool_id=self.cognito_user_pool_id, client_id=self.app_id
        )

    def test_init(self):
        group = GroupObj(group_data=self.group_data, cognito_obj=self.cognito_obj)
        self.assertEqual(group.group_name, "test_group")
        self.assertEqual(group.precedence, 1)


class CognitoAuthTestCase(unittest.TestCase):
    def setUp(self):
        if env("USE_CLIENT_SECRET") == "True":
            self.app_id = env("COGNITO_APP_WITH_SECRET_ID", "app")
            self.client_secret = env("COGNITO_CLIENT_SECRET")
        else:
            self.app_id = env("COGNITO_APP_ID", "app")
            self.client_secret = None
        self.cognito_user_pool_id = env("COGNITO_USER_POOL_ID", "us-east-1_123456789")
        self.username = env("COGNITO_TEST_USERNAME", "bob")
        self.password = env("COGNITO_TEST_PASSWORD", "bobpassword")
        self.user = Cognito(
            self.cognito_user_pool_id,
            self.app_id,
            username=self.username,
            client_secret=self.client_secret,
        )

    @patch("pycognito.aws_srp.AWSSRP.authenticate_user", _mock_authenticate_user)
    @patch("pycognito.Cognito.verify_token", _mock_verify_tokens)
    def test_authenticate(self):

        self.user.authenticate(self.password)
        self.assertNotEqual(self.user.access_token, None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)

    @patch("pycognito.aws_srp.AWSSRP.authenticate_user", _mock_authenticate_user)
    @patch("pycognito.Cognito.verify_token", _mock_verify_tokens)
    def test_verify_token(self):
        self.user.authenticate(self.password)
        bad_access_token = "{}wrong".format(self.user.access_token)

        with self.assertRaises(TokenVerificationException):
            self.user.verify_token(bad_access_token, "access_token", "access")

    @patch("pycognito.Cognito", autospec=True)
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

    @patch("pycognito.aws_srp.AWSSRP.authenticate_user", _mock_authenticate_user)
    @patch("pycognito.Cognito.verify_token", _mock_verify_tokens)
    @patch("pycognito.Cognito._add_secret_hash", return_value=None)
    def test_renew_tokens(self, _):

        stub = Stubber(self.user.client)

        # By the stubber nature, we need to add the sequence
        # of calls for the AWS SRP auth to test the whole process
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

    @patch("pycognito.Cognito", autospec=True)
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
        # This is a sample JWT with an expiration time set to January, 1st, 3000
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

    @patch("pycognito.Cognito", autospec=True)
    def test_validate_verification(self, cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id, username=self.username)
        u.validate_verification("4321")

    @patch("pycognito.Cognito", autospec=True)
    def test_confirm_forgot_password(self, cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id, username=self.username)
        u.confirm_forgot_password("4553", "samplepassword")
        with self.assertRaises(TypeError):
            u.confirm_forgot_password(self.password)

    @patch("pycognito.aws_srp.AWSSRP.authenticate_user", _mock_authenticate_user)
    @patch("pycognito.Cognito.verify_token", _mock_verify_tokens)
    @patch("pycognito.Cognito.check_token", return_value=True)
    def test_change_password(self, _):
        # u = cognito_user(self.cognito_user_pool_id, self.app_id,
        #                  username=self.username)
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

    @patch("pycognito.Cognito.verify_token", _mock_verify_tokens)
    def test_admin_authenticate(self):

        stub = Stubber(self.user.client)

        # By the stubber nature, we need to add the sequence
        # of calls for the AWS SRP auth to test the whole process
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
                "AuthFlow": "ADMIN_NO_SRP_AUTH",
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


class AWSSRPTestCase(unittest.TestCase):
    def setUp(self):
        if env("USE_CLIENT_SECRET") == "True":
            self.client_secret = env("COGNITO_CLIENT_SECRET")
            self.app_id = env("COGNITO_APP_WITH_SECRET_ID", "app")
        else:
            self.app_id = env("COGNITO_APP_ID", "app")
            self.client_secret = None
        self.cognito_user_pool_id = env("COGNITO_USER_POOL_ID", "us-east-1_123456789")
        self.username = env("COGNITO_TEST_USERNAME")
        self.password = env("COGNITO_TEST_PASSWORD")
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

    @patch("pycognito.aws_srp.AWSSRP.get_auth_params", _mock_get_params)
    @patch("pycognito.aws_srp.AWSSRP.process_challenge", return_value={})
    def test_authenticate_user(self, _):

        stub = Stubber(self.aws.client)

        # By the stubber nature, we need to add the sequence
        # of calls for the AWS SRP auth to test the whole process
        stub.add_response(
            method="initiate_auth",
            service_response={
                "ChallengeName": "PASSWORD_VERIFIER",
                "ChallengeParameters": {},
            },
            expected_params={
                "AuthFlow": "USER_SRP_AUTH",
                "AuthParameters": _mock_get_params(None),
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
        self.assertEqual(
            self.aws.get_cognito_formatted_timestamp(
                datetime.datetime(2022, 1, 1, 0, 0, 0)
            ),
            "Sat Jan 1 00:00:00 UTC 2022",
        )

        self.assertEqual(
            self.aws.get_cognito_formatted_timestamp(
                datetime.datetime(2022, 1, 2, 12, 0, 0)
            ),
            "Sun Jan 2 12:00:00 UTC 2022",
        )

        self.assertEqual(
            self.aws.get_cognito_formatted_timestamp(
                datetime.datetime(2022, 1, 3, 9, 0, 0)
            ),
            "Mon Jan 3 09:00:00 UTC 2022",
        )

        self.assertEqual(
            self.aws.get_cognito_formatted_timestamp(
                datetime.datetime(2022, 12, 31, 23, 59, 59)
            ),
            "Sat Dec 31 23:59:59 UTC 2022",
        )


@moto.mock_aws
class UtilsTestCase(unittest.TestCase):
    username = "bob@test.com"
    password = "Test1234!"

    def setUp(self) -> None:

        cognitoidp_client = boto3.client("cognito-idp", region_name="us-east-1")

        user_pool = cognitoidp_client.create_user_pool(
            PoolName="pycognito-test-pool",
            AliasAttributes=[
                "email",
            ],
            UsernameAttributes=[
                "email",
            ],
        )
        self.user_pool_id = user_pool["UserPool"]["Id"]

        user_pool_client = cognitoidp_client.create_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientName="test-client",
            RefreshTokenValidity=1,
            AccessTokenValidity=1,
            IdTokenValidity=1,
            TokenValidityUnits={
                "AccessToken": "hour",
                "IdToken": "hour",
                "RefreshToken": "days",
            },
        )
        self.client_id = user_pool_client["UserPoolClient"]["ClientId"]

        cognitoidp_client.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            TemporaryPassword=self.password,
            MessageAction="SUPPRESS",
        )
        cognitoidp_client.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            Password=self.password,
            Permanent=True,
        )

    @requests_mock.Mocker()
    def test_srp_requests_http_auth(self, m):
        # Get Moto's static public jwks
        jwks_public_key_filename = os.path.join(
            os.path.dirname(moto.cognitoidp.__file__), "resources/jwks-public.json"
        )
        jwks_public_key_f = open(jwks_public_key_filename, "rb")

        # Create some test data
        test_data = str(uuid.uuid4())

        # Mock a test endpoint. We pretend this endpoint would require an Authorization header
        m.get("http://test.com", text=test_data)
        # Pycognito will automatically verify the token it receives. Mock the proper endpoint and return the static
        # key from above
        m.get(
            f"https://cognito-idp.us-east-1.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json",
            body=jwks_public_key_f,
        )

        now = datetime.datetime.utcnow()

        # Standup the actual Requests plugin
        srp_auth = RequestsSrpAuth(
            username=self.username,
            password=self.password,
            user_pool_id=self.user_pool_id,
            user_pool_region="us-east-1",
            client_id=self.client_id,
        )

        # Make the actual request
        req = requests.get("http://test.com", auth=srp_auth)
        req.raise_for_status()
        # Ensure the data returns matches the mocked endpoint
        self.assertEqual(test_data, req.text)

        # Get the access token used
        access_token_orig = srp_auth.cognito_client.access_token

        # Make a second request with a time 2 hours in the future
        with freezegun.freeze_time(now + datetime.timedelta(hours=2)):
            req = requests.get("http://test.com", auth=srp_auth)
            req.raise_for_status()

        access_token_new = srp_auth.cognito_client.access_token
        # Check that the access token was refreshed to a new one
        self.assertNotEqual(access_token_orig, access_token_new)


@moto.mock_aws
class AdminUpdateProfileTestCase(unittest.TestCase):
    username = "user@test.com"
    password = "Testing123!"

    def setUp(self) -> None:

        cognito_idp_client = boto3.client("cognito-idp", region_name="us-east-1")

        user_pool = cognito_idp_client.create_user_pool(
            PoolName="pycognito-test-pool",
            AliasAttributes=[
                "email",
            ],
            UsernameAttributes=[
                "email",
            ],
        )
        self.user_pool_id = user_pool["UserPool"]["Id"]

        cognito_idp_client.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            TemporaryPassword=self.password,
            MessageAction="SUPPRESS",
        )
        cognito_idp_client.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            Password=self.password,
            Permanent=True,
        )
        client_app = cognito_idp_client.create_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientName="test-client",
            RefreshTokenValidity=1,
            AccessTokenValidity=1,
            IdTokenValidity=1,
            TokenValidityUnits={
                "AccessToken": "hour",
                "IdToken": "hour",
                "RefreshToken": "days",
            },
        )
        self.client_id = client_app["UserPoolClient"]["ClientId"]

    def test_cognito_attr_list(self):
        assert (
            is_cognito_attr_list(
                [{"Name": "given_name", "Value": "John", "Bad_Key": "Test"}]
            )
            is False
        )
        assert (
            is_cognito_attr_list(
                [{"Name": "given_name", "Value": "John"}, {"Bad_Key": "Test"}]
            )
            is False
        )
        assert (
            is_cognito_attr_list(
                [
                    {"Name": "given_name", "Value": "John"},
                    {"Name": "middle_name", "Value": "Smith"},
                ]
            )
            is True
        )

    def test_user_admin_update_profile(self):
        cognito = Cognito(
            user_pool_id=self.user_pool_id,
            username=self.username,
            client_id=self.client_id,
        )
        cognito.authenticate(self.password)

        # verify attr dict from cognito_to_dict and dict_to_cognito works as expected
        cognito.admin_update_profile(attrs={"given_name": "John"})
        assert cognito.get_user().given_name == "John"

        # verify attr_map works as expected
        cognito.admin_update_profile(
            attrs={"gn": "Steve"}, attr_map={"given_name": "gn"}
        )
        assert cognito.get_user().given_name == "Steve"

        # verify that cognito formatted list works as expected
        cognito.admin_update_profile(
            attrs=[{"Name": "given_name", "Value": "Bob"}], username=self.username
        )
        assert cognito.get_user().given_name == "Bob"

        # is_cognito_attr_list returns False so dict_to_cognito is called which will fail on this bad list input
        try:
            cognito.admin_update_profile(
                attrs=[{"Name": "given_name", "Value": "John", "Bad_Key": "Test"}],
                username=self.username,
            )
        except AttributeError as err:
            self.assertEqual(str(err), "'list' object has no attribute 'items'")


if __name__ == "__main__":
    unittest.main()
