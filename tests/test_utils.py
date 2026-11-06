import gzip
import json
import os.path
import unittest
from unittest.mock import patch
import uuid

import boto3
import moto
import moto.cognitoidp
import pendulum
import requests
import requests_mock

from src.pycognito.utils import RequestsSrpAuth


@moto.mock_aws
class UtilsTestCase(unittest.TestCase):
    username = "bob@test.com"
    password = "Test1234!"

    def setUp(self) -> None:
        cognitoidp_client = boto3.client("cognito-idp", region_name="us-east-1")

        user_pool = cognitoidp_client.create_user_pool(
            PoolName="pycognito-test-pool",
        )
        self.user_pool_id = user_pool["UserPool"]["Id"]

        user_pool_client = cognitoidp_client.create_user_pool_client(
            UserPoolId=self.user_pool_id,
            ClientName="test-client",
            RefreshTokenValidity=1,
            AccessTokenValidity=1,
            IdTokenValidity=1,
            TokenValidityUnits={
                "AccessToken": "hours",
                "IdToken": "hours",
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
        # Load Moto's static public JWKS
        jwks_public_key_filename = os.path.join(
            os.path.dirname(moto.cognitoidp.__file__), "resources/jwks-public.json.gz"
        )
        with gzip.open(jwks_public_key_filename, "rb") as f:
            jwks_public_keys = json.loads(f.read().decode("utf-8"))

        test_data = str(uuid.uuid4())
        m.get("http://test.com", text=test_data)
        m.get(
            f"https://cognito-idp.us-east-1.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json",
            json=jwks_public_keys,
        )

        # Capture the real current time; we will patch pendulum.now to this + 2h below
        now = pendulum.now("UTC")

        srp_auth = RequestsSrpAuth(
            username=self.username,
            password=self.password,
            user_pool_id=self.user_pool_id,
            user_pool_region="us-east-1",
            client_id=self.client_id,
            boto3_client_kwargs=json.loads(os.environ.get("BOTO3_CLIENT_EXTRAS", "{}")),
        )

        req = requests.get("http://test.com", auth=srp_auth)
        req.raise_for_status()
        self.assertEqual(test_data, req.text)

        access_token_orig = srp_auth.cognito_client.access_token

        # Advance time 2 hours by patching pendulum.now directly.
        with patch("pendulum.now", return_value=now.add(hours=2)):
            req = requests.get("http://test.com", auth=srp_auth)
            req.raise_for_status()

        access_token_new = srp_auth.cognito_client.access_token
        self.assertNotEqual(access_token_orig, access_token_new)


if __name__ == "__main__":
    unittest.main()
