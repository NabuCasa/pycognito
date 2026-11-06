"""
Token verification with real RSA-signed JWTs, AWSSRP challenge handling,
device HTTP calls, Cognito constructor options, and attribute helpers.
"""

import base64
import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pendulum
import requests_mock

from src.pycognito import Cognito, TokenVerificationException
from src.pycognito.aws_srp import AWSSRP, generate_hash_device
from src.pycognito.exceptions import (
    ForceChangePasswordException,
    MFAChallengeException,
    SMSMFAChallengeException,
    SoftwareTokenMFAChallengeException,
)
from src.pycognito.utils import (
    camel_to_snake,
    cognito_to_dict,
    dict_to_cognito,
    is_cognito_attr_list,
    snake_to_camel,
)

POOL_ID = "us-east-1_123456789"
CLIENT_ID = "testclientid"
ISSUER = f"https://cognito-idp.us-east-1.amazonaws.com/{POOL_ID}"
KID = "test-kid"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWK = jwt.algorithms.RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key(), as_dict=True)
_JWK.update({"kid": KID, "alg": "RS256", "use": "sig"})
JWKS = {"keys": [_JWK]}


def make_token(use, kid=KID, **claims):
    payload = {
        "iss": ISSUER,
        "exp": pendulum.now("UTC").add(hours=1).int_timestamp,
        "iat": pendulum.now("UTC").int_timestamp,
        "token_use": use,
    }
    if use == "id":
        payload["aud"] = CLIENT_ID
    payload.update(claims)
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": kid})


def at_hash(access_token):
    digest = hashlib.sha256(access_token.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# TokensMixin
# ---------------------------------------------------------------------------


class VerifyTokensTestCase(unittest.TestCase):
    def _cognito(self, **kwargs):
        cognito = Cognito(POOL_ID, CLIENT_ID, **kwargs)
        cognito.pool_jwk = JWKS
        return cognito

    def test_verify_tokens_sets_tokens_and_claims(self):
        access = make_token("access", username="bob")
        id_token = make_token("id", at_hash=at_hash(access), email="bob@example.com")
        cognito = self._cognito(access_token=access, id_token=id_token)
        cognito.verify_tokens()
        self.assertEqual(cognito.access_claims["username"], "bob")
        self.assertEqual(cognito.id_claims["email"], "bob@example.com")

    def test_token_use_mismatch(self):
        cognito = self._cognito()
        with self.assertRaisesRegex(TokenVerificationException, "token use"):
            cognito.verify_token(
                make_token("access", token_use="id"), "access_token", "access"
            )

    def test_wrong_audience(self):
        cognito = self._cognito()
        token = make_token("id", aud="another-client")
        with self.assertRaises(TokenVerificationException):
            cognito.verify_token(token, "id_token", "id")

    def test_expired_token(self):
        cognito = self._cognito()
        token = make_token(
            "access", exp=pendulum.now("UTC").subtract(hours=1).int_timestamp
        )
        with self.assertRaises(TokenVerificationException):
            cognito.verify_token(token, "access_token", "access")

    def test_at_hash_mismatch(self):
        cognito = self._cognito(access_token=make_token("access"))
        token = make_token("id", at_hash="not-the-right-hash")
        with self.assertRaisesRegex(TokenVerificationException, "at_hash"):
            cognito.verify_token(token, "id_token", "id")

    def test_non_integer_iat(self):
        cognito = self._cognito()
        token = make_token("access", iat="not-a-number")
        with self.assertRaisesRegex(TokenVerificationException, "iat"):
            cognito.verify_token(token, "access_token", "access")

    def test_unknown_kid(self):
        cognito = self._cognito()
        token = make_token("access", kid="rotated-away")
        with self.assertRaisesRegex(TokenVerificationException, "rotated-away"):
            cognito.verify_token(token, "access_token", "access")

    def test_get_keys_from_environment(self):
        cognito = Cognito(POOL_ID, CLIENT_ID)
        with patch.dict(os.environ, {"COGNITO_JWKS": json.dumps(JWKS)}):
            self.assertEqual(cognito.get_keys(), JWKS)
        self.assertEqual(cognito.get_key(KID), _JWK)

    def test_get_keys_fetches_and_caches_well_known_jwks(self):
        cognito = Cognito(POOL_ID, CLIENT_ID)
        with patch.dict(os.environ, {}, clear=False) as env:
            env.pop("COGNITO_JWKS", None)
            with requests_mock.Mocker() as m:
                m.get(f"{ISSUER}/.well-known/jwks.json", json=JWKS)
                self.assertEqual(cognito.get_keys(), JWKS)
                cognito.get_keys()
                self.assertEqual(m.call_count, 1)


class CheckTokenTestCase(unittest.TestCase):
    def test_requires_access_token(self):
        with self.assertRaises(AttributeError):
            Cognito(POOL_ID, CLIENT_ID).check_token()

    def test_valid_token_is_not_renewed(self):
        cognito = Cognito(POOL_ID, CLIENT_ID, access_token=make_token("access"))
        with patch.object(Cognito, "renew_access_token") as renew:
            self.assertFalse(cognito.check_token())
        renew.assert_not_called()

    def test_expired_token_is_renewed(self):
        expired = make_token(
            "access", exp=pendulum.now("UTC").subtract(minutes=1).int_timestamp
        )
        cognito = Cognito(POOL_ID, CLIENT_ID, access_token=expired)
        with patch.object(Cognito, "renew_access_token") as renew:
            self.assertTrue(cognito.check_token())
        renew.assert_called_once()

    def test_expired_token_not_renewed_when_renew_false(self):
        expired = make_token(
            "access", exp=pendulum.now("UTC").subtract(minutes=1).int_timestamp
        )
        cognito = Cognito(POOL_ID, CLIENT_ID, access_token=expired)
        with patch.object(Cognito, "renew_access_token") as renew:
            self.assertTrue(cognito.check_token(renew=False))
        renew.assert_not_called()


# ---------------------------------------------------------------------------
# Cognito constructor options
# ---------------------------------------------------------------------------


class ConstructorTestCase(unittest.TestCase):
    def test_region_derived_from_pool_id(self):
        cognito = Cognito("eu-west-1_abc", CLIENT_ID)
        self.assertEqual(cognito.user_pool_region, "eu-west-1")
        self.assertEqual(cognito.client.meta.region_name, "eu-west-1")

    def test_explicit_region_and_static_credentials(self):
        cognito = Cognito(
            POOL_ID,
            CLIENT_ID,
            user_pool_region="ap-southeast-2",
            access_key="AKIAEXAMPLE",
            secret_key="secret",
        )
        credentials = cognito.client._request_signer._credentials
        self.assertEqual(cognito.client.meta.region_name, "ap-southeast-2")
        self.assertEqual(credentials.access_key, "AKIAEXAMPLE")
        self.assertEqual(credentials.secret_key, "secret")

    def test_endpoint_url_changes_user_pool_url(self):
        cognito = Cognito(
            POOL_ID,
            CLIENT_ID,
            boto3_client_kwargs={"endpoint_url": "http://localhost:9229"},
        )
        self.assertEqual(cognito.user_pool_url, f"http://localhost:9229/{POOL_ID}")
        self.assertEqual(cognito.client.meta.endpoint_url, "http://localhost:9229")

    def test_default_user_pool_url(self):
        self.assertEqual(Cognito(POOL_ID, CLIENT_ID).user_pool_url, ISSUER)

    def test_botocore_config_is_used(self):
        config = Config(connect_timeout=7)
        cognito = Cognito(POOL_ID, CLIENT_ID, botocore_config=config)
        self.assertEqual(cognito.client.meta.config.connect_timeout, 7)

    def test_session_creates_client(self):
        session = MagicMock()
        cognito = Cognito(POOL_ID, CLIENT_ID, session=session)
        session.client.assert_called_once_with("cognito-idp", region_name="us-east-1")
        self.assertIs(cognito.client, session.client.return_value)


# ---------------------------------------------------------------------------
# AWSSRP
# ---------------------------------------------------------------------------

CHALLENGE_PARAMS = {
    "USERNAME": "bob",
    "USER_ID_FOR_SRP": "bob",
    "SALT": "a1b2c3d4e5f6",
    "SRP_B": "ab" * 192,
    "SECRET_BLOCK": base64.standard_b64encode(b"secret-block").decode(),
}
SESSION = "session-" + "x" * 20
TOKENS = {
    "AuthenticationResult": {
        "AccessToken": "a",
        "IdToken": "i",
        "RefreshToken": "r",
        "TokenType": "Bearer",
    }
}


class AWSSRPConstructorTestCase(unittest.TestCase):
    def test_region_and_client_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            AWSSRP("bob", "pw", POOL_ID, CLIENT_ID, pool_region="us-east-1", client=1)

    def test_partial_device_arguments_rejected(self):
        with self.assertRaises(ValueError):
            AWSSRP(
                "bob", "pw", POOL_ID, CLIENT_ID, pool_region="us-east-1", device_key="k"
            )


class AWSSRPParamsTestCase(unittest.TestCase):
    def setUp(self):
        self.aws = AWSSRP(
            "bob",
            "pw",
            POOL_ID,
            CLIENT_ID,
            pool_region="us-east-1",
            client_secret="client-secret",
            device_key="us-east-1_dev",
            device_group_key="group",
            device_password="device-pw",
        )

    def test_auth_params_include_secret_hash_and_device_key(self):
        params = self.aws.get_auth_params()
        self.assertEqual(
            params["SECRET_HASH"],
            AWSSRP.get_secret_hash("bob", CLIENT_ID, "client-secret"),
        )
        self.assertEqual(params["DEVICE_KEY"], "us-east-1_dev")

    def test_process_challenge_includes_secret_hash_and_device_key(self):
        response = self.aws.process_challenge(CHALLENGE_PARAMS, {"USERNAME": "bob"})
        self.assertEqual(response["USERNAME"], "bob")
        self.assertIn("PASSWORD_CLAIM_SIGNATURE", response)
        self.assertIn("SECRET_HASH", response)
        self.assertEqual(response["DEVICE_KEY"], "us-east-1_dev")

    def test_process_device_challenge(self):
        response = self.aws.process_device_challenge(CHALLENGE_PARAMS)
        self.assertEqual(response["DEVICE_KEY"], "us-east-1_dev")
        self.assertIn("PASSWORD_CLAIM_SIGNATURE", response)
        self.assertIn("SECRET_HASH", response)

    def test_generate_hash_device(self):
        password, config = generate_hash_device("group", "us-east-1_dev")
        self.assertEqual(len(base64.standard_b64decode(password)), 40)
        self.assertEqual(set(config), {"PasswordVerifier", "Salt"})


@patch.object(AWSSRP, "process_challenge", return_value={"USERNAME": "bob"})
class AWSSRPAuthenticateTestCase(unittest.TestCase):
    def setUp(self):
        self.client = boto3.client("cognito-idp", region_name="us-east-1")
        self.stub = Stubber(self.client)
        self.stub.activate()
        self.aws = AWSSRP("bob", "pw", POOL_ID, CLIENT_ID, client=self.client)

    def tearDown(self):
        self.stub.deactivate()

    def _initiate(self, challenge="PASSWORD_VERIFIER"):
        self.stub.add_response(
            "initiate_auth",
            {"ChallengeName": challenge, "ChallengeParameters": CHALLENGE_PARAMS},
        )

    def _respond(self, response, expected=None):
        self.stub.add_response("respond_to_auth_challenge", response, expected)

    def test_client_metadata_is_forwarded(self, _):
        self._initiate()
        self._respond(
            TOKENS,
            {
                "ClientId": CLIENT_ID,
                "ChallengeName": "PASSWORD_VERIFIER",
                "ChallengeResponses": {"USERNAME": "bob"},
                "ClientMetadata": {"k": "v"},
            },
        )
        self.assertEqual(self.aws.authenticate_user(client_metadata={"k": "v"}), TOKENS)

    def test_new_password_required_raises(self, _):
        self._initiate()
        self._respond({"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": SESSION})
        with self.assertRaises(ForceChangePasswordException):
            self.aws.authenticate_user()

    def test_sms_mfa_raises_with_tokens(self, _):
        self._initiate()
        self._respond({"ChallengeName": "SMS_MFA", "Session": SESSION})
        with self.assertRaises(SMSMFAChallengeException) as ctx:
            self.aws.authenticate_user()
        self.assertIsInstance(ctx.exception, MFAChallengeException)
        self.assertEqual(ctx.exception.get_tokens()["Session"], SESSION)

    def test_software_token_mfa_raises(self, _):
        self._initiate()
        self._respond({"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": SESSION})
        with self.assertRaises(SoftwareTokenMFAChallengeException):
            self.aws.authenticate_user()

    def test_unsupported_initial_challenge(self, _):
        self._initiate("CUSTOM_CHALLENGE")
        with self.assertRaises(NotImplementedError):
            self.aws.authenticate_user()

    @patch.object(AWSSRP, "process_device_challenge", return_value={"USERNAME": "bob"})
    def test_device_srp_flow(self, *_):
        self.aws.device_key = "us-east-1_dev"
        self._initiate()
        self._respond({"ChallengeName": "DEVICE_SRP_AUTH"})
        self._respond(
            {"ChallengeName": "DEVICE_PASSWORD_VERIFIER", "ChallengeParameters": {}}
        )
        self._respond(TOKENS)
        self.assertEqual(self.aws.authenticate_user(), TOKENS)
        self.stub.assert_no_pending_responses()

    def test_set_new_password_challenge(self, _):
        self._initiate()
        self._respond({"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": SESSION})
        self._respond(
            TOKENS,
            {
                "ClientId": CLIENT_ID,
                "ChallengeName": "NEW_PASSWORD_REQUIRED",
                "Session": SESSION,
                "ChallengeResponses": {"USERNAME": "bob", "NEW_PASSWORD": "new-pw"},
            },
        )
        self.assertEqual(self.aws.set_new_password_challenge("new-pw"), TOKENS)

    def test_set_new_password_challenge_when_not_required(self, _):
        self._initiate()
        self._respond(TOKENS)
        self.assertEqual(self.aws.set_new_password_challenge("new-pw"), TOKENS)

    def test_set_new_password_unsupported_challenge(self, _):
        self._initiate("CUSTOM_CHALLENGE")
        with self.assertRaises(NotImplementedError):
            self.aws.set_new_password_challenge("new-pw")


class AWSSRPDeviceHttpTestCase(unittest.TestCase):
    URL = "https://cognito-idp.us-east-1.amazonaws.com/"

    def setUp(self):
        self.aws = AWSSRP("bob", "pw", POOL_ID, CLIENT_ID, pool_region="us-east-1")

    def test_confirm_device(self):
        tokens = {
            "AuthenticationResult": {
                "AccessToken": "access",
                "NewDeviceMetadata": {
                    "DeviceKey": "us-east-1_dev",
                    "DeviceGroupKey": "group",
                },
            }
        }
        with requests_mock.Mocker() as m:
            m.post(self.URL, json={"UserConfirmationNecessary": False})
            _, device_password = self.aws.confirm_device(tokens, device_name="laptop")
            body = m.last_request.json()
            headers = m.last_request.headers
        self.assertTrue(device_password)
        self.assertEqual(body["DeviceKey"], "us-east-1_dev")
        self.assertEqual(body["DeviceName"], "laptop")
        self.assertIn("DeviceSecretVerifierConfig", body)
        self.assertTrue(headers["X-Amz-Target"].endswith("ConfirmDevice"))

    def test_update_device_status(self):
        for remembered, status in ((True, "remembered"), (False, "not_remembered")):
            with requests_mock.Mocker() as m:
                m.post(self.URL, json={})
                self.aws.update_device_status(remembered, "access", "us-east-1_dev")
                self.assertEqual(
                    m.last_request.json()["DeviceRememberedStatus"], status
                )

    def test_update_device_status_requires_bool(self):
        with self.assertRaises(ValueError):
            self.aws.update_device_status("yes", "access", "us-east-1_dev")

    def test_forget_device(self):
        with requests_mock.Mocker() as m:
            m.post(self.URL, json={})
            self.aws.forget_device("access", "us-east-1_dev")
            self.assertEqual(
                m.last_request.json(),
                {"AccessToken": "access", "DeviceKey": "us-east-1_dev"},
            )
            self.assertTrue(
                m.last_request.headers["X-Amz-Target"].endswith("ForgetDevice")
            )


# ---------------------------------------------------------------------------
# Attribute and case helpers
# ---------------------------------------------------------------------------


class AttributeHelpersTestCase(unittest.TestCase):
    def test_cognito_to_dict_converts_booleans_and_maps_names(self):
        attrs = [
            {"Name": "email_verified", "Value": "true"},
            {"Name": "given_name", "Value": "Bob"},
        ]
        self.assertEqual(
            cognito_to_dict(attrs, {"given_name": "first_name"}),
            {"email_verified": True, "first_name": "Bob"},
        )
        self.assertEqual(
            cognito_to_dict([{"Name": "x", "Value": "false"}]), {"x": False}
        )

    def test_dict_to_cognito_normalises_booleans_and_maps_names(self):
        self.assertEqual(
            dict_to_cognito(
                {"first_name": "Bob", "flag": True}, {"given_name": "first_name"}
            ),
            [{"Name": "flag", "Value": "true"}, {"Name": "given_name", "Value": "Bob"}],
        )
        self.assertEqual(
            dict_to_cognito({"flag": False}), [{"Name": "flag", "Value": "false"}]
        )

    def test_is_cognito_attr_list_rejects_non_dict_items(self):
        self.assertFalse(is_cognito_attr_list(["email"]))
        self.assertFalse(is_cognito_attr_list({"Name": "email"}))
        self.assertFalse(is_cognito_attr_list([{"Name": "a", "Other": "b"}]))
        self.assertTrue(is_cognito_attr_list([{"Name": "a", "Value": "b"}]))

    def test_case_conversion(self):
        self.assertEqual(camel_to_snake("UserPoolId"), "user_pool_id")
        self.assertEqual(snake_to_camel("user_pool_id"), "userPoolId")


if __name__ == "__main__":
    unittest.main()
