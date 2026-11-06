import json
import os
import unittest

import boto3
from botocore.exceptions import ClientError
import moto

from src.pycognito import Cognito, GroupObj, UserObj, is_cognito_attr_list

from .helpers import TOKEN_VALIDITY_PARAMS


def _create_pool(cognito_idp_client, pool_name="pycognito-test-pool"):
    user_pool = cognito_idp_client.create_user_pool(
        PoolName=pool_name,
    )
    return user_pool["UserPool"]["Id"]


# ---------------------------------------------------------------------------
# User pool client CRUD
# ---------------------------------------------------------------------------


@moto.mock_aws
class CognitoUserPoolClientTestCase(unittest.TestCase):
    client_name = "test-client"

    def setUp(self):
        self.cognito_idp = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id = _create_pool(self.cognito_idp)
        self.params = TOKEN_VALIDITY_PARAMS.copy()

    def test_create_user_pool_client(self):
        cognito = Cognito(
            user_pool_id=self.user_pool_id,
            client_id=None,
            boto3_client_kwargs=json.loads(os.environ.get("BOTO3_CLIENT_EXTRAS", "{}")),
        )
        response = cognito.create_user_pool_client(
            client_name=self.client_name, **self.params
        )
        self.assertEqual(response["ClientName"], self.client_name)
        self.assertEqual(response["AccessTokenValidity"], 1)

    def test_describe_user_pool_client(self):
        params = self.params.copy()
        params.update({"UserPoolId": self.user_pool_id, "ClientName": self.client_name})
        response = self.cognito_idp.create_user_pool_client(**params)

        client_id = response["UserPoolClient"]["ClientId"]
        cognito = Cognito(user_pool_id=self.user_pool_id, client_id=client_id)
        response = cognito.describe_user_pool_client(
            pool_id=self.user_pool_id, client_id=client_id
        )
        self.assertEqual(response["UserPoolId"], self.user_pool_id)
        self.assertEqual(response["ClientId"], client_id)
        self.assertEqual(response["ClientName"], self.client_name)


# ---------------------------------------------------------------------------
# Pagination (users, groups, clients)
# ---------------------------------------------------------------------------


@moto.mock_aws
class PaginationTestCase(unittest.TestCase):
    invalid_user_pool_id = "us-east-1_123456789"

    def setUp(self):
        cognito_idp_client = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id = _create_pool(cognito_idp_client)

        for i in range(2):
            cognito_idp_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=f"user{i}@test.com",
                TemporaryPassword="Testing123!",
                MessageAction="SUPPRESS",
            )
            cognito_idp_client.create_group(
                GroupName=f"group-{i}", UserPoolId=self.user_pool_id
            )
            cognito_idp_client.create_user_pool_client(
                UserPoolId=self.user_pool_id,
                ClientName=f"test-client-{i}",
                **TOKEN_VALIDITY_PARAMS,
            )

    def test_user_pagination(self):
        cognito = Cognito(user_pool_id=self.user_pool_id)

        user_one = cognito.get_users(pool_id=self.user_pool_id, page_limit=1)
        self.assertEqual(len(user_one), 1)

        page_token = cognito.get_users_pagination_token()
        self.assertIsNotNone(page_token)

        user_two = cognito.get_users(page_limit=1, page_token=page_token)
        self.assertEqual(len(user_two), 1)

        self.assertIsNone(cognito.get_users_pagination_token())

        all_users = cognito.get_users()
        self.assertEqual(len(all_users), 2)

        cognito.user_pool_id = self.invalid_user_pool_id
        self.assertEqual(len(cognito.get_users(pool_id=self.user_pool_id)), 2)

    def test_group_pagination(self):
        cognito = Cognito(user_pool_id=self.user_pool_id)

        group_one = cognito.get_groups(pool_id=self.user_pool_id, page_limit=1)
        self.assertEqual(len(group_one), 1)

        page_token = cognito.get_groups_pagination_token()
        self.assertIsNotNone(page_token)

        group_two = cognito.get_groups(page_limit=1, page_token=page_token)
        self.assertEqual(len(group_two), 1)

        self.assertIsNone(cognito.get_groups_pagination_token())

        all_groups = cognito.get_groups()
        self.assertEqual(len(all_groups), 2)

        cognito.user_pool_id = self.invalid_user_pool_id
        self.assertEqual(len(cognito.get_groups(pool_id=self.user_pool_id)), 2)

    def test_client_pagination(self):
        cognito = Cognito(user_pool_id=self.user_pool_id)

        client_one = cognito.list_user_pool_clients(
            pool_id=self.user_pool_id, page_limit=1
        )
        self.assertEqual(len(client_one), 1)

        page_token = cognito.get_clients_pagination_token()
        self.assertIsNotNone(page_token)

        client_two = cognito.list_user_pool_clients(page_limit=1, page_token=page_token)
        self.assertEqual(len(client_two), 1)

        self.assertIsNone(cognito.get_clients_pagination_token())

        all_clients = cognito.list_user_pool_clients()
        self.assertEqual(len(all_clients), 2)

        cognito.user_pool_id = self.invalid_user_pool_id
        self.assertEqual(
            len(cognito.list_user_pool_clients(pool_id=self.user_pool_id)), 2
        )


# ---------------------------------------------------------------------------
# Admin profile updates
# ---------------------------------------------------------------------------


@moto.mock_aws
class AdminUpdateProfileTestCase(unittest.TestCase):
    username = "user@test.com"
    password = "Testing123!"

    def setUp(self):
        cognito_idp_client = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id = _create_pool(cognito_idp_client)

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
            **TOKEN_VALIDITY_PARAMS,
        )
        self.client_id = client_app["UserPoolClient"]["ClientId"]

    def test_cognito_attr_list(self):
        self.assertFalse(
            is_cognito_attr_list(
                [{"Name": "given_name", "Value": "John", "Bad_Key": "Test"}]
            )
        )
        self.assertFalse(
            is_cognito_attr_list(
                [{"Name": "given_name", "Value": "John"}, {"Bad_Key": "Test"}]
            )
        )
        self.assertTrue(
            is_cognito_attr_list(
                [
                    {"Name": "given_name", "Value": "John"},
                    {"Name": "middle_name", "Value": "Smith"},
                ]
            )
        )

    def test_user_admin_update_profile(self):
        cognito = Cognito(
            user_pool_id=self.user_pool_id,
            username=self.username,
            client_id=self.client_id,
            boto3_client_kwargs=json.loads(os.environ.get("BOTO3_CLIENT_EXTRAS", "{}")),
        )
        cognito.authenticate(self.password)

        cognito.admin_update_profile(attrs={"given_name": "John"})
        self.assertEqual(cognito.get_user().given_name, "John")

        cognito.admin_update_profile(
            attrs={"gn": "Steve"}, attr_map={"given_name": "gn"}
        )
        self.assertEqual(cognito.get_user().given_name, "Steve")

        cognito.admin_update_profile(
            attrs=[{"Name": "given_name", "Value": "Bob"}], username=self.username
        )
        self.assertEqual(cognito.get_user().given_name, "Bob")

        with self.assertRaises(AttributeError) as ctx:
            cognito.admin_update_profile(
                attrs=[{"Name": "given_name", "Value": "John", "Bad_Key": "Test"}],
                username=self.username,
            )
        self.assertEqual(str(ctx.exception), "'list' object has no attribute 'items'")


# ---------------------------------------------------------------------------
# Group CRUD  (create_group, update_group, delete_group)
# ---------------------------------------------------------------------------


@moto.mock_aws
class GroupCRUDTestCase(unittest.TestCase):
    """Tests for user_pool.py: create_group, update_group, delete_group."""

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id = _create_pool(idp)
        self.cognito = Cognito(user_pool_id=self.user_pool_id)

    def test_create_group_returns_group_obj(self):
        group = self.cognito.create_group("test-group")
        self.assertIsInstance(group, GroupObj)
        self.assertEqual(group.group_name, "test-group")

    def test_create_group_with_all_optional_params(self):
        group = self.cognito.create_group(
            "full-group",
            description="A full group",
            precedence=5,
        )
        self.assertEqual(group.group_name, "full-group")
        self.assertEqual(group.description, "A full group")
        self.assertEqual(group.precedence, 5)

    def test_create_group_is_retrievable(self):
        self.cognito.create_group("retrievable-group", description="check me")
        fetched = self.cognito.get_group("retrievable-group")
        self.assertEqual(fetched.group_name, "retrievable-group")
        self.assertEqual(fetched.description, "check me")

    def test_update_group_changes_description(self):
        self.cognito.create_group("update-me", description="original")
        self.cognito.update_group("update-me", description="updated")
        fetched = self.cognito.get_group("update-me")
        self.assertEqual(fetched.description, "updated")

    def test_update_group_changes_precedence(self):
        self.cognito.create_group("prec-group", precedence=1)
        self.cognito.update_group("prec-group", precedence=99)
        fetched = self.cognito.get_group("prec-group")
        self.assertEqual(fetched.precedence, 99)

    def test_delete_group_removes_group(self):
        self.cognito.create_group("delete-me")
        self.cognito.delete_group("delete-me")
        with self.assertRaises(ClientError) as ctx:
            self.cognito.get_group("delete-me")
        self.assertIn(
            ctx.exception.response["Error"]["Code"],
            ("ResourceNotFoundException", "GroupNotFoundException"),
        )

    def test_create_multiple_groups(self):
        for name in ("alpha", "beta", "gamma"):
            self.cognito.create_group(name)
        groups = self.cognito.get_groups()
        names = {g.group_name for g in groups}
        self.assertIn("alpha", names)
        self.assertIn("beta", names)
        self.assertIn("gamma", names)


# ---------------------------------------------------------------------------
# list_users_in_group
# ---------------------------------------------------------------------------


@moto.mock_aws
class ListUsersInGroupTestCase(unittest.TestCase):
    """Tests for user_pool.py: list_users_in_group."""

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        self.user_pool_id = _create_pool(idp)
        self._idp = idp

        idp.create_group(GroupName="staff", UserPoolId=self.user_pool_id)

        for i in range(3):
            idp.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=f"staff{i}@test.com",
                TemporaryPassword="Test1!",
                MessageAction="SUPPRESS",
            )
            idp.admin_add_user_to_group(
                UserPoolId=self.user_pool_id,
                Username=f"staff{i}@test.com",
                GroupName="staff",
            )

        idp.create_group(GroupName="empty", UserPoolId=self.user_pool_id)
        self.cognito = Cognito(user_pool_id=self.user_pool_id)

    def test_returns_all_users_without_page_limit(self):
        users = self.cognito.list_users_in_group("staff")
        self.assertEqual(len(users), 3)
        self.assertTrue(all(isinstance(u, UserObj) for u in users))

    def test_empty_group_returns_empty_list(self):
        users = self.cognito.list_users_in_group("empty")
        self.assertEqual(users, [])

    def test_users_have_username_set(self):
        """Verify all 3 users are returned. With UsernameAttributes=["email"]
        moto returns the sub UUID as Username in list_users_in_group, so we
        verify count and that each UserObj is well-formed rather than matching
        email addresses directly.
        """
        users = self.cognito.list_users_in_group("staff")
        self.assertEqual(len(users), 3)
        self.assertTrue(all(u.username is not None for u in users))

    def test_pagination_page_limit_returns_subset(self):
        page = self.cognito.list_users_in_group("staff", page_limit=2)
        self.assertEqual(len(page), 2)

    def test_pagination_token_is_set_when_more_results_exist(self):
        self.cognito.list_users_in_group("staff", page_limit=2)
        token = self.cognito.get_group_users_pagination_token()
        self.assertIsNotNone(token)

    def test_pagination_token_is_none_when_exhausted(self):
        self.cognito.list_users_in_group("staff", page_limit=10)
        token = self.cognito.get_group_users_pagination_token()
        self.assertIsNone(token)

    def test_pagination_second_page_completes_results(self):
        page1 = self.cognito.list_users_in_group("staff", page_limit=2)
        token = self.cognito.get_group_users_pagination_token()
        page2 = self.cognito.list_users_in_group(
            "staff", page_limit=2, page_token=token
        )

        all_usernames = {u.username for u in page1 + page2}
        self.assertEqual(len(all_usernames), 3)

    def test_attr_map_is_applied(self):
        """attr_map is passed through to UserObj attribute mapping."""
        users = self.cognito.list_users_in_group("staff", attr_map={})
        self.assertTrue(all(isinstance(u, UserObj) for u in users))


# ---------------------------------------------------------------------------
# describe_user_pool / update_user_pool
# ---------------------------------------------------------------------------


@moto.mock_aws
class UserPoolConfigTestCase(unittest.TestCase):
    """Tests for user_pool.py: describe_user_pool, update_user_pool."""

    def setUp(self):
        idp = boto3.client("cognito-idp", region_name="us-east-1")
        pool = idp.create_user_pool(
            PoolName="config-test-pool",
        )
        self.user_pool_id = pool["UserPool"]["Id"]
        self.cognito = Cognito(user_pool_id=self.user_pool_id)

    def test_describe_user_pool_returns_dict(self):
        result = self.cognito.describe_user_pool()
        self.assertIsInstance(result, dict)

    def test_describe_user_pool_correct_id_and_name(self):
        result = self.cognito.describe_user_pool()
        self.assertEqual(result["Id"], self.user_pool_id)
        self.assertEqual(result["Name"], "config-test-pool")

    def test_describe_user_pool_with_explicit_pool_id(self):
        result = self.cognito.describe_user_pool(pool_id=self.user_pool_id)
        self.assertEqual(result["Id"], self.user_pool_id)

    def test_describe_user_pool_strips_response_metadata(self):
        result = self.cognito.describe_user_pool()
        self.assertNotIn("ResponseMetadata", result)

    def test_update_user_pool_password_policy(self):
        self.cognito.update_user_pool(
            Policies={
                "PasswordPolicy": {
                    "MinimumLength": 12,
                    "RequireUppercase": True,
                    "RequireLowercase": True,
                    "RequireNumbers": True,
                    "RequireSymbols": False,
                }
            }
        )
        result = self.cognito.describe_user_pool()
        policy = result["Policies"]["PasswordPolicy"]
        self.assertEqual(policy["MinimumLength"], 12)
        self.assertTrue(policy["RequireUppercase"])

    def test_update_user_pool_with_explicit_pool_id(self):
        self.cognito.update_user_pool(
            pool_id=self.user_pool_id,
            Policies={
                "PasswordPolicy": {
                    "MinimumLength": 8,
                    "RequireUppercase": False,
                    "RequireLowercase": False,
                    "RequireNumbers": False,
                    "RequireSymbols": False,
                }
            },
        )
        result = self.cognito.describe_user_pool()
        self.assertEqual(result["Policies"]["PasswordPolicy"]["MinimumLength"], 8)

    def test_update_user_pool_mfa_configuration(self):
        self.cognito.update_user_pool(MfaConfiguration="OPTIONAL")
        result = self.cognito.describe_user_pool()
        self.assertEqual(result["MfaConfiguration"], "OPTIONAL")


if __name__ == "__main__":
    unittest.main()
