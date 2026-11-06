import os
import unittest

from src.pycognito import Cognito, GroupObj, UserObj


class UserObjTestCase(unittest.TestCase):
    def setUp(self):
        if os.environ.get("USE_CLIENT_SECRET", "False") == "True":
            self.app_id = os.environ.get("COGNITO_APP_WITH_SECRET_ID")
        else:
            self.app_id = os.environ.get("COGNITO_APP_ID")
        self.cognito_user_pool_id = os.environ.get(
            "COGNITO_USER_POOL_ID", "us-east-1_123456789"
        )
        self.username = os.environ.get("COGNITO_TEST_USERNAME")

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
        if os.environ.get("USE_CLIENT_SECRET", "False") == "True":
            self.app_id = os.environ.get("COGNITO_APP_WITH_SECRET_ID")
        else:
            self.app_id = os.environ.get("COGNITO_APP_ID")
        self.cognito_user_pool_id = os.environ.get(
            "COGNITO_USER_POOL_ID", "us-east-1_123456789"
        )
        self.group_data = {"GroupName": "test_group", "Precedence": 1}
        self.cognito_obj = Cognito(
            user_pool_id=self.cognito_user_pool_id, client_id=self.app_id
        )

    def test_init(self):
        group = GroupObj(group_data=self.group_data, cognito_obj=self.cognito_obj)
        self.assertEqual(group.group_name, "test_group")
        self.assertEqual(group.precedence, 1)


if __name__ == "__main__":
    unittest.main()
