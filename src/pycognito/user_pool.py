"""
UserPoolMixin — user, group, pool-client, and identity-provider management.

All methods here are exercised by CognitoUserPoolClientTestCase,
PaginationTestCase, and AdminUpdateProfileTestCase in test_user_pool.py.
"""

from __future__ import annotations

from typing import List, Union

from ._base import CognotoBase
from .utils import dict_to_cognito, is_cognito_attr_list


class UserPoolMixin(CognotoBase):
    """Mixin providing user, group, pool-client, and identity-provider operations."""

    # ------------------------------------------------------------------
    # Pagination token accessors
    # ------------------------------------------------------------------

    def get_users_pagination_token(self) -> Union[str, None]:
        """Return the pagination token set by the last get_users call."""
        return self._users_pagination_next_token

    def get_groups_pagination_token(self) -> Union[str, None]:
        """Return the pagination token set by the last get_groups call."""
        return self._groups_pagination_next_token

    def get_clients_pagination_token(self) -> Union[str, None]:
        """Return the pagination token set by the last list_user_pool_clients call."""
        return self._clients_pagination_next_token

    def get_group_users_pagination_token(self) -> Union[str, None]:
        """Return the pagination token set by the last list_users_in_group call."""
        return self._group_users_pagination_next_token

    def get_devices_pagination_token(self) -> Union[str, None]:
        """Return the pagination token set by the last list_devices or admin_list_devices call."""
        return self._devices_pagination_next_token

    # ------------------------------------------------------------------
    # Object factories
    # ------------------------------------------------------------------

    def get_user_obj(
        self, username=None, attribute_list=None, metadata=None, attr_map=None
    ):
        """
        Instantiate self.user_class from raw Cognito data.
        :param username: Username (defaults to self.username or metadata["username"])
        :param attribute_list: Raw Cognito attribute list
        :param metadata: Extra metadata dict (user_status, create_date, etc.)
        :param attr_map: Mapping from Cognito attribute names to local names
        :return: self.user_class instance
        """
        if username is None:
            if metadata is None:
                username = self.username
            else:
                username = self.username or metadata.get("username")

        return self.user_class(
            username=username,
            attribute_list=attribute_list,
            cognito_obj=self,
            metadata=metadata,
            attr_map=attr_map,
        )

    def get_group_obj(self, group_data):
        """
        Instantiate self.group_class from raw Cognito group data.
        :param group_data: Raw group dict from list_groups / get_group
        :return: self.group_class instance
        """
        return self.group_class(group_data=group_data, cognito_obj=self)

    # ------------------------------------------------------------------
    # User read operations
    # ------------------------------------------------------------------

    def get_user(self, attr_map=None):
        """
        Return a UserObj for the authenticated user (uses self.access_token).
        :param attr_map: Attribute map applied to the returned UserObj
        :return: UserObj instance
        """
        user = self.client.get_user(AccessToken=self.access_token)
        user_metadata = {
            "username": user.get("Username"),
            "id_token": self.id_token,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
        }
        return self.get_user_obj(
            username=self.username,
            attribute_list=user.get("UserAttributes"),
            metadata=user_metadata,
            attr_map=attr_map,
        )

    def get_users(
        self,
        attr_map=None,
        pool_id: Union[str, None] = None,
        page_limit: Union[int, None] = None,
        page_token: Union[str, None] = None,
    ):
        """
        Return all users for a user pool as UserObj instances.
        When page_limit is set returns that many results (1–60) and stores the
        next-page token in self._users_pagination_next_token.
        :param attr_map: Attribute map applied to each UserObj
        :param pool_id: User pool ID (defaults to self.user_pool_id)
        :param page_limit: Max results from this request (1–60)
        :param page_token: Pagination token from a previous call
        :return: List of self.user_class instances
        """
        if pool_id is None:
            pool_id = self.user_pool_id

        kwargs = {"UserPoolId": pool_id}
        if page_limit:
            kwargs["Limit"] = page_limit
        if page_token:
            kwargs["PaginationToken"] = page_token

        response = self.client.list_users(**kwargs)
        user_list = response.get("Users")
        page_token = response.get("PaginationToken")

        if page_limit is None:
            while page_token:
                response = self.client.list_users(
                    UserPoolId=pool_id, PaginationToken=page_token
                )
                user_list.extend(response.get("Users"))
                page_token = response.get("PaginationToken")
        self._users_pagination_next_token = page_token

        return [
            self.get_user_obj(
                user.get("Username"),
                attribute_list=user.get("Attributes"),
                metadata={"username": user.get("Username")},
                attr_map=attr_map,
            )
            for user in user_list
        ]

    def admin_get_user(self, attr_map=None):
        """
        Get the user's details using admin super privileges.
        :param attr_map: Attribute map applied to the returned UserObj
        :return: UserObj instance
        """
        user = self.client.admin_get_user(
            UserPoolId=self.user_pool_id, Username=self.username
        )
        user_metadata = {
            "enabled": user.get("Enabled"),
            "user_status": user.get("UserStatus"),
            "username": user.get("Username"),
            "create_date": user.get("UserCreateDate"),
            "modified_date": user.get("UserLastModifiedDate"),
            "id_token": self.id_token,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
        }
        return self.get_user_obj(
            username=self.username,
            attribute_list=user.get("UserAttributes"),
            metadata=user_metadata,
            attr_map=attr_map,
        )

    # ------------------------------------------------------------------
    # User write operations
    # ------------------------------------------------------------------

    def admin_create_user(
        self,
        username,
        temporary_password="",
        additional_kwargs=None,
        attr_map=None,
        **kwargs,
    ):
        """
        Create a user using admin super privileges.
        :param username: User Pool username
        :param temporary_password: Temporary password; omit/pass None for auto-generated
        :param additional_kwargs: Extra params such as MessageAction
        :param attr_map: Attribute map to Cognito's attribute names
        :param kwargs: Additional user attributes
        :return: Cognito admin_create_user response (ResponseMetadata stripped)
        """
        if additional_kwargs is None:
            additional_kwargs = {}
        if temporary_password:
            additional_kwargs["TemporaryPassword"] = temporary_password
        response = self.client.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=username,
            UserAttributes=dict_to_cognito(kwargs, attr_map),
            **additional_kwargs,
        )
        kwargs.update(username=username)
        self._set_attributes(response, kwargs)

        response.pop("ResponseMetadata")
        return response

    def admin_set_user_password(self, username, password, permanent=False):
        """
        Explicitly set a user's password.
        :param username: The Cognito username
        :param password: The password to set
        :param permanent: True → status CONFIRMED; False → FORCE_CHANGE_PASSWORD
        """
        self.client.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=username,
            Password=password,
            Permanent=permanent,
        )

    def admin_update_profile(self, attrs, attr_map=None, username=None):
        """
        Update the specified user's attributes.
        :param attrs: Dict of attribute names/values, or a pre-formatted Cognito list
        :param attr_map: Mapping from local names to Cognito attribute names
        :param username: Username to update (defaults to self.username)
        """
        if username is None:
            username = self.username

        if not is_cognito_attr_list(attrs):
            user_attrs = dict_to_cognito(attrs, attr_map)
        else:
            user_attrs = attrs

        self.client.admin_update_user_attributes(
            UserPoolId=self.user_pool_id,
            Username=username,
            UserAttributes=user_attrs,
        )

    def update_profile(self, attrs, attr_map=None):
        """
        Update attributes of the currently authenticated user.
        :param attrs: Dict of attribute names/values
        :param attr_map: Mapping from local names to Cognito attribute names
        """
        user_attrs = dict_to_cognito(attrs, attr_map)
        self.client.update_user_attributes(
            UserAttributes=user_attrs, AccessToken=self.access_token
        )

    def admin_enable_user(self, username):
        """Enable the specified user."""
        self.client.admin_enable_user(
            UserPoolId=self.user_pool_id,
            Username=username,
        )

    def admin_disable_user(self, username):
        """Disable the specified user."""
        self.client.admin_disable_user(
            UserPoolId=self.user_pool_id,
            Username=username,
        )

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------

    def get_group(self, group_name):
        """
        Get a group by name.
        :param group_name: Name of the group
        :return: self.group_class instance
        """
        response = self.client.get_group(
            GroupName=group_name, UserPoolId=self.user_pool_id
        )
        return self.get_group_obj(response.get("Group"))

    def get_groups(
        self,
        pool_id: Union[str, None] = None,
        page_limit: Union[int, None] = None,
        page_token: Union[str, None] = None,
    ):
        """
        Return all groups for a user pool as GroupObj instances.
        When page_limit is set returns that many results and stores the
        next-page token in self._groups_pagination_next_token.
        :param pool_id: User pool ID (defaults to self.user_pool_id)
        :param page_limit: Max results from this request (1–60)
        :param page_token: Pagination token from a previous call
        :return: List of self.group_class instances
        """
        if pool_id is None:
            pool_id = self.user_pool_id

        kwargs = {"UserPoolId": pool_id}
        if page_limit:
            kwargs["Limit"] = page_limit
        if page_token:
            kwargs["NextToken"] = page_token

        response = self.client.list_groups(**kwargs)
        group_list = response.get("Groups")
        page_token = response.get("NextToken")

        if page_limit is None:
            while page_token:
                response = self.client.list_groups(
                    UserPoolId=pool_id, NextToken=page_token
                )
                group_list.extend(response.get("Groups"))
                page_token = response.get("NextToken")
        self._groups_pagination_next_token = page_token

        return [self.get_group_obj(group_data) for group_data in group_list]

    def admin_add_user_to_group(self, username, group_name):
        """
        Add a user to a group.
        :param username: The username
        :param group_name: The group to add the user to
        """
        self.client.admin_add_user_to_group(
            UserPoolId=self.user_pool_id,
            Username=username,
            GroupName=group_name,
        )

    def admin_remove_user_from_group(self, username, group_name):
        """
        Remove a user from a group.
        :param username: The username
        :param group_name: The group to remove the user from
        """
        self.client.admin_remove_user_from_group(
            UserPoolId=self.user_pool_id,
            Username=username,
            GroupName=group_name,
        )

    def admin_list_groups_for_user(self, username):
        """
        Return the list of group names the user belongs to.
        :param username: The username to query
        :return: List of group name strings
        """

        def process_groups_response(groups_response):
            return [g["GroupName"] for g in groups_response["Groups"]]

        groups_response = self.client.admin_list_groups_for_user(
            Username=username, UserPoolId=self.user_pool_id, Limit=60
        )
        user_groups = process_groups_response(groups_response)

        while "NextToken" in groups_response.keys():
            groups_response = self.client.admin_list_groups_for_user(
                Username=username,
                UserPoolId=self.user_pool_id,
                Limit=60,
                NextToken=groups_response["NextToken"],
            )
            user_groups.extend(process_groups_response(groups_response))

        return user_groups

    # ------------------------------------------------------------------
    # Pool client operations
    # ------------------------------------------------------------------

    def list_user_pool_clients(
        self,
        pool_id: Union[str, None] = None,
        page_limit: Union[int, None] = None,
        page_token: Union[str, None] = None,
    ) -> List[dict]:
        """
        Return configuration info for a user pool's app clients.
        When page_limit is set returns that many results and stores the
        next-page token in self._clients_pagination_next_token.
        :param pool_id: User pool ID (defaults to self.user_pool_id)
        :param page_limit: Max results from this request (1–60)
        :param page_token: Pagination token from a previous call
        :return: List of client dicts
        """
        if pool_id is None:
            pool_id = self.user_pool_id

        kwargs = {"UserPoolId": pool_id}
        if page_limit:
            kwargs["MaxResults"] = page_limit
        if page_token:
            kwargs["NextToken"] = page_token

        response = self.client.list_user_pool_clients(**kwargs)
        client_list = response.get("UserPoolClients")
        page_token = response.get("NextToken")

        if page_limit is None:
            while page_token:
                response = self.client.list_user_pool_clients(
                    UserPoolId=pool_id, NextToken=page_token
                )
                client_list.extend(response.get("UserPoolClients"))
                page_token = response.get("NextToken")
        self._clients_pagination_next_token = page_token

        return client_list

    def delete_user_pool_client(self, pool_id=None, client_id=None):
        """
        Delete a user pool app client.
        :param pool_id: User pool ID (defaults to self.user_pool_id)
        :param client_id: Client ID (defaults to self.client_id)
        """
        if pool_id is None:
            pool_id = self.user_pool_id
        if client_id is None:
            client_id = self.client_id
        self.client.delete_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
        )

    def create_user_pool_client(self, client_name, pool_id=None, **kwargs):
        """
        Create a user pool app client.
        :param client_name: Name for the new client
        :param pool_id: User pool ID (defaults to self.user_pool_id)
        :param kwargs: Additional CreateUserPoolClient parameters
        :return: UserPoolClient response dict
        """
        if pool_id is None:
            pool_id = self.user_pool_id
        response = self.client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=client_name,
            **kwargs,
        )
        return response["UserPoolClient"]

    def describe_user_pool_client(self, pool_id: str, client_id: str):
        """
        Return configuration for a specific app client.
        :param pool_id: The user pool ID
        :param client_id: The client ID
        :return: UserPoolClient dict
        """
        return self.client.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id
        )["UserPoolClient"]

    def admin_update_user_pool_client(self, pool_id: str, client_id: str, **kwargs):
        """
        Update configuration for a specific app client.
        :param pool_id: The user pool ID
        :param client_id: The client ID
        :param kwargs: UpdateUserPoolClient parameters
        """
        self.client.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=client_id,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Identity provider management
    # ------------------------------------------------------------------

    def admin_create_identity_provider(
        self, pool_id, provider_name, provider_type, provider_details, **kwargs
    ):
        """
        Create an identity provider for a user pool.
        :param pool_id: The user pool ID
        :param provider_name: The identity provider name
        :param provider_type: The identity provider type (e.g. "Google", "SAML")
        :param provider_details: Provider-specific configuration dict
        """
        self.client.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            ProviderType=provider_type,
            ProviderDetails=provider_details,
            **kwargs,
        )

    def admin_describe_identity_provider(self, pool_id, provider_name):
        """
        Describe an existing identity provider.
        :param pool_id: The user pool ID
        :param provider_name: The identity provider name
        :return: Identity provider dict
        """
        return self.client.describe_identity_provider(
            UserPoolId=pool_id, ProviderName=provider_name
        )

    def admin_update_identity_provider(self, pool_id, provider_name, **kwargs):
        """
        Update an existing identity provider.
        :param pool_id: The user pool ID
        :param provider_name: The identity provider name
        :param kwargs: UpdateIdentityProvider parameters
        """
        self.client.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def list_devices(self, page_limit=None, page_token=None):
        """
        List devices associated with the currently authenticated user.
        Calls cognito-idp ListDevices using self.access_token, following every
        page unless page_limit is set.  When page_limit is set returns that
        many results and stores the next-page token, available from
        get_devices_pagination_token().
        :param page_limit: Max results from this request (1–60)
        :param page_token: Pagination token from a previous call
        :return: List of device dicts.
        """
        return self._paginate_devices(
            self.client.list_devices,
            {"AccessToken": self.access_token},
            page_limit,
            page_token,
        )

    def admin_list_devices(self, username=None, page_limit=None, page_token=None):
        """
        Admin-privilege list of devices for the specified user.
        Calls cognito-idp AdminListDevices, following every page unless
        page_limit is set.  When page_limit is set returns that many results
        and stores the next-page token, available from
        get_devices_pagination_token().
        :param username: Username whose devices to list. Defaults to self.username.
        :param page_limit: Max results from this request (1–60)
        :param page_token: Pagination token from a previous call
        :return: List of device dicts.
        """
        if username is None:
            username = self.username
        return self._paginate_devices(
            self.client.admin_list_devices,
            {"UserPoolId": self.user_pool_id, "Username": username},
            page_limit,
            page_token,
        )

    def _paginate_devices(self, operation, kwargs, page_limit, page_token):
        """Shared pagination for ListDevices and AdminListDevices."""
        if page_limit:
            kwargs["Limit"] = page_limit
        if page_token:
            kwargs["PaginationToken"] = page_token

        response = operation(**kwargs)
        devices = response.get("Devices", [])
        page_token = response.get("PaginationToken")

        if page_limit is None:
            while page_token:
                kwargs["PaginationToken"] = page_token
                response = operation(**kwargs)
                devices.extend(response.get("Devices", []))
                page_token = response.get("PaginationToken")
        self._devices_pagination_next_token = page_token
        return devices

    def get_device(self, device_key):
        """
        Describe a specific device for the currently authenticated user.
        Calls cognito-idp GetDevice using self.access_token.
        :param device_key: The device key to describe.
        :return: Device dict.
        """
        response = self.client.get_device(
            DeviceKey=device_key, AccessToken=self.access_token
        )
        return response["Device"]

    def admin_get_device(self, device_key, username=None):
        """
        Admin-privilege describe of a specific device.
        Calls cognito-idp AdminGetDevice.
        :param device_key: The device key to describe.
        :param username: Username who owns the device. Defaults to self.username.
        :return: Device dict.
        """
        if username is None:
            username = self.username
        response = self.client.admin_get_device(
            DeviceKey=device_key, UserPoolId=self.user_pool_id, Username=username
        )
        return response["Device"]

    def admin_forget_device(self, device_key, username=None):
        """
        Admin-privilege removal of a remembered device.
        Calls cognito-idp AdminForgetDevice.
        :param device_key: The device key to forget.
        :param username: Username who owns the device. Defaults to self.username.
        """
        if username is None:
            username = self.username
        self.client.admin_forget_device(
            UserPoolId=self.user_pool_id, Username=username, DeviceKey=device_key
        )

    # ------------------------------------------------------------------
    # Group CRUD
    # ------------------------------------------------------------------

    def create_group(
        self, group_name, description=None, role_arn=None, precedence=None
    ):
        """
        Create a new group in the user pool.
        Calls cognito-idp CreateGroup.
        :param group_name: Name of the group.
        :param description: Optional description.
        :param role_arn: Optional IAM role ARN.
        :param precedence: Optional integer precedence.
        :return: GroupObj instance for the created group.
        """
        kwargs = {"GroupName": group_name, "UserPoolId": self.user_pool_id}
        if description is not None:
            kwargs["Description"] = description
        if role_arn is not None:
            kwargs["RoleArn"] = role_arn
        if precedence is not None:
            kwargs["Precedence"] = precedence
        response = self.client.create_group(**kwargs)
        return self.get_group_obj(response["Group"])

    def update_group(
        self, group_name, description=None, role_arn=None, precedence=None
    ):
        """
        Update an existing group's properties.
        Calls cognito-idp UpdateGroup.
        :param group_name: Name of the group to update.
        :param description: New description.
        :param role_arn: New IAM role ARN.
        :param precedence: New precedence integer.
        """
        kwargs = {"GroupName": group_name, "UserPoolId": self.user_pool_id}
        if description is not None:
            kwargs["Description"] = description
        if role_arn is not None:
            kwargs["RoleArn"] = role_arn
        if precedence is not None:
            kwargs["Precedence"] = precedence
        self.client.update_group(**kwargs)

    def delete_group(self, group_name):
        """
        Delete a group from the user pool.
        Calls cognito-idp DeleteGroup.
        :param group_name: Name of the group to delete.
        """
        self.client.delete_group(
            GroupName=group_name,
            UserPoolId=self.user_pool_id,
        )

    def list_users_in_group(
        self,
        group_name,
        attr_map=None,
        page_limit=None,
        page_token=None,
    ):
        """
        Return all users that belong to the specified group.
        Calls cognito-idp ListUsersInGroup with automatic pagination unless
        page_limit is set.  When page_limit is set the next-page token is
        stored in self._group_users_pagination_next_token.
        :param group_name: The group name to query.
        :param attr_map: Optional attribute map applied to each UserObj.
        :param page_limit: Maximum results from a single request.
        :param page_token: Pagination token for the next page.
        :return: List of UserObj instances.
        """
        kwargs = {"GroupName": group_name, "UserPoolId": self.user_pool_id}
        if page_limit:
            kwargs["Limit"] = page_limit
        if page_token:
            kwargs["NextToken"] = page_token

        response = self.client.list_users_in_group(**kwargs)
        user_list = response.get("Users", [])
        next_token = response.get("NextToken")

        if page_limit is None:
            while next_token:
                response = self.client.list_users_in_group(
                    GroupName=group_name,
                    UserPoolId=self.user_pool_id,
                    NextToken=next_token,
                )
                user_list.extend(response.get("Users", []))
                next_token = response.get("NextToken")
        self._group_users_pagination_next_token = next_token

        return [
            self.get_user_obj(
                user.get("Username"),
                attribute_list=user.get("Attributes"),
                metadata={"username": user.get("Username")},
                attr_map=attr_map,
            )
            for user in user_list
        ]

    # ------------------------------------------------------------------
    # Federated identity
    # ------------------------------------------------------------------

    def admin_link_provider_for_user(
        self,
        destination_username,
        provider_name,
        provider_attribute_name,
        provider_attribute_value,
    ):
        """
        Link a federated identity provider account to an existing Cognito user.
        Calls cognito-idp AdminLinkProviderForUser.
        :param destination_username: The Cognito username to link to.
        :param provider_name: The identity provider name (e.g. "Google").
        :param provider_attribute_name: Provider attribute used to identify
            the user (e.g. "Cognito_Subject").
        :param provider_attribute_value: The provider attribute value.
        """
        self.client.admin_link_provider_for_user(
            UserPoolId=self.user_pool_id,
            DestinationUser={
                "ProviderName": "Cognito",
                "ProviderAttributeValue": destination_username,
            },
            SourceUser={
                "ProviderName": provider_name,
                "ProviderAttributeName": provider_attribute_name,
                "ProviderAttributeValue": provider_attribute_value,
            },
        )

    def admin_disable_provider_for_user(
        self,
        provider_name,
        provider_attribute_value,
        provider_attribute_name="Cognito_Subject",
    ):
        """
        Unlink (disable) a federated provider from a Cognito user.
        Calls cognito-idp AdminDisableProviderForUser.
        :param provider_name: The identity provider name.
        :param provider_attribute_value: The provider user identifier to unlink.
        :param provider_attribute_name: Provider attribute that identifies the
            user (default "Cognito_Subject").
        """
        self.client.admin_disable_provider_for_user(
            UserPoolId=self.user_pool_id,
            User={
                "ProviderName": provider_name,
                "ProviderAttributeName": provider_attribute_name,
                "ProviderAttributeValue": provider_attribute_value,
            },
        )

    # ------------------------------------------------------------------
    # User pool management
    # ------------------------------------------------------------------

    def describe_user_pool(self, pool_id=None):
        """
        Return configuration details of the user pool.
        Calls cognito-idp DescribeUserPool.
        :param pool_id: The user pool ID. Defaults to self.user_pool_id.
        :return: User pool configuration dict.
        """
        if pool_id is None:
            pool_id = self.user_pool_id
        response = self.client.describe_user_pool(UserPoolId=pool_id)
        return response["UserPool"]

    def update_user_pool(self, pool_id=None, **kwargs):
        """
        Update configuration properties of the user pool.
        Calls cognito-idp UpdateUserPool.
        :param pool_id: The user pool ID. Defaults to self.user_pool_id.
        :param kwargs: UpdateUserPool parameters (e.g. Policies, LambdaConfig,
            AutoVerifiedAttributes, SmsConfiguration, EmailConfiguration).
        """
        if pool_id is None:
            pool_id = self.user_pool_id
        self.client.update_user_pool(UserPoolId=pool_id, **kwargs)

    # ------------------------------------------------------------------
    # Session helper
    # ------------------------------------------------------------------

    def switch_session(self, session):
        """
        Swap in a different boto3 session (useful for testing with placebo).
        :param session: boto3 session
        """
        self.client = session.client("cognito-idp")
