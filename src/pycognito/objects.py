"""
Model objects returned by the Cognito client.

UserObj and GroupObj wrap the raw boto3 response dicts and provide
attribute-style access.  They hold a back-reference to the Cognito
instance so their save() / delete() methods can delegate upward.
"""

from .utils import cognito_to_dict


class UserObj:
    def __init__(
        self, username, attribute_list, cognito_obj, metadata=None, attr_map=None
    ):
        """
        :param username: Cognito username string
        :param attribute_list: Raw Cognito attribute list from admin_get_user / get_user
        :param cognito_obj: The owning Cognito instance
        :param metadata: Optional dict of extra metadata (user_status, create_date, etc.)
        :param attr_map: Optional mapping from Cognito attribute names to local names
        """
        self.username = username
        self._cognito = cognito_obj
        self._attr_map = {} if attr_map is None else attr_map
        self._data = cognito_to_dict(attribute_list, self._attr_map)
        self.sub = self._data.pop("sub", None)
        self.email_verified = self._data.pop("email_verified", None)
        self.phone_number_verified = self._data.pop("phone_number_verified", None)
        self._metadata = {} if metadata is None else metadata

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.__unicode__()}>"

    def __unicode__(self):
        return self.username

    def __getattr__(self, name):
        if name in list(self.__dict__.get("_data", {}).keys()):
            return self._data.get(name)
        if name in list(self.__dict__.get("_metadata", {}).keys()):
            return self._metadata.get(name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in list(self.__dict__.get("_data", {}).keys()):
            self._data[name] = value
        else:
            super().__setattr__(name, value)

    def save(self, admin=False):
        if admin:
            self._cognito.admin_update_profile(self._data, self._attr_map)
            return
        self._cognito.update_profile(self._data, self._attr_map)

    def delete(self, admin=False):
        if admin:
            self._cognito.admin_delete_user()
            return
        self._cognito.delete_user()


class GroupObj:
    def __init__(self, group_data, cognito_obj):
        """
        :param group_data: Raw dict from list_groups / get_group boto3 response
        :param cognito_obj: The owning Cognito instance
        """
        self._data = group_data
        self._cognito = cognito_obj
        self.group_name = self._data.pop("GroupName", None)
        self.description = self._data.pop("Description", None)
        self.creation_date = self._data.pop("CreationDate", None)
        self.last_modified_date = self._data.pop("LastModifiedDate", None)
        self.role_arn = self._data.pop("RoleArn", None)
        self.precedence = self._data.pop("Precedence", None)

    def __unicode__(self):
        return self.group_name

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.__unicode__()}>"
