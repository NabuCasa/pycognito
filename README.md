# pyCognito

Makes working with AWS Cognito easier for Python developers.

## Getting Started

- [Python Versions Supported](#python-versions-supported)
- [Install](#install)
- [Environment Variables](#environment-variables)
  - [COGNITO_JWKS](#cognito_jwks) (optional)
- [Cognito Utility Class](#cognito-utility-class) `pycognito.Cognito`
  - [Cognito Attributes](#cognito-attributes)
  - [Authentication](#authentication)
    - [Register](#register)
    - [Authenticate](#authenticate)
    - [Admin Authenticate](#admin-authenticate)
    - [New Password Challenge](#new-password-challenge)
    - [Confirm Sign Up](#confirm-sign-up)
    - [Admin Confirm Sign Up](#admin-confirm-sign-up)
    - [Resend Confirmation Code](#resend-confirmation-code)
  - [Password Management](#password-management)
    - [Initiate Forgot Password](#initiate-forgot-password)
    - [Confirm Forgot Password](#confirm-forgot-password)
    - [Change Password](#change-password)
    - [Admin Reset Password](#admin-reset-password)
    - [Admin Set User Password](#admin-set-user-password)
  - [User Management](#user-management)
    - [Get User Object](#get-user-object)
    - [Get User](#get-user)
    - [Get Users](#get-users)
    - [Admin Get User](#admin-get-user)
    - [Admin Create User](#admin-create-user)
    - [Update Profile](#update-profile)
    - [Admin Update Profile](#admin-update-profile)
    - [Send Verification](#send-verification)
    - [Validate Verification](#validate-verification)
    - [Admin Enable User](#admin-enable-user)
    - [Admin Disable User](#admin-disable-user)
    - [Delete User](#delete-user)
    - [Admin Delete User](#admin-delete-user)
    - [User Objects](#user-objects)
  - [Token & Session Management](#token--session-management)
    - [Check Token](#check-token)
    - [Verify Tokens](#verify-tokens)
    - [Renew Access Token](#renew-access-token)
    - [Admin Renew Access Token](#admin-renew-access-token)
    - [Logout](#logout)
    - [Revoke Token](#revoke-token)
    - [Admin User Global Sign Out](#admin-user-global-sign-out)
  - [Group Management](#group-management)
    - [Get Group Object](#get-group-object)
    - [Get Group](#get-group)
    - [Get Groups](#get-groups)
    - [Create Group](#create-group)
    - [Update Group](#update-group)
    - [Delete Group](#delete-group)
    - [List Users In Group](#list-users-in-group)
    - [Admin Add User To Group](#admin-add-user-to-group)
    - [Admin Remove User From Group](#admin-remove-user-from-group)
    - [Admin List Groups For User](#admin-list-groups-for-user)
  - [User Pool & Client Management](#user-pool--client-management)
    - [Describe User Pool](#describe-user-pool)
    - [Update User Pool](#update-user-pool)
    - [List User Pool Clients](#list-user-pool-clients)
    - [Create User Pool Client](#create-user-pool-client)
    - [Describe User Pool Client](#describe-user-pool-client)
    - [Delete User Pool Client](#delete-user-pool-client)
    - [Admin Update User Pool Client](#admin-update-user-pool-client)
  - [Identity Providers](#identity-providers)
    - [Admin Create Identity Provider](#admin-create-identity-provider)
    - [Admin Describe Identity Provider](#admin-describe-identity-provider)
    - [Admin Update Identity Provider](#admin-update-identity-provider)
    - [Admin Link Provider For User](#admin-link-provider-for-user)
    - [Admin Disable Provider For User](#admin-disable-provider-for-user)
  - [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
    - [Associate Software Token](#associate-software-token)
    - [Verify Software Token](#verify-software-token)
    - [Set User MFA Preference](#set-user-mfa-preference)
    - [Admin Set User MFA Preference](#admin-set-user-mfa-preference)
    - [Get User Pool MFA Config](#get-user-pool-mfa-config)
    - [Set User Pool MFA Config](#set-user-pool-mfa-config)
    - [Respond to Software Token MFA Challenge](#respond-to-software-token-mfa-challenge)
    - [Respond to SMS MFA Challenge](#respond-to-sms-mfa-challenge)
- [Cognito SRP Utility](#cognito-srp-utility)
  - [Using AWSSRP](#using-awssrp)
- [Device Authentication Support](#device-authentication-support)
  - [Receiving DeviceKey and DeviceGroupKey](#receiving-devicekey-and-devicegroupkey)
  - [Confirming a Device](#confirming-a-device)
  - [Updating Device Status](#updating-device-status)
  - [Authenticating your Device](#authenticating-your-device)
  - [Using Device Auth with the Cognito Class](#using-device-auth-with-the-cognito-class)
  - [Forget Device](#forget-device)
  - [Device Management with the Cognito Class](#device-management-with-the-cognito-class)
- [SRP Requests Authenticator](#srp-requests-authenticator)
- [Switching boto3 Sessions](#switching-boto3-sessions)
- [Contributing](#contributing)

---

## Python Versions Supported

These match the Python runtimes AWS Lambda currently supports.

- 3.10
- 3.11
- 3.12
- 3.13
- 3.14

## Install

`pip install pycognito`

## Environment Variables

#### COGNITO_JWKS

**Optional:** This environment variable is a dictionary that represent the well known JWKs assigned to your user pool by AWS Cognito. You can find the keys for your user pool by substituting in your AWS region and pool id for the following example.
`https://cognito-idp.{aws-region}.amazonaws.com/{user-pool-id}/.well-known/jwks.json`

**Example Value (Not Real):**

```commandline
COGNITO_JWKS={"keys": [{"alg": "RS256","e": "AQAB","kid": "123456789ABCDEFGHIJKLMNOP","kty": "RSA","n": "123456789ABCDEFGHIJKLMNOP","use": "sig"},{"alg": "RS256","e": "AQAB","kid": "123456789ABCDEFGHIJKLMNOP","kty": "RSA","n": "123456789ABCDEFGHIJKLMNOP","use": "sig"}]}
```

---

## Cognito Utility Class

### Example with All Arguments

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id',
    client_secret='optional-client-secret',
    username='optional-username',
    id_token='optional-id-token',
    refresh_token='optional-refresh-token',
    access_token='optional-access-token',
    access_key='optional-access-key',
    secret_key='optional-secret-key',
    device_key='optional-device-key',
    device_group_key='optional-device-group-key',
    device_password='optional-device-password',
    device_name='optional-device-name')
```

#### Arguments

- **user_pool_id:** Cognito User Pool ID
- **client_id:** Cognito User Pool Application client ID
- **client_secret:** App client secret (if app client is configured with client secret)
- **username:** User Pool username
- **id_token:** ID Token returned by authentication
- **refresh_token:** Refresh Token returned by authentication
- **access_token:** Access Token returned by authentication
- **access_key:** AWS IAM access key
- **secret_key:** AWS IAM secret key
- **device_key:** Device Key for a previously confirmed device (see [Device Authentication Support](#device-authentication-support))
- **device_group_key:** Device Group Key for a previously confirmed device
- **device_password:** Device Password for a previously confirmed device
- **device_name:** Friendly name for the device
- **session:** Optional boto3 Session to use when creating the boto3 client
- **botocore_config:** Optional `botocore.config.Config` object for the boto3 client
- **boto3_client_kwargs:** Optional dict of extra keyword arguments forwarded to `boto3.client()`

### Examples with Realistic Arguments

#### User Pool Id

Used when you only need information about the user pool's clients, groups, or users (ex. list users in the user pool). Client ID can be optionally specified.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')
```

#### Username

Used when the user has not logged in yet. Start with these arguments when you plan to authenticate with either SRP (authenticate) or admin_authenticate (admin_initiate_auth).

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')
```

#### Tokens

Used after the user has already authenticated and you need to build a new Cognito instance (ex. for use in a view).

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='your-id-token',
    refresh_token='your-refresh-token',
    access_token='your-access-token')

u.verify_tokens() # See method doc below; may throw an exception
```

---

## Cognito Attributes

After any authentication or other explicit verification of tokens, the following additional attributes will be available:

- `id_claims` — A dict of verified claims from the id token
- `access_claims` — A dict of verified claims from the access token

---

## Authentication

Methods for registering users, signing in, and confirming accounts.

#### Register

Register a user to the user pool

**Important:** The arguments for `set_base_attributes` and `add_custom_attributes` methods depend on your user pool's configuration, and make sure the client id (app id) used has write permissions for the attributes you are trying to create. Example, if you want to create a user with a given_name equal to Johnson make sure the client_id you're using has permissions to edit or create given_name for a user in the pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

u.set_base_attributes(email='you@you.com', some_random_attr='random value')

u.register('username', 'password')
```

Register with custom attributes.

Firstly, add custom attributes on 'General settings -> Attributes' page.
Secondly, set permissions on 'Generals settings-> App clients-> Show details-> Set attribute read and write permissions' page.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

u.set_base_attributes(email='you@you.com', some_random_attr='random value')

u.add_custom_attributes(state='virginia', city='Centreville')

u.register('username', 'password')
```

**Arguments**

- **username:** User Pool username
- **password:** User Pool password
- **attr_map:** (optional) Attribute map to Cognito's attributes
- **client_metadata:** (optional) Dict passed to the pool's Lambda triggers (for example Pre sign-up) as `ClientMetadata`

Returns the `sign_up` response (`UserConfirmed`, `UserSub` and, when confirmation is required, `CodeDeliveryDetails`).

#### Authenticate

Authenticates a user

If this method call succeeds the instance will have the following attributes **id_token**, **refresh_token**, **access_token**, **token_type**, **id_claims**, and **access_claims**.

If Cognito asks for a second factor, `authenticate` raises `SMSMFAChallengeException` or `SoftwareTokenMFAChallengeException` and stores the challenge on `u.mfa_tokens`. Answer it with [Respond to SMS MFA Challenge](#respond-to-sms-mfa-challenge) or [Respond to Software Token MFA Challenge](#respond-to-software-token-mfa-challenge). If the user must set a new password first it raises `ForceChangePasswordException`; see [New Password Challenge](#new-password-challenge).

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.authenticate(password='bobs-password')
```

**Arguments**

- **password:** User's password
- **client_metadata:** (optional) Dict passed to the pool's Lambda triggers as `ClientMetadata` when responding to the SRP challenge

#### Admin Authenticate

Authenticate the user using admin super privileges, with the `ADMIN_USER_PASSWORD_AUTH` flow. The app client must have `ALLOW_ADMIN_USER_PASSWORD_AUTH` enabled, and the caller needs AWS credentials allowed to call `AdminInitiateAuth`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.admin_authenticate(password='bobs-password')
```

- **password:** User's password

#### New Password Challenge

Respond to a `NEW_PASSWORD_REQUIRED` challenge using the SRP protocol. Cognito issues this challenge when a user's account requires a password change before a session can be established (for example, after admin-created accounts or forced resets).

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.new_password_challenge(password='temporary-password', new_password='permanent-password')
```

**Arguments**

- **password:** The user's current (temporary) password
- **new_password:** The new password the user wants to set

#### Confirm Sign Up

Use the confirmation code that is sent via email or text to confirm the user's account

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.confirm_sign_up('users-conf-code',username='bob')
```

**Arguments**

- **confirmation_code:** Confirmation code sent via text or email
- **username:** User's username

#### Admin Confirm Sign Up

Confirm a user's registration as an admin without requiring a confirmation code. Useful for programmatically confirming test users or automating post-registration workflows.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.admin_confirm_sign_up()
```

You can also confirm a different user by passing a username explicitly:

```python
u.admin_confirm_sign_up(username='alice')
```

**Arguments**

- **username:** (optional) User's username. Defaults to `self.username`.

#### Resend Confirmation Code

Resend the confirmation code message to a user who has not yet confirmed their account.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.resend_confirmation_code(username='bob')
```

**Arguments**

- **username:** User's username

---

## Password Management

Methods for resetting, changing, and managing user passwords.

#### Initiate Forgot Password

Sends a verification code to the user to use to change their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.initiate_forgot_password()
```

**Arguments**

No arguments

#### Confirm Forgot Password

Allows a user to enter a code provided when they reset their password
to update their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.confirm_forgot_password('your-confirmation-code','your-new-password')
```

**Arguments**

- **confirmation_code:** The confirmation code sent by a user's request
  to retrieve a forgotten password
- **password:** New password

#### Change Password

Changes the user's password

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.change_password('previous-password','proposed-password')
```

**Arguments**

- **previous_password:** - User's previous password
- **proposed_password:** - The password that the user wants to change to.

#### Admin Reset Password

Trigger an admin-initiated password reset for the specified user. Sends a verification code via the user's configured delivery channel (email or SMS).

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_reset_password(username='bob')
```

**Arguments**

- **username:** The user to reset
- **client_metadata:** (optional) Metadata forwarded to Lambda triggers

#### Admin Set User Password

Explicitly set a user's password. Setting `permanent=True` moves the user to `CONFIRMED` status; `permanent=False` leaves them in `FORCE_CHANGE_PASSWORD`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_set_user_password(username='bob', password='NewPass1234!', permanent=True)
```

**Arguments**

- **username:** The Cognito username
- **password:** The password to set
- **permanent:** `True` → status `CONFIRMED`; `False` → `FORCE_CHANGE_PASSWORD` (default: `False`)

---

## User Management

Methods for creating, reading, updating, and deleting users, as well as managing their attributes and verification status.

#### Get User Object

Returns an instance of the specified user_class.

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.get_user_obj(username='bjones',
    attribute_list=[{'Name': 'string','Value': 'string'},],
    metadata={},
    attr_map={"given_name":"first_name","family_name":"last_name"}
    )
```

**Arguments**

- **username:** Username of the user
- **attribute_list:** List of tuples that represent the user's attributes as returned by the admin_get_user or get_user boto3 methods
- **metadata: (optional)** Metadata about the user
- **attr_map: (optional)** Dictionary that maps the Cognito attribute names to what we'd like to display to the users

#### Get User

Get all of the user's attributes. Gets the user's attributes using Boto3 and uses that info to create an instance of the user_class

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

user = u.get_user(attr_map={"given_name":"first_name","family_name":"last_name"})
```

**Arguments**

- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Get Users

Get a list of the users in the user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

user = u.get_users(attr_map={"given_name":"first_name","family_name":"last_name"})
```

You can paginate through retrieving users by specifying the page_limit and page_token arguments. Without `page_limit`, every page is fetched and returned in one list. With `page_limit`, one page is returned and the token for the next page is available from `get_users_pagination_token()`, which returns `None` once there are no more pages.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

users = u.get_users(page_limit=10)
page_token = u.get_users_pagination_token()
while page_token:
    more_users = u.get_users(page_limit=10, page_token=page_token)
    users.extend(more_users)
    page_token = u.get_users_pagination_token()
```

**Arguments**

- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users
- **pool_id:** The user pool ID to list users for (uses self.user_pool_id if None)
- **page_limit:** Max results to return from this request (1 to 60)
- **page_token:** Used to return the next set of items

#### Admin Get User

Get a user's details using admin super privileges. Returns a `UserObj` instance.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

user = u.admin_get_user()
print(user.given_name, user.user_status)
```

**Arguments**

- **attr_map:** (optional) Attribute map applied to the returned `UserObj`

#### Admin Create User

Create a user using admin super privileges. The user will be in `FORCE_CHANGE_PASSWORD` status by default. Pass the username to `admin_set_user_password` with `permanent=True` afterwards to move them straight to `CONFIRMED`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_create_user(
    username='newuser@example.com',
    temporary_password='Temp1234!',
    email='newuser@example.com'
)
```

Suppress the welcome email (useful in tests or automated pipelines):

```python
u.admin_create_user(
    username='testuser@example.com',
    temporary_password='Temp1234!',
    additional_kwargs={'MessageAction': 'SUPPRESS'}
)
```

**Arguments**

- **username:** User Pool username
- **temporary_password:** Temporary password. Pass `None` to have Cognito auto-generate one.
- **additional_kwargs:** (optional) Dict of extra `AdminCreateUser` parameters such as `MessageAction`
- **attr_map:** (optional) Attribute map to Cognito's attribute names
- **\*\*kwargs:** Additional user attributes (e.g. `email`, `given_name`, `phone_number`)

#### Update Profile

Update the user's profile

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.update_profile({'given_name':'Edward','family_name':'Smith',},attr_map=dict())
```

**Arguments**

- **attrs:** Dictionary of attribute name, values
- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Admin Update Profile

Update the specified user's attributes using admin super privileges. Accepts either a plain dict or a pre-formatted Cognito attribute list.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

# Update self.username using a plain dict
u.admin_update_profile(attrs={'given_name': 'Robert'})

# Update a different user
u.admin_update_profile(attrs={'given_name': 'Alice'}, username='alice')

# Map local attribute names to Cognito attribute names
u.admin_update_profile(attrs={'first': 'Robert'}, attr_map={'given_name': 'first'})

# Supply a pre-formatted Cognito attribute list
u.admin_update_profile(
    attrs=[{'Name': 'given_name', 'Value': 'Robert'}],
    username='bob'
)
```

**Arguments**

- **attrs:** Dict of attribute names/values, or a pre-formatted Cognito attribute list
- **attr_map:** (optional) Mapping from local attribute names to Cognito attribute names
- **username:** (optional) Username to update. Defaults to `self.username`.

#### Send Verification

Send verification email or text for either the email or phone attributes.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
```

**Arguments**

- **attribute:** - The attribute (email or phone) that needs to be verified

#### Validate Verification

Verify a user attribute using the confirmation code sent by `send_verification`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
code = input('Enter the verification code sent to your email: ')
u.validate_verification(confirmation_code=code, attribute='email')
```

**Arguments**

- **confirmation_code:** Code sent by `send_verification`
- **attribute:** The attribute to verify (default: `"email"`)

#### Admin Enable User

Enable a previously disabled user, allowing them to sign in again.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_enable_user(username='bob')
```

**Arguments**

- **username:** Username of the user to enable

#### Admin Disable User

Disable a user, preventing them from signing in without deleting their account.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_disable_user(username='bob')
```

**Arguments**

- **username:** Username of the user to disable

#### Delete User

Delete the currently authenticated user.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.delete_user()
```

**Arguments**

No arguments

#### Admin Delete User

Delete a user using admin super privileges.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.admin_delete_user()
```

**Arguments**

No arguments — deletes `self.username` from `self.user_pool_id`.

#### User Objects

`get_user`, `admin_get_user`, `get_users`, and `list_users_in_group` return instances of `u.user_class` (`UserObj` by default). Cognito attributes are available as Python attributes, using any `attr_map` you passed. Metadata such as `user_status` is also available.

`UserObj.save()` writes changed attributes back with [Update Profile](#update-profile), and `UserObj.delete()` calls [Delete User](#delete-user). Pass `admin=True` to use [Admin Update Profile](#admin-update-profile) or [Admin Delete User](#admin-delete-user) instead; both act on the `Cognito` instance's `username`.

```python
user = u.get_user(attr_map={'given_name': 'first_name'})
user.first_name = 'Robert'
user.save()

user.delete(admin=True)
```

---

## Token & Session Management

Methods for checking, verifying, refreshing, and invalidating tokens.

#### Check Token

Checks the `exp` claim of the access token. If it has expired, the tokens are refreshed by calling `renew_access_token` (unless `renew=False`). Returns `True` if the access token had expired, otherwise `False`. **IMPORTANT:** Access token is required

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.check_token()
```

**Arguments**

- **renew:** (optional) Refresh the tokens when the access token has expired. Defaults to `True`.

#### Verify Tokens

Verifies the current `id_token` and `access_token`.
An exception will be thrown if they do not pass verification.
It can be useful to call this method immediately after instantiation when you're providing externally-remembered tokens to the `Cognito()` constructor.
Note that if you're calling `check_token()` after instantiation, you'll still want to call `verify_tokens()` afterwards in case it did nothing.
This method also ensures that the `id_claims` and `access_claims` attributes are set with the verified claims from each token.

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.check_token()  # Optional, if you want to maybe renew the tokens
u.verify_tokens()
```

**Arguments**

No arguments for verify_tokens

#### Renew Access Token

Refreshes the access and id tokens using the stored refresh token. Called automatically by `check_token` when the access token has expired. If `device_key` is set on the instance it is included in the auth parameters automatically.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.renew_access_token()
```

**Arguments**

No arguments

#### Admin Renew Access Token

Admin-privilege equivalent of `renew_access_token`. Uses `admin_initiate_auth` with `REFRESH_TOKEN_AUTH` so that server-side processes can refresh tokens without user interaction. Requires the instance to already hold a valid `refresh_token`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob',
    refresh_token='refresh-token')

u.admin_renew_access_token()
```

**Arguments**

No arguments

#### Logout

Signs the user out everywhere by calling Cognito's `GlobalSignOut` with the current access token. This invalidates **every** refresh token issued to the user, on all devices and app clients, so all of their sessions end. Afterwards the `id_token`, `refresh_token`, `access_token`, and `token_type` attributes are set to `None`.

To end only this session and leave the user signed in elsewhere, use [Revoke Token](#revoke-token) instead. To sign out a user without their access token, use [Admin User Global Sign Out](#admin-user-global-sign-out).

Already-issued access and ID tokens stay cryptographically valid until they expire, so services that only check the JWT signature will keep accepting them until then.

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.logout()
```

**Arguments**

No arguments for logout

#### Revoke Token

Revokes a single refresh token by calling Cognito's `RevokeToken`. The access and ID tokens issued from that refresh token stop working, but the user's other sessions (other devices or app clients) are not affected. This is a narrower action than [Logout](#logout), which signs the user out of every session.

When the revoked token is the instance's own `refresh_token` (the default), the `id_token`, `refresh_token`, `access_token`, and `token_type` attributes are set to `None`. Revoking any other token leaves them unchanged.

The app client must have token revocation enabled, which is the default for new clients. If the client has a secret, it's sent automatically.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

# Revoke this instance's refresh token (ends this session only)
u.revoke_token()

# Or revoke a different refresh token, e.g. one stored for another device
u.revoke_token(token='another-refresh-token')
```

**Arguments**

- **token:** (optional) Refresh token to revoke. Defaults to `self.refresh_token`. Raises `AttributeError` if there is no token to revoke.

#### Admin User Global Sign Out

Invalidates all tokens for a user across all clients, regardless of which client they used to sign in. Requires admin credentials. This is the admin equivalent of [Logout](#logout): it doesn't need the user's access token, and it doesn't clear the tokens held on the instance.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

# Sign out self.username
u.admin_user_global_sign_out()

# Or sign out a different user explicitly
u.admin_user_global_sign_out(username='alice')
```

**Arguments**

- **username:** (optional) Username to sign out. Defaults to `self.username`.

---

## Group Management

Methods for creating and managing groups and group membership.

#### Get Group Object

Returns an instance of the specified group_class.

```python
u = Cognito('your-user-pool-id', 'your-client-id')

group_data = {'GroupName': 'user_group', 'Description': 'description',
            'Precedence': 1}

group_obj = u.get_group_obj(group_data)
```

**Arguments**

- **group_data:** Dictionary with group's attributes.

#### Get Group

Get all of the group's attributes. Returns an instance of the group_class.
Requires developer credentials.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

group = u.get_group(group_name='some_group_name')
```

**Arguments**

- **group_name:** Name of a group

#### Get Groups

Get a list of groups in the specified user pool (defaults to user pool set on instantiation if not specified). Requires developer credentials.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

groups = u.get_groups()
```

You can paginate through retrieving groups by specifying the page_limit and page_token arguments. Without `page_limit`, every page is fetched and returned in one list. With `page_limit`, one page is returned and the token for the next page is available from `get_groups_pagination_token()`, which returns `None` once there are no more pages.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

groups = u.get_groups(page_limit=10)
page_token = u.get_groups_pagination_token()
while page_token:
    more_groups = u.get_groups(page_limit=10, page_token=page_token)
    groups.extend(more_groups)
    page_token = u.get_groups_pagination_token()
```

**Arguments**

- **pool_id:** The user pool ID to list groups for (uses self.user_pool_id if None)
- **page_limit:** Max results to return from this request (1 to 60)
- **page_token:** Used to return the next set of items

#### Create Group

Create a new group in the user pool. Returns a `GroupObj` instance.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

group = u.create_group(
    group_name='admins',
    description='Administrator group',
    precedence=1
)
print(group.group_name)
```

**Arguments**

- **group_name:** Name of the group
- **description:** (optional) Description of the group
- **role_arn:** (optional) IAM role ARN associated with the group
- **precedence:** (optional) Integer priority — lower numbers take precedence

#### Update Group

Update an existing group's properties.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.update_group(group_name='admins', description='Senior admins', precedence=1)
```

**Arguments**

- **group_name:** Name of the group to update
- **description:** (optional) New description
- **role_arn:** (optional) New IAM role ARN
- **precedence:** (optional) New precedence integer

#### Delete Group

Delete a group from the user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.delete_group(group_name='old-group')
```

**Arguments**

- **group_name:** Name of the group to delete

#### List Users In Group

Return all users that belong to a group as a list of `UserObj` instances. Paginates automatically unless `page_limit` is set.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

users = u.list_users_in_group(group_name='admins')
```

Paginate manually using `get_group_users_pagination_token`:

```python
users = u.list_users_in_group(group_name='admins', page_limit=10)
page_token = u.get_group_users_pagination_token()
while page_token:
    more_users = u.list_users_in_group(group_name='admins', page_limit=10, page_token=page_token)
    users.extend(more_users)
    page_token = u.get_group_users_pagination_token()
```

**Arguments**

- **group_name:** The group name to query
- **attr_map:** (optional) Attribute map applied to each returned `UserObj`
- **page_limit:** (optional) Max results to return from this request (1 to 60); enables manual pagination
- **page_token:** (optional) Pagination token from a previous call

#### Admin Add User To Group

Add a user to a group.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_add_user_to_group(username='bob', group_name='admins')
```

**Arguments**

- **username:** The username to add
- **group_name:** The group to add the user to

#### Admin Remove User From Group

Remove a user from a group.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_remove_user_from_group(username='bob', group_name='admins')
```

**Arguments**

- **username:** The username to remove
- **group_name:** The group to remove the user from

#### Admin List Groups For User

Return the list of group names the user belongs to. Every page of results is fetched, so the list is complete.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

group_names = u.admin_list_groups_for_user(username='bob')
# ['admins', 'editors']
```

**Arguments**

- **username:** The username to query

---

## User Pool & Client Management

Methods for inspecting and configuring user pools and their application clients.

#### Describe User Pool

Return the configuration details of a user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

pool = u.describe_user_pool()
print(pool['Name'], pool['MfaConfiguration'])
```

**Arguments**

- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.

#### Update User Pool

Update configuration properties of a user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.update_user_pool(
    Policies={
        'PasswordPolicy': {
            'MinimumLength': 12,
            'RequireUppercase': True,
            'RequireLowercase': True,
            'RequireNumbers': True,
            'RequireSymbols': False
        }
    }
)
```

**Arguments**

- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.
- **\*\*kwargs:** `UpdateUserPool` parameters such as `Policies`, `MfaConfiguration`, `LambdaConfig`, `EmailConfiguration`

#### List User Pool Clients

Returns a list of client dicts of the specified user pool (defaults to user pool set on instantiation if not specified). Requires developer credentials.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

clients = u.list_user_pool_clients()
```

You can paginate through retrieving clients by specifying the page_limit and page_token arguments. Without `page_limit`, every page is fetched and returned in one list. With `page_limit`, one page is returned and the token for the next page is available from `get_clients_pagination_token()`, which returns `None` once there are no more pages.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

clients = u.list_user_pool_clients(page_limit=10)
page_token = u.get_clients_pagination_token()
while page_token:
    more_clients = u.list_user_pool_clients(page_limit=10, page_token=page_token)
    clients.extend(more_clients)
    page_token = u.get_clients_pagination_token()
```

**Arguments**

- **pool_id:** The user pool ID to list clients for (uses self.user_pool_id if None)
- **page_limit:** Max results to return from this request (1 to 60)
- **page_token:** Used to return the next set of items

#### Create User Pool Client

Create a new application client for the user pool. Returns the `UserPoolClient` response dict.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id', client_id=None)

client = u.create_user_pool_client(
    client_name='my-app-client',
    ExplicitAuthFlows=['ALLOW_USER_SRP_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH']
)
print(client['ClientId'])
```

**Arguments**

- **client_name:** Name for the new client
- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.
- **\*\*kwargs:** Additional `CreateUserPoolClient` parameters (e.g. `ExplicitAuthFlows`, `TokenValidityUnits`)

#### Describe User Pool Client

Return configuration details for a specific app client.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

details = u.describe_user_pool_client(
    pool_id='your-user-pool-id',
    client_id='your-client-id'
)
print(details['ClientName'])
```

**Arguments**

- **pool_id:** The user pool ID
- **client_id:** The client ID to describe

#### Delete User Pool Client

Delete an application client from the user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.delete_user_pool_client()  # deletes self.client_id from self.user_pool_id
```

**Arguments**

- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.
- **client_id:** (optional) Client ID to delete. Defaults to `self.client_id`.

#### Admin Update User Pool Client

Update configuration for a specific app client.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_update_user_pool_client(
    pool_id='your-user-pool-id',
    client_id='your-client-id',
    ExplicitAuthFlows=['ALLOW_USER_SRP_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH'],
    AccessTokenValidity=1
)
```

**Arguments**

- **pool_id:** The user pool ID
- **client_id:** The client ID to update
- **\*\*kwargs:** `UpdateUserPoolClient` parameters to change

---

## Identity Providers

Methods for configuring and linking federated identity providers (Google, Facebook, SAML, OIDC, etc.).

#### Admin Create Identity Provider

Create a federated identity provider for a user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_create_identity_provider(
    pool_id='your-user-pool-id',
    provider_name='Google',
    provider_type='Google',
    provider_details={
        'client_id': 'google-client-id',
        'client_secret': 'google-client-secret',
        'authorize_scopes': 'email profile openid'
    }
)
```

**Arguments**

- **pool_id:** The user pool ID
- **provider_name:** The identity provider name
- **provider_type:** The identity provider type (e.g. `"Google"`, `"Facebook"`, `"SAML"`, `"OIDC"`)
- **provider_details:** Provider-specific configuration dict
- **\*\*kwargs:** Additional `CreateIdentityProvider` parameters

#### Admin Describe Identity Provider

Return the configuration of an existing identity provider.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

provider = u.admin_describe_identity_provider(
    pool_id='your-user-pool-id',
    provider_name='Google'
)
print(provider['ProviderType'])
```

**Arguments**

- **pool_id:** The user pool ID
- **provider_name:** The identity provider name

#### Admin Update Identity Provider

Update the configuration of an existing identity provider.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_update_identity_provider(
    pool_id='your-user-pool-id',
    provider_name='Google',
    ProviderDetails={
        'client_id': 'new-google-client-id',
        'client_secret': 'new-google-client-secret',
        'authorize_scopes': 'email profile openid'
    }
)
```

**Arguments**

- **pool_id:** The user pool ID
- **provider_name:** The identity provider name to update
- **\*\*kwargs:** `UpdateIdentityProvider` parameters

#### Admin Link Provider For User

Link a federated identity provider account to an existing Cognito user.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_link_provider_for_user(
    destination_username='bob',
    provider_name='Google',
    provider_attribute_name='Cognito_Subject',
    provider_attribute_value='google-subject-id-123'
)
```

**Arguments**

- **destination_username:** The Cognito username to link to
- **provider_name:** The identity provider name (e.g. `"Google"`)
- **provider_attribute_name:** Provider attribute used as the link key (typically `"Cognito_Subject"`)
- **provider_attribute_value:** The provider's unique identifier for this user

#### Admin Disable Provider For User

Unlink (disable) a federated provider from a Cognito user. After this call the user can no longer sign in via that provider.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.admin_disable_provider_for_user(
    provider_name='Google',
    provider_attribute_value='google-subject-id-123'
)
```

**Arguments**

- **provider_name:** The identity provider name
- **provider_attribute_value:** The provider's unique identifier for the user to unlink
- **provider_attribute_name:** (optional) Provider attribute that identifies the user. Defaults to `"Cognito_Subject"`, which is what social and OIDC providers use; SAML providers can use another attribute.

---

## Multi-Factor Authentication (MFA)

Methods for setting up, configuring, and responding to MFA challenges (TOTP software tokens and SMS).

#### Associate Software Token

Get the secret code to issue the software token MFA code.
Begins setup of time-based one-time password (TOTP) multi-factor authentication (MFA) for a user.

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

secret_code = u.associate_software_token()
# Display the secret_code to the user and enter it into a TOTP generator (such as Google Authenticator) to have them generate a 6-digit code.
```

**Arguments**

No arguments for associate_software_token

#### Verify Software Token

Verify the 6-digit code issued based on the secret code issued by associate_software_token. If this validation is successful, Cognito will enable Software token MFA.

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

secret_code = u.associate_software_token()
# Display the secret_code to the user and enter it into a TOTP generator (such as Google Authenticator) to have them generate a 6-digit code.
code = input('Enter the 6-digit code.')
device_name = input('Enter the device name')
u.verify_software_token(code, device_name)
```

**Arguments**

- **code:** 6-digit code generated by the TOTP generator app
- **device_name:** Name of a device

#### Set User MFA Preference

Enable and prioritize Software Token MFA and SMS MFA.

If both Software Token MFA and SMS MFA are invalid, the preference value will be ignored.

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

# SMS MFA are valid. SMS preference.
u.set_user_mfa_preference(True, False, "SMS")
# Software Token MFA are valid. Software token preference.
u.set_user_mfa_preference(False, True, "SOFTWARE_TOKEN")
# Both Software Token MFA and SMS MFA are valid. Software token preference
u.set_user_mfa_preference(True, True, "SOFTWARE_TOKEN")
# Both Software Token MFA and SMS MFA are disabled.
u.set_user_mfa_preference(False, False)
```

**Arguments**

- **sms_mfa:** SMS MFA enabled / disabled (bool)
- **software_token_mfa:** Software Token MFA enabled / disabled (bool)
- **preferred:** Which is the priority, SMS or Software Token? The expected value is "SMS" or "SOFTWARE_TOKEN". However, it is not needed only if both of the previous arguments are False.

#### Admin Set User MFA Preference

Admin-privilege version of `set_user_mfa_preference`. Changes another user's MFA settings without requiring their access token.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

# Enable Software Token MFA for a user
u.admin_set_user_mfa_preference(
    username='bob',
    sms_mfa=False,
    software_token_mfa=True,
    preferred='SOFTWARE_TOKEN'
)

# Enable SMS MFA for a user
u.admin_set_user_mfa_preference(
    username='bob',
    sms_mfa=True,
    software_token_mfa=False,
    preferred='SMS'
)

# Disable all MFA for a user
u.admin_set_user_mfa_preference(username='bob', sms_mfa=False, software_token_mfa=False)
```

**Arguments**

- **username:** The user whose MFA preference to update
- **sms_mfa:** Enable SMS MFA (bool)
- **software_token_mfa:** Enable Software Token MFA (bool)
- **preferred:** `"SMS"`, `"SOFTWARE_TOKEN"`, or `None` when both are `False`

#### Get User Pool MFA Config

Return the pool-level MFA policy. `ResponseMetadata` is stripped from the result.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

config = u.get_user_pool_mfa_config()
print(config['MfaConfiguration'])  # 'OFF', 'OPTIONAL', or 'ON'
```

**Arguments**

- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.

#### Set User Pool MFA Config

Set the pool-level MFA policy. `MfaConfiguration` can be `"OFF"`, `"OPTIONAL"`, or `"ON"`.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

# Require TOTP MFA for all users
u.set_user_pool_mfa_config(
    MfaConfiguration='ON',
    SoftwareTokenMfaConfiguration={'Enabled': True}
)

# Make MFA optional
u.set_user_pool_mfa_config(
    MfaConfiguration='OPTIONAL',
    SoftwareTokenMfaConfiguration={'Enabled': True}
)

# Disable MFA entirely
u.set_user_pool_mfa_config(
    MfaConfiguration='OFF',
    SoftwareTokenMfaConfiguration={'Enabled': False}
)
```

**Arguments**

- **pool_id:** (optional) User pool ID. Defaults to `self.user_pool_id`.
- **\*\*kwargs:** `SetUserPoolMfaConfig` parameters such as `MfaConfiguration`, `SmsMfaConfiguration`, `SoftwareTokenMfaConfiguration`

#### Respond to Software Token MFA Challenge

Responds when a Software Token MFA challenge is requested at login.

```python
from pycognito import Cognito
from pycognito.exceptions import SoftwareTokenMFAChallengeException

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

try:
    u.authenticate(password='bobs-password')
except SoftwareTokenMFAChallengeException as error:
    code = input('Enter the 6-digit code generated by the TOTP generator (such as Google Authenticator).')
    u.respond_to_software_token_mfa_challenge(code)
```

When recreating a Cognito instance

```python
from pycognito import Cognito
from pycognito.exceptions import SoftwareTokenMFAChallengeException

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

try:
    u.authenticate(password='bobs-password')
except SoftwareTokenMFAChallengeException as error:
    mfa_tokens = error.get_tokens()

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')
code = input('Enter the 6-digit code generated by the TOTP generator (such as Google Authenticator).')
u.respond_to_software_token_mfa_challenge(code, mfa_tokens)

```

**Arguments**

- **code:** 6-digit code generated by the TOTP generator app
- **mfa_tokens:** mfa_token stored in MFAChallengeException. Not required if you have not regenerated the Cognito instance.

#### Respond to SMS MFA Challenge

Responds when a SMS MFA challenge is requested at login.

```python
from pycognito import Cognito
from pycognito.exceptions import SMSMFAChallengeException

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

try:
    u.authenticate(password='bobs-password')
except SMSMFAChallengeException as error:
    code = input('Enter the 6-digit code you received by SMS.')
    u.respond_to_sms_mfa_challenge(code)
```

When recreating a Cognito instance

```python
from pycognito import Cognito
from pycognito.exceptions import SMSMFAChallengeException

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

try:
    u.authenticate(password='bobs-password')
except SMSMFAChallengeException as error:
    mfa_tokens = error.get_tokens()

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')
code = input('Enter the 6-digit code generated by the TOTP generator (such as Google Authenticator).')
u.respond_to_sms_mfa_challenge(code, mfa_tokens)

```

**Arguments**

- **code:** 6-digit code you received by SMS
- **mfa_tokens:** mfa_token stored in MFAChallengeException. Not required if you have not regenerated the Cognito instance.

---

## Cognito SRP Utility

The `AWSSRP` class is used to perform [SRP(Secure Remote Password protocol)](https://www.ietf.org/rfc/rfc2945.txt) authentication.
This is the preferred method of user authentication with AWS Cognito.
The process involves a series of authentication challenges and responses, which if successful,
results in a final response that contains ID, access and refresh tokens.

### Using AWSSRP

The `AWSSRP` class takes a username, password, cognito user pool id, cognito app id, an optional
client secret (if app client is configured with client secret), an optional pool_region or `boto3` client.
Afterwards, the `authenticate_user` class method is used for SRP authentication. It accepts an optional
`client_metadata` dict, which is passed to the pool's Lambda triggers. Like `Cognito.authenticate`, it raises
`ForceChangePasswordException`, `SMSMFAChallengeException`, or `SoftwareTokenMFAChallengeException` when Cognito
returns one of those challenges.

```python
import boto3
from pycognito.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client)
tokens = aws.authenticate_user()

# Optionally pass metadata through to Lambda triggers
tokens = aws.authenticate_user(client_metadata={'source': 'web'})
```

To complete a `NEW_PASSWORD_REQUIRED` challenge directly with `AWSSRP`, call `set_new_password_challenge`:

```python
tokens = aws.set_new_password_challenge(new_password='new-password')
```

---

## Device Authentication Support

You must use the `USER_SRP_AUTH` authentication flow to use the device tracking feature. Read more about [Remembered Devices](https://repost.aws/knowledge-center/cognito-user-pool-remembered-devices)

### Receiving DeviceKey and DeviceGroupKey

Once the `authenticate_user` class method is used for SRP authentication, the response also returns `DeviceKey` and `DeviceGroupKey`.
These Keys will later be used to confirm the device.

```python
import boto3
from pycognito.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client)
tokens = aws.authenticate_user()
device_key = tokens["AuthenticationResult"]["NewDeviceMetadata"]["DeviceKey"]
device_group_key = tokens["AuthenticationResult"]["NewDeviceMetadata"]["DeviceGroupKey"]
```

### Confirming a Device

The `confirm_device` class method is used for confirming a device, it takes two inputs, `tokens` and `device_name` (`device_name` is optional and defaults to the machine's hostname).
The method returns two values, `response` and `device_password`. `device_password` will later be used to authenticate your device with
the Cognito user pool.

```python
response, device_password = aws.confirm_device(tokens=tokens, device_name='My Laptop')
```

### Updating Device Status

The `update_device_status` class method is used to update whether or not your device should be remembered. This method takes
three inputs, `is_remembered`, `access_token` and `device_key`. `is_remembered` is a boolean value, which sets the device status as
`"remembered"` on `True` and `"not_remembered"` on `False`, `access_token` is the Access Token provided by Cognito and `device_key` is the key
provided by the `authenticate_user` method.

```python
response = aws.update_device_status(False, tokens["AuthenticationResult"]["AccessToken"], device_key)
```

### Authenticating your Device

To authenticate your Device, add `device_key`, `device_group_key`, `device_password`, and optionally `device_name` to the `AWSSRP` class.

```python
import boto3
from pycognito.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client, device_key="device_key",
             device_group_key="device_group_key", device_password="device_password",
             device_name="My Device")
tokens = aws.authenticate_user()
```

### Using Device Auth with the Cognito Class

The `Cognito` class supports device authentication directly. Pass device parameters at construction time and they are forwarded automatically through the SRP flow, token refresh, and device confirmation steps.

When `NewDeviceMetadata` is present in the authentication response, `device_key` and `device_group_key` are updated on the instance automatically and `confirm_device` is called to complete registration.

```python
from pycognito import Cognito

# Authenticate with a previously confirmed device
u = Cognito(
    'your-user-pool-id', 'your-client-id',
    username='bob',
    device_key='us-east-1_abc123',
    device_group_key='device-group-key',
    device_password='device-password',
    device_name='Bobs Laptop'
)
u.authenticate(password='bobs-password')

# DEVICE_KEY is included automatically in refresh calls
u.renew_access_token()
```

`RequestsSrpAuth` also accepts the same device parameters and forwards them to the underlying `Cognito` instance:

```python
import requests
from pycognito.utils import RequestsSrpAuth

auth = RequestsSrpAuth(
    username='myusername',
    password='secret',
    user_pool_id='eu-west-1_1234567',
    client_id='4dn6jbcbhqcofxyczo3ms9z4cc',
    user_pool_region='eu-west-1',
    device_key='us-east-1_abc123',
    device_group_key='device-group-key',
    device_password='device-password',
    device_name='My Service'
)

response = requests.get('http://test.com', auth=auth)
```

### Forget Device

To forget device, you can call the `forget_device` class method. It takes `access_token` and `device_key` as input.

```python
response = aws.forget_device(access_token='access_token', device_key='device_key')
```

### Device Management with the Cognito Class

The `Cognito` class can list, describe, and forget a user's remembered devices. Each method returns the device dicts from the Cognito API (`DeviceKey`, `DeviceAttributes`, `DeviceCreateDate`, and so on).

#### list_devices

List devices associated with the currently authenticated user (uses `access_token`). Without `page_limit`, every page is fetched and returned in one list. With `page_limit`, one page is returned and the token for the next page is available from `get_devices_pagination_token()`, which returns `None` once there are no more pages.

```python
# All devices
devices = u.list_devices()

# Or page through them
devices = u.list_devices(page_limit=10)
page_token = u.get_devices_pagination_token()
while page_token:
    devices.extend(u.list_devices(page_limit=10, page_token=page_token))
    page_token = u.get_devices_pagination_token()
```

- **page_limit:** (optional) Max results to return from this request (1 to 60)
- **page_token:** (optional) Token for the next page of results

#### get_device

Describe one of the authenticated user's devices.

```python
device = u.get_device(device_key='us-east-1_abc123')
```

- **device_key:** The device key to describe

#### admin_list_devices

Admin-privilege list of devices for the specified user. Paginates the same way as `list_devices`, and shares `get_devices_pagination_token()` with it.

```python
devices = u.admin_list_devices(username='bob')

devices = u.admin_list_devices(username='bob', page_limit=10)
page_token = u.get_devices_pagination_token()
```

- **username:** (optional) Username whose devices to list. Defaults to `self.username`.
- **page_limit:** (optional) Max results to return from this request (1 to 60)
- **page_token:** (optional) Token for the next page of results

#### admin_get_device

Admin-privilege describe of a specific device.

```python
device = u.admin_get_device(device_key='us-east-1_abc123', username='bob')
```

- **device_key:** The device key to describe
- **username:** (optional) Username who owns the device. Defaults to `self.username`.

#### admin_forget_device

Admin-privilege removal of a remembered device.

```python
u.admin_forget_device(device_key='us-east-1_abc123', username='bob')
```

- **device_key:** The device key to forget
- **username:** (optional) Username who owns the device. Defaults to `self.username`.

---

## SRP Requests Authenticator

`pycognito.utils.RequestsSrpAuth` is a [Requests](https://docs.python-requests.org/en/latest/)
authentication plugin to automatically populate an HTTP header with a Cognito token. By default, it'll populate
the `Authorization` header using the Cognito Access Token as a `bearer` token.

`RequestsSrpAuth` handles fetching new tokens using the refresh tokens.

### Usage

```python
import requests
from pycognito.utils import RequestsSrpAuth

auth = RequestsSrpAuth(
  username='myusername',
  password='secret',
  user_pool_id='eu-west-1_1234567',
  client_id='4dn6jbcbhqcofxyczo3ms9z4cc',
  user_pool_region='eu-west-1',
)

response = requests.get('http://test.com', auth=auth)
```

**Arguments**

- **username:** Cognito username
- **password:** User's password
- **user_pool_id:** Cognito User Pool ID
- **client_id:** Cognito App Client ID
- **user_pool_region:** (optional) AWS region. Inferred from `user_pool_id` if not provided.
- **client_secret:** (optional) App client secret
- **http_header_prefix:** (optional) Prefix string before the token value. Defaults to `"Bearer "`.
- **auth_token_type:** (optional) Whether to send the `ACCESS_TOKEN` or `ID_TOKEN`. Defaults to `ACCESS_TOKEN`.
- **boto3_client_kwargs:** (optional) Extra keyword arguments forwarded to `boto3.client()`
- **device_key:** (optional) Device Key for a previously confirmed device
- **device_group_key:** (optional) Device Group Key for a previously confirmed device
- **device_password:** (optional) Device Password for a previously confirmed device
- **device_name:** (optional) Friendly device name

---

## Switching boto3 Sessions

`switch_session` replaces the instance's boto3 client with one created from a different `boto3.Session`, for example to change credentials or to record and replay API calls in tests.

```python
import boto3
from pycognito import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')
u.switch_session(boto3.Session(profile_name='other-profile'))
```

- **session:** The `boto3.Session` to create the new `cognito-idp` client from

---

## Contributing

Contributions are welcome — bug fixes, new features, and documentation improvements alike.

### Development Setup

You'll need Python 3.10+ and [Make](https://www.gnu.org/software/make/).

```bash
git clone https://github.com/pvizeli/pycognito.git
cd pycognito
```

You should set up a virtual environment and run tests via pytest:

```bash
python -m venv venv
source venv/bin/activate
make init
```

`make init` installs the development dependencies and sets up the pre-commit hooks automatically.

### Available Make Targets

| Target           | Description                                               |
|------------------|-----------------------------------------------------------|
| `make init`      | Install dev dependencies and set up pre-commit hooks      |
| `make lint`      | Run `ruff` linter (no fixes applied)                      |
| `make format`    | Run `ruff` formatter (no fixes applied)                   |
| `make lint-fix`  | Run `ruff` linter and formatter (auto fix where possible) |
| `make test`      | Run tests with coverage (fails below 80%)                 |

### Running Tests

Tests use `pytest` to run against the current Python version:
```bash
make test        # current Python only
```
To test against all compatible Python versions (3.10–3.14) in isolated environments install `act`
and simulate a github push request
```bash
act push
```

Coverage is enforced at 80%. The test suite uses [moto](https://github.com/getmoto/moto) to mock AWS Cognito — no live AWS account is required.

### Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting. Pre-commit hooks run `ruff` automatically on every commit. To run manually:
```bash
make lint
```

### Submitting a Pull Request

1. Fork the repository and create a branch from `master`
2. Make your changes and ensure `make lint format test` passes locally
3. Add or update tests to cover your change
4. Open a pull request with a clear description of what changed and why
