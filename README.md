# pyCognito

Makes working with AWS Cognito easier for Python developers.

## Getting Started

- [Python Versions Supported](#python-versions-supported)
- [Install](#install)
- [Environment Variables](#environment-variables)
  - [COGNITO_JWKS](#cognito-jwks) (optional)
- [Cognito Utility Class](#cognito-utility-class) `pycognito.Cognito`
  - [Cognito Methods](#cognito-methods)
    - [Register](#register)
    - [Authenticate](#authenticate)
    - [Admin Authenticate](#admin-authenticate)
    - [Initiate Forgot Password](#initiate-forgot-password)
    - [Confirm Forgot Password](#confirm-forgot-password)
    - [Change Password](#change-password)
    - [Confirm Sign Up](#confirm-sign-up)
    - [Update Profile](#update-profile)
    - [Send Verification](#send-verification)
    - [Get User Object](#get-user-object)
    - [Get User](#get-user)
    - [Get Users](#get-users)
    - [Get Group Object](#get-group-object)
    - [Get Group](#get-group)
    - [Get Groups](#get-groups)
    - [Check Token](#check-token)
    - [Verify Tokens](#verify-tokens)
    - [Logout](#logout)
    - [Associate Software Token](#associate-software-token)
    - [Verify Software Token](#verify-software-token)
    - [Set User MFA Preference](#set-user-mfa-preference)
    - [Respond to Software Token MFA challenge](#respond-to-software-token-mfa-challenge)
    - [Respond to SMS MFA challenge](#respond-to-sms-mfa-challenge)
- [Cognito SRP Utility](#cognito-srp-utility)
  - [Using AWSSRP](#using-awssrp)
- [Device Authentication Support](#device-authentication-support)
  - [Receiving DeviceKey and DeviceGroupKey](#receiving-devicekey-and-devicegroupkey)
  - [Confirming a Device](#confirming-a-device)
  - [Updating Device Status](#updating-device-status)
  - [Authenticating your Device](#authenticating-your-device)
  - [Forget Device](#forget-device)
- [SRP Requests Authenticator](#srp-requests-authenticator)

## Python Versions Supported

- 3.9
- 3.10
- 3.11
- 3.12

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

## Cognito Utility Class

### Example with All Arguments

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    client_secret='optional-client-secret',
    username='optional-username',
    id_token='optional-id-token',
    refresh_token='optional-refresh-token',
    access_token='optional-access-token',
    access_key='optional-access-key',
    secret_key='optional-secret-key')
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

### Examples with Realistic Arguments

#### User Pool Id and Client ID Only

Used when you only need information about the user pool (ex. list users in the user pool)

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

## Cognito Attributes

After any authentication or other explicit verification of tokens, the following additional attributes will be available:

- `id_claims` — A dict of verified claims from the id token
- `access_claims` — A dict of verified claims from the access token

## Cognito Methods

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

##### Arguments

- **username:** User Pool username
- **password:** User Pool password
- **attr_map:** Attribute map to Cognito's attributes

#### Authenticate

Authenticates a user

If this method call succeeds the instance will have the following attributes **id_token**, **refresh_token**, **access_token**, **expires_in**, **expires_datetime**, and **token_type**.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.authenticate(password='bobs-password')
```

##### Arguments

- **password:** - User's password

#### Admin Authenticate

Authenticate the user using admin super privileges

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.admin_authenticate(password='bobs-password')
```

- **password:** User's password

#### Initiate Forgot Password

Sends a verification code to the user to use to change their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.initiate_forgot_password()
```

##### Arguments

No arguments

#### Confirm Forgot Password

Allows a user to enter a code provided when they reset their password
to update their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.confirm_forgot_password('your-confirmation-code','your-new-password')
```

##### Arguments

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

##### Arguments

- **previous_password:** - User's previous password
- **proposed_password:** - The password that the user wants to change to.

#### Confirm Sign Up

Use the confirmation code that is sent via email or text to confirm the user's account

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.confirm_sign_up('users-conf-code',username='bob')
```

##### Arguments

- **confirmation_code:** Confirmation code sent via text or email
- **username:** User's username

#### Update Profile

Update the user's profile

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.update_profile({'given_name':'Edward','family_name':'Smith',},attr_map=dict())
```

##### Arguments

- **attrs:** Dictionary of attribute name, values
- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Send Verification

Send verification email or text for either the email or phone attributes.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
```

##### Arguments

- **attribute:** - The attribute (email or phone) that needs to be verified

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

##### Arguments

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

##### Arguments

- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Get Users

Get a list of the user in the user pool.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

user = u.get_users(attr_map={"given_name":"first_name","family_name":"last_name"})
```

##### Arguments

- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Get Group object

Returns an instance of the specified group_class.

```python
u = Cognito('your-user-pool-id', 'your-client-id')

group_data = {'GroupName': 'user_group', 'Description': 'description',
            'Precedence': 1}

group_obj = u.get_group_obj(group_data)
```

##### Arguments

- **group_data:** Dictionary with group's attributes.

#### Get Group

Get all of the group's attributes. Returns an instance of the group_class.
Requires developer credentials.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

group = u.get_group(group_name='some_group_name')
```

##### Arguments

- **group_name:** Name of a group

#### Get Groups

Get a list of groups in the user pool. Requires developer credentials.

```python
from pycognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

groups = u.get_groups()
```

#### Check Token

Checks the exp attribute of the access_token and either refreshes the tokens by calling the renew_access_tokens method or does nothing. **IMPORTANT:** Access token is required

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.check_token()
```

##### Arguments

No arguments for check_token

#### Verify Tokens

Verifies the current `id_token` and `access_token`.
An exception will be thrown if they do not pass verification.
It can be useful to call this method immediately after instantiation when you're providing externally-remembered tokens to the `Cognito()` constructor.
Note that if you're calling `check_tokens()` after instantitation, you'll still want to call `verify_tokens()` afterwards it in case it did nothing.
This method also ensures that the `id_claims` and `access_claims` attributes are set with the verified claims from each token.

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.check_tokens()  # Optional, if you want to maybe renew the tokens
u.verify_tokens()
```

##### Arguments

No arguments for verify_tokens

#### Logout

Logs the user out of all clients and removes the expires_in, expires_datetime, id_token, refresh_token, access_token, and token_type attributes.

```python
from pycognito import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.logout()
```

##### Arguments

No arguments for logout

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

##### Arguments

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

##### Arguments

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

##### Arguments

- **sms_mfa:** SMS MFA enabled / disabled (bool)
- **software_token_mfa:** Software Token MFA enabled / disabled (bool)
- **preferred:** Which is the priority, SMS or Software Token? The expected value is "SMS" or "SOFTWARE_TOKEN". However, it is not needed only if both of the previous arguments are False.

#### Respond to Software Token MFA challenge

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

##### Arguments

- **code:** 6-digit code generated by the TOTP generator app
- **mfa_tokens:** mfa_token stored in MFAChallengeException. Not required if you have not regenerated the Cognito instance.

#### Respond to SMS MFA challenge

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

##### Arguments

- **code:** 6-digit code you received by SMS
- **mfa_tokens:** mfa_token stored in MFAChallengeException. Not required if you have not regenerated the Cognito instance.

## Cognito SRP Utility

The `AWSSRP` class is used to perform [SRP(Secure Remote Password protocol)](https://www.ietf.org/rfc/rfc2945.txt) authentication.
This is the preferred method of user authentication with AWS Cognito.
The process involves a series of authentication challenges and responses, which if successful,
results in a final response that contains ID, access and refresh tokens.

### Using AWSSRP

The `AWSSRP` class takes a username, password, cognito user pool id, cognito app id, an optional
client secret (if app client is configured with client secret), an optional pool_region or `boto3` client.
Afterwards, the `authenticate_user` class method is used for SRP authentication.

```python
import boto3
from pycognito.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client)
tokens = aws.authenticate_user()
```

## Device Authentication Support

You must use the `USER_SRP_AUTH` authentication flow to use the device tracking feature. Read more about [Remembered Devices](https://repost.aws/knowledge-center/cognito-user-pool-remembered-devices)

### Receiving DeviceKey and DeviceGroupKey

Once the `authenticate_user` class method is used for SRP authentication, the response also returns `DeviceKey` and `DeviceGrouKey`.
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

The `confirm_device` class method is used for confirming a device, it takes two inputs, `tokens` and `DeviceName` (`DeviceName` is optional).
The method returns two values, `response` and `device_password`. `device_password` will later be used to authenticate your device with
the Cognito user pool.

```python
response, device_password = aws.confirm_device(tokens=tokens)
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

To authenticate your Device, you can just add `device_key`, `device_group_key` and `device_password` to the AWSSRP class.

```python
import boto3
from pycognito.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client, device_key="device_key",
             device_group_key="device_group_key", device_password="device_password")
tokens = aws.authenticate_user()
```

### Forget Device

To forget device, you can call the `forget_device` class method. It takes `access_token` and `device_key` as input.

```python
resonse = aws.forget_device(access_token='access_token', device_key='device_key')
```

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
