"""
pycognito/_base.py
==================
``CognotoBase`` — a :class:`typing.Protocol` that declares every instance
attribute and cross-mixin method the four mixins expect to find on ``self``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, Type, TypedDict

try:
    from mypy_boto3_cognito_idp import CognitoIdentityProviderClient as _ClientT
except ImportError:
    _ClientT = Any  # type: ignore[assignment, misc]

if TYPE_CHECKING:
    from mypy_boto3_cognito_idp.type_defs import (
        AttributeTypeTypeDef,
        GroupTypeTypeDef,
        InitiateAuthResponseTypeDef,
    )

    from .objects import GroupObj, UserObj


# ---------------------------------------------------------------------------
# TypedDicts for structures not covered by boto3-stubs
# (these come from HTTP endpoints, not the boto3 service model)
# ---------------------------------------------------------------------------


class JwkKeyTypeDef(TypedDict, total=False):
    """A single JSON Web Key as returned by Cognito's JWKS endpoint."""

    alg: str  # Algorithm, e.g. "RS256"
    e: str  # RSA public exponent
    kid: str  # Key ID — matched against the JWT header ``kid`` field
    kty: str  # Key type, e.g. "RSA"
    n: str  # RSA modulus
    use: str  # Key use, e.g. "sig"


class JwksTypeDef(TypedDict):
    """Shape of the ``/.well-known/jwks.json`` response."""

    keys: List[JwkKeyTypeDef]


class CognitoClaimsTypeDef(TypedDict, total=False):
    """
    JWT claims present in Cognito access tokens and ID tokens.

    All fields are optional (``total=False``) because the two token types
    carry different subsets of these claims.
    """

    # Common to both token types
    sub: str  # Subject — stable unique user UUID
    iss: str  # Issuer URL
    exp: int  # Expiry (Unix epoch seconds)
    iat: int  # Issued-at (Unix epoch seconds)
    jti: str  # JWT ID
    token_use: str  # ``"access"`` or ``"id"``
    # Access-token only
    client_id: str
    scope: str
    auth_time: int
    username: str
    origin_jti: str
    event_id: str
    # ID-token only
    aud: str
    at_hash: str
    email: str
    email_verified: bool
    phone_number: str
    phone_number_verified: bool
    given_name: str
    family_name: str
    name: str


class MfaTokensTypeDef(TypedDict, total=False):
    """
    MFA challenge state stored on the ``Cognito`` instance when authentication
    is interrupted by ``SMS_MFA`` or ``SOFTWARE_TOKEN_MFA``.

    Passed to ``respond_to_sms_mfa_challenge`` /
    ``respond_to_software_token_mfa_challenge`` when the ``Cognito`` instance
    has been re-created between the initial auth call and the challenge response.
    """

    ChallengeName: str  # e.g. ``"SMS_MFA"``
    Session: str  # Opaque session token required for the response
    ChallengeParameters: Dict[str, str]


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class CognotoBase(Protocol):
    """
    Structural protocol declaring every attribute and cross-mixin method
    that the pycognito mixins access on ``self``.
    """

    # ------------------------------------------------------------------
    # Pool / app identity
    # ------------------------------------------------------------------

    user_pool_id: str
    """Cognito User Pool ID, e.g. ``us-east-1_AbcDef123``."""

    user_pool_region: str
    """AWS region inferred or supplied at construction time."""

    client_id: Optional[str]
    """App client ID.  ``None`` for admin-only operations."""

    client_secret: Optional[str]
    """App client secret, or ``None`` if the client has no secret."""

    pool_domain_url: Optional[str]
    """
    Custom domain / endpoint URL extracted from ``boto3_client_kwargs``.
    Usually ``None`` for standard AWS deployments.
    """

    @property
    def user_pool_url(self) -> str:
        """
        Computed issuer URL for this pool, e.g.
        ``https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc``.
        """
        ...

    # ------------------------------------------------------------------
    # boto3 client
    # ------------------------------------------------------------------

    client: _ClientT
    """
    boto3 ``cognito-idp`` service client.
    """

    # ------------------------------------------------------------------
    # User identity
    # ------------------------------------------------------------------

    username: Optional[str]
    """Cognito username (may be an email when ``UsernameAttributes`` includes email)."""

    # ------------------------------------------------------------------
    # Tokens
    # ------------------------------------------------------------------

    id_token: Optional[str]
    """Raw ID JWT string; set after successful authentication."""

    access_token: Optional[str]
    """Raw access JWT string; set after successful authentication."""

    refresh_token: Optional[str]
    """Refresh token string; set after successful authentication."""

    token_type: Optional[str]
    """Token type returned by Cognito, e.g. ``"Bearer"``."""

    id_claims: Optional[CognitoClaimsTypeDef]
    """
    Verified claims from the ID token, set by ``verify_token`` on authentication.
    Contains standard OIDC claims plus Cognito user-pool attributes.
    ``None`` until the first successful authentication.
    """

    access_claims: Optional[CognitoClaimsTypeDef]
    """
    Verified claims from the access token, set by ``verify_token`` on
    authentication.  Contains ``sub``, ``scope``, ``client_id``, ``username``.
    ``None`` until the first successful authentication.
    """

    # ------------------------------------------------------------------
    # JWKS cache
    # ------------------------------------------------------------------

    pool_jwk: Optional[JwksTypeDef]
    """
    Cached JWKS dict for this pool, populated on the first ``get_keys()``
    call.  Holds ``{"keys": [...]}`` from the ``/.well-known/jwks.json``
    endpoint.  ``None`` until first use.
    """

    # ------------------------------------------------------------------
    # MFA
    # ------------------------------------------------------------------

    mfa_tokens: Optional[MfaTokensTypeDef]
    """
    MFA challenge state stored when authentication is interrupted.
    Contains the ``Session`` token and ``ChallengeName`` required by
    ``respond_to_*_mfa_challenge``.  ``None`` when no challenge is active.
    """

    # ------------------------------------------------------------------
    # Attribute staging
    # ------------------------------------------------------------------

    base_attributes: Optional[Dict[str, Any]]
    """Standard Cognito user attributes staged for ``register``."""

    custom_attributes: Optional[Dict[str, Any]]
    """Custom (``custom:*``) attributes staged for registration."""

    # ------------------------------------------------------------------
    # Device authentication (PR #306)
    # ------------------------------------------------------------------

    device_key: Optional[str]
    """Device key returned by Cognito after device confirmation."""

    device_group_key: Optional[str]
    """Device group key returned alongside ``device_key``."""

    device_password: Optional[str]
    """Device password established by ``confirm_device``."""

    device_name: Optional[str]
    """Optional friendly device name supplied at construction time."""

    # ------------------------------------------------------------------
    # Object factories
    # ------------------------------------------------------------------

    @property
    def user_class(self) -> Type["UserObj"]:
        """
        Class used to construct user objects.
        """
        ...

    @property
    def group_class(self) -> Type["GroupObj"]:
        """
        Class used to construct group objects.
        """
        ...

    # ------------------------------------------------------------------
    # Pagination state
    # ------------------------------------------------------------------

    _users_pagination_next_token: Optional[str]
    _groups_pagination_next_token: Optional[str]
    _clients_pagination_next_token: Optional[str]
    _group_users_pagination_next_token: Optional[str]
    _devices_pagination_next_token: Optional[str]

    # ------------------------------------------------------------------
    # Cross-mixin method stubs
    # ------------------------------------------------------------------

    def verify_token(
        self, token: str, id_name: str, token_use: str
    ) -> CognitoClaimsTypeDef:
        """
        Defined in ``TokensMixin``.  Verifies *token*, stores the decoded
        claims on ``self``, and returns the claims dict.
        """
        ...

    def get_keys(self) -> JwksTypeDef:
        """
        Defined in ``TokensMixin``.  Returns the JWKS dict for this pool,
        fetching and caching it on the first call.
        """
        ...

    def get_key(self, kid: str) -> JwkKeyTypeDef:
        """
        Defined in ``TokensMixin``.  Returns the JWK matching *kid*,
        raising ``jwt.PyJWTError`` when not found.
        """
        ...

    def check_token(self, renew: bool = True) -> bool:
        """
        Defined in ``TokensMixin``.  Returns ``True`` when the access token
        has expired; calls ``renew_access_token()`` automatically when
        *renew* is ``True``.
        """
        ...

    def renew_access_token(self) -> None:
        """
        Defined in ``AuthMixin``.  Refreshes ``access_token`` and
        ``id_token`` using the cached ``refresh_token``.
        """
        ...

    def _set_tokens(self, tokens: "InitiateAuthResponseTypeDef") -> None:
        """
        Defined in ``TokensMixin``.  Verifies and sets ``access_token``,
        ``id_token``, ``refresh_token``, ``token_type``, and any device
        metadata from a Cognito ``AuthenticationResult`` response.
        """
        ...

    def _add_secret_hash(
        self,
        parameters: Dict[str, str],
        param_name: str,
        username: Optional[str] = None,
    ) -> None:
        """
        Defined in ``AuthMixin``.  Computes the HMAC-SHA256 ``SecretHash``
        and inserts it into *parameters* at *param_name*.  No-op when no
        ``client_secret`` is configured.
        """
        ...

    def _set_attributes(
        self, response: Dict[str, Any], attribute_dict: Dict[str, Any]
    ) -> None:
        """
        Defined in ``AuthMixin``.  Copies each key/value in *attribute_dict*
        onto ``self`` when the HTTP response carries a 200 status.
        """
        ...

    def get_user_obj(
        self,
        username: Optional[str] = None,
        attribute_list: Optional[List["AttributeTypeTypeDef"]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        attr_map: Optional[Dict[str, str]] = None,
    ) -> "UserObj":
        """
        Defined in ``UserPoolMixin``.  Constructs a
        :class:`~pycognito.objects.UserObj` from a Cognito attribute list.
        """
        ...

    def get_group_obj(self, group_data: "GroupTypeTypeDef") -> "GroupObj":
        """
        Defined in ``UserPoolMixin``.  Constructs a
        :class:`~pycognito.objects.GroupObj` from a Cognito group dict.
        """
        ...
