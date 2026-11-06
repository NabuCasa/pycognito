"""
Custom exceptions raised by pycognito.

TokenVerificationException  — JWT could not be verified
ForceChangePasswordException — Cognito requires a password change before auth
MFAChallengeException        — base for MFA challenges (carries session tokens)
SMSMFAChallengeException     — SMS_MFA challenge subclass
SoftwareTokenMFAChallengeException — SOFTWARE_TOKEN_MFA challenge subclass
"""


class TokenVerificationException(Exception):
    """Raised when a Cognito JWT fails verification."""


class ForceChangePasswordException(Exception):
    """
    Raised during authentication when Cognito requires the user to change
    their password before a session can be established.
    """


class MFAChallengeException(Exception):
    """
    Base exception for MFA challenges returned during authentication.
    Carries the challenge tokens so they can be retrieved by the caller
    and passed to the appropriate respond_to_*_mfa_challenge method.
    """

    def __init__(self, message, tokens):
        super().__init__(message)
        self._tokens = tokens

    def get_tokens(self):
        """Return the raw challenge tokens dict from Cognito."""
        return self._tokens


class SMSMFAChallengeException(MFAChallengeException):
    """Raised when Cognito returns an SMS_MFA challenge."""


class SoftwareTokenMFAChallengeException(MFAChallengeException):
    """Raised when Cognito returns a SOFTWARE_TOKEN_MFA challenge."""
