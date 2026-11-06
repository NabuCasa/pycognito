"""
Tests for not-yet-implemented MFA configuration stubs in mfa.py.

Implemented stubs (real tests elsewhere):
  - admin_set_user_mfa_preference  → test_mfa.py: AdminSetUserMFAPreferenceTestCase
  - get_user_pool_mfa_config       → test_mfa.py: UserPoolMFAConfigTestCase
  - set_user_pool_mfa_config       → test_mfa.py: UserPoolMFAConfigTestCase

No remaining stubs in mfa.py — this file is intentionally empty of
NotImplementedError tests. It is kept so the test layout remains
consistent with the source module structure.
"""

import unittest

if __name__ == "__main__":
    unittest.main()
