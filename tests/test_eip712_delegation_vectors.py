import unittest
import time

from reference.identity import (
    build_session_delegation,
    eip712_sign_session_delegation,
    eip712_verify_session_delegation,
)


class TestEIP712DelegationVectors(unittest.TestCase):
    def setUp(self):
        try:
            from eth_account import Account  # noqa: F401
        except Exception:
            self.skipTest("eth-account not installed")

        # Deterministic test key (DO NOT use in production)
        self.priv_hex = "0x" + "11" * 32

    def test_vector_1_valid_delegation(self):
        now = int(time.time())
        delegation = build_session_delegation(
            agent="neo",
            hot_pub_raw32=b"\xdf" * 32,
            valid_from=now - 10,
            valid_until=now + 600,
            nonce=1,
            statement="I authorize this Ed25519 key for A2A Secure messaging on behalf of Neo",
        )
        addr, sig = eip712_sign_session_delegation(self.priv_hex, delegation)
        ok, reason = eip712_verify_session_delegation(sig, delegation, addr, last_known_nonce=0, now=now)
        self.assertTrue(ok, reason)

    def test_vector_2_expired_delegation(self):
        now = int(time.time())
        delegation = build_session_delegation(
            agent="neo",
            hot_pub_raw32=b"\xdf" * 32,
            valid_from=now - 1000,
            valid_until=now - 5,
            nonce=1,
            statement="I authorize this Ed25519 key for A2A Secure messaging on behalf of Neo",
        )
        addr, sig = eip712_sign_session_delegation(self.priv_hex, delegation)
        ok, reason = eip712_verify_session_delegation(sig, delegation, addr, last_known_nonce=0, now=now)
        self.assertFalse(ok)
        self.assertEqual(reason, "delegation_not_valid_now")

    def test_vector_3_revoked_nonce_too_low(self):
        now = int(time.time())
        delegation = build_session_delegation(
            agent="neo",
            hot_pub_raw32=b"\xdf" * 32,
            valid_from=now - 10,
            valid_until=now + 600,
            nonce=1,
            statement="I authorize this Ed25519 key for A2A Secure messaging on behalf of Neo",
        )
        addr, sig = eip712_sign_session_delegation(self.priv_hex, delegation)
        ok, reason = eip712_verify_session_delegation(sig, delegation, addr, last_known_nonce=2, now=now)
        self.assertFalse(ok)
        self.assertEqual(reason, "delegation_nonce_too_low")


if __name__ == "__main__":
    unittest.main()
