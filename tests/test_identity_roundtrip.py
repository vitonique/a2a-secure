import unittest
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from reference.identity import (
    HotKey,
    build_session_delegation,
    eip712_sign_session_delegation,
    eip712_recover_session_delegation,
    sign_message_dict,
    verify_message_dict,
)


class TestIdentityRoundtrip(unittest.TestCase):
    def test_eip712_sign_and_recover_roundtrip(self):
        # Generate an ephemeral Ethereum account (no external wallet dependency)
        try:
            from eth_account import Account
        except Exception:
            self.skipTest("eth-account not installed")

        acct = Account.create()
        priv_hex = acct.key.hex()  # includes 0x

        now = int(time.time())
        delegation = build_session_delegation(b"\x11" * 32, now - 5, now + 300, 42)
        addr, sig = eip712_sign_session_delegation(priv_hex, delegation)
        recovered = eip712_recover_session_delegation(sig, delegation)

        self.assertEqual(addr.lower(), recovered.lower())

    def test_hotkey_message_sig_roundtrip(self):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        now = int(time.time())
        hk = HotKey(priv=priv, pub=pub, created_at=now, expires_at=now + 60)

        msg = {
            "schema_version": "2.4",
            "trace_id": "test-1",
            "sender": "Neo",
            "message": "hello",
            "wake": False,
        }
        sig_b64 = sign_message_dict(hk, msg)
        pub_raw32 = hk.pub_raw32()

        self.assertTrue(verify_message_dict(pub_raw32, {**msg, "sig": sig_b64}, sig_b64))


if __name__ == "__main__":
    unittest.main()
