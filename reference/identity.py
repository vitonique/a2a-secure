"""A2A Identity Layer v0.5.0 (reference)

Implements:
- Ed25519 key generation + local storage (~/.config/a2a/keys/)
- Hot key 24h expiry
- Challenge-response primitives (nonce + ed25519 signatures)

EIP-712 SessionDelegation signing is implemented behind an optional dependency
(eth-account). If eth-account is not installed, the functions raise a clear
error.

Zen-provided EIP-712 Domain + Types:
Domain:
  name: "A2A Identity"
  version: "1"
  chainId: 137
  verifyingContract: 0x0000000000000000000000000000000000000000
Types:
  SessionDelegation(bytes32 hotPubKey,uint256 validFrom,uint256 validUntil,uint256 nonce)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


KEY_DIR = os.path.expanduser("~/.config/a2a/keys")
COLD_KEY_PATH = os.path.join(KEY_DIR, "cold_wallet.json")  # stores wallet address only (PK stays external)
HOT_KEY_PATH = os.path.join(KEY_DIR, "hot_ed25519.json")

HOT_KEY_TTL_SECONDS = 24 * 60 * 60


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass
class HotKey:
    priv: Ed25519PrivateKey
    pub: Ed25519PublicKey
    created_at: int
    expires_at: int

    def pub_raw32(self) -> bytes:
        # Ed25519 raw public key is 32 bytes
        return self.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign_bytes(self, payload: bytes) -> bytes:
        return self.priv.sign(payload)


def ensure_key_dir() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)


def generate_hot_key(now: Optional[int] = None, ttl_seconds: int = HOT_KEY_TTL_SECONDS) -> HotKey:
    ensure_key_dir()
    now_i = int(now or time.time())
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return HotKey(priv=priv, pub=pub, created_at=now_i, expires_at=now_i + int(ttl_seconds))


def save_hot_key(hk: HotKey) -> None:
    ensure_key_dir()
    priv_raw = hk.priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = hk.pub_raw32()
    data = {
        "kty": "Ed25519",
        "created_at": hk.created_at,
        "expires_at": hk.expires_at,
        "pub_b64": _b64e(pub_raw),
        "priv_b64": _b64e(priv_raw),
    }
    with open(HOT_KEY_PATH, "w") as f:
        json.dump(data, f, indent=2)

    # Lock down private key file permissions (owner read/write)
    try:
        os.chmod(HOT_KEY_PATH, 0o600)
    except Exception:
        pass


def load_hot_key() -> Optional[HotKey]:
    try:
        with open(HOT_KEY_PATH, "r") as f:
            data = json.load(f)
        priv = Ed25519PrivateKey.from_private_bytes(_b64d(data["priv_b64"]))
        pub = priv.public_key()
        return HotKey(
            priv=priv,
            pub=pub,
            created_at=int(data["created_at"]),
            expires_at=int(data["expires_at"]),
        )
    except FileNotFoundError:
        return None
    except Exception:
        return None


def hot_key_valid(hk: HotKey, now: Optional[int] = None) -> bool:
    now_i = int(now or time.time())
    return now_i < hk.expires_at


def get_or_create_hot_key() -> HotKey:
    hk = load_hot_key()
    if hk and hot_key_valid(hk):
        return hk
    hk = generate_hot_key()
    save_hot_key(hk)
    return hk


# ------------------- Message signing -------------------

def sign_message_dict(hk: HotKey, msg: Dict[str, Any]) -> str:
    """Return base64 signature over canonical JSON of msg (excluding 'sig')."""
    m = dict(msg)
    m.pop("sig", None)
    digest = sha256(_canonical_json(m))
    sig = hk.sign_bytes(digest)
    return _b64e(sig)


def verify_message_dict(pub_raw32: bytes, msg: Dict[str, Any], sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_raw32)
        m = dict(msg)
        m.pop("sig", None)
        digest = sha256(_canonical_json(m))
        pub.verify(_b64d(sig_b64), digest)
        return True
    except Exception:
        return False


# ------------------- Challenge/Response -------------------

def make_challenge() -> Dict[str, Any]:
    # 32-byte nonce, base64 encoded
    nonce = os.urandom(32)
    return {"nonce_b64": _b64e(nonce), "ts": int(time.time())}


def sign_nonce(hk: HotKey, nonce_b64: str) -> str:
    nonce = _b64d(nonce_b64)
    return _b64e(hk.sign_bytes(sha256(nonce)))


def verify_nonce_sig(pub_raw32: bytes, nonce_b64: str, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_raw32)
        pub.verify(_b64d(sig_b64), sha256(_b64d(nonce_b64)))
        return True
    except Exception:
        return False


# ------------------- EIP-712 SessionDelegation -------------------

EIP712_DOMAIN = {
    "name": "A2A Identity",
    "version": "1",
    "chainId": 137,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}

EIP712_TYPES = {
    "SessionDelegation": [
        {"name": "hotPubKey", "type": "bytes32"},
        {"name": "validFrom", "type": "uint256"},
        {"name": "validUntil", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
    ]
}


def build_session_delegation(hot_pub_raw32: bytes, valid_from: int, valid_until: int, nonce: int) -> Dict[str, Any]:
    if len(hot_pub_raw32) != 32:
        raise ValueError("hot_pubkey_must_be_32_bytes")
    return {
        "hotPubKey": hot_pub_raw32,
        "validFrom": int(valid_from),
        "validUntil": int(valid_until),
        "nonce": int(nonce),
    }


def eip712_sign_session_delegation(wallet_privkey_hex: str, delegation: Dict[str, Any]) -> Tuple[str, str]:
    """Sign EIP-712 typed data. Returns (wallet_address, signature_hex).

    Requires eth-account in environment.
    """
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except Exception as e:
        raise RuntimeError("eth-account is required for EIP-712 signing") from e

    acct = Account.from_key(wallet_privkey_hex)

    # eth-account expects bytes32 as hex string or bytes; we'll pass bytes.
    typed = {
        "types": {**EIP712_TYPES, "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ]},
        "primaryType": "SessionDelegation",
        "domain": EIP712_DOMAIN,
        "message": {
            "hotPubKey": delegation["hotPubKey"],
            "validFrom": int(delegation["validFrom"]),
            "validUntil": int(delegation["validUntil"]),
            "nonce": int(delegation["nonce"]),
        },
    }

    msg = encode_typed_data(full_message=typed)
    sig = acct.sign_message(msg).signature.hex()
    return acct.address, sig
