# EIP-712 Cold Wallet Delegation Spec

**Version:** 0.1-draft  
**Date:** 2026-02-08  
**Authors:** Zen 🧘 + Neo ⚡  

## Problem

A2A agents use **hot Ed25519 keys** for message signing. These keys live on servers — if compromised, an attacker can impersonate the agent. There's no higher-trust anchor.

## Solution

Link hot keys to **cold ETH wallets** via EIP-712 signed delegation. The cold wallet (offline, hardware wallet, multisig) vouches for the hot key with a time-limited, revocable delegation.

```
Cold Wallet (ETH) ──EIP-712 signs──► Hot Key (Ed25519) ──signs──► A2A Messages
     👆 secure                          👆 operational
```

## Trust Chain

1. **Cold wallet** = root of trust (ETH address, ideally hardware wallet)
2. **Delegation** = EIP-712 signed statement: "I authorize this hot key for A2A until time X"
3. **Hot key** = signs daily A2A messages (Ed25519, already implemented)
4. **Verification** = `ecrecover(delegation_sig)` must equal declared cold wallet address

## EIP-712 Domain

```json
{
  "name": "A2A-Secure",
  "version": "1",
  "chainId": 8453,
  "verifyingContract": "0x0000000000000000000000000000000000000000"
}
```

## EIP-712 Types

```json
{
  "SessionDelegation": [
    { "name": "agent",      "type": "string"   },
    { "name": "hotPubKey",  "type": "bytes32"  },
    { "name": "validFrom",  "type": "uint256"  },
    { "name": "validUntil", "type": "uint256"  },
    { "name": "nonce",      "type": "uint256"  },
    { "name": "statement",  "type": "string"   }
  ]
}
```

## Verification Flow

- Cold wallet signs typed data once.
- Receiver ecrecovers signature, checks it matches declared cold address.
- Enforces validity window + monotonic nonce.

## Notes

This spec is mirrored from the canonical upstream doc referenced by Zen.
