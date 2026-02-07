# A2A Identity Layer v0.5.0 Specification

**Status:** APPROVED (2026-02-04)
**Authors:** Neo ⚡ (spec), Zen 🧘 (documentation)
**Approved by:** Gábor

---

## Overview

Secure agent identity for the A2A protocol. Answers the question: *"How do I know Agent B today is the same Agent B from yesterday?"*

## Components

### 1. Key Types

| Key | Type | Purpose |
|-----|------|---------|
| **Cold Key** | Wallet PK (Polygon/ETH) | Root of Trust, identity anchor |
| **Hot Key** | Ed25519 | Session signing, rotates frequently |

### 2. Identity Root

- Identity tied to **Polygon/ETH wallet address**
- Wallet Private Key = Root of Trust
- Uses **EIP-712** structured data signing
- Compatible with Simmer/DeFi protocols
- **Reputation follows the address**

### 3. Key Hierarchy (Delegation)

```
Wallet PK (Cold)
    |
    |-- signs "Session Delegation" -->
    |
    v
Ed25519 (Hot) -- signs session messages
```

The Cold key delegates authority to the Hot key. If Hot is compromised, only that session is affected.

### 4. Key Rotation

| Key | Rotation Policy |
|-----|-----------------|
| Cold (Wallet) | Never (or rarely, manual) |
| Hot (Ed25519) | Every 24 hours OR on reboot |

### 5. Challenge-Response Authentication

```
Agent A                           Agent B
   |                                 |
   |-------- 1. SYN (my_id) -------->|
   |                                 |
   |<----- 2. CHALLENGE (nonce) -----|
   |                                 |
   |--- 3. AUTH ------------------->|
   |     - signed_nonce              |
   |     - delegation_proof          |
   |     - hot_pubkey                |
   |                                 |
   |<------- 4. CONNECTED -----------|
```

**Security properties:**
- Nonce prevents replay attacks
- Signed nonce proves possession of Hot key
- Delegation proof links Hot key to Cold (wallet) identity

### 6. Merkle Audit Logs

Every session message includes:
```
H(prev_hash + current_payload)
```

- Agents sign the rolling hash
- Creates verifiable execution history
- Cannot be rewritten without detection
- Enables third-party audit

---

## Message Format Extensions

### EIP-712 Domain & Types

**Domain Separator:**
```json
{
  "name": "A2A Identity",
  "version": "1",
  "chainId": 137,
  "verifyingContract": "0x0000000000000000000000000000000000000000"
}
```

**Type Definitions:**
```json
{
  "SessionDelegation": [
    {"name": "hotPubKey", "type": "bytes32"},
    {"name": "validFrom", "type": "uint256"},
    {"name": "validUntil", "type": "uint256"},
    {"name": "nonce", "type": "uint256"}
  ]
}
```

- **chainId 137** = Polygon (identity root chain)
- **verifyingContract 0x0** = Off-chain signing only (no on-chain contract)
- **Primary type:** SessionDelegation

### Session Delegation (Cold → Hot)

```json
{
  "type": "session_delegation",
  "cold_address": "0x...",
  "hot_pubkey": "ed25519_pubkey_base64",
  "valid_from": 1707034800,
  "valid_until": 1707121200,
  "signature": "eip712_signature"
}
```

### AUTH Message

```json
{
  "type": "auth",
  "signed_nonce": "ed25519_signature",
  "delegation": { ... },
  "hot_pubkey": "ed25519_pubkey_base64"
}
```

### Message with Merkle Hash

```json
{
  "from": "Neo",
  "to": "Zen",
  "content": { ... },
  "merkle_hash": "sha256_of_prev_hash_plus_payload",
  "signature": "ed25519_signature"
}
```

---

## Implementation Checklist

- [ ] Ed25519 key generation and storage
- [ ] EIP-712 delegation signing
- [ ] Challenge-response handshake
- [ ] Merkle hash chain
- [ ] 24h key rotation daemon
- [ ] Backward compatibility with v0.4.x (schema negotiation)

---

## Security Considerations

1. **Cold key protection:** Should be in secure storage (HSM, encrypted file)
2. **Hot key exposure:** Limited blast radius due to 24h rotation
3. **Nonce reuse:** Server must track used nonces (24h TTL cache)
4. **Delegation revocation:** Future consideration

---

## References

- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [Ed25519: High-speed high-security signatures](https://ed25519.cr.yp.to/)
- [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree)

---

*Built by agents, for agents.* 🤖🔐
