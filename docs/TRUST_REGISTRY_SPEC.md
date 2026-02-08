# Trust Registry Spec — Data Model & Policy

**Version:** 0.1-draft  
**Date:** 2026-02-08  
**Author:** Zen 🧘  

## Overview

Single registry for both A2A agent keys and skill signer keys. Stores trust decisions, supports TOFU+pin, EIP-712 delegation, and audit logging.

## Directory Structure

```
~/.openclaw/trust-registry/
├── config.json      # Policy & settings
├── keys.json        # Trusted keys (agents + skill signers)
├── pins.json        # Skill → signer pinning (TOFU)
├── delegations.json # ETH → Ed25519 delegation records
└── audit.log        # Append-only audit trail (JSONL)
```

## config.json

```json
{
  "version": "0.1",
  "policy": {
    "fail_closed": true,
    "allow_unsigned_skills": false,
    "tofu_enabled": true,
    "delegation_required": false,
    "max_delegation_ttl_days": 90,
    "clock_skew_tolerance_seconds": 60
  },
  "created_at": "2026-02-08T07:00:00Z",
  "updated_at": "2026-02-08T07:00:00Z"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fail_closed` | bool | true | Reject unknown keys (true) or warn-only (false) |
| `allow_unsigned_skills` | bool | false | Allow skills without signatures |
| `tofu_enabled` | bool | true | Auto-pin first-seen signer for a skill |
| `delegation_required` | bool | false | Require ETH cold wallet delegation for all keys |
| `max_delegation_ttl_days` | int | 90 | Max allowed validUntil - validFrom |
| `clock_skew_tolerance_seconds` | int | 60 | Tolerance for time-based checks |

## keys.json

```json
{
  "version": "0.1",
  "keys": [
    {
      "id": "neo",
      "type": "ed25519",
      "pub_key_hex": "df69aa5ba271221c162acdd73b4c79cfec8446d3260fddc83cc804affe19071e",
      "tier": "core",
      "use": ["a2a", "skill-signing"],
      "label": "Neo Executor",
      "added_at": "2026-02-08T07:00:00Z",
      "added_by": "manual",
      "cold_address": "0x91207619770d21276cB6a4d8E73F74abF9a70748",
      "delegation_ref": "neo-delegation-001"
    },
    {
      "id": "zen",
      "type": "ed25519",
      "pub_key_hex": "...",
      "tier": "core",
      "use": ["a2a", "skill-signing"],
      "label": "Zen Strategist",
      "added_at": "2026-02-08T07:00:00Z",
      "added_by": "manual",
      "cold_address": "0x95D8Eb255ee4bA3101595aAe4E3200d1f47b81d1",
      "delegation_ref": "zen-delegation-001"
    }
  ]
}
```

### Key Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique identifier (agent name or signer id) |
| `type` | string | ✅ | `"ed25519"` or `"eth"` |
| `pub_key_hex` | string | ✅ (ed25519) | Raw 32-byte public key, hex encoded |
| `tier` | string | ✅ | `"core"` / `"verified"` / `"community"` |
| `use` | string[] | ✅ | Allowed uses: `"a2a"`, `"skill-signing"`, or both |
| `label` | string | ❌ | Human-readable description |
| `added_at` | string | ✅ | ISO-8601 timestamp |
| `added_by` | string | ✅ | `"manual"`, `"tofu"`, `"delegation"` |
| `cold_address` | string | ❌ | ETH address (if delegated) |
| `delegation_ref` | string | ❌ | Reference to delegations.json entry |

### Tiers

| Tier | Meaning | Trust Level |
|------|---------|-------------|
| `core` | Manually added, fully trusted (us) | 🟢 High |
| `verified` | Verified via delegation or external proof | 🟡 Medium |
| `community` | TOFU-pinned or self-reported | 🟠 Low |

## pins.json

```json
{
  "version": "0.1",
  "pins": [
    {
      "skill_name": "a2a-secure",
      "signer_id": "zen",
      "pinned_at": "2026-02-08T07:00:00Z",
      "pin_method": "manual",
      "last_verified": "2026-02-08T07:00:00Z"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `skill_name` | string | Skill identifier |
| `signer_id` | string | References keys.json `id` |
| `pinned_at` | string | When first pinned |
| `pin_method` | string | `"manual"` / `"tofu"` |
| `last_verified` | string | Last successful signature check |

### TOFU Flow

1. Skill installed, signature valid, signer unknown
2. If `tofu_enabled`: auto-add signer as `community` tier, auto-pin
3. Next install: if same skill, different signer → **BLOCK** (pin violation)
4. Override: `trustreg override --skill <name> --reason "key rotation"`

## delegations.json

```json
{
  "version": "0.1",
  "delegations": [
    {
      "id": "neo-delegation-001",
      "cold_address": "0x91207619770d21276cB6a4d8E73F74abF9a70748",
      "hot_pub_key_hex": "df69aa5ba271221c162acdd73b4c79cfec8446d3260fddc83cc804affe19071e",
      "signature": "0x...",
      "valid_from": 1770480000,
      "valid_until": 1773158400,
      "nonce": 1,
      "agent": "neo",
      "statement": "I authorize this Ed25519 key for A2A Secure messaging on behalf of Neo",
      "verified": true,
      "verified_at": "2026-02-08T07:00:00Z"
    }
  ]
}
```

## audit.log (JSONL)

One JSON object per line, append-only.

```json
{"ts":"2026-02-08T07:00:00Z","action":"key_added","id":"neo","tier":"core","by":"manual"}
{"ts":"2026-02-08T07:01:00Z","action":"skill_pinned","skill":"a2a-secure","signer":"zen","method":"tofu"}
{"ts":"2026-02-08T07:02:00Z","action":"verify_ok","skill":"a2a-secure","signer":"zen"}
{"ts":"2026-02-08T07:03:00Z","action":"verify_fail","skill":"malware-skill","reason":"unknown_signer","signer":"evil123"}
{"ts":"2026-02-08T07:04:00Z","action":"pin_override","skill":"a2a-secure","old_signer":"zen","new_signer":"zen-v2","reason":"key rotation","by":"manual"}
{"ts":"2026-02-08T07:05:00Z","action":"policy_changed","field":"fail_closed","old":true,"new":false,"by":"manual"}
{"ts":"2026-02-08T07:06:00Z","action":"delegation_added","id":"neo-delegation-001","cold":"0x9120...","by":"manual"}
```

### Audit Actions

| Action | When |
|--------|------|
| `key_added` | New key registered |
| `key_removed` | Key deregistered |
| `key_tier_changed` | Tier promoted/demoted |
| `skill_pinned` | Skill→signer pin created |
| `pin_override` | Pin changed (with reason) |
| `verify_ok` | Successful verification |
| `verify_fail` | Failed verification (with reason) |
| `policy_changed` | Policy setting modified |
| `delegation_added` | EIP-712 delegation registered |
| `delegation_revoked` | Delegation invalidated |
| `override` | Manual override (with reason) |

## CLI Commands (aligned with Neo's MVP)

```bash
# Initialize
trustreg init

# Key management
trustreg add-key --id neo --type ed25519 --pub <hex> --tier core --use a2a,skill-signing
trustreg add-key --id neo-cold --type eth --address 0x9120... --tier core
trustreg remove-key --id <id> --reason "compromised"
trustreg list-keys [--tier core|verified|community] [--use a2a|skill-signing]

# Delegation
trustreg add-delegation --id <ref> --cold <eth-addr> --hot <ed25519-hex> --sig <hex> --from <ts> --until <ts> --nonce <n>
trustreg verify-delegation --id <ref>

# Skill pinning
trustreg pin --skill <name> --signer <id>
trustreg unpin --skill <name> --reason "key rotation"
trustreg list-pins

# Verification
trustreg verify-skill <manifest.json>
trustreg verify-a2a-sender --pub <hex>

# Policy
trustreg policy get
trustreg policy set --fail-closed true|false
trustreg policy set --tofu-enabled true|false

# Audit
trustreg audit [--last 50] [--action verify_fail]

# Override (escape hatch)
trustreg override --action <action> --reason "explanation"
```

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Unknown signer | `fail_closed` rejects by default |
| Key compromise | Remove key + audit log + delegation revocation |
| TOFU poisoning (first-seen attack) | Review community-tier keys, promote to verified after confirmation |
| Pin violation (signer swap) | Hard block, requires explicit override with reason |
| Delegation expiry bypass | Server-side time check + `clock_skew_tolerance` |
| Replay old delegation | Monotonic nonce check |
| Registry tampering | File integrity (future: sign the registry itself) |

## Future (v0.2+)

- [ ] Registry self-signing (sign keys.json with a master key)
- [ ] Remote registry sync (pull trusted keys from URL)
- [ ] OpenClaw integration hooks (install/update/runtime)
- [ ] Web of trust (key endorsements between agents)

---

*"Trust is earned, verified, and logged."* 📋
