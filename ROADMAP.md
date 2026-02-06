# A2A Secure — Roadmap

## ✅ v0.4.0 (Released)
- AES-GCM 256 encryption
- Instant wake
- Store-and-fetch for large payloads
- Idempotency (24h TTL)
- Schema versioning
- Trace ID
- Retry/Recovery with dead letter queue

## ✅ v0.5.0 (Released — 2026-02-04)
- Ed25519 hot key generation + storage
- 24h key rotation / expiry check
- Challenge-response authentication (SYN → CHALLENGE → AUTH → CONNECTED)
- Message signature verification
- EIP-712 SessionDelegation signing (cold → hot)
- `/stats` endpoint for basic metrics

## ✅ v0.5.1 (Released — 2026-02-06)
- [x] **Never Truncate**: Auto store-and-fetch for long messages
- [x] Key file permissions (`chmod 600` on private keys)
- [x] Key backup guidance (KEY_BACKUP.md, encrypted-at-rest)
- [x] Move inline imports to module level
- [x] EIP-712 delegation *verification* (ecrecover)
- [x] Stats persistence across restarts (JSON: `~/.a2a/stats.json`)

## ✅ v0.6.0 (Released — 2026-02-06)
- GitHub Actions CI workflow (compile + unit tests)
- Identity roundtrip tests:
  - EIP-712 sign → recover
  - Ed25519 hotkey sign/verify smoke

## 🔧 v0.7.0 (In Progress)

### Zero Shared Secret Bootstrap (PRIORITY)
- [x] ETH wallet setup (Zen + Neo)
- [x] Age encryption key exchange
- [ ] Public key registry / discovery mechanism
- [ ] First-contact via signed introduction (no pre-shared secret)
- [ ] `require_signature=true` server flag
- [ ] DNS-TXT or well-known endpoint for agent pubkeys

### Merged from v0.6.1
- [ ] Stats schema versioning
- [ ] CLI harmonization (`send.py --stats` + server `/stats` consistency)
- [ ] `/health` endpoint (no-wake, stable heartbeat)

### Recovery Mechanisms
- [ ] Multi-sig recovery (N-of-M trusted agents)
- [ ] Social recovery (vouch system)
- [ ] Time-locked key rotation announcements
- [ ] Wallet migration path (old wallet → new wallet)

## 📋 v0.8.0 (Planned)

### Audit & Compliance
- [ ] Merkle rolling hash for audit logs
- [ ] Signed audit trail export
- [ ] Third-party verifiable execution history

### Backward Compatibility
- [ ] Unsigned message fallback for v0.4.x peers
- [ ] Graceful degradation when identity layer unavailable
- [ ] Schema negotiation improvements

## 🔮 v0.9.0+ (Future)

### Federation
- [ ] Multi-hop message routing
- [ ] Agent directory / registry
- [ ] Reputation aggregation across networks

### Advanced Identity
- [ ] DID (Decentralized Identifier) support
- [ ] Verifiable Credentials integration
- [ ] Cross-chain identity (not just Base/Polygon)

### Performance
- [ ] Connection pooling
- [ ] Batch message signing
- [ ] Compression for large payloads

---

## Agent Wallets (v0.7.0)

| Agent | ETH Wallet | Age Public Key |
|-------|------------|----------------|
| Zen 🧘 | `0x95D8Eb255ee4bA3101595aAe4E3200d1f47b81d1` | `age1yrx5a6rse85ywpa4mpjkw7cctfcc2apjqc22hn0gt935emlyxa3qpgn37x` |
| Neo ⚡ | `0x91207619770d21276cB6a4d8E73F74abF9a70748` | `age12hnxkhfdljpsarvw48dlv0qgxw5jyfluyeddr3lyna0sqmv0zytqa4ta8j` |

---

## Contributing

Want to help? Pick an item from the current milestone and:
1. Open an issue to discuss
2. Fork the repo
3. Submit a PR

Spec: [IDENTITY_SPEC.md](https://github.com/vitonique/a2a-secure)

---

*Last updated: 2026-02-06*
