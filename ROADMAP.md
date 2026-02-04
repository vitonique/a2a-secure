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

## 🔧 v0.5.1 (In Progress)
- [x] **Never Truncate**: Auto store-and-fetch for long messages
- [x] Key file permissions (`chmod 600` on private keys)
- [ ] Key backup guidance (encrypted-at-rest)
- [ ] Move inline imports to module level
- [ ] EIP-712 delegation *verification* (ecrecover)
- [ ] Stats persistence across restarts

## 📋 v0.6.0 (Planned)

### Zero Shared Secret Bootstrap
- [ ] Public key registry / discovery mechanism
- [ ] First-contact via signed introduction (no pre-shared secret)
- [ ] DNS-TXT or well-known endpoint for agent pubkeys

### Recovery Mechanisms
- [ ] Multi-sig recovery (N-of-M trusted agents)
- [ ] Social recovery (vouch system)
- [ ] Time-locked key rotation announcements
- [ ] Wallet migration path (old wallet → new wallet)

### Audit & Compliance
- [ ] Merkle rolling hash for audit logs
- [ ] Signed audit trail export
- [ ] Third-party verifiable execution history

### Backward Compatibility
- [ ] Unsigned message fallback for v0.4.x peers
- [ ] Graceful degradation when identity layer unavailable
- [ ] Schema negotiation improvements

## 🔮 v0.7.0+ (Future)

### Federation
- [ ] Multi-hop message routing
- [ ] Agent directory / registry
- [ ] Reputation aggregation across networks

### Advanced Identity
- [ ] DID (Decentralized Identifier) support
- [ ] Verifiable Credentials integration
- [ ] Cross-chain identity (not just Polygon)

### Performance
- [ ] Connection pooling
- [ ] Batch message signing
- [ ] Compression for large payloads

---

## Contributing

Want to help? Pick an item from v0.5.1 or v0.6.0 and:
1. Open an issue to discuss
2. Fork the repo
3. Submit a PR

Spec: [IDENTITY_SPEC.md](https://github.com/vitonique/a2a-secure)

---

*Last updated: 2026-02-04*
