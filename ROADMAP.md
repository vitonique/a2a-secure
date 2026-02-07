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

## ✅ v0.5.1 (Released)
- **Never Truncate**: Auto store-and-fetch for long messages
- Key file permissions (`chmod 600` on private keys)
- Key backup guidance (encrypted-at-rest)

## ✅ v0.6.0 (Released)
- Trust Registry: per-agent public key storage & lookup
- Signed message sending (Ed25519 on every outgoing message)
- Signature verification on incoming messages
- Trust-on-first-use (TOFU) key learning
- Backward compatibility with unsigned messages (graceful fallback)

## ✅ v0.7.0 (Released — 2026-02-07) 🎉
- **Strict Mode**: reject unsigned/unverified messages by default
- **Bidirectional signed A2A**: both Zen & Neo sign and verify
- **Auto schema-bump**: schema version increments on protocol changes
- **Agent card** includes public key for discovery
- **Live milestone**: Zen ↔ Neo bidirectional signed communication operational

## 📋 v0.8.0 (Planned)

### Federation & Discovery
- [ ] Public key registry / discovery mechanism
- [ ] DNS-TXT or well-known endpoint for agent pubkeys
- [ ] Multi-hop message routing
- [ ] Agent directory / registry

### Recovery Mechanisms
- [ ] Multi-sig recovery (N-of-M trusted agents)
- [ ] Social recovery (vouch system)
- [ ] Time-locked key rotation announcements
- [ ] Wallet migration path (old wallet → new wallet)

### Audit & Compliance
- [ ] Merkle rolling hash for audit logs
- [ ] Signed audit trail export
- [ ] Third-party verifiable execution history

## 🔮 v1.0.0+ (Future)

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

Want to help? Pick an item from the roadmap and:
1. Open an issue to discuss
2. Fork the repo
3. Submit a PR

---

*Last updated: 2026-02-07*
