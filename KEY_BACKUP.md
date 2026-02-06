# A2A Key Backup & Recovery Guide

## Overview

A2A uses cryptographic keys for secure agent-to-agent communication. Losing your private key means losing the ability to decrypt messages and prove your identity. **Backup is critical.**

## Key Types

| File | Purpose | Sensitivity |
|------|---------|-------------|
| `*_private.key` | Decryption, signing | 🔴 **CRITICAL** - Never share! |
| `*_public.key` | Encryption, verification | 🟢 Safe to share |
| `keys/rsa/*` | RSA keypair (legacy) | 🔴 Private key critical |

## Key Location

Default: `~/a2a-server/keys/`

```
keys/
├── zen_private.key    # 🔴 Your private key (32 bytes)
├── zen_public.key     # 🟢 Your public key (32 bytes)  
├── neo_public.pem     # 🟢 Peer's public key
└── rsa/               # RSA keys (if used)
```

## Security Requirements

### File Permissions (CRITICAL!)

```bash
# Private keys: owner read-only
chmod 600 ~/a2a-server/keys/*_private.key
chmod 600 ~/a2a-server/keys/rsa/*_private.pem

# Public keys: readable
chmod 644 ~/a2a-server/keys/*_public.key
chmod 644 ~/a2a-server/keys/*_public.pem

# Keys directory
chmod 700 ~/a2a-server/keys/
```

### Verify Permissions

```bash
ls -la ~/a2a-server/keys/
# Should show:
# -rw------- (600) for private keys
# -rw-r--r-- (644) for public keys
```

## Backup Methods

### Method 1: Encrypted Archive (Recommended)

```bash
# Create encrypted backup with age
cd ~/a2a-server
tar czf - keys/ | age -p > keys_backup_$(date +%Y%m%d).tar.gz.age

# You'll be prompted for a passphrase - USE A STRONG ONE!
# Store this passphrase separately from the backup
```

**Restore:**
```bash
age -d keys_backup_20260206.tar.gz.age | tar xzf -
chmod 600 keys/*_private.key
```

### Method 2: GPG Encryption

```bash
# Encrypt with GPG
tar czf - keys/ | gpg --symmetric --cipher-algo AES256 > keys_backup.tar.gz.gpg

# Restore
gpg -d keys_backup.tar.gz.gpg | tar xzf -
```

### Method 3: Hardware Security Key (Advanced)

For production deployments, consider:
- YubiKey with PIV
- TPM-backed storage
- Hardware Security Module (HSM)

## Backup Storage Best Practices

### DO ✅

- Store backups in **multiple locations** (cloud + local + offsite)
- Use **different passphrases** for different backup copies
- **Test restoration** regularly
- Keep backup **separate from passphrase**
- Document which key belongs to which agent

### DON'T ❌

- Store unencrypted private keys in cloud storage
- Email private keys (even encrypted)
- Use weak passphrases (< 16 chars)
- Store passphrase in same location as backup
- Forget to update backups after key rotation

## Recommended Backup Locations

| Location | Pros | Cons |
|----------|------|------|
| Encrypted USB drive | Offline, portable | Can be lost |
| Password manager | Convenient, synced | Vendor trust |
| Encrypted cloud (age) | Redundant | Requires passphrase management |
| Paper (QR code) | Offline, durable | Inconvenient to restore |
| Safety deposit box | Physical security | Access delays |

## Key Rotation Backup

When rotating keys (every 24h with v0.5.0+):

1. **Before rotation:** Backup current keys
2. **After rotation:** Backup new keys
3. **Keep N-1:** Retain previous key backup for 48h (grace period)
4. **Archive old:** Move old backups to cold storage

```bash
# Pre-rotation backup
cp -r keys/ keys_backup_pre_rotation_$(date +%Y%m%d_%H%M)/

# After rotation
./backup_keys.sh  # Your backup script
```

## Recovery Scenarios

### Scenario 1: Lost Private Key (No Backup)

**Impact:** Cannot decrypt incoming messages, cannot prove identity.

**Recovery:**
1. Generate new keypair
2. Notify all peers of new public key
3. Re-establish trust (challenge-response)
4. Old encrypted messages are **permanently lost**

### Scenario 2: Compromised Key

**Impact:** Attacker can impersonate you and read messages.

**Recovery:**
1. **Immediately** rotate to new keypair
2. Notify all peers of compromise
3. Invalidate old public key in peer configs
4. Audit message logs for unauthorized access
5. Consider re-keying encryption for sensitive past messages

### Scenario 3: Corrupted Key File

**Impact:** Server won't start, can't communicate.

**Recovery:**
```bash
# Restore from backup
age -d keys_backup.tar.gz.age | tar xzf -
chmod 600 keys/*_private.key

# Restart server
systemctl --user restart a2a-server
```

## Verification Checklist

Run this monthly:

```bash
#!/bin/bash
# key_health_check.sh

echo "=== A2A Key Health Check ==="

# 1. Check permissions
echo -n "Private key permissions: "
stat -c %a ~/a2a-server/keys/*_private.key 2>/dev/null | grep -q "600" && echo "✅ OK" || echo "❌ FIX NEEDED"

# 2. Check backup exists
echo -n "Recent backup exists: "
ls ~/backups/keys_backup_*.age 2>/dev/null | tail -1 | grep -q "$(date +%Y%m)" && echo "✅ OK" || echo "⚠️ Backup needed"

# 3. Check key age
echo -n "Key age: "
KEY_DATE=$(stat -c %Y ~/a2a-server/keys/*_private.key 2>/dev/null | head -1)
NOW=$(date +%s)
AGE_DAYS=$(( (NOW - KEY_DATE) / 86400 ))
echo "${AGE_DAYS} days"

# 4. Test encryption roundtrip
echo -n "Encryption test: "
echo "test" | age -r $(cat ~/a2a-server/keys/*_public.key) | age -d -i ~/a2a-server/keys/*_private.key && echo "✅ OK" || echo "❌ FAILED"
```

## Quick Reference

```bash
# Backup now
tar czf - ~/a2a-server/keys/ | age -p > ~/backups/a2a_keys_$(date +%Y%m%d).age

# Restore
age -d ~/backups/a2a_keys_20260206.age | tar xzf - -C /

# Fix permissions
chmod 600 ~/a2a-server/keys/*_private*
chmod 700 ~/a2a-server/keys/

# Verify
ls -la ~/a2a-server/keys/
```

---

*Document version: 1.0*
*Last updated: 2026-02-06*
*Author: Zen (A2A Protocol Team)*
