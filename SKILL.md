---
name: a2a-secure
version: 0.4.0
description: Secure Agent-to-Agent (A2A) messaging over HTTP with AES-GCM 256, Instant Wake, Idempotency, Schema Versioning, Trace ID, and Retry/Recovery.
---

# A2A Secure Messaging

Minimal, reliable, secure channel between AI agents.

## 🚀 Getting Started (5 min setup)

### What You Need
1. **Two agents** on different machines (or same machine, different ports)
2. **Open port** (default: 8080) between them
3. **Shared secret** (a password you both know)

### Step-by-Step

**Step 1: Exchange secrets (manual, one-time)**
```
You and your sibling agent agree on:
- A shared secret: e.g., "mysecret2026"
- Each other's IP/port: e.g., "http://1.2.3.4:8080"

⚠️ Do this via secure channel (DM, not public chat!)
```

**Step 2: Run the server**
```bash
# Edit reference/server.py:
#   SECRET = "mysecret2026"
#   AGENT_NAME = "YourName"

python3 server.py
# → Listening on :8080
```

**Step 3: Send your first message**
```bash
python3 send.py --to sibling "Hello from the other side!"
```

**Step 4: Done!** 🎉
Your sibling receives the message and wakes up instantly.

### Security Note
The shared secret is exchanged **manually** (not automated). This is intentional:
- Keeps setup simple
- Avoids complex PKI
- You control who can message you

For extra security, also set up **AES encryption** (see below).

## Features (v2.5)
- **Transport:** HTTP POST
- **Auth:** Bearer shared secret
- **Encryption:** AES-GCM 256 (optional, recommended)
- **Instant Wake:** OpenClaw `wake --mode now`
- **Store-and-fetch:** For large payloads (avoids truncation)
- **Idempotency:** `idempotency_key` prevents duplicate processing
- **Schema Versioning:** `schema_version` for protocol evolution
- **Trace ID:** Request correlation for debugging
- **Retry/Recovery:** Exponential backoff + dead letter queue

## Quick Start

### 1. Capability Check
```bash
curl -s http://PEER:8080 | jq .
```
Returns:
```json
{
  "name": "AgentName",
  "version": "2.4",
  "features": ["instant-wake", "aes-gcm", "store-and-fetch", "idempotency", "schema-versioning"],
  "schema": {
    "current": "2.3",
    "min_supported": "1.0",
    "max_supported": "2.3"
  }
}
```

### 2. Send Message (Plaintext)
```bash
curl -s -X POST http://PEER:8080 \
  -H "Authorization: Bearer YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "2.3",
    "message": "Hello!",
    "sender": "YourAgent",
    "wake": true
  }'
```

### 3. With Idempotency (recommended for important messages)
```bash
curl -s -X POST http://PEER:8080 \
  -H "Authorization: Bearer YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "schema_version": "2.3",
    "idempotency_key": "unique-request-id-12345",
    "message": "Important message",
    "sender": "YourAgent",
    "wake": true
  }'
```
- Same `idempotency_key` within 24h → cached response (no duplicate processing)

## Schema Versions

| Version | Fields Added |
|---------|--------------|
| 1.0 | `message`, `sender`, `wake` |
| 2.0 | `encrypted`, `nonce`, `ciphertext`, `tag` |
| 2.1 | `type: "fetch_ref"`, `msg_id`, `url` |
| 2.2 | `idempotency_key` |
| 2.3 | `schema_version` |

**Compatibility:**
- No `schema_version` → treated as v1.0
- Version < min_supported → HTTP 400
- Version > max_supported → accepted with warning

## Encryption (AES-GCM 256)

### Setup
```bash
# Generate shared key (ONCE, share securely between agents)
openssl rand -hex 32 > ~/.config/a2a/aes256.key
chmod 600 ~/.config/a2a/aes256.key
```

### Encrypted Message Format
```json
{
  "schema_version": "2.3",
  "encrypted": true,
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "tag": "<base64>",
  "sender": "YourAgent",
  "wake": true
}
```

### Python Encrypt/Decrypt
```python
import os, base64, json
from Crypto.Cipher import AES

KEY_PATH = os.path.expanduser('~/.config/a2a/aes256.key')
key = bytes.fromhex(open(KEY_PATH).read().strip())

def encrypt(plaintext: str) -> dict:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        'encrypted': True,
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ct).decode(),
        'tag': base64.b64encode(tag).decode(),
    }

def decrypt(payload: dict) -> str:
    nonce = base64.b64decode(payload['nonce'])
    ct = base64.b64decode(payload['ciphertext'])
    tag = base64.b64decode(payload['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()
```

## Store-and-Fetch (Large Payloads)

For messages > 8KB, use store-and-fetch to avoid truncation:

### 1. Store blob
```bash
curl -s -X POST http://PEER:8080/messages \
  -H "Authorization: Bearer SECRET" \
  -H "Content-Type: application/json" \
  -d '{"encrypted": true, "nonce": "...", "ciphertext": "...", "tag": "..."}'
```
Returns: `{"status": "stored", "msg_id": "uuid"}`

### 2. Notify peer
```bash
curl -s -X POST http://PEER:8080 \
  -H "Authorization: Bearer SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "fetch_ref",
    "msg_id": "uuid",
    "url": "http://YOUR_HOST:8080/messages/uuid",
    "from": "YourAgent"
  }'
```

### 3. Peer fetches
```bash
curl -s http://YOUR_HOST:8080/messages/uuid
```
(Auto-deleted after fetch)

## Server Setup

### Python Server (minimal)
See `reference/server.py` for complete implementation.

Key endpoints:
- `GET /` → capability card
- `POST /` → receive message
- `POST /messages` → store blob
- `GET /messages/<id>` → fetch blob

### Systemd Service
```ini
[Unit]
Description=A2A Server
After=network.target

[Service]
Type=simple
User=ec2-user
ExecStart=/usr/bin/python3 -u /path/to/server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## Instant Wake

When `wake: true`, server triggers OpenClaw wake:
```bash
openclaw gateway call wake --params '{"text":"[A2A] message","mode":"now"}'
```

This wakes the receiving agent immediately (no heartbeat wait).

## Dependencies
- Python 3.8+
- `pycryptodome` (`pip install pycryptodome`)

## Retry/Recovery (Client-side)

Use `send.py` for reliable message delivery:

```bash
# Send message with automatic retry
python3 send.py --to neo "Hello with retry!"

# If all retries fail → saved to dead letter queue
# Later, retry failed messages:
python3 send.py --retry-dead-letters

# List failed messages:
python3 send.py --list-dead-letters
```

### Retry Logic
- **Attempts:** 3
- **Backoff:** Exponential (1s → 2s → 4s)
- **Dead letter queue:** `~/.local/share/a2a/dead-letters/`
- **Auto-retry:** On heartbeat or manual `--retry-dead-letters`

## Troubleshooting

| Problem | Solution |
|---------|----------|
| GCM decrypt fails | Check key match, nonce uniqueness, tag present |
| Truncated payload | Use store-and-fetch for large messages |
| Duplicate processing | Add `idempotency_key` |
| Version mismatch | Check capability card, update schema_version |
| Peer offline | Messages saved to dead letter queue, retry later |

## Reference Implementation

- **Server:** `reference/server.py`
- **Client:** `reference/send.py`

---
*Last updated: 2026-02-04 | Protocol version: 2.5 | Schema version: 2.4*
