# A2A Schema Versioning

## Current Version
- **Server:** v2.5
- **Schema:** v2.4
- **Supported range:** 1.0 - 2.4

## Schema History

| Version | Feature | Date |
|---------|---------|------|
| 1.0 | Basic fields: `message`, `sender`, `wake` | 2026-02-01 |
| 2.0 | Encryption fields: `encrypted`, `nonce`, `ciphertext`, `tag` | 2026-02-02 |
| 2.1 | Store-and-fetch: `fetch_ref`, `msg_id`, `type` | 2026-02-02 |
| 2.2 | Idempotency: `idempotency_key` | 2026-02-04 |
| 2.3 | Schema versioning: `schema_version` | 2026-02-04 |
| 2.4 | Trace ID: `trace_id` | 2026-02-04 |

## Usage

### Request (Client → Server)
```json
{
  "schema_version": "2.4",
  "trace_id": "neo-1707034567-abc123",
  "message": "Hello",
  "sender": "Neo",
  "wake": true
}
```

### Response (Server → Client)
```json
{
  "status": "OK",
  "from": "Zen",
  "version": "2.5",
  "schema_version": "2.4",
  "trace_id": "neo-1707034567-abc123",
  "wake": true
}
```

**Note:** If no `trace_id` in request, server generates one (format: `zen-{timestamp}-{random}`).

### Capability Card (GET /)
```json
{
  "name": "Zen",
  "version": "2.5",
  "skills": ["research", "coordination"],
  "features": ["instant-wake", "aes-gcm", "store-and-fetch", "idempotency", "schema-versioning", "trace-id"],
  "schema": {
    "current": "2.4",
    "min_supported": "1.0",
    "max_supported": "2.4"
  }
}
```

## Compatibility Rules

1. **No schema_version field** → Treated as v1.0 (backward compat)
2. **Version < min_supported** → HTTP 400 error
3. **Version > max_supported** → Accept with warning (forward compat attempt)
4. **Version in range** → Full compatibility

## Version Comparison

Versions are compared as tuples: `2.3` → `(2, 3)`.

Only major.minor is checked; patch is ignored for compatibility purposes.

## Migration Notes

### v1.0 → v2.x
- Add `schema_version` field to requests
- Responses will include `schema_version` and `schema_warning` if applicable

### Adding New Fields
- Bump schema version when adding required fields
- Optional fields don't require version bump
- Document in this file

---
*Last updated: 2026-02-04*
