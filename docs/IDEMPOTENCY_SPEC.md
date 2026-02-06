# A2A Idempotency Specification v0.1

## Problem
Network retries can cause duplicate message processing, leading to:
- Double trade execution
- Duplicate alerts
- Wasted compute

## Solution
Add `idempotency_key` to every A2A message.

## Message Format (v2.3)

```json
{
  "message": "...",
  "sender": "Zen",
  "type": "trade_signal",
  "idempotency_key": "550e8400-e29b-41d4-a716-446655440000",
  "wake": true
}
```

## Server Behavior

### On Receive:
1. Extract `idempotency_key` from message
2. Check if key exists in dedup store
3. If EXISTS → return cached response, skip processing
4. If NEW → process message, store key + response

### Dedup Store:
- Storage: `/tmp/a2a-idempotency/`
- Format: `{key}.json` containing `{"response": ..., "timestamp": ...}`
- TTL: 24 hours
- Cleanup: On startup + hourly

## Implementation Checklist

### Zen Server:
- [ ] Add idempotency_key check on receive
- [ ] Create dedup store directory
- [ ] Store processed keys with responses
- [ ] Return cached response for duplicates
- [ ] Add TTL cleanup

### Neo Server:
- [ ] Same as above

### Client (sender) side:
- [ ] Generate UUID for each NEW message
- [ ] Reuse same UUID for retries
- [ ] Log idempotency_key with each send

## Testing

```bash
# Send same message twice with same key
KEY="test-$(date +%s)"
curl -X POST http://localhost:8080 \
  -H "Authorization: Bearer zenneo2026" \
  -d "{\"message\":\"test\",\"idempotency_key\":\"$KEY\"}"

# Second call should return cached response
curl -X POST http://localhost:8080 \
  -H "Authorization: Bearer zenneo2026" \
  -d "{\"message\":\"test\",\"idempotency_key\":\"$KEY\"}"
```

## Backward Compatibility
- Messages WITHOUT idempotency_key → process normally (no dedup)
- Gradually add keys to all A2A calls

---
*Spec version: 0.1 | Authors: Zen + Neo | Date: 2026-02-04*
