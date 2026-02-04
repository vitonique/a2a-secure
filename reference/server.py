#!/usr/bin/env python3
"""A2A Server v2.4 + v0.5.0 Identity Layer (Reference Implementation)

Features:
- Bearer token auth
- Instant Wake via OpenClaw CLI
- Store-and-fetch for large payloads
- Idempotency (24h TTL)
- Schema versioning
- v0.5.0 Identity Layer: Ed25519 hot keys, challenge-response handshake, message signature verification

Usage:
1. Set SECRET below (shared with peer)
2. Set AGENT_NAME
3. Run: python3 server.py
4. Expose port 8080 (firewall/security group)

Endpoints:
- GET  /                -> capability card
- POST /                -> receive message
- POST /messages        -> store encrypted blob
- GET  /messages/<id>   -> fetch blob (delete-on-fetch)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import time
import os
import uuid

from identity import get_or_create_hot_key, hot_key_valid, make_challenge, verify_nonce_sig, verify_message_dict

# ============ CONFIGURE THESE ============
# Step 1: Agree on a shared secret with your sibling agent
#         Exchange this via secure DM, not public chat!
SECRET = "your-shared-secret"  # Same on both agents

# Step 2: Set your agent name
AGENT_NAME = "YourAgent"

# Step 3: List your skills (for capability discovery)
AGENT_SKILLS = ["research", "coding"]
# =========================================

# Schema versioning
SCHEMA_VERSION = "2.4"
SCHEMA_MIN = "1.0"
SCHEMA_MAX = "2.4"

# Identity layer
IDENTITY_VERSION = "0.5.0"
CHALLENGE_TTL_SECONDS = 60
PENDING_CHALLENGES = {}  # client_id -> {nonce_b64, ts}

CARD = {
    "name": AGENT_NAME,
    "version": "2.4",
    "skills": AGENT_SKILLS,
    "features": ["instant-wake", "aes-gcm", "store-and-fetch", "idempotency", "schema-versioning", "identity-v0.5.0"],
    "schema": {
        "current": SCHEMA_VERSION,
        "min_supported": SCHEMA_MIN,
        "max_supported": SCHEMA_MAX,
    },
}

# Storage config
MAX_INLINE_BYTES = 8000
TTL_SECONDS = 24 * 60 * 60
DELETE_ON_FETCH = True
STORE_DIR = "/tmp/a2a-messages"
IDEMPOTENCY_DIR = "/tmp/a2a-idempotency"
IDEMPOTENCY_TTL = 24 * 60 * 60

os.makedirs(STORE_DIR, exist_ok=True)
os.makedirs(IDEMPOTENCY_DIR, exist_ok=True)

MSG_INDEX = {}  # msg_id -> {"ts": epoch, "path": filepath}


def parse_version(v):
    """Parse version string to tuple."""
    try:
        return tuple(int(p) for p in str(v).split(".")[:3])
    except Exception:
        return (1, 0)


def check_schema_version(data):
    """Check schema compatibility. Returns (ok, version, warning)."""
    if not isinstance(data, dict):
        return True, "1.0", None
    
    client_version = data.get("schema_version")
    if client_version is None:
        return True, "1.0", "no_schema_version_field"
    
    client_v = parse_version(client_version)
    min_v = parse_version(SCHEMA_MIN)
    max_v = parse_version(SCHEMA_MAX)
    
    if client_v < min_v:
        return False, client_version, f"version_too_old:min={SCHEMA_MIN}"
    if client_v > max_v:
        return True, client_version, f"version_newer_than_server:max={SCHEMA_MAX}"
    return True, client_version, None


def check_idempotency(key):
    """Check if key was processed. Returns cached response or None."""
    if not key:
        return None
    path = os.path.join(IDEMPOTENCY_DIR, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if time.time() - data.get("ts", 0) > IDEMPOTENCY_TTL:
            os.remove(path)
            return None
        return data.get("response")
    except Exception:
        return None


def store_idempotency(key, response):
    """Store idempotency key with response."""
    if not key:
        return
    path = os.path.join(IDEMPOTENCY_DIR, f"{key}.json")
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "response": response}, f)
    except Exception:
        pass


def cleanup_expired():
    """Remove expired messages and idempotency keys."""
    now = time.time()
    # Messages
    for msg_id in list(MSG_INDEX.keys()):
        meta = MSG_INDEX.get(msg_id, {})
        if now - meta.get("ts", 0) > TTL_SECONDS:
            try:
                if meta.get("path") and os.path.exists(meta["path"]):
                    os.remove(meta["path"])
            except Exception:
                pass
            MSG_INDEX.pop(msg_id, None)
    # Idempotency
    try:
        for fname in os.listdir(IDEMPOTENCY_DIR):
            path = os.path.join(IDEMPOTENCY_DIR, fname)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                if now - data.get("ts", 0) > IDEMPOTENCY_TTL:
                    os.remove(path)
            except Exception:
                pass
    except Exception:
        pass


def send_wake(message_text):
    """Send instant wake via OpenClaw CLI."""
    try:
        params = {"text": f"[A2A] {message_text[:500]}", "mode": "now"}
        result = subprocess.run(
            ["/usr/bin/openclaw", "gateway", "call", "wake", "--params", json.dumps(params)],
            capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except Exception:
        # Fallback: write trigger file for heartbeat pickup
        try:
            with open("/tmp/a2a-wake.trigger", "w") as f:
                f.write(message_text[:500])
        except Exception:
            pass
        return False


def _cleanup_challenges():
    now = int(time.time())
    for cid in list(PENDING_CHALLENGES.keys()):
        if now - int(PENDING_CHALLENGES[cid].get("ts", 0)) > CHALLENGE_TTL_SECONDS:
            PENDING_CHALLENGES.pop(cid, None)


class Handler(BaseHTTPRequestHandler):

    def _json(self, code: int, payload: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def _unauth(self):
        self._json(401, {"error": "Unauthorized"})

    def do_GET(self):
        if self.path == "/" or self.path == "":
            return self._json(200, CARD)
        
        if self.path.startswith("/messages/"):
            msg_id = self.path.split("/messages/", 1)[1]
            meta = MSG_INDEX.get(msg_id)
            if not meta or not os.path.exists(meta.get("path", "")):
                MSG_INDEX.pop(msg_id, None)
                return self._json(404, {"error": "Not Found"})
            
            try:
                with open(meta["path"], "r") as f:
                    blob = json.load(f)
            except Exception as e:
                return self._json(500, {"error": str(e)})
            
            if DELETE_ON_FETCH:
                try:
                    os.remove(meta["path"])
                except Exception:
                    pass
                MSG_INDEX.pop(msg_id, None)
            
            return self._json(200, blob)
        
        return self._json(404, {"error": "Not Found"})

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {SECRET}":
            return self._unauth()
        
        cleanup_expired()
        
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        
        try:
            data = json.loads(body)
        except Exception:
            data = {"message": body}
        
        # Check idempotency
        idem_key = data.get("idempotency_key") if isinstance(data, dict) else None
        if idem_key:
            cached = check_idempotency(idem_key)
            if cached:
                return self._json(200, cached)
        
        # Store endpoint
        if self.path == "/messages":
            if not isinstance(data, dict) or not data.get("encrypted"):
                return self._json(400, {"error": "only_encrypted_payloads_allowed"})
            
            msg_id = data.get("msg_id") or str(uuid.uuid4())
            path = os.path.join(STORE_DIR, f"{msg_id}.json")
            try:
                with open(path, "w") as f:
                    json.dump(data, f)
                MSG_INDEX[msg_id] = {"ts": time.time(), "path": path}
            except Exception as e:
                return self._json(500, {"error": str(e)})
            
            return self._json(200, {
                "status": "stored",
                "msg_id": msg_id,
                "max_inline_bytes": MAX_INLINE_BYTES,
                "ttl_seconds": TTL_SECONDS,
                "schema_version": SCHEMA_VERSION,
            })
        
        # Schema check
        schema_ok, detected_version, schema_warning = check_schema_version(data)
        if not schema_ok:
            return self._json(400, {
                "error": "schema_version_incompatible",
                "details": schema_warning,
                "server_schema": CARD["schema"],
            })
        
        # Handle fetch_ref
        if isinstance(data, dict) and data.get("type") == "fetch_ref":
            wake_text = f"fetch_ref from={data.get('from')} msg_id={data.get('msg_id')}"
            wake_sent = send_wake(wake_text)
            return self._json(200, {
                "status": "OK",
                "from": AGENT_NAME,
                "wake": wake_sent,
                "version": CARD["version"],
                "schema_version": SCHEMA_VERSION,
                "mode": "fetch_ref",
            })

        # ---------------- Identity v0.5.0 handshake ----------------
        if isinstance(data, dict) and data.get("type") == "SYN":
            _cleanup_challenges()
            client_id = data.get("from") or data.get("client_id") or "unknown"
            chall = make_challenge()
            PENDING_CHALLENGES[client_id] = {"nonce_b64": chall["nonce_b64"], "ts": chall["ts"]}
            return self._json(200, {
                "status": "CHALLENGE",
                "from": AGENT_NAME,
                "identity_version": IDENTITY_VERSION,
                "nonce_b64": chall["nonce_b64"],
                "expires_in": CHALLENGE_TTL_SECONDS,
            })

        if isinstance(data, dict) and data.get("type") == "AUTH":
            _cleanup_challenges()
            client_id = data.get("from") or data.get("client_id") or "unknown"
            pending = PENDING_CHALLENGES.get(client_id)
            if not pending:
                return self._json(400, {"error": "no_pending_challenge"})
            nonce_b64 = pending.get("nonce_b64")
            hot_pub_b64 = (data.get("identity") or {}).get("hot_pub_b64")
            nonce_sig_b64 = (data.get("identity") or {}).get("nonce_sig_b64")
            if not hot_pub_b64 or not nonce_sig_b64:
                return self._json(400, {"error": "missing_identity_fields"})
            try:
                hot_pub_raw = __import__("base64").b64decode(hot_pub_b64)
            except Exception:
                return self._json(400, {"error": "bad_hot_pub_b64"})
            if len(hot_pub_raw) != 32:
                return self._json(400, {"error": "hot_pubkey_wrong_length"})
            if not verify_nonce_sig(hot_pub_raw, nonce_b64, nonce_sig_b64):
                return self._json(401, {"error": "nonce_signature_invalid"})
            # success
            PENDING_CHALLENGES.pop(client_id, None)
            return self._json(200, {"status": "CONNECTED", "from": AGENT_NAME, "identity_version": IDENTITY_VERSION})

        # ---------------- Normal message with optional signature verification ----------------
        if isinstance(data, dict) and data.get("sig") and (data.get("identity") or {}).get("hot_pub_b64"):
            try:
                hot_pub_raw = __import__("base64").b64decode((data.get("identity") or {}).get("hot_pub_b64"))
            except Exception:
                hot_pub_raw = b""
            if len(hot_pub_raw) == 32:
                ok = verify_message_dict(hot_pub_raw, data, data.get("sig"))
                if not ok:
                    return self._json(401, {"error": "message_signature_invalid"})

        # Normal message
        msg = data.get("message") if isinstance(data, dict) else body
        if msg is None:
            msg = "[encrypted]" if data.get("encrypted") else json.dumps(data)[:500]
        
        print(f"[A2A] Received (schema v{detected_version}): {str(msg)[:200]}", flush=True)
        wake_sent = send_wake(str(msg))
        
        response = {
            "status": "OK",
            "from": AGENT_NAME,
            "wake": wake_sent,
            "version": CARD["version"],
            "schema_version": SCHEMA_VERSION,
        }
        if schema_warning:
            response["schema_warning"] = schema_warning
        
        if idem_key:
            store_idempotency(idem_key, response)
        
        return self._json(200, response)

    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}", flush=True)


if __name__ == "__main__":
    print(f"🤖 A2A Server v2.4 starting on :8080", flush=True)
    print(f"   Agent: {AGENT_NAME} | Schema: {SCHEMA_VERSION}", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
