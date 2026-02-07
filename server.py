#!/usr/bin/env python3
"""Zen A2A Server v2.5

- Auth: Bearer shared secret
- Instant Wake: uses OpenClaw `wake --mode now`
- v2.2 Store-and-Fetch: avoids relay truncation for long encrypted payloads
- v2.3 Idempotency: prevents duplicate message processing
- v2.4 Schema Versioning: explicit message format negotiation
- v2.5 Trace ID: request correlation for debugging

Endpoints:
- GET  /                      -> capability card (includes schema info)
- POST /                      -> receive message (plaintext or encrypted or fetch_ref)
- POST /messages              -> store encrypted blob, returns msg_id
- GET  /messages/<msg_id>     -> fetch stored blob (delete-on-fetch)

Schema Versions:
- 1.0: Basic message (message, sender, wake)
- 2.0: Encrypted fields (nonce, ciphertext, tag)
- 2.1: Store-and-fetch (fetch_ref, msg_id)
- 2.2: Idempotency (idempotency_key)
- 2.3: Schema versioning (schema_version field)
- 2.4: Trace ID (trace_id field)

Notes:
- Store only *encrypted* payloads (never plaintext secrets).
- Message store is best-effort (in-memory + disk fallback) with TTL.
- Backward compatibility: messages without schema_version are treated as 1.0
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import time
import os
import uuid
import base64

# v0.7.0: Identity module for signature verification
from identity import verify_message_dict

def get_secret():
    """Load shared secret from encrypted store."""
    try:
        result = subprocess.run(
            [os.path.expanduser("~/bin/get-secret"), "a2a", "shared_secret"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        print(f"Warning: Could not load secret from age store: {e}")
    # Fallback (should not happen in production)
    return os.environ.get("A2A_SECRET", "")

# v0.7.0: Require signatures on normal messages (identity-based auth)
REQUIRE_SIGNATURE = True  # LIVE TEST  # Need to add verify_message_dict first!
IDENTITY_VERSION = "0.7.0"
START_TS = int(time.time())

# Schema versioning
SCHEMA_VERSION = "2.5"
SCHEMA_MIN = "1.0"
SCHEMA_MAX = "2.5"

CARD = {
    "name": "Zen",
    "version": "2.5",
    "skills": ["research", "coordination"],
    "features": ["instant-wake", "aes-gcm", "store-and-fetch", "idempotency", "schema-versioning", "trace-id"],
    "schema": {
        "current": SCHEMA_VERSION,
        "min_supported": SCHEMA_MIN,
        "max_supported": SCHEMA_MAX,
    },
}

# Idempotency config
IDEMPOTENCY_DIR = "/tmp/a2a-idempotency"
IDEMPOTENCY_TTL = 24 * 60 * 60  # 24 hours
os.makedirs(IDEMPOTENCY_DIR, exist_ok=True)

# Store-and-fetch config
MAX_INLINE_BYTES = 8000  # Increased from 2000 to handle longer responses
TTL_SECONDS = 24 * 60 * 60
DELETE_ON_FETCH = True
STORE_DIR = "/tmp/a2a-messages"
os.makedirs(STORE_DIR, exist_ok=True)

# In-memory index: msg_id -> {"ts": epoch, "path": filePath}
MSG_INDEX = {}

# Idempotency helpers
def check_idempotency(key):
    """Check if idempotency key was already processed. Returns cached response or None."""
    if not key:
        return None
    path = os.path.join(IDEMPOTENCY_DIR, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        # Check TTL
        if time.time() - data.get("ts", 0) > IDEMPOTENCY_TTL:
            os.remove(path)
            return None
        print(f"[IDEMPOTENCY] Cache hit for key: {key[:20]}...", flush=True)
        return data.get("response")
    except Exception as e:
        print(f"[IDEMPOTENCY] Error reading cache: {e}", flush=True)
        return None

def store_idempotency(key, response):
    """Store idempotency key with its response."""
    if not key:
        return
    path = os.path.join(IDEMPOTENCY_DIR, f"{key}.json")
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "response": response}, f)
        print(f"[IDEMPOTENCY] Stored key: {key[:20]}...", flush=True)
    except Exception as e:
        print(f"[IDEMPOTENCY] Error storing: {e}", flush=True)

def cleanup_idempotency():
    """Remove expired idempotency keys."""
    try:
        now = time.time()
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

def parse_version(v):
    """Parse version string to tuple for comparison."""
    try:
        parts = str(v).split(".")
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return (1, 0)  # Default to 1.0

def check_schema_version(data):
    """
    Check schema version compatibility.
    Returns (ok, detected_version, warning) tuple.
    - ok: True if compatible
    - detected_version: the version string detected
    - warning: optional warning message
    """
    if not isinstance(data, dict):
        return True, "1.0", None  # Non-dict payloads treated as 1.0
    
    client_version = data.get("schema_version")
    
    if client_version is None:
        # No version specified - backward compat, treat as 1.0
        return True, "1.0", "no_schema_version_field"
    
    client_v = parse_version(client_version)
    min_v = parse_version(SCHEMA_MIN)
    max_v = parse_version(SCHEMA_MAX)
    
    if client_v < min_v:
        return False, client_version, f"version_too_old:min={SCHEMA_MIN}"
    
    if client_v > max_v:
        # Accept but warn - forward compat attempt
        return True, client_version, f"version_newer_than_server:max={SCHEMA_MAX}"
    
    return True, client_version, None


def get_or_create_trace_id(data):
    """
    Get trace_id from request or generate one.
    Format: zen-{timestamp}-{random}
    """
    if isinstance(data, dict) and data.get("trace_id"):
        return data["trace_id"]
    # Generate new trace_id
    import random
    import string
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"zen-{int(time.time())}-{rand}"

WAKE_INLINE_LIMIT = 1500  # Messages longer than this use store-and-fetch

def send_wake(message_text):
    """Send INSTANT wake event via OpenClaw CLI.
    
    Never Truncate: If message > WAKE_INLINE_LIMIT, store full message
    and send short notification with fetch reference.
    """
    try:
        # Never truncate: store long messages, send reference
        if len(message_text) > WAKE_INLINE_LIMIT:
            # Store full message in local file
            msg_id = f"wake-{int(time.time())}-{os.urandom(4).hex()}"
            store_path = f"/tmp/a2a-wake-store/{msg_id}.txt"
            os.makedirs("/tmp/a2a-wake-store", exist_ok=True)
            with open(store_path, "w") as f:
                f.write(message_text)
            
            # Send short notification with reference
            preview = message_text[:200] + "..." if len(message_text) > 200 else message_text
            wake_text = f"[A2A] Neo: {preview}\n\n📎 Full message: cat {store_path}"
            print(f"[WAKE] Long message ({len(message_text)} bytes) stored as {msg_id}", flush=True)
        else:
            wake_text = f"[A2A] Neo: {message_text}"
        
        params = {
            "text": wake_text,
            "mode": "now"
        }
        
        result = subprocess.run(
            ["/usr/bin/openclaw", "gateway", "call", "wake", "--params", json.dumps(params)],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0:
            print(f"[WAKE] ✅ INSTANT WAKE SENT!", flush=True)
            return True
        else:
            print(f"[WAKE] Error (code {result.returncode}): {result.stderr}", flush=True)
            # Fallback: write trigger file with full message
            try:
                with open("/tmp/zen-a2a-wake.trigger", "w") as f:
                    f.write(message_text)  # Never truncate!
                print(f"[WAKE] 📁 Wrote fallback trigger file", flush=True)
            except:
                pass
            return False
    except subprocess.TimeoutExpired:
        print(f"[WAKE] Timeout - writing fallback trigger", flush=True)
        try:
            with open("/tmp/zen-a2a-wake.trigger", "w") as f:
                f.write(message_text)  # Never truncate!
        except:
            pass
        return True
    except Exception as e:
        print(f"[WAKE] Failed: {e}", flush=True)
        return False

class Handler(BaseHTTPRequestHandler):

    def _json(self, code: int, payload: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def _unauth(self):
        self._json(401, {"error": "Unauthorized"})

    def _cleanup_expired(self):
        now = time.time()
        expired = []
        for msg_id, meta in MSG_INDEX.items():
            if now - meta.get("ts", 0) > TTL_SECONDS:
                expired.append(msg_id)
        for msg_id in expired:
            try:
                path = MSG_INDEX[msg_id].get("path")
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            MSG_INDEX.pop(msg_id, None)

    def do_GET(self):
        # Capability card
        if self.path == "/" or self.path == "":
            return self._json(200, CARD)

        # v0.7.0: Lightweight health endpoint (no wake)
        if self.path == "/health":
            now_i = int(time.time())
            health = {
                "status": "OK",
                "from": CARD.get("name", "Zen"),
                "version": CARD.get("version"),
                "schema_version": SCHEMA_VERSION,
                "identity_version": IDENTITY_VERSION,
                "ts": now_i,
                "uptime_seconds": now_i - START_TS,
            }
            return self._json(200, health)

        # Fetch stored message blob
        if self.path.startswith("/messages/"):
            msg_id = self.path.split("/messages/", 1)[1]
            meta = MSG_INDEX.get(msg_id)
            if not meta:
                return self._json(404, {"error": "Not Found"})
            path = meta.get("path")
            if not path or not os.path.exists(path):
                MSG_INDEX.pop(msg_id, None)
                return self._json(404, {"error": "Not Found"})

            try:
                with open(path, "r", encoding="utf-8") as f:
                    blob = json.load(f)
            except Exception as e:
                return self._json(500, {"error": f"read_failed: {e}"})

            if DELETE_ON_FETCH:
                try:
                    os.remove(path)
                except Exception:
                    pass
                MSG_INDEX.pop(msg_id, None)

            return self._json(200, blob)

        return self._json(404, {"error": "Not Found"})

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        auth_ok = (auth == f"Bearer {get_secret()}")

        self._cleanup_expired()
        cleanup_idempotency()

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        
        # Check idempotency early (for all POST requests)
        try:
            data_check = json.loads(body)
            idem_key = data_check.get("idempotency_key") if isinstance(data_check, dict) else None
            if idem_key:
                cached = check_idempotency(idem_key)
                if cached:
                    return self._json(200, cached)
        except Exception:
            idem_key = None

        # 1) Store message blob endpoint
        if self.path == "/messages":
            # For now we keep /messages behind Authorization to prevent abuse.
            # (It can be upgraded to signature-based auth later as well.)
            if not auth_ok:
                return self._unauth()
            try:
                data = json.loads(body)
            except Exception:
                return self._json(400, {"error": "invalid_json"})

            # Only store encrypted payloads
            if not isinstance(data, dict) or not data.get("encrypted"):
                return self._json(400, {"error": "only_encrypted_payloads_allowed"})

            msg_id = data.get("msg_id") or str(uuid.uuid4())
            path = os.path.join(STORE_DIR, f"{msg_id}.json")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                MSG_INDEX[msg_id] = {"ts": time.time(), "path": path}
            except Exception as e:
                return self._json(500, {"error": f"store_failed: {e}"})

            return self._json(200, {"status": "stored", "msg_id": msg_id, "max_inline_bytes": MAX_INLINE_BYTES, "ttl_seconds": TTL_SECONDS, "delete_on_fetch": DELETE_ON_FETCH, "schema_version": SCHEMA_VERSION})

        # 2) Default inbound message endpoint
        try:
            data = json.loads(body)
        except Exception:
            data = {"message": body}

        # Get or create trace_id early for fetch_ref
        trace_id = get_or_create_trace_id(data)

        # Support fetch_ref pings (notify the agent to fetch)
        if isinstance(data, dict) and data.get("type") == "fetch_ref":
            # Keep wake notification short; agent will fetch the payload via GET.
            msg_id = data.get("msg_id")
            url = data.get("url")
            from_ = data.get("from") or data.get("sender")
            wake_text = f"[A2A fetch_ref] from={from_} msg_id={msg_id}"
            print(f"[A2A] [{trace_id}] RECEIVED fetch_ref: {wake_text}", flush=True)
            wake_sent = send_wake(wake_text)
            return self._json(200, {"status": "OK", "from": "Zen", "wake": wake_sent, "version": CARD["version"], "schema_version": SCHEMA_VERSION, "trace_id": trace_id, "mode": "fetch_ref"})

        # Schema version check
        schema_ok, detected_version, schema_warning = check_schema_version(data)
        if not schema_ok:
            return self._json(400, {
                "error": "schema_version_incompatible",
                "details": schema_warning,
                "client_version": detected_version,
                "server_schema": CARD["schema"],
                "trace_id": trace_id,
            })

        # If shared-secret auth is missing, we require signatures (zero shared secret mode).
        if (not auth_ok) and (not REQUIRE_SIGNATURE):
            return self._unauth()

        # v0.7.0: Signature verification
        if isinstance(data, dict):
            hot_pub_b64 = (data.get("identity") or {}).get("hot_pub_b64")
            sig_b64 = data.get("sig")
            
            if REQUIRE_SIGNATURE and (not hot_pub_b64 or not sig_b64):
                return self._json(401, {"error": "signature_required", "trace_id": trace_id})
            
            if hot_pub_b64 and sig_b64:
                try:
                    hot_pub_raw = base64.b64decode(hot_pub_b64)
                except Exception:
                    hot_pub_raw = b""
                if len(hot_pub_raw) == 32:
                    ok = verify_message_dict(hot_pub_raw, data, sig_b64)
                    if not ok:
                        return self._json(401, {"error": "message_signature_invalid", "trace_id": trace_id})
                    print(f"[A2A] [{trace_id}] Signature VERIFIED ✅", flush=True)
                elif REQUIRE_SIGNATURE:
                    return self._json(401, {"error": "hot_pubkey_wrong_length", "trace_id": trace_id})

        # Otherwise treat as normal message
        msg = None
        if isinstance(data, dict):
            # Common payload style
            msg = data.get("message")
            if msg is None:
                # If encrypted payload came directly, keep it minimal
                if data.get("encrypted"):
                    msg = "[A2A] received encrypted payload (inline)."
                else:
                    msg = json.dumps(data)[:2000]
        if msg is None:
            msg = body
        if isinstance(msg, dict):
            msg = msg.get("text", str(msg))

        print(f"[A2A] [{trace_id}] RECEIVED (schema v{detected_version}): {msg}", flush=True)
        wake_sent = send_wake(str(msg))

        response = {
            "status": "OK",
            "from": "Zen",
            "wake": wake_sent,
            "version": CARD["version"],
            "schema_version": SCHEMA_VERSION,
            "trace_id": trace_id,
        }
        
        # Add warning if schema mismatch
        if schema_warning:
            response["schema_warning"] = schema_warning
        
        # Store idempotency if key was provided
        if idem_key:
            store_idempotency(idem_key, response)
        
        return self._json(200, response)

    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}", flush=True)

if __name__ == "__main__":
    print(f"🧘 Zen A2A Server v2.5 (trace-id) starting on 8080...", flush=True)
    print(f"   Schema: v{SCHEMA_VERSION} (supports {SCHEMA_MIN}-{SCHEMA_MAX})", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
