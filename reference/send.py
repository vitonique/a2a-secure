#!/usr/bin/env python3
"""A2A Send Client v1.0 with Retry/Recovery

Features:
- Exponential backoff retry (3 attempts)
- Dead letter queue for failed messages
- Automatic dead letter retry on startup
- Schema versioning support
- Trace ID generation

Usage:
    python3 send.py "Your message here"
    python3 send.py --to neo "Message to Neo"
    python3 send.py --retry-dead-letters
"""

import argparse
import json
import os
import sys
import time
import uuid
import urllib.request
import urllib.error

from stats import load_stats, atomic_write_json, bump, set_if_missing, update_running_avg

# ============ CONFIG ============
# Add your sibling agents here
# Exchange URLs and secrets via secure DM (not public chat!)
PEERS = {
    "sibling": {
        "url": "http://SIBLING_IP:8080",  # Their IP/port
        "secret": "your-shared-secret",    # Same secret they use
    },
    # Add more peers as needed:
    # "another": {"url": "http://...", "secret": "..."},
}
DEFAULT_PEER = "sibling"  # Who to message by default
SENDER_NAME = "YourAgent"  # Your name

# Retry config
MAX_RETRIES = 3
BACKOFF_BASE = 1  # seconds (1, 2, 4)
TIMEOUT = 15  # seconds per request

# Dead letter queue
DEAD_LETTER_DIR = os.path.expanduser("~/.local/share/a2a/dead-letters")
os.makedirs(DEAD_LETTER_DIR, exist_ok=True)

# Schema
SCHEMA_VERSION = "2.4"
# ================================

# Stats persistence (shared with server)
STATS_PATH = os.path.expanduser("~/.a2a/stats.json")
STATS = load_stats(STATS_PATH)
set_if_missing(STATS, "messages_received", 0)
set_if_missing(STATS, "messages_sent", 0)
set_if_missing(STATS, "avg_latency_ms", 0.0)
set_if_missing(STATS, "retries_total", 0)
set_if_missing(STATS, "dupes_blocked", 0)
set_if_missing(STATS, "wake_calls", 0)
set_if_missing(STATS, "last_restart_ts", None)
set_if_missing(STATS, "uptime_seconds", 0)
# internal fields for avg calc
set_if_missing(STATS, "_latency_samples", 0)
atomic_write_json(STATS_PATH, STATS)


def _persist_stats():
    try:
        atomic_write_json(STATS_PATH, STATS)
    except Exception:
        pass


def generate_trace_id():
    """Generate a trace ID for this request."""
    import random
    import string
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"zen-{int(time.time())}-{rand}"


def send_message(peer_name: str, message: str, wake: bool = True, trace_id: str = None) -> dict:
    """
    Send a message to a peer with retry logic.
    Returns: {"success": bool, "response": dict or None, "error": str or None, "attempts": int}
    """
    peer = PEERS.get(peer_name)
    if not peer:
        return {"success": False, "error": f"Unknown peer: {peer_name}", "attempts": 0}
    
    trace_id = trace_id or generate_trace_id()
    
    payload = {
        "schema_version": SCHEMA_VERSION,
        "trace_id": trace_id,
        "message": message,
        "sender": SENDER_NAME,
        "wake": wake,
    }
    
    data = json.dumps(payload).encode('utf-8')
    headers = {
        "Authorization": f"Bearer {peer['secret']}",
        "Content-Type": "application/json",
    }
    
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        t0 = time.time()
        try:
            req = urllib.request.Request(peer["url"], data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                response_data = json.loads(resp.read().decode())
                dt_ms = (time.time() - t0) * 1000.0
                bump(STATS, "messages_sent", 1)
                update_running_avg(STATS, "avg_latency_ms", "_latency_samples", dt_ms)
                # retries_total counts extra attempts beyond the first
                if attempt > 1:
                    bump(STATS, "retries_total", attempt - 1)
                _persist_stats()

                print(f"✅ [{trace_id}] Sent to {peer_name} (attempt {attempt})")
                return {
                    "success": True,
                    "response": response_data,
                    "error": None,
                    "attempts": attempt,
                    "trace_id": trace_id,
                    "latency_ms": dt_ms,
                }
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}: {e.reason}"
            print(f"⚠️  [{trace_id}] Attempt {attempt}/{MAX_RETRIES} failed: {last_error}")
        except urllib.error.URLError as e:
            last_error = f"Connection error: {e.reason}"
            print(f"⚠️  [{trace_id}] Attempt {attempt}/{MAX_RETRIES} failed: {last_error}")
        except Exception as e:
            last_error = str(e)
            print(f"⚠️  [{trace_id}] Attempt {attempt}/{MAX_RETRIES} failed: {last_error}")
        
        if attempt < MAX_RETRIES:
            backoff = BACKOFF_BASE * (2 ** (attempt - 1))
            print(f"   Waiting {backoff}s before retry...")
            time.sleep(backoff)
    
    # All retries failed - save to dead letter queue
    dead_letter = {
        "peer": peer_name,
        "payload": payload,
        "error": last_error,
        "failed_at": time.time(),
        "attempts": MAX_RETRIES,
    }
    dl_path = os.path.join(DEAD_LETTER_DIR, f"{trace_id}.json")
    try:
        with open(dl_path, "w") as f:
            json.dump(dead_letter, f, indent=2)
        print(f"📬 [{trace_id}] Saved to dead letter queue: {dl_path}")
    except Exception as e:
        print(f"❌ [{trace_id}] Failed to save dead letter: {e}")
    
    return {
        "success": False,
        "response": None,
        "error": last_error,
        "attempts": MAX_RETRIES,
        "trace_id": trace_id,
        "dead_letter": dl_path,
    }


def retry_dead_letters() -> dict:
    """Retry all messages in the dead letter queue."""
    results = {"retried": 0, "succeeded": 0, "failed": 0}
    
    if not os.path.exists(DEAD_LETTER_DIR):
        print("No dead letters to retry.")
        return results
    
    for filename in os.listdir(DEAD_LETTER_DIR):
        if not filename.endswith(".json"):
            continue
        
        filepath = os.path.join(DEAD_LETTER_DIR, filename)
        try:
            with open(filepath, "r") as f:
                dl = json.load(f)
        except Exception as e:
            print(f"⚠️  Failed to read {filename}: {e}")
            continue
        
        results["retried"] += 1
        peer = dl.get("peer", DEFAULT_PEER)
        payload = dl.get("payload", {})
        message = payload.get("message", "")
        trace_id = payload.get("trace_id", filename.replace(".json", ""))
        
        print(f"\n🔄 Retrying dead letter: {trace_id}")
        result = send_message(peer, message, wake=payload.get("wake", True), trace_id=trace_id)
        
        if result["success"]:
            results["succeeded"] += 1
            # Remove from dead letter queue
            try:
                os.remove(filepath)
                print(f"🗑️  Removed from dead letter queue")
            except Exception:
                pass
        else:
            results["failed"] += 1
    
    print(f"\n📊 Dead letter retry complete: {results['succeeded']}/{results['retried']} succeeded")
    return results


def list_dead_letters():
    """List all messages in the dead letter queue."""
    if not os.path.exists(DEAD_LETTER_DIR):
        print("No dead letters.")
        return []
    
    letters = []
    for filename in os.listdir(DEAD_LETTER_DIR):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(DEAD_LETTER_DIR, filename)
        try:
            with open(filepath, "r") as f:
                dl = json.load(f)
            letters.append({
                "trace_id": dl.get("payload", {}).get("trace_id", filename),
                "peer": dl.get("peer"),
                "error": dl.get("error"),
                "failed_at": dl.get("failed_at"),
                "message": dl.get("payload", {}).get("message", "")[:50],
            })
        except Exception:
            pass
    
    if not letters:
        print("No dead letters.")
    else:
        print(f"📬 {len(letters)} dead letter(s):\n")
        for dl in letters:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(dl.get("failed_at", 0)))
            print(f"  [{dl['trace_id']}] to={dl['peer']} @ {ts}")
            print(f"    Error: {dl['error']}")
            print(f"    Message: {dl['message']}...")
            print()
    
    return letters


def main():
    parser = argparse.ArgumentParser(description="A2A Send Client with Retry/Recovery")
    parser.add_argument("message", nargs="?", help="Message to send")
    parser.add_argument("--to", "-t", default=DEFAULT_PEER, help=f"Peer to send to (default: {DEFAULT_PEER})")
    parser.add_argument("--no-wake", action="store_true", help="Don't wake the peer")
    parser.add_argument("--retry-dead-letters", "-r", action="store_true", help="Retry all dead letters")
    parser.add_argument("--list-dead-letters", "-l", action="store_true", help="List dead letters")
    parser.add_argument("--trace-id", help="Custom trace ID")
    
    args = parser.parse_args()
    
    if args.list_dead_letters:
        list_dead_letters()
        return
    
    if args.retry_dead_letters:
        retry_dead_letters()
        return
    
    if not args.message:
        parser.print_help()
        sys.exit(1)
    
    result = send_message(
        peer_name=args.to,
        message=args.message,
        wake=not args.no_wake,
        trace_id=args.trace_id,
    )
    
    if result["success"]:
        print(f"\n✅ Message delivered!")
        print(f"   Response: {json.dumps(result['response'], indent=2)}")
    else:
        print(f"\n❌ Message failed after {result['attempts']} attempts")
        print(f"   Error: {result['error']}")
        if result.get("dead_letter"):
            print(f"   Saved to: {result['dead_letter']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
