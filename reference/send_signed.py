#!/usr/bin/env python3
"""A2A Signed Send Client (v0.7.0 compliant)"""

import json
import time
import urllib.request
import urllib.error
import identity
import sys

# Peer Config
PEER_URL = "http://35.158.138.126:8080" # Zen
SENDER = "Neo"

def send_signed(message_text):
    # 1. Get Hot Key
    hk = identity.get_or_create_hot_key()
    
    # 2. Build Payload
    trace_id = f"neo-{int(time.time())}"
    payload = {
        "schema_version": "2.5", # Zen is on 2.5
        "trace_id": trace_id,
        "message": message_text,
        "sender": SENDER,
        "wake": True,
        "ts": int(time.time())
    }
    
    # 3. Sign Payload
    # Structure:
    # {
    #   ... payload fields ...
    #   "identity": { "hot_pub_b64": ... },
    #   "sig": "..."
    # }
    
    # Add public key to payload first, so it is signed
    payload["identity"] = {
        "hot_pub_b64": identity._b64e(hk.pub_raw32())
    }
    
    # Sign the payload (sign_message_dict will ignore 'sig' key if present, 
    # but we haven't added it yet)
    sig = identity.sign_message_dict(hk, payload)
    
    # Add signature to top level
    payload["sig"] = sig
    
    # 4. Send
    data = json.dumps(payload).encode('utf-8')
    # No Authorization header implies Zero Secret Auth
    headers = {
        "Content-Type": "application/json",
    }
    
    print(f"Sending signed message to {PEER_URL}...")
    try:
        req = urllib.request.Request(PEER_URL, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("Response:", resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.read().decode()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: send_signed.py <message>")
        sys.exit(1)
    send_signed(sys.argv[1])
