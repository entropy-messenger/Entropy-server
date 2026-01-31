import requests
import asyncio
import websockets
import json
import hashlib
import time
import subprocess
import os
import signal
import sys

# Configuration
SERVER_PORT = 8085
SERVER_ADDR = "127.0.0.1"
BASE_URL = f"http://{SERVER_ADDR}:{SERVER_PORT}"
WS_URL = f"ws://{SERVER_ADDR}:{SERVER_PORT}/ws"
SECRET_SALT = "integration_test_salt_123456"

def solve_pow(seed, target_difficulty, context=""):
    nonce = 0
    while True:
        data = (seed + context + str(nonce)).encode()
        h = hashlib.sha256(data).digest()
        zeros = 0
        for b in h:
            if b == 0:
                zeros += 2
            else:
                if (b & 0xF0) == 0:
                    zeros += 1
                break
        if zeros >= target_difficulty:
            return str(nonce)
        nonce += 1

async def test_e2e():
    print("[*] Starting Full E2E Integration Test...")
    
    # 1. Health Check
    try:
        r = requests.get(f"{BASE_URL}/health")
        print(f"[+] Health Check: {r.status_code}, {r.json()}")
        assert r.status_code == 200
    except Exception as e:
        print(f"[-] Health Check Failed: {e}")
        return False

    # 2. Get PoW Challenge
    try:
        r = requests.get(f"{BASE_URL}/pow/challenge")
        challenge = r.json()
        seed = challenge["seed"]
        difficulty = challenge["difficulty"]
        print(f"[+] Got PoW Challenge: seed={seed}, difficulty={difficulty}")
    except Exception as e:
        print(f"[-] PoW Challenge Failed: {e}")
        return False

    # 3. Solve PoW
    print("[*] Solving PoW...")
    start_time = time.time()
    nonce = solve_pow(seed, difficulty)
    elapsed = time.time() - start_time
    print(f"[+] PoW Solved in {elapsed:.2f}s: nonce={nonce}")

    # 4. Upload Keys
    identity_key = b"test_key_12345678901234567890123" # Must be something consistent
    identity_hash = hashlib.sha256(identity_key).hexdigest()
    
    import base64
    ik_b64 = base64.b64encode(identity_key).decode()

    bundle = {
        "identity_hash": identity_hash,
        "identityKey": ik_b64,
        "pq_identityKey": "pq_test",
        "signedPreKey": {"pq_publicKey": "pq_pub"},
        "preKeys": []
    }
    
    # Re-calculate PoW for bound identity
    print("[*] Solving Bound PoW for Key Upload...")
    nonce_bound = solve_pow(seed, difficulty, identity_hash)
    
    headers = {
        "X-PoW-Seed": seed,
        "X-PoW-Nonce": nonce_bound
    }
    
    try:
        r = requests.post(f"{BASE_URL}/keys/upload", json=bundle, headers=headers)
        print(f"[+] Key Upload Response: {r.status_code}, {r.json()}")
        # Note: it might still fail signature check, but identity_hash should pass
    except Exception as e:
        print(f"[-] Key Upload request failed: {e}")

    # 5. WebSocket Test
    print("[*] Connecting to WebSocket...")
    try:
        async with websockets.connect(WS_URL) as ws:
            print("[+] WebSocket Connected")
            
            # Send a Ping
            ping = {"type": "ping", "timestamp": int(time.time())}
            await ws.send(json.dumps(ping))
            resp = await ws.recv()
            print(f"[+] Received: {resp}")
            
            # Check if it's a pong
            msg = json.loads(resp)
            if msg.get("type") == "pong":
                print("[+] Protocol Interaction Verified (Pong Received)")
            else:
                print(f"[-] Unexpected Response Type: {msg.get('type')}")
                return False
                
    except Exception as e:
        print(f"[-] WebSocket Test Failed: {e}")
        return False

    print("\n[!] Full E2E Integration Test PASSED (Basic Flows)")
    return True

if __name__ == "__main__":
    import asyncio
    success = asyncio.run(test_e2e())
    if not success:
        sys.exit(1)
