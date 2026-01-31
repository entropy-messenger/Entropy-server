import requests
import asyncio
import websockets
import json
import hashlib
import time
import sys
import os

# Configuration
PORT = 8085
BASE_URL = f"http://localhost:{PORT}"
WS_URL = f"ws://localhost:{PORT}/ws"

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

async def client_session(name, identity_hash):
    print(f"[*] [{name}] Starting session...")
    
    # 1. Get Challenge
    r = requests.get(f"{BASE_URL}/pow/challenge")
    challenge = r.json()
    seed = challenge["seed"]
    difficulty = challenge["difficulty"]
    print(f"[*] [{name}] Got challenge: difficulty={difficulty}")

    # 2. Solve PoW for Auth
    # The server expects the identity_hash to be bound to the PoW context
    print(f"[*] [{name}] Solving PoW for identity {identity_hash}...")
    nonce = solve_pow(seed, difficulty, identity_hash)

    # 3. Connect WebSocket
    async with websockets.connect(WS_URL) as ws:
        print(f"[+] [{name}] Connected to WebSocket")
        
        # 4. Authenticate
        auth_msg = {
            "type": "auth",
            "payload": {
                "identity_hash": identity_hash,
                "seed": seed,
                "nonce": nonce
            }
        }
        await ws.send(json.dumps(auth_msg))
        
        # Wait for auth_success or error
        resp = await ws.recv()
        resp_data = json.loads(resp)
        print(f"[+] [{name}] Auth Response: {resp_data.get('type')}")
        
        if resp_data.get("type") == "auth_success":
            print(f"[!] [{name}] AUTHENTICATED SUCCESSFULLY")
            
            # Send a test ping
            await ws.send(json.dumps({"type": "ping", "timestamp": int(time.time())}))
            ping_resp = await ws.recv()
            print(f"[+] [{name}] Ping-Pong: {json.loads(ping_resp).get('type')}")
            
            return ws, identity_hash
        else:
            print(f"[-] [{name}] Auth Failed: {resp_data}")
            return None, None

async def run_full_integration():
    alice_id = hashlib.sha256(b"alice").hexdigest()
    bob_id = hashlib.sha256(b"bob").hexdigest()

    print("\n--- PHASE 1: ALICE AUTH ---")
    alice_ws, _ = await client_session("Alice", alice_id)
    
    print("\n--- PHASE 2: BOB AUTH ---")
    bob_ws, _ = await client_session("Bob", bob_id)

    if alice_ws and bob_ws:
        print("\n--- PHASE 3: RELAY TEST ---")
        # Alice sends message to Bob
        # The protocol for relaying messages usually involves a 'to' field and a 'body' or 'payload'
        # based on src/message_relay.cpp, it expects a JSON object with 'to' and it will forward the whole JSON.
        msg_to_bob = {
            "type": "chat",
            "to": bob_id,
            "from": alice_id,
            "body": "Hello Bob! This is Alice."
        }
        print("[*] Alice sending message to Bob...")
        await alice_ws.send(json.dumps(msg_to_bob))
        
        # Bob should receive it
        # Note: Bob might receive a 'dummy_pacing' packet first
        while True:
            received = await bob_ws.recv()
            data = json.loads(received)
            if data.get("type") == "dummy_pacing":
                continue
            print(f"[+] Bob Received: {data}")
            if data.get("from") == alice_id:
                print("[!!!] E2E RELAY SUCCESSFUL")
                break
            break # Exit if it's something else
            
    print("\n--- CLEANUP ---")
    if alice_ws: await alice_ws.close()
    if bob_ws: await bob_ws.close()

if __name__ == "__main__":
    try:
        asyncio.run(run_full_integration())
    except Exception as e:
        print(f"[-] Test execution failed: {e}")
        sys.exit(1)
