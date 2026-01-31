import requests
import asyncio
import websockets
import json
import hashlib
import time
import sys

# Configuration
PORT = 8092
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

async def authenticate_ws(ws, name, identity_hash):
    r = requests.get(f"{BASE_URL}/pow/challenge")
    challenge = r.json()
    seed = challenge["seed"]
    diff = challenge["difficulty"]
    nonce = solve_pow(seed, diff, identity_hash)
    
    auth_msg = {
        "type": "auth",
        "payload": {
            "identity_hash": identity_hash,
            "seed": seed,
            "nonce": nonce
        }
    }
    await ws.send(json.dumps(auth_msg))
    resp = await ws.recv()
    return json.loads(resp).get("type") == "auth_success"

async def test_binary_relay():
    print("[*] Testing Binary Data Relay...")
    alice_id = hashlib.sha256(b"alice_bin").hexdigest()
    bob_id = hashlib.sha256(b"bob_bin").hexdigest()
    
    async with websockets.connect(WS_URL) as ws_alice, \
               websockets.connect(WS_URL) as ws_bob:
        
        await authenticate_ws(ws_alice, "Alice", alice_id)
        await authenticate_ws(ws_bob, "Bob", bob_id)
        
        # Binary messages in Entropy (per protocol docs) usually have a 64-byte recipient prefix
        # followed by the payload.
        # recipient_hash (64 chars hex) -> 32 bytes binary
        recipient_bin = bob_id.encode('ascii')
        payload = b"Top secret binary message \x00\xff\xde\xad\xbe\xef"
        msg = recipient_bin + payload
        
        print("[*] Alice sending binary message to Bob...")
        await ws_alice.send(msg)
        
        # Bob should receive it. Note: Bob receives the payload, possibly with some wrapper
        # if the server wraps binary messages. In Entropy server, it seems it just relays 
        # the payload if it's a raw binary frame?
        # Let's check src/message_relay.cpp:240 relay_binary
        
        # Bob might get a pacing dummy first
        while True:
            received = await ws_bob.recv()
            if isinstance(received, str):
                if "dummy_pacing" in received: continue
                print(f"[-] Bob received unexpected text: {received}")
                continue
            
            print(f"[+] Bob received binary message of length {len(received)}")
            # Server pads messages to 1536 bytes for metadata resistance
            if len(received) == 1536:
                assert received.startswith(payload)
            else:
                assert received == payload
            print("[!] Binary Relay VERIFIED")
            break

async def test_multicast_relay():
    print("[*] Testing Multicast Relay...")
    alice_id = hashlib.sha256(b"alice_multi").hexdigest()
    bob_id = hashlib.sha256(b"bob_multi").hexdigest()
    charlic_id = hashlib.sha256(b"charlie_multi").hexdigest()
    
    async with websockets.connect(WS_URL) as ws0, \
               websockets.connect(WS_URL) as ws1, \
               websockets.connect(WS_URL) as ws2:
        
        await authenticate_ws(ws0, "Alice", alice_id)
        await authenticate_ws(ws1, "Bob", bob_id)
        await authenticate_ws(ws2, "Charlie", charlic_id)
        
        multicast = {
            "type": "group_multicast",
            "targets": [
                {"to": bob_id, "body": {"text": "Broadcast message to Bob"}},
                {"to": charlic_id, "body": {"text": "Broadcast message to Charlie"}}
            ]
        }
        
        print("[*] Alice sending multicast to Bob and Charlie...")
        await ws0.send(json.dumps(multicast))
        
        # Both Bob and Charlie should receive it via relay_message wrapper
        async def wait_for_msg(ws, name):
            while True:
                m = await ws.recv()
                if "dummy_pacing" in m: continue
                print(f"[+] {name} received: {m}")
                return m

        m1 = await wait_for_msg(ws1, "Bob")
        m2 = await wait_for_msg(ws2, "Charlie")
        
        assert "Broadcast message" in m1
        assert "Broadcast message" in m2
        print("[!] Multicast Relay VERIFIED")

async def test_metrics():
    print("[*] Testing Metrics Endpoint...")
    r = requests.get(f"{BASE_URL}/metrics")
    print(f"[+] Metrics status: {r.status_code}")
    assert r.status_code == 200
    assert "active_connections" in r.text
    print("[!] Metrics Access VERIFIED")

async def run_all():
    print("=== STARTING ADVANCED PROTOCOL TESTS ===")
    try:
        await test_binary_relay()
        await test_multicast_relay()
        await test_metrics()
        print("\n[!!!] ALL ADVANCED TESTS PASSED")
    except Exception as e:
        print(f"\n[-] ADVANCED TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(run_all())
