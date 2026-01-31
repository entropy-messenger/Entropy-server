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
            if b == 0: zeros += 2
            else:
                if (b & 0xF0) == 0: zeros += 1
                break
        if zeros >= target_difficulty: return str(nonce)
        nonce += 1

async def test_alias_exhaustion():
    print("[*] Testing Alias Exhaustion (Max 50)...")
    async with websockets.connect(WS_URL) as ws:
        # Auth Alice
        r = requests.get(f"{BASE_URL}/pow/challenge")
        challenge = r.json()
        identity_hash = hashlib.sha256(b"alias_alice").hexdigest()
        nonce = solve_pow(challenge["seed"], challenge["difficulty"], identity_hash)
        
        await ws.send(json.dumps({
            "type": "auth",
            "payload": {"identity_hash": identity_hash, "seed": challenge["seed"], "nonce": nonce}
        }))
        await ws.recv() # auth_success
        
        # Add 50 aliases
        for i in range(50):
            time.sleep(0.5) # Avoid triggering request rate limiter
            alias = f"alias_{i}"
            # Need PoW for each alias to be realistic
            r_alias = requests.get(f"{BASE_URL}/pow/challenge")
            chal_alias = r_alias.json()
            nonce_alias = solve_pow(chal_alias["seed"], chal_alias["difficulty"], alias)
            
            await ws.send(json.dumps({
                "type": "subscribe_alias",
                "payload": {"alias": alias, "seed": chal_alias["seed"], "nonce": nonce_alias}
            }))
            while True:
                resp = await ws.recv()
                data = json.loads(resp)
                if data.get("type") == "dummy_pacing": continue
                break
            
            if data.get("type") != "alias_subscribed":
                print(f"[-] FAILED at alias {i}: {data}")
                return False
                
        print("[+] 50 aliases successfully added.")
        
        # 51st should fail
        alias_51 = "alias_51"
        r_51 = requests.get(f"{BASE_URL}/pow/challenge")
        nonce_51 = solve_pow(r_51.json()["seed"], r_51.json()["difficulty"], alias_51)
        await ws.send(json.dumps({
            "type": "subscribe_alias",
            "payload": {"alias": alias_51, "seed": r_51.json()["seed"], "nonce": nonce_51}
        }))
        resp = await ws.recv()
        data = json.loads(resp)
        if data.get("type") == "error" and "limit reached" in data.get("message", "").lower():
            print("[!] Alias Limit Enforcement VERIFIED")
            return True
        else:
            print(f"[-] FAILED: Expected limit error but got {data}")
            return False

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_alias_exhaustion())
