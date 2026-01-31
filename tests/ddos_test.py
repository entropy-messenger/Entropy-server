import requests
import asyncio
import websockets
import json
import time
import sys
import os

PORT = 8092
URL = f"http://localhost:{PORT}"

async def flood_connections(count, max_per_ip):
    print(f"[*] Simulating DDoS: Opening {count} connections (Limit: {max_per_ip})...")
    conns = []
    rejected = 0
    
    for i in range(count):
        try:
            # We use /ws upgrade request directly to hit the ConnectionManager
            ws = await asyncio.wait_for(websockets.connect(f"ws://localhost:{PORT}/ws"), timeout=1.0)
            conns.append(ws)
            # Try to authenticate many sessions from same IP
            auth = {"type": "auth", "payload": {"identity_hash": f"user_{i}", "seed": "...", "nonce": "..."}}
            await ws.send(json.dumps(auth))
            # The server should drop/close those exceeding limit
        except Exception:
            rejected += 1
            
    print(f"[+] Total connections attempted: {count}")
    print(f"[+] Active connections: {len(conns)}")
    print(f"[+] Rejected/Failed: {rejected}")
    
    for ws in conns:
        await ws.close()
    
    # Check if rejected count makes sense
    if len(conns) > max_per_ip + 10: # +10 for some slack in timing
         print("[-] FAILED: Connection limit not strictly enforced")
         return False
    print("[!] Resource Exhaustion Protection VERIFIED")
    return True

async def test_invalid_pow_flood(count):
    print(f"[*] Flooding {count} invalid PoW attempts...")
    # Hit /keys/upload with zeroed PoW
    data = {"test": "data"}
    headers = {"X-PoW-Seed": "0"*64, "X-PoW-Nonce": "123"}
    
    start = time.time()
    for _ in range(count):
        requests.post(f"{URL}/keys/upload", json=data, headers=headers)
    elapsed = time.time() - start
    print(f"[+] Processed {count} malicious requests in {elapsed:.2f}s ({count/elapsed:.1f} req/s)")
    # If the server is still responsive, it passed
    r = requests.get(f"{URL}/health")
    assert r.status_code == 200
    print("[!] CPU Starvation Resistance VERIFIED")
    return True

if __name__ == "__main__":
    import asyncio
    async def run():
        await flood_connections(200, 100)
        await test_invalid_pow_flood(50)
    asyncio.run(run())
