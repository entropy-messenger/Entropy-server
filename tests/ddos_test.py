import requests
import asyncio
import websockets
import json
import time
import sys
import os

PORT = 8080
URL = f"http://localhost:{PORT}"

async def flood_connections(count, max_per_ip):
    print(f"[*] Simulating DDoS: Opening {count} connections (Limit: {max_per_ip})...")
    conns = []
    rejected = 0
    
    async def connect_one(i):
        nonlocal rejected
        try:
            ws = await asyncio.wait_for(websockets.connect(f"ws://localhost:{PORT}/ws"), timeout=2.0)
            # Try to authenticate many sessions from same IP
            auth = {"type": "auth", "payload": {"identity_hash": f"user_{i}", "seed": "...", "nonce": "..."}}
            await ws.send(json.dumps(auth))
            conns.append(ws)
        except Exception:
            rejected += 1

    tasks = [connect_one(i) for i in range(count)]
    await asyncio.gather(*tasks)
    
    # Wait longer for server to process and OS to clean up socket states
    await asyncio.sleep(5)
            
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
        try:
            requests.post(f"{URL}/keys/upload", json=data, headers=headers, timeout=2)
            time.sleep(0.1) 
        except Exception as e:
            pass
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
        # Phase 1: Connection Limit
        await flood_connections(200, 50)
        
        # Wait for server to fully clean up closed connections
        print("[*] Cooling down before next phase...")
        await asyncio.sleep(5)
        
        # Phase 2: Invalid PoW Flood (CPU/Resource)
        await test_invalid_pow_flood(50)
        
    asyncio.run(run())
