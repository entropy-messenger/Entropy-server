import hashlib
import redis
import time

def verify_forensic_burn(user_hash, salt):
    print(f"[*] Verifying Forensic Wipe for {user_hash}...")
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    
    # Calculate blinded ID as server does
    data = (user_hash + salt).encode()
    blinded = hashlib.sha256(data).hexdigest()
    
    # Common prefixes in Entropy
    prefixes = ["keys:", "msg:", "sess:", "seen:", "rn:"]
    found = []
    
    for p in prefixes:
        key = p + blinded
        if r.exists(key):
            found.append(key)
            
    
    if found:
        print(f"[-] FORENSIC FAIL: Residual data found: {found}")
        return False
    
    print("[!] Forensic Wipe VERIFIED: No residual keys found in Redis.")
    return True

if __name__ == "__main__":
    # Sanity check connection
    import sys
    try:
        verify_forensic_burn("non_existent_check", "test")
    except Exception as e:
        print(f"[-] Redis verification failed: {e}")
        sys.exit(1)
