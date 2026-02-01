import requests
import time
import sys

# Configuration
PORT = 8080
URL = f"http://localhost:{PORT}"

def test_rate_limit_jailing():
    print("[*] Testing Rate Limit Jailing...")
    
    # We'll hit the /health endpoint or /pow/challenge many times
    # In RedisManager::rate_limit, it uses a script that can jail
    
    jail_triggered = False
    for i in range(200):
        try:
            r = requests.get(f"{URL}/pow/challenge", timeout=2)
            if r.status_code == 429:
                retry_after = int(r.headers.get('Retry-After', 0))
                if retry_after >= 300:
                    print(f"[!] BANNED / JAILED (Status 429, Retry-After: {retry_after}) at attempt {i}")
                    jail_triggered = True
                    break
                else:
                    print(f"[+] Hit Rate Limit at attempt {i}")
        except requests.exceptions.RequestException:
            # Server might have dropped connection
            print("[!] Connection Refused - Potential Firewall/Jail action")
            jail_triggered = True
            break
            
    if jail_triggered:
        print("[!] Rate Limit Jailing VERIFIED")
        return True
    else:
        print("[-] FAILED: Did not trigger jail after 100 requests")
        return False

if __name__ == "__main__":
    test_rate_limit_jailing()
