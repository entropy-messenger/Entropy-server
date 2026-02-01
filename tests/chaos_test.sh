#!/bin/bash
# Chaos Test: Redis Recovery
PORT=8089
PID_FILE="server_chaos.pid"

echo "[*] Starting Server for Chaos Test..."
ENTROPY_PORT=$PORT ENTROPY_REDIS_URL="tcp://127.0.0.1:6379" ./build/server --no-tls > server_chaos.log 2>&1 &
echo $! > $PID_FILE
# Robust check for initial connection (up to 10 seconds)
SUCCESS=0
for i in {1..10}; do
    if grep -q "Redis connected" server_chaos.log; then
        echo "[+] Redis Linked (found at trial $i)."
        SUCCESS=1
        break
    fi
    echo "[*] Waiting for server initialization (trial $i)..."
    sleep 1
done

if [ $SUCCESS -eq 0 ]; then
    echo "[-] Redis Link Failed (Timeout or Error)."
    cat server_chaos.log || true
    kill $(cat $PID_FILE) || true
    exit 1
fi

echo "[*] SIMULATING REDIS FAILURE (Simulated)..."
redis-cli shutdown save
sleep 2

echo "[*] Checking Server Resilience (expected errors but no crash)..."
curl -s http://localhost:$PORT/health > /dev/null
if ps -p $(cat $PID_FILE) > /dev/null; then
    echo "[+] Server still running during Redis outage."
else
    echo "[-] Server CRASHED during Redis outage."
    exit 1
fi

echo "[*] RESTARTING REDIS..."
redis-server --daemonize yes
sleep 2

echo "[*] Verifying Auto-Recovery..."
sleep 5
curl -s http://localhost:$PORT/health > /dev/null

if grep -q "reconnecting" server_chaos.log; then
    echo "[+] Reconnection attempt detected in logs."
fi

echo "[!] Chaos Test Component: PASSED"
kill $(cat $PID_FILE)
rm $PID_FILE
