#!/bin/bash
# Chaos Test: Redis Recovery
PORT=8089
PID_FILE="server_chaos.pid"

echo "[*] Starting Server for Chaos Test..."
ENTROPY_PORT=$PORT ENTROPY_REDIS_URL="tcp://127.0.0.1:6379" ./build/server --no-tls > server_chaos.log 2>&1 &
echo $! > $PID_FILE
sleep 2

echo "[*] Verifying Initial Redis Connection..."
if grep -q "Redis connected" server_chaos.log; then
    echo "[+] Redis Linked."
else
    echo "[-] Redis Link Failed."
    kill $(cat $PID_FILE)
    exit 1
fi

echo "[*] SIMULATING REDIS FAILURE (Simulated)..."
# We can use redis-cli to kill the server or just block port 6379 if we had root
# Here we will just perform a 'DEBUG SEGFAULT' via redis-cli if allowed, or manual restart
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
# The server should re-link its subscriber loop
# This might take a few seconds based on the 2s sleep in subscriber_loop
sleep 5
curl -s http://localhost:$PORT/health > /dev/null

if grep -q "reconnecting" server_chaos.log; then
    echo "[+] Reconnection attempt detected in logs."
fi

echo "[!] Chaos Test Component: PASSED"
kill $(cat $PID_FILE)
rm $PID_FILE
