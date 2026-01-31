#!/bin/bash
set -e

PORT=8092
export ENTROPY_PORT=$PORT
export ENTROPY_SECRET_SALT="full_test_salt_9876543210"
export ENTROPY_ALLOWED_ORIGINS="*"

echo "=== STARTING FULL TEST SUITE ==="
echo "[*] Flushing Redis..."
redis-cli FLUSHALL

# 1. Start Server
./build/server --no-tls > server_full.log 2>&1 &
SERVER_PID=$!
echo "[*] Server started with PID $SERVER_PID on port $PORT"
sleep 3

function cleanup {
    echo "[*] Cleaning up..."
    kill $SERVER_PID || true
}
trap cleanup EXIT

# Update config in python scripts if needed, or just pass as env
# My python scripts currently hardcode ports, let's fix that or use multiple ports and start multiple servers?
# To be safe, I'll just run them one by one, updating the python script port or ensuring they match.
# All my scripts currently use different ports, which is fine but requires multiple servers.
# Better to run one server and adjust scripts.

echo "[*] Running Protocol Compliance Tests..."
# Adjusting script to use $PORT
sed -i "s/PORT = .*/PORT = $PORT/" tests/protocol_compliance_test.py
python3 tests/protocol_compliance_test.py

echo "[*] Running Advanced Relay Tests..."
sed -i "s/PORT = .*/PORT = $PORT/" tests/advanced_relay_test.py
python3 tests/advanced_relay_test.py

echo "[*] Running Metadata Uniformity & Session Tests..."
sed -i "s/PORT = .*/PORT = $PORT/" tests/metadata_test.py
python3 tests/metadata_test.py

echo "[*] Waiting for Rate Limit Window Reset (60s)..."
sleep 60
echo "[*] Running Alias Limit Tests..."
sed -i "s/PORT = .*/PORT = $PORT/" tests/alias_limit_test.py
python3 tests/alias_limit_test.py

echo "[*] Verifying Forensic Wipe..."
python3 tests/forensic_verify.py

echo "[*] Running DDoS Simulation..."
sed -i "s/PORT = .*/PORT = $PORT/" tests/ddos_test.py
# Using python3 -c to run the async main from shell is hard, but we added main block to ddos_test.py
python3 tests/ddos_test.py

echo "[*] Running Rate Limit Jail Tests..."
sed -i "s/PORT = .*/PORT = $PORT/" tests/jail_test.py
python3 tests/jail_test.py

echo "[*] Running Chaos & Recovery Tests..."
# Stop the main test server first to avoid port conflicts or log confusion, 
# though chaos_test uses a different port (8089).
# But chaos_test kills Redis, so we must be careful.
# The cleanup trap maps to SIGEXIT, so if we run chaos_test which assumes control, 
# we should probably run it after we are done with the main server.
# However, cleanup will kill SERVER_PID.
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
# Unset trap to avoid double kill
trap - EXIT

./tests/chaos_test.sh

echo "=== ALL E2E TESTS PASSED ==="
