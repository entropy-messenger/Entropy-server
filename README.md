
# 🌌 Entropy Server

> **Zero-Trace, End-to-End Encrypted Messaging Infrastructure**

Entropy is a high-performance, privacy-first messaging server designed for environments where metadata protection and anonymity are paramount. It uses a blinded-ID routing system to ensure the server never knows who is talking to whom.

![Status](https://img.shields.io/badge/status-proprietary-red)
![C++](https://img.shields.io/badge/std-c%2B%2B17-blue)
![Security](https://img.shields.io/badge/security-audited-green)

---

## 🔐 Core Philosophy

*   **Zero Knowledge Routing**: Routing is done via blinded hashes. The server cannot correlate a sender to a receiver's real identity.
*   **Ephemeral by Design**: Messages are stored in volatile memory (Redis) only until delivery. No persistent logs.
*   **Forensic Resistance**: "Burn" account feature instantly purges all trace of an ID from volatile memory.
*   **DoS Resistant**: Integrated Proof-of-Work (PoW) and token-bucket rate limiting at the application layer.

## 🚀 Features

*   **Protocol**: WebSockets (WSS) over TLS 1.2/1.3.
*   **Encryption**: Clients manage 100% of the keys (Ed25519/X25519). The server is a dumb relay.
*   **Anonymity**: No phone numbers, no emails, no usernames. Only public key hashes.
*   **Scalability**: Built on `boost::beast` and Redis for horizontal scaling.

---

## 🛠️ Quick Start

### Prerequisites
*   Linux / macOS
*   C++17 Compiler (GCC/Clang)
*   CMake 3.12+
*   Redis 6+
*   OpenSSL 1.1+

### Build
```bash
git clone https://github.com/your-username/entropy.git
cd entropy/server
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Configuration
Copy the example environment file:
```bash
cp .env.example .env
```
Edit `.env` to set your secure salt and ports:
```ini
ENTROPY_PORT=8080
ENTROPY_SECRET_SALT=REPLACE_WITH_LONG_RANDOM_STRING_URGENTLY
ENTROPY_REDIS_URL=tcp://127.0.0.1:6379
```

### Run
```bash
# Load env vars and start (TLS disabled for local dev)
set -a; source .env; set +a
./server --no-tls
```

---

## 🛡️ Security Architecture

### 1. Blinded Routing
When Alice sends to Bob, she sends to `Hash(BobID + ServerSalt)`. The server only sees the blinded hash. It cannot reverse this to find "Bob" without the salt, and external observers cannot correlate it to Bob's public ID.

### 2. Rate Limiting
*   **Connection**: Max connections per IP (Configurable).
*   **PoW**: Expensive operations (Registration, Key Upload) require solving a SHA-256 puzzle.
*   **Traffic**: Granular token buckets for different message types.

### 3. Forensic Burn
Sending a signed `Isotope-Burn` request to `/account/burn` forces the server to `DEL` all keys associated with that blinded ID in Redis immediately.

---

## 🧪 Testing

We include a comprehensive suite of Python-based attack vectors and C++ unit tests.

```bash
# Run unit tests
cd build && ctest

# Run full security audit (requires server running)
python3 tests/full_audit.py
```

## 🏢 Internal Development

This repository contains proprietary code. Access and use are currently restricted to authorized personnel only. 

---

**⚠️ DISCLAIMER:** This software is provided for educational and research purposes. Use responsibly.
