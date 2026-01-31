
# 🌌 Entropy Server

> **Zero-Trace, End-to-End Encrypted Messaging Infrastructure**

Entropy is a high-performance, privacy-first messaging server designed for environments where metadata protection and anonymity are paramount. It uses a blinded-ID routing system to ensure the server never knows who is talking to whom.

![Status](https://img.shields.io/badge/status-active-green)
![C++](https://img.shields.io/badge/std-c%2B%2B17-blue)
![License](https://img.shields.io/badge/license-AGPLv3-blue)

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
*   **Operating System**: Linux / macOS
*   **Compiler**: C++23 compliant (GCC 13+ or Clang 16+ highly recommended)
*   **Build System**: CMake 3.14+
*   **Libraries**:
    *   **Boost 1.75+**: Required components: `system`, `thread`, `json`
    *   **OpenSSL 1.1.1+ / 3.0+**: For TLS 1.3 and cryptographic primitives
*   **Database**: Redis 6+ (optimized for volatile storage)

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

## ⚙️ Configuration

Entropy is configured primarily via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `ENTROPY_PORT` | Port to listen on | `8080` |
| `ENTROPY_ADDR` | Address to bind to | `0.0.0.0` |
| `ENTROPY_SECRET_SALT` | **CRITICAL**: Salt for blinded routing. | (Must be set) |
| `ENTROPY_REDIS_URL` | Redis connection URL | `tcp://127.0.0.1:6379` |
| `ENTROPY_ALLOWED_ORIGINS`| Comma-separated CORS origins | (Empty) |
| `ENTROPY_RATE_LIMIT` | Global requests per second | `100.0` |
| `ENTROPY_MAX_CONNS_PER_IP`| Connection cap per IP | `10` |
| `ENTROPY_ADMIN_TOKEN` | Optional token for admin metrics | (Empty) |

---

## 🛡️ Security Architecture

### 1. Blinded Routing (Zero-Metadata)
Entropy prevents the server from correlating participants. 
*   **The Problem**: In standard E2EE, the server knows Alice is talking to Bob.
*   **The Solution**: Alice sends messages to `SHA256(BobID + ServerSalt)`. Without the `ServerSalt`, an attacker cannot determine Bob's identity even with access to the database or traffic logs.

### 2. Proof-of-Work (PoW) Defense
Expensive operations (Registration, Key Uploads) require a SHA-256 challenge solution. Difficulty scales dynamically based on:
*   **Server Load**: Higher active connections increase difficulty globally.
*   **Resource Scarcity**: Shorter, desirable nicknames (e.g., "alice") require exponentially more work.
*   **Account Maturity**: Older, verified identities are rewarded with lower difficulty.

### 3. K-Anonymity Discovery
To hide interest in a peer, clients can fetch keys in batches. The server supports a sampler that returns random "decoy" keys, allowing clients to hide their target ID among $K$ others.

### 4. Forensic Burn
A signed `BURN` request triggers an atomic purge of all identity-associated data in Redis. This ensures that even if the server is seized, no metadata traces remain for that identifier.

---

## 🛠️ Operations

### 🐳 Docker Deployment
Use our production-ready `docker-compose.yml`:
```bash
# Set your salt first!
export ENTROPY_SECRET_SALT=$(openssl rand -hex 32)
docker-compose up -d
```

### 🛑 Graceful Shutdown
The server handles `SIGINT` and `SIGTERM`. Upon receiving a signal, it:
1. Stops accepting new connections.
2. Flushes pending write queues for active sessions.
3. Closes all WebSockets cleanly.
4. Shuts down the Boost.Asio I/O context.

---

## 🧪 Testing

We include a comprehensive suite of Python-based attack vectors and C++ unit tests.

```bash
# Run unit tests
cd build && ctest

# Run full security audit (requires server running)
python3 tests/security_audit.py
```

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPLv3) - see the LICENSE file for details.

---

**⚠️ DISCLAIMER:** This software is provided for educational and research purposes. Use responsibly.
