# 📂 Server Project Structure

Summary of the Entropy Relay Server codebase organization.

```text
.
├── include/                 # Header Files (.hpp)
│   ├── handlers/            # REST & WS endpoint logic
│   ├── http_session.hpp     # REST API handler
│   ├── websocket_session.hpp# WebSocket state machine
│   ├── connection_manager.hpp# Active client tracking
│   ├── redis_manager.hpp    # Database abstraction
│   ├── security_logger.hpp  # Blinded auditing
│   └── rate_limiter.hpp     # DoS protection
│
├── src/                     # Implementation (.cpp)
│   ├── main.cpp             # Entry point, SSL & Thread Pool setup
│   ├── message_relay.cpp    # Routing logic
│   ├── pow_verifier.cpp     # SHA256 challenge math
│   └── ...                  # Implementations for headers
│
├── tests/                   # C++ Unit & Integration Tests
│   ├── test_main.cpp
│   └── test_*.cpp           # Component tests
│
├── cmake/                   # Build system modules
├── Dockerfile               # Containerization
├── docker-compose.yml       # Dev/Prod deployment orchestrator
├── README.md                # Quickstart
├── SPECS.md                 # Architecture & Protocols
└── API.md                   # Endpoint documentation
```

## 🏗️ Execution Flow

1.  **Listener**: Accepts raw TCP connections and performs the TLS handshake.
2.  **HTTP Session**: Detects if the request is a REST call or a WebSocket upgrade.
3.  **WebSocket Session**: Upgrades the connection and begins the "Wait for Auth" lifecycle.
4.  **Connection Manager**: Maintains a thread-safe registry of all active connections, mapping `ID_HASH` -> `session_handle`.
5.  **Redis Manager**: Facilitates communication between nodes in a cluster and manages volatile data storage (keys, offline messages).
