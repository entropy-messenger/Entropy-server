# Entropy Server Test Suite

This directory contains a comprehensive unit test suite for the Entropy server, built using Google Test (GTest).

## Features Tested
- **Input Validation**: Verifies Ed25519 signatures, hex formats, hashes, and JSON parsing safety.
- **Proof of Work (PoW)**: Validates difficulty calculation logic, nickname-specific costs, and verification algorithms.
- **Metrics**: Ensures Prometheus-compatible metrics are correctly tracked and serialized.
- **Challenge Generation**: Verifies the uniqueness and entropy of cryptographically secure seeds.
- **Message Relay**: Tests message sanitization, padding, and size limits.
- **Configuration**: Ensures default server settings are correctly initialized.

## Prerequisites
- CMake 3.14+
- Boost (System, Thread, JSON)
- OpenSSL
- A C++23 compatible compiler (GCC 13+ or Clang 16+)

## How to Build and Run
A helper script `run_tests.sh` is provided in the server root. You can run it directly:

```bash
chmod +x run_tests.sh
./run_tests.sh
```

Alternatively, you can build manually:

```bash
mkdir -p tests/build
cd tests/build
cmake ..
make -j$(nproc) unit_tests
./unit_tests
```

## Note on External Dependencies
The test suite uses `FetchContent` to automatically download and build Google Test and other required libraries (hiredis, redis-plus-plus) during the first build. This ensures the tests are standalone and do not require changing your project's main `CMakeLists.txt` or source code.
