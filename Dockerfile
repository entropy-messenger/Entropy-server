# Build Stage
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libboost-json-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libboost-system1.81.0 \
    libboost-thread1.81.0 \
    libboost-json1.81.0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security: Run as non-root user
RUN groupadd -r entropy && useradd -r -g entropy -d /app -s /sbin/nologin entropy

WORKDIR /app
COPY --from=builder /app/build/server /app/entropy-server

RUN mkdir -p /app/data /app/certs && \
    chown -R entropy:entropy /app

ENV ENTROPY_PORT=8080
ENV ENTROPY_ADDR=0.0.0.0
ENV ENTROPY_REDIS_URL=tcp://redis:6379
ENV ENTROPY_SECRET_SALT="REPLACE_THIS_WITH_A_SECURE_RANDOM_STRING_IN_PRODUCTION"

USER entropy
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${ENTROPY_PORT}/health || exit 1

# Note: --no-tls assumes SSL termination via reverse proxy
CMD ["./entropy-server", "--no-tls"]
