# Build Stage
FROM debian:bookworm-slim AS builder

# Install build dependencies
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

# Copy source code
COPY . .

# Build the application
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libboost-system1.81.0 \
    libboost-thread1.81.0 \
    libboost-json1.81.0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN groupadd -r entropy && useradd -r -g entropy -d /app -s /sbin/nologin entropy

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/build/server /app/entropy-server

# Create data and certs directories with correct permissions
RUN mkdir -p /app/data /app/certs && \
    chown -R entropy:entropy /app

# Explicitly copy any default certs if they exist (though usually generated or mounted)
# COPY --from=builder /app/certs /app/certs # If you want to include default self-signed certs

# Default environment variables
ENV ENTROPY_PORT=8080
ENV ENTROPY_ADDR=0.0.0.0
ENV ENTROPY_REDIS_URL=tcp://redis:6379
ENV ENTROPY_SECRET_SALT="REPLACE_THIS_WITH_A_SECURE_RANDOM_STRING_IN_PRODUCTION"

# Switch to the non-root user
USER entropy

EXPOSE 8080

# Healthcheck to ensure the relay is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${ENTROPY_PORT}/health || exit 1

# Command to run the application
# Note: --no-tls can be used if SSL is handled by a reverse proxy (recommended)
CMD ["./entropy-server", "--no-tls"]
