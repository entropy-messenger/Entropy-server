#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <shared_mutex>

#include "redis_manager.hpp"

namespace entropy {

 
// Protection Layer for Server resource management.
// Acts as a thin wrapper over RedisManager to provide distributed rate limiting
// and Proof-of-Work challenge orchestration across the cluster.
class RateLimiter {
public:
    explicit RateLimiter(RedisManager& redis);
    ~RateLimiter() = default;

    /**
     * Evaluates a rate-limit request against a specific key (e.g., blinded IP or identity).
     * @param key Unique identifier for the rate-limit bucket.
     * @param limit Maximum number of tokens/requests allowed.
     * @param window_sec Period for the token-bucket window.
     * @param cost Resource cost of the current operation.
     * @return Detailed success/failure result with retry metadata.
     */
    RateLimitResult check(const std::string& key, int limit, int window_sec, int cost = 1);
    
    // --- Proof-of-Work (PoW) Orchestration ---
    // Initiates a new computational challenge by issuing a random seed.
    std::string issue_challenge(int ttl_sec);
    
    // Verifies the uniqueness and validity of a submitted seed.
    bool consume_challenge(const std::string& seed);

private:
    RedisManager& redis_;
};

} 
