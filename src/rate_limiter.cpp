#include "rate_limiter.hpp"
#include <algorithm>
#include <mutex>

namespace entropy {

RateLimiter::RateLimiter(RedisManager& redis)
    : redis_(redis)
{}

// Evaluates a rate limit request against the Redis-backed token bucket.
// Returns success/failure along with remaining capacity or retry wait time.
RateLimitResult RateLimiter::check(const std::string& key, int limit, int window_sec, int cost) {
    return redis_.rate_limit(key, limit, window_sec, cost);
}

// Generates a new Proof-of-Work challenge seed and stores it temporarily in Redis.
std::string RateLimiter::issue_challenge(int ttl_sec) {
    return redis_.issue_challenge(ttl_sec);
}

// Verifies if a challenge seed is valid and has not been used before, then marks it as consumed.
bool RateLimiter::consume_challenge(const std::string& seed) {
    return redis_.consume_challenge(seed);
}

}
