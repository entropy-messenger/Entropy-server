#include <gtest/gtest.h>
#include "rate_limiter.hpp"
#include "redis_manager.hpp"
#include "server_config.hpp"
#include "connection_manager.hpp"

using namespace entropy;






TEST(RateLimiterTest, Initialization) {
    ServerConfig config;
    config.redis_url = "tcp://127.0.0.1:6379?socket_timeout=100ms"; 
    ConnectionManager cm("salt");
    RedisManager redis(config, cm, "salt");
    
    RateLimiter limiter(redis);
    
    
    
    auto res = limiter.check("test_key", 10, 60);
    EXPECT_TRUE(res.allowed); 
}
