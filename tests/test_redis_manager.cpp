#include <gtest/gtest.h>
#include "redis_manager.hpp"
#include "server_config.hpp"
#include "connection_manager.hpp"
#include <thread>
#include <chrono>

using namespace entropy;

class RedisManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.redis_url = "tcp://127.0.0.1:6379?read_timeout=100ms";
        cm = std::make_unique<ConnectionManager>("test_salt");
        redis = std::make_unique<RedisManager>(config, *cm, "test_salt");
        
        
        if (redis->is_connected()) {
            redis->burn_account("test_user");
            redis->burn_account("offline_user");
        }
    }

    ServerConfig config;
    std::unique_ptr<ConnectionManager> cm;
    std::unique_ptr<RedisManager> redis;
};

TEST_F(RedisManagerTest, ConnectionStatus) {
    if (!redis->is_connected()) {
        GTEST_SKIP() << "Redis not available at 127.0.0.1:6379";
    }
    EXPECT_TRUE(redis->is_connected());
}

TEST_F(RedisManagerTest, OfflineMessaging) {
    if (!redis->is_connected()) GTEST_SKIP();

    std::string user = "offline_user";
    std::string msg = "{\"data\": \"hello\"}";
    
    EXPECT_TRUE(redis->store_offline_message(user, msg));
    
    auto retrieved = redis->retrieve_offline_messages(user);
    ASSERT_EQ(retrieved.size(), 1);
    EXPECT_EQ(retrieved[0], msg);
    
    
    auto second_retrieval = redis->retrieve_offline_messages(user);
    EXPECT_EQ(second_retrieval.size(), 0);
}

TEST_F(RedisManagerTest, RegistrationAndResolution) {
    if (!redis->is_connected()) GTEST_SKIP();

    std::string nick = "quantum";
    std::string user_hash = "hash123";
    
    
    redis->burn_account(user_hash);

    EXPECT_TRUE(redis->register_nickname(nick, user_hash));
    EXPECT_EQ(redis->resolve_nickname(nick), user_hash);
    
    
    EXPECT_TRUE(redis->register_nickname(nick, user_hash));
    
    
    EXPECT_FALSE(redis->register_nickname(nick, "different_hash"));
}

TEST_F(RedisManagerTest, ForensicBurn) {
    if (!redis->is_connected()) GTEST_SKIP();

    std::string user = "test_user";
    std::string bundle = "{\"keys\": \"ABC\"}";
    
    redis->store_user_bundle(user, bundle);
    redis->store_offline_message(user, "msg1");
    redis->register_nickname("test_nick", user);
    
    
    EXPECT_EQ(redis->get_user_bundle(user), bundle);
    EXPECT_EQ(redis->resolve_nickname("test_nick"), user);

    
    EXPECT_TRUE(redis->burn_account(user));
    
    
    EXPECT_EQ(redis->get_user_bundle(user), "");
    EXPECT_EQ(redis->resolve_nickname("test_nick"), "");
    EXPECT_EQ(redis->retrieve_offline_messages(user).size(), 0);
}

TEST_F(RedisManagerTest, LuaRateLimiter) {
    if (!redis->is_connected()) GTEST_SKIP();

    std::string key = "rl_test_user";
    int limit = 2;
    int window = 10;
    
    
    auto r1 = redis->rate_limit(key, limit, window);
    EXPECT_TRUE(r1.allowed);
    
    auto r2 = redis->rate_limit(key, limit, window);
    EXPECT_TRUE(r2.allowed);
    
    
    auto r3 = redis->rate_limit(key, limit, window);
    EXPECT_FALSE(r3.allowed);
}
