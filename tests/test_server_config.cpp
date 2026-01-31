#include <gtest/gtest.h>
#include "server_config.hpp"

using namespace entropy;

TEST(ServerConfigTest, DefaultValues) {
    ServerConfig config;
    EXPECT_EQ(config.address, "0.0.0.0");
    EXPECT_EQ(config.port, 8080);
    EXPECT_FALSE(config.enable_tls);
    EXPECT_EQ(config.max_message_size, 1024 * 1024);
    EXPECT_EQ(config.secret_salt, "aura salt");
}
