#include <gtest/gtest.h>
#include "connection_manager.hpp"
#include "websocket_session.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/tcp_stream.hpp>

using namespace entropy;


class ConnectionManagerTest : public ::testing::Test {
protected:
    ConnectionManager cm{"test_salt"};
};

TEST_F(ConnectionManagerTest, BlindId) {
    std::string id = "user123";
    std::string blinded = cm.blind_id(id);
    EXPECT_NE(id, blinded);
    EXPECT_EQ(blinded.length(), 64); 
    EXPECT_EQ(blinded, cm.blind_id(id)); 
}

TEST_F(ConnectionManagerTest, ConnectionCount) {
    EXPECT_EQ(cm.connection_count(), 0);
}

TEST_F(ConnectionManagerTest, IpCount) {
    EXPECT_EQ(cm.connection_count_for_ip("127.0.0.1"), 0);
}



