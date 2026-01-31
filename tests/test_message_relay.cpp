#include <gtest/gtest.h>
#include "message_relay.hpp"
#include <boost/json.hpp>

using namespace entropy;

TEST(MessageRelayTest, SanitizeField) {
    EXPECT_EQ(MessageRelay::sanitize_field("valid_string"), "valid_string");
    EXPECT_EQ(MessageRelay::sanitize_field("string with \" quotes"), "string with   quotes");
    
    std::string long_string(1000, 'a');
    std::string sanitized = MessageRelay::sanitize_field(long_string, 100);
    EXPECT_EQ(sanitized.length(), 100);
}

TEST(MessageRelayTest, PadJson) {
    boost::json::object obj;
    obj["foo"] = "bar";
    
    size_t target_size = 1024;
    MessageRelay::pad_json(obj, target_size);
    
    std::string serialized = boost::json::serialize(obj);
    EXPECT_GE(serialized.length(), target_size);
    EXPECT_TRUE(obj.contains("padding"));
}

TEST(MessageRelayTest, ValidateMessageSize) {
    
    
    EXPECT_EQ(MessageRelay::MAX_MESSAGE_SIZE, 5 * 1024 * 1024);
}
