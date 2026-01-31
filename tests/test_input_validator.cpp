#include <gtest/gtest.h>
#include "input_validator.hpp"
#include <vector>
#include <string>

using namespace entropy;

TEST(InputValidatorTest, ValidHex) {
    EXPECT_TRUE(InputValidator::is_valid_hex("abcdef0123456789"));
    EXPECT_TRUE(InputValidator::is_valid_hex("ABCDEF"));
    EXPECT_FALSE(InputValidator::is_valid_hex("ghijk"));
    EXPECT_FALSE(InputValidator::is_valid_hex(""));
}

TEST(InputValidatorTest, ValidHexWithLength) {
    EXPECT_TRUE(InputValidator::is_valid_hex("abcd", 4));
    EXPECT_FALSE(InputValidator::is_valid_hex("abcd", 5));
    EXPECT_FALSE(InputValidator::is_valid_hex("abcde", 4));
}

TEST(InputValidatorTest, ValidHash) {
    std::string valid_hash(64, 'a');
    std::string invalid_hash(63, 'a');
    EXPECT_TRUE(InputValidator::is_valid_hash(valid_hash));
    EXPECT_FALSE(InputValidator::is_valid_hash(invalid_hash));
    EXPECT_FALSE(InputValidator::is_valid_hash(valid_hash + "g"));
}

TEST(InputValidatorTest, ValidAlphanumeric) {
    EXPECT_TRUE(InputValidator::is_valid_alphanumeric("user123_test-name"));
    EXPECT_FALSE(InputValidator::is_valid_alphanumeric("user!@#"));
    EXPECT_FALSE(InputValidator::is_valid_alphanumeric(""));
}

TEST(InputValidatorTest, WithinSizeLimit) {
    EXPECT_TRUE(InputValidator::is_within_size_limit(100, 200));
    EXPECT_TRUE(InputValidator::is_within_size_limit(200, 200));
    EXPECT_FALSE(InputValidator::is_within_size_limit(201, 200));
}

TEST(InputValidatorTest, SafeParseJson) {
    std::string json_str = "{\"key\": \"value\", \"number\": 123}";
    auto val = InputValidator::safe_parse_json(json_str);
    EXPECT_TRUE(val.is_object());
    EXPECT_EQ(val.as_object()["key"].as_string(), "value");
    EXPECT_EQ(val.as_object()["number"].as_int64(), 123);
}

TEST(InputValidatorTest, SafeParseJsonInvalid) {
    EXPECT_THROW(InputValidator::safe_parse_json("{invalid}"), boost::system::system_error);
}
