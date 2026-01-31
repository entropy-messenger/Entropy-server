#include <gtest/gtest.h>
#include "input_validator.hpp"
#include <string>
#include <vector>
#include <random>

using namespace entropy;

TEST(FuzzTest, JsonParserHardening) {
    
    std::vector<std::string> malicious_inputs = {
        "{", 
        "}", 
        "[", 
        "]",
        "{\"a\":", 
        "{\"a\":}", 
        "{\"a\":[]}",
        "{\"a\":" + std::string(1000, 'a') + "}", 
        "{\"a\":" + std::string(1000, '[') + std::string(1000, ']') + "}", 
        "null",
        "true",
        "123",
        "\"string\"",
        "",
        "\0",
        "{\"\\u0000\": \"\\u0000\"}", 
        "{\"a\": 1e1000}", 
    };
    
    for (const auto& input : malicious_inputs) {
        try {
            
            
            InputValidator::safe_parse_json(input);
        } catch (...) {
            
        }
    }
    SUCCEED();
}

TEST(FuzzTest, FieldSanitization) {
    
    std::string input = "";
    for (int i = 0; i < 256; ++i) {
        input += static_cast<char>(i);
    }
    
    
    
    
    
    
    for (char c : input) {
        InputValidator::is_valid_alphanumeric(std::string(1, c));
    }
    SUCCEED();
}
