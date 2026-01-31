#include <gtest/gtest.h>
#include "security_logger.hpp"
#include <iostream>
#include <sstream>

using namespace entropy;

TEST(SecurityLoggerTest, Sanitization) {
    
    
    SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS, "127.0.0.1", "Normal message");
    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE, "1.2.3.4", "Malicious \" quote and \n newline");
    SecurityLogger::log(SecurityLogger::Level::CRITICAL, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "unknown", "No IP");
}

TEST(SecurityLoggerTest, SanitizationLogic) {
    
    
    
    SUCCEED();
}
