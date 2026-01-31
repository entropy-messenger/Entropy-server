#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace entropy {

// Logs security events using blinded IP identifiers (salted hash).
class SecurityLogger {
public:
    enum class Level {
        INFO,
        WARNING,
        ERROR,
        CRITICAL
    };
    
    enum class EventType {
        AUTH_SUCCESS,
        AUTH_FAILURE,
        RATE_LIMIT_HIT,
        INVALID_INPUT,
        POW_FAILURE,
        REPLAY_ATTEMPT,
        SUSPICIOUS_ACTIVITY,
        CONNECTION_REJECTED
    };
    
    /**
     * Records a security-relevant event with blinded identifiers.
     * @param level Severity level of the event.
     * @param event The specific type of security event.
     * @param remote_addr The source IP address (will be blinded before logging).
     * @param message Optional descriptive message (will be sanitized).
     */
    static void log(Level level, EventType event, const std::string& remote_addr, 
                   const std::string& message = "") {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        struct tm gmt;
        gmtime_r(&time_t, &gmt);
        
        std::stringstream ss;
        ss << "[" << std::put_time(&gmt, "%Y-%m-%d %H:%M:%S") << " UTC] "
           << "[" << level_to_string(level) << "] "
           << "[" << event_to_string(event) << "] ";
        
        // Salt Rotation Logic:
        // A random salt is generated and rotated every 6 hours.
        // This ensures Forward Secrecy for logs: even if a future salt is compromised,
        // past IP-to-Hash mappings cannot be reversed.
        static std::string log_salt;
        static std::chrono::steady_clock::time_point last_rotation;
        
        auto now_steady = std::chrono::steady_clock::now();
        if (log_salt.empty() || std::chrono::duration_cast<std::chrono::hours>(now_steady - last_rotation).count() >= 6) {
            unsigned char b[32];
            if (RAND_bytes(b, 32) != 1) {
                std::cerr << "[CRITICAL] CSPRNG failure in SecurityLogger. Terminating instance for safety.\n";
                std::terminate(); 
            }
            std::stringstream salt_ss;
            for(int i=0; i<32; i++) salt_ss << std::hex << std::setw(2) << std::setfill('0') << (int)b[i];
            log_salt = salt_ss.str();
            last_rotation = now_steady;
            
            std::cout << "[" << std::put_time(&gmt, "%Y-%m-%d %H:%M:%S") << " UTC] [INFO] [SECURITY] msg=\"IP blinding salt rotated for log forward secrecy\"\n";
        }
        
        // Blind the IP address using the current session salt
        std::string hidden_ip = remote_addr;
        if (remote_addr != "unknown") {
            std::string data = remote_addr + log_salt;
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
            
            std::stringstream hs;
            for(int i = 0; i < 6; i++) hs << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            hidden_ip = "anon_" + hs.str();
        }
        ss << "ip=" << hidden_ip;
        
        if (!message.empty()) {
            ss << " msg=\"" << sanitize_log_message(message) << "\"";
        }
        
        // Log to appropriate destination based on severity
        if (level == Level::ERROR || level == Level::CRITICAL) {
            std::cerr << ss.str() << "\n";
        } else {
            std::cout << ss.str() << "\n";
        }
    }
    
private:
    static std::string level_to_string(Level level) {
        switch (level) {
            case Level::INFO: return "INFO";
            case Level::WARNING: return "WARN";
            case Level::ERROR: return "ERROR";
            case Level::CRITICAL: return "CRIT";
            default: return "UNKNOWN";
        }
    }
    
    static std::string event_to_string(EventType event) {
        switch (event) {
            case EventType::AUTH_SUCCESS: return "AUTH_SUCCESS";
            case EventType::AUTH_FAILURE: return "AUTH_FAILURE";
            case EventType::RATE_LIMIT_HIT: return "RATE_LIMIT";
            case EventType::INVALID_INPUT: return "INVALID_INPUT";
            case EventType::POW_FAILURE: return "POW_FAILURE";
            case EventType::REPLAY_ATTEMPT: return "REPLAY_ATTEMPT";
            case EventType::SUSPICIOUS_ACTIVITY: return "SUSPICIOUS";
            case EventType::CONNECTION_REJECTED: return "CONN_REJECTED";
            default: return "UNKNOWN_EVENT";
        }
    }
    
    // Escapes non-printable characters and quotes to ensure log integrity
    static std::string sanitize_log_message(const std::string& msg) {
        std::string result;
        result.reserve(msg.size());
        for (char c : msg) {
            if (c == '"' || c == '\\' || c == '\n' || c == '\r') {
                result += ' ';
            } else if (std::isprint(static_cast<unsigned char>(c))) {
                result += c;
            }
        }
        return result;
    }
};

}
