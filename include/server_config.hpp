#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace entropy {

 
// Core server configuration and security policy definitions.
struct ServerConfig {
    // --- Network & Infrastructure ---
    std::string address = "0.0.0.0";
    uint16_t port = 8080;
    std::string redis_url = "tcp://127.0.0.1:6379";
    std::string redis_password = "";
    std::string redis_username = "";
    int thread_count = 0;  // 0 defaults to hardware concurrency
    
    // --- Transport Layer Security (TLS) ---
    bool enable_tls = false;
    std::string cert_path = "certs/server.crt";
    std::string key_path = "certs/server.key";
    
    // --- Connection & Resource Management ---
    size_t max_message_size = 1024 * 1024;  // 1MB
    size_t max_connections_per_ip = 10;
    size_t max_global_connections = 100000;
    int connection_timeout_sec = 60;
    int websocket_ping_interval_sec = 15;
    
    // --- Global Rate Limiting (Token Bucket) ---
    double rate_limit_per_sec = 100.0;
    size_t rate_limit_burst = 200;
    
    // Anti-Spam (Proof-of-Work) limit
    int pow_rate_limit = 20; 
    
    // --- Per-Endpoint API Limits (Requests per window, managed by Redis) ---
    int global_rate_limit = 120; // Default window: 10s
    int keys_upload_limit = 5;   // Window: 60s
    int keys_fetch_limit = 20;   // Window: 60s
    int keys_random_limit = 10;  // Window: 60s
    int relay_limit = 30;        // Window: 60s
    int nick_register_limit = 5; // Window: 60s
    int nick_lookup_limit = 30;  // Window: 60s
    int account_burn_limit = 3;  // Window: 300s

    // --- Identity & Secrets ---
    std::string secret_salt = "entropy_default_deployment_salt"; // MUST be overridden via ENV in production
    std::string admin_token = ""; // Used for privileged stats/metrics access
    
    // --- Cross-Origin Resource Sharing (CORS) ---
    std::vector<std::string> allowed_origins = {};
    std::vector<std::string> allowed_methods = {"GET", "POST", "OPTIONS"};
    std::vector<std::string> allowed_headers = {"Content-Type", "Authorization"};
    
    // --- Protocol Constraints ---
    size_t max_nickname_length = 32;
    size_t max_prekeys_per_upload = 100;
    int max_pow_difficulty = 5; 
    size_t max_json_depth = 16;

    // --- Traffic Normalization Configuration (Pacing) ---
    struct Pacing {
        static constexpr int idle_threshold_ms = 5000;
        static constexpr size_t packet_size = 1024;
        static constexpr int tick_interval_ms = 500;
    } pacing;
};

} 
