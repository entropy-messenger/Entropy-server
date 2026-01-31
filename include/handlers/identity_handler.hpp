#pragma once

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <string>
#include "server_config.hpp"
#include "connection_manager.hpp"
#include "metrics.hpp"
#include "key_storage.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;

namespace entropy {

class IdentityHandler {
public:
    IdentityHandler(const ServerConfig& config, 
                    KeyStorage& key_storage, 
                    RedisManager& redis,
                    RateLimiter& rate_limiter)
        : config_(config)
        , key_storage_(key_storage)
        , redis_(redis)
        , rate_limiter_(rate_limiter) {}

    http::response<http::string_body> handle_keys_upload(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_keys_fetch(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_keys_random(const http::request<http::string_body>& req, const std::string& remote_addr);
    
    http::response<http::string_body> handle_nickname_register(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_nickname_lookup(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_account_burn(const http::request<http::string_body>& req, const std::string& remote_addr);
    
    http::response<http::string_body> handle_pow_challenge(const http::request<http::string_body>& req, const std::string& remote_addr);

private:
    const ServerConfig& config_;
    KeyStorage& key_storage_;
    RedisManager& redis_;
    RateLimiter& rate_limiter_;
    
    std::string blind_ip(const std::string& ip, const std::string& salt);
    bool validate_pow(const http::request<http::string_body>& req, RateLimiter& rate_limiter, const std::string& remote_addr, int target_difficulty = -1, const std::string& context = "");

    template<class Body>
    void add_security_headers(http::response<Body>& res) {
        res.set("X-Content-Type-Options", "nosniff");
        res.set("X-Frame-Options", "DENY");
        res.set("Content-Security-Policy", "default-src 'none'");
    }
    
    template<class Body>
    void add_cors_headers(http::response<Body>& res) {
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type, X-PoW-Seed, X-PoW-Nonce");
    }
    
    http::response<http::string_body> handle_rate_limited(const RateLimitResult& res_info, unsigned version);
};

} // namespace entropy
