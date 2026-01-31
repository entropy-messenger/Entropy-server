#include "pow_verifier.hpp"
#include "http_session.hpp"
#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "message_relay.hpp"
#include "rate_limiter.hpp"
#include "metrics.hpp"
#include "security_logger.hpp"
#include "input_validator.hpp"
#include <boost/json.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "input_validator.hpp"

namespace json = boost::json;

namespace entropy {

static bool validate_pow(const http::request<http::string_body>& req, RateLimiter& rate_limiter, const std::string& remote_addr, int target_difficulty = -1, const std::string& context = "") {
    auto seed_it = req.find("X-PoW-Seed");
    auto nonce_it = req.find("X-PoW-Nonce");
    
    if (seed_it == req.end() || nonce_it == req.end()) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Missing PoW headers");
        return false;
    }
    
    std::string seed(seed_it->value());
    std::string nonce(nonce_it->value());

    
    if (seed.length() != 64 || !InputValidator::is_valid_hex(seed, 64)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Invalid PoW seed format");
        return false;
    }
    
    if (nonce.length() > 32 || !std::all_of(nonce.begin(), nonce.end(), ::isdigit)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Invalid PoW nonce format");
        return false;
    }

    if (seed.empty() || !rate_limiter.consume_challenge(seed)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::REPLAY_ATTEMPT,
                          remote_addr, "Challenge seed already consumed or invalid");
        return false;
    }

    
    if (!::entropy::PoWVerifier::verify(seed, nonce, context, target_difficulty)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "PoW verification failed (incorrect solution or difficulty mismatch)");
        return false;
    }
    
    return true;
}


// HTTPS Session state (TLS transport)
HttpSession::HttpSession(
    beast::ssl_stream<beast::tcp_stream>&& stream,
    const ServerConfig& config,
    ConnectionManager& conn_manager,
    MessageRelay& relay,
    RateLimiter& rate_limiter,
    KeyStorage& key_storage,
    RedisManager& redis
)
    : stream_(std::move(stream))
    , is_tls_(true)
    , config_(config)
    , conn_manager_(conn_manager)
    , relay_(relay)
    , rate_limiter_(rate_limiter)
    , key_storage_(key_storage)
    , redis_(redis)
{
    try {
        auto& s = std::get<beast::ssl_stream<beast::tcp_stream>>(stream_);
        auto ep = beast::get_lowest_layer(s).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
}

// Plaintext HTTP Session state (usually behind a local proxy or for testing)
HttpSession::HttpSession(
    beast::tcp_stream&& stream,
    const ServerConfig& config,
    ConnectionManager& conn_manager,
    MessageRelay& relay,
    RateLimiter& rate_limiter,
    KeyStorage& key_storage,
    RedisManager& redis
)
    : stream_(std::move(stream))
    , is_tls_(false)
    , config_(config)
    , conn_manager_(conn_manager)
    , relay_(relay)
    , rate_limiter_(rate_limiter)
    , key_storage_(key_storage)
    , redis_(redis)
{
    try {
        auto& s = std::get<beast::tcp_stream>(stream_);
        auto ep = beast::get_lowest_layer(s).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
}

// Starts the asynchronous session activity
void HttpSession::run() {
    if (is_tls_) {
        // Perform SSL/TLS handshake before processing HTTP requests
        auto self = shared_from_this();
        std::get<beast::ssl_stream<beast::tcp_stream>>(stream_).async_handshake(
            ssl::stream_base::server,
            [self](beast::error_code ec) {
                self->on_handshake(ec);
            });
    } else {
        do_read();
    }
}

void HttpSession::on_handshake(beast::error_code ec) {
    if (ec) {
        // Silent closure on handshake failure to prevent resource exhaustion from scanners
        return;
    }
    do_read();
}

// Initiates the asynchronous read of an HTTP request
void HttpSession::do_read() {
    req_ = {};
    
    // Enforce connection timeout to prevent slow-loris attacks
    if (is_tls_) {
        beast::get_lowest_layer(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)).expires_after(
            std::chrono::seconds(60)); 
    } else {
        beast::get_lowest_layer(std::get<beast::tcp_stream>(stream_)).expires_after(
            std::chrono::seconds(60)); 
    }
    
    auto self = shared_from_this();
    parser_.emplace();
    parser_->body_limit(config_.max_message_size);

    if (is_tls_) {
        http::async_read(
            std::get<beast::ssl_stream<beast::tcp_stream>>(stream_),
            buffer_,
            *parser_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    } else {
        http::async_read(
            std::get<beast::tcp_stream>(stream_),
            buffer_,
            *parser_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    }
}

// Handles the completion of an asynchronous read operation
void HttpSession::on_read(beast::error_code ec, std::size_t  ) {
    if (ec == http::error::end_of_stream || ec) {
        return;
    }
    
    req_ = parser_->release();
    
    // Apply Global Token-Bucket Rate Limiting using the blinded IP as the identifier.
    std::string b_ip = blind_ip(remote_addr_);
    auto limit_res = rate_limiter_.check("global:" + b_ip, config_.global_rate_limit, 10);
    if (!limit_res.allowed) {
        send_response(handle_rate_limited(limit_res));
        return;
    }
    
    handle_request();
}

void HttpSession::handle_request() {
    
    // Check for WebSocket Upgrade
    if (websocket::is_upgrade(req_)) {
        upgrade_to_websocket();
        return;
    }
    
    auto target = req_.target();
    auto method = req_.method();
    
    // Handle CORS Preflight
    if (method == http::verb::options) {
        send_response(handle_cors_preflight());
        return;
    }
    
    // --- Routing Table ---

    // Health Checks & Metrics
    if (target == "/health" && method == http::verb::get) {
        send_response(handle_health());
    } else if (target == "/stats" && method == http::verb::get) {
        if (verify_admin_request()) {
            send_response(handle_stats());
        } else {
            send_response(handle_not_found());
        }
    } else if (target == "/metrics" && method == http::verb::get) {
        if (verify_admin_request()) {
            send_response(handle_metrics());
        } else {
            send_response(handle_not_found());
        }

    // Key Management APIs
    } else if (target.find("/keys/upload") == 0 && method == http::verb::post) {
        auto res = rate_limiter_.check("up:" + blind_ip(remote_addr_), config_.keys_upload_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_keys_upload());
    } else if (target.find("/keys/fetch") == 0 && method == http::verb::get) {
        auto res = rate_limiter_.check("fetch:" + blind_ip(remote_addr_), config_.keys_fetch_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_keys_fetch());
    } else if (target.find("/keys/random") == 0 && method == http::verb::get) {
        auto res = rate_limiter_.check("keys_rand:" + blind_ip(remote_addr_), config_.keys_random_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_keys_random());

    // Message Relay APIs (HTTP fallback)
    } else if (target.find("/relay") == 0 && target.find("/relay/multicast") == std::string::npos && method == http::verb::post) {
        auto res = rate_limiter_.check("relay:" + blind_ip(remote_addr_), config_.relay_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_relay());
    } else if (target.find("/relay/multicast") == 0 && method == http::verb::post) {
        send_response(handle_relay_multicast());

    // Proof-of-Work & Identity
    } else if (target.find("/pow/challenge") == 0 && method == http::verb::get) {
        auto res = rate_limiter_.check("pow_limit:" + blind_ip(remote_addr_), config_.pow_rate_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_pow_challenge());
    } else if (target.find("/nickname/register") == 0 && method == http::verb::post) {
        auto res = rate_limiter_.check("nick_reg:" + blind_ip(remote_addr_), config_.nick_register_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_nickname_register());
    } else if (target.find("/nickname/lookup") == 0 && method == http::verb::get) {
        auto res = rate_limiter_.check("nick_look:" + blind_ip(remote_addr_), config_.nick_lookup_limit, 60);
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_nickname_lookup());
    } else if (target.find("/account/burn") == 0 && method == http::verb::post) {
        auto res = rate_limiter_.check("burn:" + blind_ip(remote_addr_), config_.account_burn_limit, 300); 
        if (!res.allowed) send_response(handle_rate_limited(res));
        else send_response(handle_account_burn());

    } else {
        send_response(handle_not_found());
    }
}



// Basic health check to verify server availability and transport security status.
http::response<http::string_body> HttpSession::handle_health() {
    json::object response;
    response["status"] = "healthy";
    response["storage"] = "none";
    response["message"] = "Ephemeral relay only - no data stored";
    response["tls"] = config_.enable_tls;
    
    http::response<http::string_body> res{http::status::ok, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

// Returns high-level server statistics.
// Requires valid admin credentials/token as verified by verify_admin_request().
http::response<http::string_body> HttpSession::handle_stats() {
    json::object response;
    response["active_connections"] = static_cast<int64_t>(conn_manager_.connection_count());
    response["uptime_info"] = "Server stores ZERO messages";
    
    http::response<http::string_body> res{http::status::ok, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

// Exports Prometheus-formatted metrics for operational scrapers.
http::response<http::string_body> HttpSession::handle_metrics() {
    std::string body = MetricsRegistry::instance().collect_prometheus();
    
    http::response<http::string_body> res{http::status::ok, req_.version()};
    res.set(http::field::content_type, "text/plain; version=0.0.4");
    res.body() = body;
    res.prepare_payload();
    
    add_security_headers(res);
    
    return res;
}

// Processes identity bundle uploads (Public Keys).
// This requires a valid high-difficulty Proof-of-Work bound to the identity_hash
// to prevent identity-squatting and database exhaustion.
http::response<http::string_body> HttpSession::handle_keys_upload() {
    if (req_.body().size() > 64 * 1024) { 
        json::object error;
        error["error"] = "Payload too large";
        http::response<http::string_body> res{http::status::payload_too_large, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }

    try {
        auto json_val = InputValidator::safe_parse_json(req_.body());
        if (!json_val.is_object()) throw std::runtime_error("Not an object");
        
        auto& obj = json_val.as_object();
        
        // Enforce maximum number of pre-keys per identity to limit Redis memory footprint.
        if (obj.contains("preKeys") && obj["preKeys"].is_array()) {
            if (obj["preKeys"].as_array().size() > config_.max_prekeys_per_upload) {
                json::object error;
                error["error"] = "Too many pre-keys per upload (Max: " + std::to_string(config_.max_prekeys_per_upload) + ")";
                http::response<http::string_body> res{http::status::bad_request, req_.version()};
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(error);
                res.prepare_payload();
                add_security_headers(res);
                add_cors_headers(res);
                return res;
            }
        }

        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
             user_hash = std::string(obj["identity_hash"].as_string());
        }

        // Validate presence of required Post-Quantum cryptographic primitives.
        if (!obj.contains("pq_identityKey") || !obj.contains("signedPreKey") || !obj.at("signedPreKey").as_object().contains("pq_publicKey")) {
             json::object error;
             error["error"] = "Post-Quantum Handshake Keys Required";
             http::response<http::string_body> res{http::status::bad_request, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }
        
        if (!InputValidator::is_valid_hash(user_hash)) {
             json::object error;
             error["error"] = "Invalid identity_hash format";
             http::response<http::string_body> res{http::status::bad_request, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }

        // Verify Anti-Spam: Proof-of-Work MUST be cryptographically bound to the identity_hash.
        if (!validate_pow(req_, rate_limiter_, remote_addr_, -1, user_hash)) {
             SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                remote_addr_, "Keys upload rejected: invalid PoW or context binding");
             json::object error;
             error["error"] = "Invalid or Missing Proof-of-Work (Unbound)";
             http::response<http::string_body> res{http::status::unauthorized, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }

        // Cryptographic integrity check: Identity Hash MUST match the actual derived SHA256 of the identityKey.
        if (obj.contains("identityKey") && obj["identityKey"].is_string()) {
            std::string ik_b64 = std::string(obj["identityKey"].as_string());
            
            std::vector<unsigned char> decoded_key;
            decoded_key.resize(boost::beast::detail::base64::decoded_size(ik_b64.size()));
            auto result = boost::beast::detail::base64::decode(decoded_key.data(), ik_b64.c_str(), ik_b64.size());
            decoded_key.resize(result.first);
            
            if (result.first > 0) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(decoded_key.data(), decoded_key.size(), hash);
                std::stringstream ss;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                
                if (ss.str() != user_hash) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      remote_addr_, "Keys upload: identity_hash mismatch with identityKey");
                    json::object error;
                    error["error"] = "Cryptographic identity mismatch";
                    http::response<http::string_body> res{http::status::forbidden, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }

                // Verify self-signed bundle signature if provided
                if (!obj.contains("bundle_signature") || !obj["bundle_signature"].is_string()) {
                    json::object error;
                    error["error"] = "Bundle signature required for cryptographic ownership";
                    http::response<http::string_body> res{http::status::unauthorized, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }

                std::string sig_b64 = std::string(obj["bundle_signature"].as_string());
                std::vector<unsigned char> decoded_sig;
                decoded_sig.resize(boost::beast::detail::base64::decoded_size(sig_b64.size()));
                auto sig_res = boost::beast::detail::base64::decode(decoded_sig.data(), sig_b64.c_str(), sig_b64.size());
                decoded_sig.resize(sig_res.first);

                
                json::object sign_obj;
                sign_obj["identityKey"] = obj["identityKey"];
                sign_obj["pq_identityKey"] = obj["pq_identityKey"];
                sign_obj["signedPreKey"] = obj["signedPreKey"];
                sign_obj["preKeys"] = obj["preKeys"];
                
                std::string sign_data = json::serialize(sign_obj);
                std::vector<unsigned char> msg_vec(sign_data.begin(), sign_data.end());

                if (!InputValidator::verify_ed25519(decoded_key, msg_vec, decoded_sig)) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      remote_addr_, "Keys upload: Invalid bundle signature");
                    json::object error;
                    error["error"] = "Invalid bundle signature";
                    http::response<http::string_body> res{http::status::forbidden, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }
            }
        }
        
        
        
        if (!key_storage_.store_bundle(user_hash, req_.body())) {
             json::object error;
             error["error"] = "Storage Unavailable";
             http::response<http::string_body> res{http::status::service_unavailable, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }
        
        json::object response;
        response["status"] = "success";
        
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        
        add_security_headers(res);
        add_cors_headers(res);
        return res;
        
    } catch (...) {
        json::object error;
        error["error"] = "Invalid JSON";
        
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Retrieves identity bundles for one or more target users.
http::response<http::string_body> HttpSession::handle_keys_fetch() {
    std::string target = std::string(req_.target());
    std::string users_param;
    
    // Parse 'user' comma-separated list from query parameters
    size_t user_pos = target.find("user=");
    if (user_pos != std::string::npos) {
        users_param = std::string(target.substr(user_pos + 5));
        size_t amp_pos = users_param.find('&');
        if (amp_pos != std::string::npos) users_param = users_param.substr(0, amp_pos);
    }

    std::vector<std::string> user_hashes;
    std::stringstream ss(users_param);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty() && InputValidator::is_valid_hash(item)) {
            user_hashes.push_back(item);
        }
    }

    if (user_hashes.empty()) {
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.prepare_payload();
        return res;
    }

    // Limit batch size to prevent excessive resource consumption.
    if (user_hashes.size() > 10) user_hashes.resize(10);

    // Optimized single-user fetch
    if (user_hashes.size() == 1) {
        std::string bundle = key_storage_.get_bundle(user_hashes[0]);
        if (bundle.empty()) {
            http::response<http::string_body> res{http::status::not_found, req_.version()};
            res.prepare_payload();
            return res;
        }
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = bundle;
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    } else {
        // Multi-user batch fetch
        json::object results;
        for (const auto& h : user_hashes) {
            std::string b = key_storage_.get_bundle(h);
            if (!b.empty()) {
                try {
                    results[h] = InputValidator::safe_parse_json(b);
                } catch(...) {}
            }
        }
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(results);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Returns a set of random identity hashes for "Decoy Traffic" and "Anonymity Set" generation.
// This allows clients to initiate fake exchanges with random users to mask real activity.
http::response<http::string_body> HttpSession::handle_keys_random() {
    // Requires a basic PoW to prevent automated harvesting of the entire identity set.
    if (!validate_pow(req_, rate_limiter_, remote_addr_, 2)) {
        json::object error;
        error["error"] = "Proof-of-Work required for decoy discovery (Difficulty: 2)";
        http::response<http::string_body> res{http::status::unauthorized, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }

    std::string target = std::string(req_.target());
    int count = 5;
    
    size_t count_pos = target.find("count=");
    if (count_pos != std::string::npos) {
        try {
            std::string sub = target.substr(count_pos + 6);
            size_t amp = sub.find('&');
            if (amp != std::string::npos) sub = sub.substr(0, amp);
            count = std::stoi(sub);
        } catch(...) {}
    }

    if (count < 1) count = 1;
    if (count > 10) count = 10;

    auto hashes = redis_.get_random_user_hashes(count);
    json::array arr;
    for (const auto& h : hashes) arr.push_back(json::value(h));
    
    json::object response;
    response["hashes"] = arr;

    http::response<http::string_body> res{http::status::ok, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    add_security_headers(res);
    add_cors_headers(res);
    return res;
}

// Maps a human-readable nickname to a cryptographic identity hash.
// Requires high-difficulty PoW to prevent "Nickname Squatting".
// The registration process cryptographically binds the nickname to the identityKey
// by requiring a signature over the nickname using the identityKey.
http::response<http::string_body> HttpSession::handle_nickname_register() {
    try {
        auto json_val = InputValidator::safe_parse_json(req_.body());
        if (!json_val.is_object()) throw std::runtime_error("Not an object");
        auto& obj = json_val.as_object();
        
        std::string nickname;
        if (obj.contains("nickname") && obj["nickname"].is_string()) {
            nickname = std::string(obj["nickname"].as_string());
        }
        
        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
            user_hash = std::string(obj["identity_hash"].as_string());
        }
        
        // Basic syntax and length validation for nicknames.
        if (!InputValidator::is_valid_alphanumeric(nickname) || nickname.length() < 3 || nickname.length() > config_.max_nickname_length) {
            json::object error;
            error["error"] = "Invalid nickname: 3-" + std::to_string(config_.max_nickname_length) + " alphanumeric chars only";
            http::response<http::string_body> res{http::status::bad_request, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }

        if (!InputValidator::is_valid_hash(user_hash)) {
             json::object error;
             error["error"] = "Invalid identity_hash";
             http::response<http::string_body> res{http::status::bad_request, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }

        // Ownership Verification:
        // Ensures the requestor actually controls the identityKey corresponding to the user_hash.
        if (obj.contains("identityKey") && obj["identityKey"].is_string()) {
            std::string ik_b64 = std::string(obj["identityKey"].as_string());
            
            std::vector<unsigned char> decoded_key;
            decoded_key.resize(boost::beast::detail::base64::decoded_size(ik_b64.size()));
            auto result = boost::beast::detail::base64::decode(decoded_key.data(), ik_b64.c_str(), ik_b64.size());
            decoded_key.resize(result.first);
            if (result.first > 0) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(decoded_key.data(), decoded_key.size(), hash);
                std::stringstream ss;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                if (ss.str() != user_hash) {
                    json::object error;
                    error["error"] = "Cryptographic identity mismatch";
                    http::response<http::string_body> res{http::status::forbidden, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }

                if (!obj.contains("signature") || !obj["signature"].is_string()) {
                    json::object error;
                    error["error"] = "Ownership signature required";
                    http::response<http::string_body> res{http::status::unauthorized, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }

                std::string sig_b64 = std::string(obj.at("signature").as_string());
                std::vector<unsigned char> decoded_sig;
                decoded_sig.resize(boost::beast::detail::base64::decoded_size(sig_b64.size()));
                auto sig_res = boost::beast::detail::base64::decode(decoded_sig.data(), sig_b64.c_str(), sig_b64.size());
                decoded_sig.resize(sig_res.first);

                std::vector<unsigned char> msg_vec(nickname.begin(), nickname.end());
                if (!InputValidator::verify_ed25519(decoded_key, msg_vec, decoded_sig)) {
                    json::object error;
                    error["error"] = "Invalid ownership signature";
                    http::response<http::string_body> res{http::status::forbidden, req_.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }
            }
        } else {
             json::object error;
             error["error"] = "identityKey required for registration";
             http::response<http::string_body> res{http::status::bad_request, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }

        // Dynamic PoW Difficulty Scaling:
        // Difficulty increases if frequent registrations are detected from arbitrary IPs.
        int intensity_penalty = 0;
        int intensity = redis_.get_registration_intensity();
        if (intensity > 10) intensity_penalty = 2;
        if (intensity > 50) intensity_penalty = 4;
        if (intensity > 200) intensity_penalty = 8;
        
        long long age = redis_.get_account_age(user_hash);

        int required_difficulty = PoWVerifier::get_difficulty_for_nickname(nickname, intensity_penalty, age);
        if (!validate_pow(req_, rate_limiter_, remote_addr_, required_difficulty, nickname)) {
             json::object error;
             error["error"] = "Invalid or Missing Proof-of-Work (Target: " + std::to_string(required_difficulty) + ")";
             http::response<http::string_body> res{http::status::unauthorized, req_.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res);
             return res;
        }

        if (redis_.register_nickname(nickname, user_hash)) {
            json::object response;
            response["status"] = "success";
            response["nickname"] = nickname;
            http::response<http::string_body> res{http::status::ok, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(response);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        } else {
            json::object error;
            error["error"] = "Nickname already taken";
            http::response<http::string_body> res{http::status::conflict, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }
    } catch (...) {
        json::object error;
        error["error"] = "Invalid request";
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Resolves a human-readable nickname to its cryptographically bound identity hash.
http::response<http::string_body> HttpSession::handle_nickname_lookup() {
    std::string target = std::string(req_.target());
    std::string names_param;
    
    size_t name_pos = target.find("name=");
    if (name_pos != std::string::npos) {
        names_param = std::string(target.substr(name_pos + 5));
        size_t amp_pos = names_param.find('&');
        if (amp_pos != std::string::npos) names_param = names_param.substr(0, amp_pos);
    }

    std::vector<std::string> nicknames;
    {
        std::stringstream ss(names_param);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty()) nicknames.push_back(item);
        }
    }

    if (nicknames.empty()) {
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.prepare_payload();
        return res;
    }

    if (nicknames.size() > 10) nicknames.resize(10);

    if (nicknames.size() == 1) {
        std::string user_hash = redis_.resolve_nickname(nicknames[0]);
        if (user_hash.empty()) {
            http::response<http::string_body> res{http::status::not_found, req_.version()};
            res.prepare_payload();
            return res;
        }
        json::object response;
        response["identity_hash"] = user_hash;
        response["nickname"] = nicknames[0];
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    } else {
        json::object results;
        for (const auto& nick : nicknames) {
            std::string h = redis_.resolve_nickname(nick);
            if (!h.empty()) results[nick] = h;
        }
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(results);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Blinds an IP address using the server's secret salt.
// This is used for internal tracking and rate limiting without storing raw IP addresses,
// enhancing user privacy while maintaining operational security.
std::string HttpSession::blind_ip(const std::string& ip) {
    std::string data = ip + config_.secret_salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Relays a single message to a target recipient.
// Requires PoW bound to the recipient hash to prevent spam-flooding specific accounts.
http::response<http::string_body> HttpSession::handle_relay() {
    try {
        auto json_val = InputValidator::safe_parse_json(req_.body());
        auto& obj = json_val.as_object();
        
        std::string to_hash;
        if (obj.contains("to") && obj["to"].is_string()) {
            to_hash = std::string(obj["to"].as_string());
        }

        // Verify PoW is bound to the target 'to' recipient hash.
        if (!validate_pow(req_, rate_limiter_, remote_addr_, -1, to_hash)) {
            SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                               remote_addr_, "HTTP relay rejected: invalid PoW or context binding");
            json::object error;
            error["error"] = "Invalid or Missing Proof-of-Work (Unbound)";
            http::response<http::string_body> res{http::status::unauthorized, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }
        
        if (!InputValidator::is_valid_hash(to_hash)) {
            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                               remote_addr_, "HTTP relay: invalid recipient format");
            json::object error;
            error["error"] = "Invalid recipient format"; 
            http::response<http::string_body> res{http::status::bad_request, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }
        
        std::vector<std::string> recipients = {to_hash};
        relay_.relay_multicast(recipients, req_.body());
        
        json::object response;
        response["status"] = "relayed";
        
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
        
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::INVALID_INPUT,
                          remote_addr_, "HTTP relay: invalid request format");
        json::object error;
        error["error"] = "Invalid request format";
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Relays a single message to multiple recipients atomically.
// This is used for Group Messaging or Multi-Device synchronization.
// Requires PoW bound to a sorted fingerprint of all recipients.
http::response<http::string_body> HttpSession::handle_relay_multicast() {
    try {
        auto json_val = InputValidator::safe_parse_json(req_.body());
        auto& obj = json_val.as_object();
        
        std::string context_hint = "";
        std::vector<std::string> recipients;
        if (obj.contains("recipients") && obj["recipients"].is_array()) {
            for (const auto& r : obj["recipients"].as_array()) {
                if (r.is_string()) {
                    std::string h = std::string(r.as_string());
                    if (InputValidator::is_valid_hash(h)) {
                        recipients.push_back(h);
                    }
                }
            }
        }
        
        // Generate a deterministic context fingerprint for the recipient list.
        // This ensures a single PoW cannot be reused for different recipient sets.
        if (!recipients.empty()) {
            std::sort(recipients.begin(), recipients.end());
            std::string combined;
            for (const auto& r : recipients) combined += r;
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.size(), hash);
            std::stringstream ss;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
            context_hint = ss.str();
        }

        if (!validate_pow(req_, rate_limiter_, remote_addr_, -1, context_hint)) {
            SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                               remote_addr_, "Multicast relay rejected: invalid PoW or unbound context fingerprint");
            json::object error;
            error["error"] = "Invalid or Missing Proof-of-Work (Unbound)";
            http::response<http::string_body> res{http::status::unauthorized, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }
        
        if (recipients.empty() || recipients.size() > 100) {
            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                               remote_addr_, "Multicast: invalid or empty recipient list");
            json::object error;
            error["error"] = "Invalid recipient count";
            http::response<http::string_body> res{http::status::bad_request, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }
        
        // Multicast operations have higher rate-limiting 'cost' relative to number of recipients.
        int cost = static_cast<int>(recipients.size());
        auto limit_res = rate_limiter_.check("relay_multi:" + blind_ip(remote_addr_), 300, 60, cost);
        if (!limit_res.allowed) {
            return handle_rate_limited(limit_res);
        }

        json::object forward_obj;
        if (obj.contains("envelope")) forward_obj["envelope"] = obj["envelope"];
        if (obj.contains("ephemeralPub")) forward_obj["ephemeralPub"] = obj["ephemeralPub"];
        if (obj.contains("nonce")) forward_obj["nonce"] = obj["nonce"];
        forward_obj["type"] = "sealed_message"; 
        
        std::string forward_body = json::serialize(forward_obj);
        
        relay_.relay_multicast(recipients, forward_body);
        
        json::object response;
        response["status"] = "multicast_relayed";
        response["count"] = recipients.size();
        
        http::response<http::string_body> res{http::status::ok, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
        
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::INVALID_INPUT,
                          remote_addr_, "Multicast relay: invalid request format");
        json::object error;
        error["error"] = "Invalid request format";
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

http::response<http::string_body> HttpSession::handle_cors_preflight() {
    http::response<http::string_body> res{http::status::no_content, req_.version()};
    add_cors_headers(res);
    res.prepare_payload();
    return res;
}

http::response<http::string_body> HttpSession::handle_not_found() {
    json::object response;
    response["error"] = "Not Found";
    
    http::response<http::string_body> res{http::status::not_found, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

http::response<http::string_body> HttpSession::handle_rate_limited(const RateLimitResult& res_info) {
    json::object response;
    response["error"] = "Rate limit exceeded";
    response["retry_after"] = res_info.reset_after_sec;
    response["limit"] = res_info.limit;
    
    http::response<http::string_body> res{http::status::too_many_requests, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::retry_after, std::to_string(res_info.reset_after_sec));
    
    
    res.set("X-RateLimit-Limit", std::to_string(res_info.limit));
    res.set("X-RateLimit-Remaining", "0");
    res.set("X-RateLimit-Reset", std::to_string(std::time(nullptr) + res_info.reset_after_sec));
    
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    if (res_info.reset_after_sec >= 60) {
        res.keep_alive(false);
    }
    
    add_security_headers(res);
    add_cors_headers(res); 
    
    return res;
}

http::response<http::string_body> HttpSession::handle_pow_challenge() {
    std::string seed = rate_limiter_.issue_challenge(60); 
    
    std::string target = std::string(req_.target());
    
    int intensity_penalty = 0;
    int intensity = redis_.get_registration_intensity();
    if (intensity > 10) intensity_penalty = 2;
    if (intensity > 50) intensity_penalty = 4;
    if (intensity > 200) intensity_penalty = 8;

    
    long long age = 0;
    size_t hash_pos = target.find("identity_hash=");
    if (hash_pos != std::string::npos) {
        std::string id_hash = std::string(target.substr(hash_pos + 14));
        size_t amp_pos = id_hash.find('&');
        if (amp_pos != std::string::npos) id_hash = id_hash.substr(0, amp_pos);
        if (!id_hash.empty()) age = redis_.get_account_age(id_hash);
    }

    int difficulty = PoWVerifier::get_required_difficulty(intensity_penalty, age);

    
    size_t nick_pos = target.find("nickname=");
    if (nick_pos != std::string::npos) {
        std::string nick = std::string(target.substr(nick_pos + 9));
        size_t amp_pos = nick.find('&');
        if (amp_pos != std::string::npos) nick = nick.substr(0, amp_pos);
        if (!nick.empty()) difficulty = PoWVerifier::get_difficulty_for_nickname(nick, intensity_penalty, age);
    }


    
    json::object response;
    response["seed"] = seed;
    response["difficulty"] = difficulty;

    
    http::response<http::string_body> res{http::status::ok, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

template<class Body>
void HttpSession::add_security_headers(http::response<Body>& res) {
    res.set(http::field::server, "Entropy/2.0");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "DENY");
    res.set("X-XSS-Protection", "1; mode=block");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    res.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    
    if (config_.enable_tls) {
        res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
}

template<class Body>
void HttpSession::add_cors_headers(http::response<Body>& res) {
    std::string origin;
    auto origin_it = req_.find(http::field::origin);
    if (origin_it != req_.end()) {
        origin = std::string(origin_it->value());
    }
    
    if (!config_.allowed_origins.empty()) {
        bool origin_allowed = false;
        for (const auto& allowed : config_.allowed_origins) {
            if (allowed == "*" || allowed == origin) {
                origin_allowed = true;
                if (allowed == "*" && !origin.empty()) {
                    res.set(http::field::access_control_allow_origin, origin);
                } else {
                    res.set(http::field::access_control_allow_origin, allowed);
                }
                break;
            }
        }
        
        if (origin_allowed) {
            res.set(http::field::access_control_allow_credentials, "true");
        } else if (!origin.empty()) {
            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                               remote_addr_, "Disallowed origin: " + origin);
        }
    } 
    
    
    if (!res.count(http::field::access_control_allow_origin) && !origin.empty()) {
        if (origin.find("localhost") != std::string::npos || 
            origin.find("tauri://") != std::string::npos || 
            origin.find("127.0.0.1") != std::string::npos) {
            res.set(http::field::access_control_allow_origin, origin);
            res.set(http::field::access_control_allow_credentials, "true");
        }
    }
    
    res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
    res.set(http::field::access_control_allow_headers, "Content-Type,Authorization,X-PoW-Seed,X-PoW-Nonce,x-pow-seed,x-pow-nonce,X-Admin-Token");
    res.set(http::field::access_control_max_age, "86400");
    res.set(http::field::vary, "Origin");
}

void HttpSession::send_response(http::response<http::string_body>&& res) {
    auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
    
    auto self = shared_from_this();
    
    if (is_tls_) {
        http::async_write(
            std::get<beast::ssl_stream<beast::tcp_stream>>(stream_),
            *sp,
            [self, sp](beast::error_code ec, std::size_t bytes) {
                self->on_write(sp->need_eof(), ec, bytes);
            });
    } else {
        http::async_write(
            std::get<beast::tcp_stream>(stream_),
            *sp,
            [self, sp](beast::error_code ec, std::size_t bytes) {
                self->on_write(sp->need_eof(), ec, bytes);
            });
    }
}

void HttpSession::on_write(bool close, beast::error_code ec, std::size_t  ) {
    if (ec) {
        std::cerr << "[!] HTTP write error: " << ec.message() << "\n";
        return;
    }
    
    if (close) {
        
        if (is_tls_) {
            beast::get_lowest_layer(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)).socket().shutdown(
                tcp::socket::shutdown_send, ec);
        } else {
            beast::get_lowest_layer(std::get<beast::tcp_stream>(stream_)).socket().shutdown(
                tcp::socket::shutdown_send, ec);
        }
        return;
    }
    
    
    do_read();
}

// Authoritatively purges all data associated with an identity hash.
// This is a "Forensic Burn": it removes the public key bundle and any associated nicknames
// from the persistent storage to ensure forward secrecy and user right-to-erasure.
// Requires a high-difficulty PoW and a cryptographic signature to prove ownership.
http::response<http::string_body> HttpSession::handle_account_burn() {
    try {
        auto json_val = InputValidator::safe_parse_json(req_.body());
        if (!json_val.is_object()) throw std::runtime_error("Invalid payload");
        auto& obj = json_val.as_object();
        
        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
            user_hash = std::string(obj["identity_hash"].as_string());
        }

        // Verify high-difficulty Proof-of-Work to prevent mass-exhaustion of the burn API.
        if (!validate_pow(req_, rate_limiter_, remote_addr_, 5, user_hash)) { 
            json::object error;
            error["error"] = "Invalid PoW for burn request";
            http::response<http::string_body> res{http::status::unauthorized, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }

        // Cryptographic proof of ownership:
        // Requires a signature over "BURN:<user_hash>" using the identity's Ed25519 private key.
        if (obj.contains("identityKey") && obj["identityKey"].is_string()) {
            std::string ik_b64 = std::string(obj["identityKey"].as_string());
            
            std::vector<unsigned char> decoded_key;
            decoded_key.resize(boost::beast::detail::base64::decoded_size(ik_b64.size()));
            auto result = boost::beast::detail::base64::decode(decoded_key.data(), ik_b64.c_str(), ik_b64.size());
            decoded_key.resize(result.first);

            if (result.first > 0) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(decoded_key.data(), decoded_key.size(), hash);
                std::stringstream ss;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                if (ss.str() != user_hash) {
                    http::response<http::string_body> res{http::status::forbidden, req_.version()};
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res);
                    return res;
                }

                if (!obj.contains("signature") || !obj["signature"].is_string()) throw std::runtime_error("Signature missing");
                
                std::string sig_b64 = std::string(obj.at("signature").as_string());
                std::vector<unsigned char> decoded_sig;
                decoded_sig.resize(boost::beast::detail::base64::decoded_size(sig_b64.size()));
                auto sig_res = boost::beast::detail::base64::decode(decoded_sig.data(), sig_b64.c_str(), sig_b64.size());
                decoded_sig.resize(sig_res.first);

                std::string msg = "BURN:" + user_hash;
                std::vector<unsigned char> msg_vec(msg.begin(), msg.end());
                if (!InputValidator::verify_ed25519(decoded_key, msg_vec, decoded_sig)) {
                      throw std::runtime_error("Invalid signature");
                }
            }
        } else {
            throw std::runtime_error("identityKey required");
        }

        // Atomically remove all metadata from Redis and disk.
        if (redis_.burn_account(user_hash)) {
            SecurityLogger::log(SecurityLogger::Level::CRITICAL, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                               remote_addr_, "Account burned and purged: " + user_hash);
            json::object ok;
            ok["status"] = "account_purged";
            http::response<http::string_body> res{http::status::ok, req_.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(ok);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res);
            return res;
        }

        http::response<http::string_body> res{http::status::internal_server_error, req_.version()};
        res.prepare_payload();
        return res;
    } catch (const std::exception& e) {
        json::object error;
        error["error"] = e.what();
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    } catch (...) {
        http::response<http::string_body> res{http::status::bad_request, req_.version()};
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res);
        return res;
    }
}

// Transitions the HTTP session to a long-lived WebSocket session.
// This involves moving ownership of the underlying TCP/SSL stream.
void HttpSession::upgrade_to_websocket() {
    std::shared_ptr<WebSocketSession> ws_session;
    
    // Create appropriate session based on transport security (TLS vs Plaintext)
    if (is_tls_) {
        ws_session = std::make_shared<WebSocketSession>(
            std::move(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)),
            conn_manager_,
            config_
        );
    } else {
         ws_session = std::make_shared<WebSocketSession>(
            std::move(std::get<beast::tcp_stream>(stream_)),
            conn_manager_,
            config_
        );
    }
    
    
    MessageRelay* relay_ptr = &relay_;
    ConnectionManager* conn_mgr_ptr = &conn_manager_;
    RateLimiter* rate_limiter_ptr = &rate_limiter_;
    RedisManager* redis_ptr = &redis_;
    
    
    size_t max_conns = config_.max_connections_per_ip;
    size_t max_msg_size = 5 * 1024 * 1024; 

    ws_session->set_message_handler(
        [relay_ptr, conn_mgr_ptr, rate_limiter_ptr, redis_ptr, key_storage_ptr = &key_storage_, max_conns, max_msg_size](
            std::shared_ptr<WebSocketSession> session,
            const std::string& data,
            bool is_binary
        ) {
            auto b_ip = conn_mgr_ptr->blind_id(session->remote_address());
            int max_msgs = session->is_authenticated() ? 200 : 10;
            auto limit_res = rate_limiter_ptr->check("ws_msg:" + b_ip, max_msgs, 10);
            if (!limit_res.allowed) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT,
                                  session->remote_address(), "WebSocket rate limit exceeded");
                session->close();
                return;
            }

            if (data.size() > max_msg_size) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                                  session->remote_address(), "Message exceeds size limit");
                session->close();
                return;
            }
            
            if (is_binary) {
                if (!session->is_challenge_solved()) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      session->remote_address(), "Unauthenticated binary relay attempt");
                    session->close();
                    return;
                }
                
                if (data.size() > 64) {
                    std::string recipient = data.substr(0, 64);
                    relay_ptr->relay_binary(
                        recipient,
                        data.data() + 64,
                        data.size() - 64,
                        session
                    );
                }
                return;
            }
            
            
            try {
                auto json_val = InputValidator::safe_parse_json(data);
                if (!json_val.is_object()) {
                    SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                                      session->remote_address(), "Invalid JSON structure");
                    return;
                }
                
                auto& obj = json_val.as_object();
                std::string type;
                if (obj.contains("type")) {
                    type = std::string(obj["type"].as_string());
                }
                
                
                if (type == "ping") {
                    json::object pong;
                    pong["type"] = "pong";
                    if (obj.contains("timestamp")) pong["timestamp"] = obj["timestamp"];
                    MessageRelay::pad_json(pong, 1536);
                    session->send_text(json::serialize(pong));
                    return;
                }

                if (type == "dummy") {
                    return; 
                }

                if (type == "auth") {
                    if (obj.contains("payload")) {
                        auto& auth_payload = obj["payload"].as_object();
                        
                        std::string id_hash;
                        if (auth_payload.contains("identity_hash")) id_hash = std::string(auth_payload["identity_hash"].as_string());
                        std::string hash = MessageRelay::sanitize_field(id_hash, 256);

                        bool auth_valid = false;

                        
                        if (auth_payload.contains("session_token") && auth_payload["session_token"].is_string()) {
                            std::string token = std::string(auth_payload["session_token"].as_string());
                            if (redis_ptr->verify_session_token(hash, token)) {
                                auth_valid = true;
                            }
                        }

                        
                        if (!auth_valid) {
                            std::string seed;
                            if (auth_payload.contains("seed") && auth_payload["seed"].is_string()) 
                                seed = std::string(auth_payload["seed"].as_string());
                            
                            std::string nonce;
                            if (auth_payload.contains("nonce")) {
                                if (auth_payload["nonce"].is_string()) nonce = std::string(auth_payload["nonce"].as_string());
                                else if (auth_payload["nonce"].is_number()) nonce = std::to_string(auth_payload["nonce"].as_int64());
                            }
                            
                            
                            if (!seed.empty() && !nonce.empty() && rate_limiter_ptr->consume_challenge(seed) && 
                                ::entropy::PoWVerifier::verify(seed, nonce, hash)) {
                                auth_valid = true;
                            }
                        }

                        if (!auth_valid || hash.empty()) {
                             SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                               session->remote_address(), "Authentication failed");
                             
                             json::object error;
                             error["type"] = "error";
                             error["code"] = "auth_failed";
                             error["message"] = "Authentication failed. Token may be expired.";
                             MessageRelay::pad_json(error, 1536);
                             session->send_text(json::serialize(error));
                             
                             session->close();
                             return;
                        }
                      
                        if (!conn_mgr_ptr->add_connection_with_limit(hash, session, session->remote_address(), max_conns)) {
                            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT,
                                              session->remote_address(), "Connection limit exceeded for IP");
                            json::object error;
                            error["type"] = "error";
                            error["code"] = "connection_limit";
                            error["message"] = "Too many connections from your IP address";
                            MessageRelay::pad_json(error, 1536);
                            session->send_text(json::serialize(error));
                            session->close();
                            return;
                        }
                        
                        session->set_user_data(hash);
                        session->set_challenge_solved(true);
                        
                        relay_ptr->subscribe_user(hash);
                        
                        SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                                          session->remote_address(), "User authenticated");

                        
                        std::string new_token = redis_ptr->create_session_token(hash, 3600);

                        json::object response;
                        response["type"] = "auth_success";
                        response["identity_hash"] = hash;
                        if (!new_token.empty()) response["session_token"] = new_token;
                        
                        
                        response["keys_missing"] = key_storage_ptr->get_bundle(hash).empty();
                        
                        MessageRelay::pad_json(response, 1536);
                        session->send_text(json::serialize(response));
                        
                        relay_ptr->deliver_pending(hash, session);
                    }
                    return;
                }

                if (!session->is_challenge_solved()) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      session->remote_address(), "Unauthenticated message attempt: " + type);
                    session->close();
                    return;
                }

                if (type == "ack") {
                    if (obj.contains("ids") && obj["ids"].is_array()) {
                        std::vector<int64_t> ids;
                        for (const auto& id_val : obj["ids"].as_array()) {
                            if (id_val.is_int64()) {
                                ids.push_back(id_val.as_int64());
                            }
                        }
                        relay_ptr->confirm_delivery(ids);
                    }
                    return;
                }

                if (type == "subscribe_alias") {
                    if (obj.contains("payload")) {
                        try {
                            auto& alias_payload = obj["payload"].as_object();
                            std::string seed;
                            if (alias_payload.contains("seed") && alias_payload["seed"].is_string()) 
                                seed = std::string(alias_payload["seed"].as_string());
                            
                            std::string nonce;
                            if (alias_payload.contains("nonce")) {
                                if (alias_payload["nonce"].is_string()) nonce = std::string(alias_payload["nonce"].as_string());
                                else if (alias_payload["nonce"].is_number()) nonce = std::to_string(alias_payload["nonce"].as_int64());
                            }

                            
                            if (alias_payload.contains("alias") && alias_payload["alias"].is_string()) {
                                std::string alias = std::string(alias_payload["alias"].as_string());
                                std::string safe_alias = MessageRelay::sanitize_field(alias, 256);

                                if (seed.empty() || nonce.empty() || !rate_limiter_ptr->consume_challenge(seed) || 
                                    !::entropy::PoWVerifier::verify(seed, nonce, safe_alias)) {
                                     SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::AUTH_FAILURE,
                                                       session->remote_address(), "Alias subscription PoW invalid or unbound: " + safe_alias);
                                     session->close();
                                     return;
                                }

                                if (!safe_alias.empty() && session->can_add_alias()) {
                                    session->add_alias(safe_alias);
                                    conn_mgr_ptr->add_connection(safe_alias, session);
                                    relay_ptr->subscribe_user(safe_alias);
                                    relay_ptr->deliver_pending(safe_alias, session);
                                    
                                    json::object response;
                                    response["type"] = "alias_subscribed";
                                    response["alias"] = safe_alias;
                                    MessageRelay::pad_json(response, 1536);
                                    session->send_text(json::serialize(response));
                                } else if (!safe_alias.empty()) {
                                    json::object error;
                                    error["type"] = "error";
                                    error["message"] = "Maximum alias limit reached";
                                    session->send_text(json::serialize(error));
                                }
                            }
                        } catch (...) {}
                    }
                    return;
                }

                if (type == "volatile_relay") {
                    if (obj.contains("to") && obj.contains("body")) {
                        std::string to = std::string(obj["to"].as_string());
                        std::string body = std::string(obj["body"].as_string());
                        
                        relay_ptr->relay_volatile(to, body.data(), body.size());
                    }
                    return;
                }

                if (type == "group_multicast") {
                    if (!session->is_authenticated()) {
                        json::object err;
                        err["type"] = "error";
                        err["message"] = "Authentication required for multicast";
                        session->send_text(json::serialize(err));
                        return;
                    }
                    if (obj.contains("targets") && obj["targets"].is_array()) {
                        auto& targets = obj["targets"].as_array();
                        int cost = static_cast<int>(targets.size());
                        auto limit_res = rate_limiter_ptr->check("ws_multi:" + b_ip, 500, 60, cost);
                        
                        if (!limit_res.allowed) {
                            json::object err;
                            err["type"] = "error";
                            err["code"] = "rate_limit";
                            err["message"] = "Multicast rate limit exceeded";
                            session->send_text(json::serialize(err));
                            return;
                        }
                        
                        relay_ptr->relay_group_message(targets, session);
                    }
                    return;
                }

                relay_ptr->relay_message(data, session);
                
            } catch (const std::exception& e) {
                std::cerr << "[!] Error processing message: " << e.what() << "\n";
            }
        });
    
    
    ws_session->set_close_handler(
        [conn_mgr_ptr, relay_ptr](WebSocketSession* session) {
            std::string user_data = session->get_user_data();
            if (!user_data.empty()) {
                relay_ptr->unsubscribe_user(user_data);
            }
            for (const auto& alias : session->get_aliases()) {
                relay_ptr->unsubscribe_user(alias);
            }
            conn_mgr_ptr->remove_session(session);
            std::cout << "[*] WebSocket connection closed\n";
        });
    
    
    
    parser_.reset();
    
    ws_session->accept(
        std::move(req_),
        std::move(buffer_),
        [ws_session](beast::error_code ec) {
            if (ec) {
                std::cerr << "[!] WebSocket accept error: " << ec.message() << "\n";
                return;
            }
            std::cout << "[+] WebSocket accepted successfully\n";
            
            ws_session->run();
        });
}


template void ::entropy::HttpSession::add_security_headers(http::response<http::string_body>&);
template void ::entropy::HttpSession::add_cors_headers(http::response<http::string_body>&);

bool HttpSession::verify_admin_request() {
    
    if (remote_addr_ == "127.0.0.1" || remote_addr_ == "::1") {
        return true;
    }

    
    if (config_.admin_token.empty()) {
        return false;
    }

    auto auth_it = req_.find("X-Admin-Token");
    if (auth_it == req_.end()) {
        return false;
    }

    
    std::string provided_token(auth_it->value());
    return provided_token == config_.admin_token;
}

} 
    