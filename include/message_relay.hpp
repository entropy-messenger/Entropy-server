#pragma once

#include <string>
#include <vector>
#include <memory>
#include <boost/json.hpp>
#include "connection_manager.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"

namespace json = boost::json;

namespace entropy {

class WebSocketSession;

 
// Core Message Routing and Traffic Normalization Engine.
// Handles message distribution between local sessions and remote cluster nodes.
// Implements side-channel protections via JSON padding and packet-size normalization.
class MessageRelay {
public:
    static constexpr size_t MAX_MESSAGE_SIZE = 5 * 1024 * 1024; // 5MB Limit per relay
    
    explicit MessageRelay(ConnectionManager& conn_manager, RedisManager& redis, RateLimiter& rate_limiter);
    ~MessageRelay() = default;
    
    // --- Traffic Sanitization & Obfuscation ---
    // Filters input to prevent injection in internal logs and routing headers.
    static std::string sanitize_field(const std::string& input, size_t max_length = 256);
    
    // Normalizes JSON payload sizes to prevent length-based traffic analysis.
    static void pad_json(boost::json::object& obj, size_t target_size);
    
    // --- Message Distribution ---
    /**
     * Relays a JSON message to its destination(s).
     * If recipient is local, it's delivered directly. Otherwise, it's published to Redis.
     */
    void relay_message(const std::string& message_json, 
                       std::shared_ptr<WebSocketSession> sender);
    
    // Relays raw binary blobs to a recipient.
    void relay_binary(const std::string& recipient_hash,
                      const void* data, 
                      size_t length,
                      std::shared_ptr<WebSocketSession> sender);

    // Relays data without explicit persistent delivery guarantees (Lower latency).
    void relay_volatile(const std::string& recipient_hash,
                        const void* data,
                        size_t length);

    // Relays a single payload to multiple recipients using atomic distribution.
    void relay_multicast(const std::vector<std::string>& recipients,
                         const std::string& message_json);

    // Optimized group-message distribution.
    void relay_group_message(const boost::json::array& targets,
                            std::shared_ptr<WebSocketSession> sender);
    
    // --- Maintenance & Protocol Logic ---
    // Processes dummy packets used for noise generation.
    void handle_dummy(std::shared_ptr<WebSocketSession> sender);

    // Forces delivery of any buffered/offline messages for a newly connected recipient.
    void deliver_pending(const std::string& recipient_hash,
                         std::shared_ptr<WebSocketSession> recipient);

    // Cross-node subscription management.
    void subscribe_user(const std::string& user_hash) { redis_.subscribe_user(user_hash); }
    void unsubscribe_user(const std::string& user_hash) { redis_.unsubscribe_user(user_hash); }

    // Logic for handling delivery acknowledgments (If protocol-enforced).
    void confirm_delivery(const std::vector<int64_t>& /*ids*/) {
        // Implementation for future delivery tracking
    }
    
    // Validates that message size is within permitted bounds.
    bool validate_message_size(size_t size) const {
        return size <= MAX_MESSAGE_SIZE;
    }

private:
    ConnectionManager& conn_manager_;
    RedisManager& redis_;
    RateLimiter& rate_limiter_;
    
    // Internal routing metadata extracted from payloads
    struct RoutingInfo {
        std::string type;
        std::string to;
        bool valid;
    };
    
    // Performs fast-pass parsing of routing headers.
    RoutingInfo extract_routing(const std::string& message_json);
};

}
