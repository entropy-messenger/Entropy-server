#pragma once

#include "server_config.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <memory>
#include <string>
#include <functional>
#include <queue>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace entropy {

class ConnectionManager;

 
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    using MessageHandler = std::function<void(std::shared_ptr<WebSocketSession>, 
                                               const std::string&, bool is_binary)>;
    using CloseHandler = std::function<void(WebSocketSession*)>;
    
    
    explicit WebSocketSession(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        ConnectionManager& conn_manager,
        const ServerConfig& config
    );
    
    
    explicit WebSocketSession(
        beast::tcp_stream&& stream,
        ConnectionManager& conn_manager, 
        const ServerConfig& config
    );
    
    ~WebSocketSession();
    
    
    WebSocketSession(const WebSocketSession&) = delete;
    WebSocketSession& operator=(const WebSocketSession&) = delete;
    
     
    template<class Body, class Allocator>
    void accept(
        http::request<Body, http::basic_fields<Allocator>>&& req,
        beast::flat_buffer&& buffer,
        std::function<void(beast::error_code)> on_accept
    );
    
     
    void run();
    
     
    void send_text(const std::string& message);
    
     
    void send_binary(const std::string& data);
    
     
    void close();
    
     
    std::string remote_address() const { return remote_addr_; }
    
     
    void set_message_handler(MessageHandler handler) { on_message_ = std::move(handler); }
    void set_close_handler(CloseHandler handler) { on_close_ = std::move(handler); }
    void set_conn_guard(std::shared_ptr<void> guard) { conn_guard_ = std::move(guard); }
    
     
    void set_user_data(const std::string& data) { user_data_ = data; }
    std::string get_user_data() const { return user_data_; }

    void add_alias(const std::string& alias) { 
        if (aliases_.size() < 50) { 
            aliases_.push_back(alias); 
        }
    }
    const std::vector<std::string>& get_aliases() const { return aliases_; }

    void set_challenge_seed(const std::string& seed) { challenge_seed_ = seed; }
    std::string get_challenge_seed() const { return challenge_seed_; }
    void set_challenge_solved(bool solved) { challenge_solved_ = solved; }
    bool is_challenge_solved() const { return challenge_solved_; }

    void set_authenticated(bool auth) { authenticated_ = auth; }
    bool is_authenticated() const { return authenticated_; }

    net::any_io_executor get_executor();

    void trigger_close_handler() {
        if (!close_triggered_.exchange(true)) {
            if (on_close_) on_close_(this);
            
            on_message_ = nullptr;
            on_close_ = nullptr;
        }
    }

    bool can_add_alias() const { return aliases_.size() < 50; }

private:
    std::atomic<bool> close_triggered_{false};
    
    std::variant<
        websocket::stream<beast::ssl_stream<beast::tcp_stream>>,
        websocket::stream<beast::tcp_stream>
    > ws_;
    
    bool is_tls_;
    std::string remote_addr_;
    std::string user_data_;
    std::vector<std::string> aliases_;
    std::string challenge_seed_;
    bool challenge_solved_ = false;
    bool authenticated_ = false;
    
    ConnectionManager& conn_manager_;
    const ServerConfig& config_;
    
    beast::flat_buffer read_buffer_;
    struct QueuedMessage {
        std::shared_ptr<std::string> data;
        bool is_binary;
    };
    std::queue<QueuedMessage> write_queue_;
    bool is_writing_ = false;
    
    MessageHandler on_message_;
    CloseHandler on_close_;
    std::shared_ptr<void> conn_guard_;
    
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    void do_close();

    std::shared_ptr<net::steady_timer> pacing_timer_;
    std::chrono::steady_clock::time_point last_activity_time_;
    void start_pacing();
    void tick_pacing();
};

} 
