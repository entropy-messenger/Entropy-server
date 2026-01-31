#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "security_logger.hpp" 
#include <iostream>
#include "server_config.hpp"
#include <openssl/sha.h>
#include <random>
#include <shared_mutex>
#include "metrics.hpp"
#include <iomanip>
#include <sstream>

namespace http = boost::beast::http;

namespace entropy {


// TLS WebSocket Constructor
WebSocketSession::WebSocketSession(
    beast::ssl_stream<beast::tcp_stream>&& stream,
    ConnectionManager& conn_manager,
    const ServerConfig& config
)
    : ws_(websocket::stream<beast::ssl_stream<beast::tcp_stream>>(std::move(stream)))
    , is_tls_(true)
    , conn_manager_(conn_manager)
    , config_(config)
{
    // Extract remote address for logging and rate limiting
    try {
        auto& tls_ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        auto ep = beast::get_lowest_layer(tls_ws).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
    
    auto& tls_ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
    
    // Configure session timeouts and keep-alive behavior
    websocket::stream_base::timeout opt{};
    opt.handshake_timeout = std::chrono::seconds(10);
    opt.idle_timeout = std::chrono::seconds(60);  
    opt.keep_alive_pings = true;                   
    tls_ws.set_option(opt);
    
    // Enable per-message compression for bandwidth efficiency
    websocket::permessage_deflate pmd;
    pmd.server_enable = true;
    pmd.client_enable = true;
    tls_ws.set_option(pmd);
    
    // Set global message size limit to prevent OOM attacks
    tls_ws.read_message_max(config_.max_message_size); 
    last_activity_time_ = std::chrono::steady_clock::now();
}

// Plaintext WebSocket Constructor (fallback or behind reverse-proxy)
WebSocketSession::WebSocketSession(
    beast::tcp_stream&& stream,
    ConnectionManager& conn_manager,
    const ServerConfig& config
)
    : ws_(websocket::stream<beast::tcp_stream>(std::move(stream)))
    , is_tls_(false)
    , conn_manager_(conn_manager)
    , config_(config)
{
    try {
        auto& plain_ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        auto ep = beast::get_lowest_layer(plain_ws).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
    
    auto& plain_ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
    
    websocket::stream_base::timeout opt{};
    opt.handshake_timeout = std::chrono::seconds(10);
    opt.idle_timeout = std::chrono::seconds(60);  
    opt.keep_alive_pings = true;                   
    plain_ws.set_option(opt);
    
    websocket::permessage_deflate pmd;
    pmd.server_enable = true;
    pmd.client_enable = true;
    plain_ws.set_option(pmd);
    
    plain_ws.read_message_max(config_.max_message_size); 
    last_activity_time_ = std::chrono::steady_clock::now();
}

WebSocketSession::~WebSocketSession() {
    trigger_close_handler();
}

// Utility to get the appropriate executor from the variant stream
net::any_io_executor WebSocketSession::get_executor() {
    if (is_tls_) {
        return std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_)
            .get_executor();
    } else {
        return std::get<websocket::stream<beast::tcp_stream>>(ws_)
            .get_executor();
    }
}

// Perform the WebSocket Upgrade handshake
template<class Body, class Allocator>
void WebSocketSession::accept(
    http::request<Body, http::basic_fields<Allocator>>&& req,
    beast::flat_buffer&& buffer,
    std::function<void(beast::error_code)> on_accept
) {
    auto self = shared_from_this();
    auto handler = [self, on_accept](beast::error_code ec) {
        if (on_accept) {
            on_accept(ec);
        }
    };
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_accept(req, handler);
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_accept(req, handler);
    }
}


template void WebSocketSession::accept<http::string_body, std::allocator<char>>(
    http::request<http::string_body, http::basic_fields<std::allocator<char>>>&& req,
    beast::flat_buffer&& buffer,
    std::function<void(beast::error_code)> on_accept
);

void WebSocketSession::run() {
    // Enable traffic shaping and noise generation
    start_pacing();
    do_read();
}

// Async read loop
void WebSocketSession::do_read() {
    auto self = shared_from_this();
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_read(
            read_buffer_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_read(
            read_buffer_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    }
}

// Process incoming WebSocket messages
void WebSocketSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    last_activity_time_ = std::chrono::steady_clock::now();
    
    if (ec == websocket::error::closed) {
        trigger_close_handler();
        return;
    }
    
    if (ec) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, 
                           SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                           remote_addr_, 
                           "WS Read Error: " + ec.message());
        trigger_close_handler();
        return;
    }
    
    std::string message = beast::buffers_to_string(beast::buffers_prefix(bytes_transferred, read_buffer_.data()));
    
    // Check if the message was received as binary or text
    bool is_binary = false;
    if (is_tls_) {
        is_binary = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_)
            .got_binary();
    } else {
        is_binary = std::get<websocket::stream<beast::tcp_stream>>(ws_)
            .got_binary();
    }
    
    read_buffer_.consume(bytes_transferred);
    
    // Route to higher-level message handler
    if (on_message_) {
        on_message_(shared_from_this(), message, is_binary);
    }
    
    do_read();
}

// Enqueue text message for asynchronous delivery
void WebSocketSession::send_text(const std::string& message) {
    auto msg_data = std::make_shared<std::string>(message);
    
    net::post(
        get_executor(),
        [self = shared_from_this(), msg_data, this]() {
            write_queue_.push({msg_data, false});
            
            if (!is_writing_) {
                do_write();
            }
        });
}

// Enqueue binary message for asynchronous delivery
void WebSocketSession::send_binary(const std::string& data) {
    auto msg_data = std::make_shared<std::string>(data);
    
    net::post(
        get_executor(),
        [self = shared_from_this(), msg_data, this]() {
            write_queue_.push({msg_data, true});
            
            if (!is_writing_) {
                do_write();
            }
        });
}

// Async write loop
void WebSocketSession::do_write() {
    if (write_queue_.empty()) {
        is_writing_ = false;
        return;
    }
    
    is_writing_ = true;
    auto item = write_queue_.front();
    
    auto self = shared_from_this();
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.binary(item.is_binary);
        ws.async_write(
            net::buffer(*item.data),
            [self, item](beast::error_code ec, std::size_t bytes) {
                self->on_write(ec, bytes);
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.binary(item.is_binary);
        ws.async_write(
            net::buffer(*item.data),
            [self, item](beast::error_code ec, std::size_t bytes) {
                self->on_write(ec, bytes);
            });
    }
    last_activity_time_ = std::chrono::steady_clock::now();
}

void WebSocketSession::on_write(beast::error_code ec, std::size_t  ) {
    if (ec) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, 
                           SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                           remote_addr_, 
                           "WS Write Error: " + ec.message());
        close();
        return;
    }
    
    write_queue_.pop();
    do_write();
}

void WebSocketSession::close() {
    do_close();
}

void WebSocketSession::do_close() {
    auto self = shared_from_this();
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_close(
            websocket::close_code::normal,
            [self, this](beast::error_code ec) {
                if (ec) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, 
                                       SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                                       remote_addr_, 
                                       "WS Close Error: " + ec.message());
                }
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_close(
            websocket::close_code::normal,
            [self, this](beast::error_code ec) {
                if (ec) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, 
                                       SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                                       remote_addr_, 
                                       "WS Close Error: " + ec.message());
                }
            });
    }
}

// Initiates the periodic Pacing loop for traffic normalization.
void WebSocketSession::start_pacing() {
    pacing_timer_ = std::make_shared<net::steady_timer>(get_executor());
    tick_pacing();
}

// Traffic Normalization Logic (Pacing):
// Sends dummy packets at regular intervals if no real activity is detected.
// This masks the true communication volume and frequency from observers.
void WebSocketSession::tick_pacing() {
    auto self = shared_from_this();
    pacing_timer_->expires_after(std::chrono::milliseconds(ServerConfig::Pacing::tick_interval_ms));
    pacing_timer_->async_wait([self, this](beast::error_code ec) {
        if (ec) return;
        
        net::post(get_executor(), [self, this]() {
            if (write_queue_.empty()) {
                
                auto now = std::chrono::steady_clock::now();
                auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_activity_time_).count();

                if (idle_ms < ServerConfig::Pacing::idle_threshold_ms) {
                    // Send dummy text to maintain a constant traffic profile
                    std::string dummy = "{\"type\":\"dummy_pacing\"}";
                    
                    if (dummy.size() < ServerConfig::Pacing::packet_size) {
                        dummy.append(ServerConfig::Pacing::packet_size - dummy.size(), ' ');
                    }
                    send_text(dummy);
                }
            }
            tick_pacing();
        });
    });
}


}
