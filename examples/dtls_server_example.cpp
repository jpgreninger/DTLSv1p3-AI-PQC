/**
 * Simple DTLS v1.3 Server Example
 * 
 * Demonstrates basic DTLS server functionality:
 * - Server setup and binding
 * - Client connection handling
 * - Secure data transmission (echo server)
 * - Multi-client support
 */

#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/memory/buffer.h>
#include <dtls/result.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <iomanip>

using namespace dtls::v13;

class DTLSServer {
private:
    std::unique_ptr<transport::UDPTransport> transport_;
    std::unique_ptr<ConnectionManager> connection_manager_;
    ConnectionConfig config_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    
    // Client connection tracking
    std::map<std::string, std::unique_ptr<Connection>> active_connections_;
    std::mutex connections_mutex_;
    
    // Server statistics
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> active_connection_count_{0};
    std::atomic<uint64_t> messages_processed_{0};
    std::atomic<uint64_t> bytes_processed_{0};

public:
    DTLSServer() : running_(false) {
        setup_default_config();
    }
    
    ~DTLSServer() {
        stop();
    }
    
    void setup_default_config() {
        // Configure supported cipher suites (DTLS v1.3)
        config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        
        // Configure supported groups for key exchange
        config_.supported_groups = {
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        
        // Configure signature algorithms
        config_.supported_signatures = {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ED25519
        };
        
        // Set timeouts and retry parameters
        config_.handshake_timeout = std::chrono::seconds(30);
        config_.retransmission_timeout = std::chrono::milliseconds(1000);
        config_.max_retransmissions = 6;
        
        // Enable modern DTLS features
        config_.enable_connection_id = true;
        config_.connection_id_length = 8;
        config_.enable_early_data = false; // Disabled for simplicity
        config_.enable_session_resumption = true;
        
        // Buffer configuration
        config_.receive_buffer_size = 16384;
        config_.send_buffer_size = 16384;
    }
    
    bool start(const std::string& bind_address = "0.0.0.0", uint16_t bind_port = 4433) {
        std::cout << "=== DTLS Server Startup ===" << std::endl;
        std::cout << "Starting server on " << bind_address << ":" << bind_port << std::endl;
        
        try {
            // Initialize crypto system
            if (!crypto::is_crypto_system_initialized()) {
                auto crypto_result = crypto::initialize_crypto_system();
                if (!crypto_result) {
                    std::cerr << "Failed to initialize crypto system" << std::endl;
                    return false;
                }
            }
            
            // Create and configure transport
            transport::TransportConfig transport_config;
            transport_config.receive_buffer_size = config_.receive_buffer_size;
            transport_config.send_buffer_size = config_.send_buffer_size;
            transport_config.worker_threads = 2; // Multiple threads for server
            transport_config.max_connections = 100; // Support up to 100 concurrent connections
            transport_config.reuse_address = true;
            transport_config.reuse_port = true;
            
            transport_ = std::make_unique<transport::UDPTransport>(transport_config);
            
            auto init_result = transport_->initialize();
            if (!init_result) {
                std::cerr << "Failed to initialize transport" << std::endl;
                return false;
            }
            
            // Bind to specified address and port
            transport::NetworkEndpoint bind_endpoint(bind_address, bind_port);
            auto bind_result = transport_->bind(bind_endpoint);
            if (!bind_result) {
                std::cerr << "Failed to bind to " << bind_address << ":" << bind_port << std::endl;
                return false;
            }
            
            auto actual_endpoint = transport_->get_local_endpoint();
            if (actual_endpoint) {
                std::cout << "Server bound to: " << actual_endpoint.value().to_string() << std::endl;
            }
            
            // Start transport
            auto start_result = transport_->start();
            if (!start_result) {
                std::cerr << "Failed to start transport" << std::endl;
                return false;
            }
            
            // Create connection manager
            connection_manager_ = ConnectionManager::create_server_manager(config_, transport_.get());
            if (!connection_manager_) {
                std::cerr << "Failed to create connection manager" << std::endl;
                return false;
            }
            
            // Set up connection event callbacks
            connection_manager_->set_new_connection_callback([this](std::unique_ptr<Connection> connection) {
                handle_new_connection(std::move(connection));
            });
            
            // Start server processing thread
            running_ = true;
            server_thread_ = std::thread(&DTLSServer::server_main_loop, this);
            
            std::cout << "DTLS server started successfully!" << std::endl;
            std::cout << "Waiting for client connections..." << std::endl;
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Server startup error: " << e.what() << std::endl;
            return false;
        }
    }
    
    void stop() {
        std::cout << "\n=== DTLS Server Shutdown ===" << std::endl;
        
        running_ = false;
        
        // Wait for server thread to finish
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        
        // Close all active connections
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (auto& [endpoint, connection] : active_connections_) {
                connection->close();
            }
            active_connections_.clear();
        }
        
        // Stop transport
        if (transport_) {
            transport_->stop();
        }
        
        // Display final statistics
        display_server_statistics();
        
        std::cout << "DTLS server stopped." << std::endl;
    }
    
    void run_forever() {
        std::cout << "\nServer running. Press Ctrl+C to stop..." << std::endl;
        
        // Simple signal handling for demo purposes
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Periodic status update
            static int status_counter = 0;
            if (++status_counter >= 30) { // Every 30 seconds
                display_status_update();
                status_counter = 0;
            }
        }
    }

private:
    void server_main_loop() {
        std::cout << "[SERVER] Main processing loop started" << std::endl;
        
        while (running_) {
            try {
                // Process incoming connections and data
                connection_manager_->process_events();
                
                // Process existing connections
                process_active_connections();
                
                // Cleanup disconnected connections
                cleanup_disconnected_connections();
                
                // Brief sleep to avoid busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                
            } catch (const std::exception& e) {
                std::cerr << "[SERVER] Processing error: " << e.what() << std::endl;
            }
        }
        
        std::cout << "[SERVER] Main processing loop stopped" << std::endl;
    }
    
    void handle_new_connection(std::unique_ptr<Connection> connection) {
        if (!connection) return;
        
        // Get client endpoint information
        auto remote_endpoint = connection->get_remote_endpoint();
        std::string endpoint_key = remote_endpoint ? remote_endpoint.value().to_string() : "unknown";
        
        std::cout << "[SERVER] New client connection from: " << endpoint_key << std::endl;
        
        // Set up connection event callback
        connection->set_event_callback([this, endpoint_key](ConnectionEvent event, const std::vector<uint8_t>& data) {
            handle_connection_event(endpoint_key, event, data);
        });
        
        // Store connection
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            active_connections_[endpoint_key] = std::move(connection);
        }
        
        // Update statistics
        total_connections_++;
        active_connection_count_++;
        
        display_connection_info(endpoint_key);
    }
    
    void handle_connection_event(const std::string& endpoint, ConnectionEvent event, const std::vector<uint8_t>& data) {
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                std::cout << "[" << endpoint << "] Handshake started" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "[" << endpoint << "] Handshake completed" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                std::cout << "[" << endpoint << "] Handshake failed" << std::endl;
                break;
            case ConnectionEvent::DATA_RECEIVED:
                handle_client_data(endpoint, data);
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "[" << endpoint << "] Connection closed" << std::endl;
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                std::cout << "[" << endpoint << "] Error occurred" << std::endl;
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                std::cout << "[" << endpoint << "] Alert received" << std::endl;
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                std::cout << "[" << endpoint << "] Key update completed" << std::endl;
                break;
        }
    }
    
    void handle_client_data(const std::string& endpoint, const std::vector<uint8_t>& data) {
        if (data.empty()) return;
        
        std::string message(data.begin(), data.end());
        std::cout << "[" << endpoint << "] Received: \"" << message << "\" (" << data.size() << " bytes)" << std::endl;
        
        // Echo the message back to the client
        std::string echo_response = "Echo: " + message;
        std::vector<uint8_t> response_data(echo_response.begin(), echo_response.end());
        
        // Find and send response through the connection
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = active_connections_.find(endpoint);
            if (it != active_connections_.end() && it->second) {
                auto send_result = it->second->send(response_data);
                if (send_result) {
                    std::cout << "[" << endpoint << "] Sent echo: \"" << echo_response << "\"" << std::endl;
                } else {
                    std::cerr << "[" << endpoint << "] Failed to send echo: " << send_result.error() << std::endl;
                }
            }
        }
        
        // Update statistics
        messages_processed_++;
        bytes_processed_ += data.size();
    }
    
    void process_active_connections() {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        
        for (auto& [endpoint, connection] : active_connections_) {
            if (connection && connection->is_connected()) {
                // Process any pending operations for this connection
                // This could include checking for incoming data, handling retransmissions, etc.
                
                // For this simple example, we just ensure the connection is healthy
                if (connection->has_error()) {
                    std::cout << "[" << endpoint << "] Connection has error, will be cleaned up" << std::endl;
                }
            }
        }
    }
    
    void cleanup_disconnected_connections() {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        
        auto it = active_connections_.begin();
        while (it != active_connections_.end()) {
            if (!it->second || !it->second->is_connected()) {
                std::cout << "[" << it->first << "] Cleaning up disconnected connection" << std::endl;
                it = active_connections_.erase(it);
                active_connection_count_--;
            } else {
                ++it;
            }
        }
    }
    
    void display_connection_info(const std::string& endpoint) {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = active_connections_.find(endpoint);
        if (it == active_connections_.end() || !it->second) return;
        
        auto& connection = it->second;
        
        std::cout << "\n=== Connection Information [" << endpoint << "] ===" << std::endl;
        
        auto cipher_info = connection->get_cipher_suite_info();
        if (cipher_info) {
            std::cout << "Cipher Suite: " << cipher_info.value().name << std::endl;
            std::cout << "Key Exchange: " << cipher_info.value().key_exchange << std::endl;
        }
        
        auto version_info = connection->get_protocol_version();
        if (version_info) {
            std::cout << "Protocol Version: DTLS v" << version_info.value().major 
                     << "." << version_info.value().minor << std::endl;
        }
        
        auto connection_id = connection->get_connection_id();
        if (connection_id && !connection_id.value().empty()) {
            std::cout << "Connection ID: ";
            for (uint8_t byte : connection_id.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    void display_status_update() {
        std::cout << "\n=== Server Status Update ===" << std::endl;
        std::cout << "Active Connections: " << active_connection_count_.load() << std::endl;
        std::cout << "Total Connections: " << total_connections_.load() << std::endl;
        std::cout << "Messages Processed: " << messages_processed_.load() << std::endl;
        std::cout << "Bytes Processed: " << bytes_processed_.load() << std::endl;
        
        if (transport_) {
            auto transport_stats = transport_->get_stats();
            std::cout << "Transport Stats:" << std::endl;
            std::cout << "  Packets Sent: " << transport_stats.packets_sent << std::endl;
            std::cout << "  Packets Received: " << transport_stats.packets_received << std::endl;
            std::cout << "  Bytes Sent: " << transport_stats.bytes_sent << std::endl;
            std::cout << "  Bytes Received: " << transport_stats.bytes_received << std::endl;
        }
        std::cout << std::endl;
    }
    
    void display_server_statistics() {
        std::cout << "\n=== Final Server Statistics ===" << std::endl;
        std::cout << "Total Connections Handled: " << total_connections_.load() << std::endl;
        std::cout << "Messages Processed: " << messages_processed_.load() << std::endl;
        std::cout << "Bytes Processed: " << bytes_processed_.load() << std::endl;
        
        if (transport_) {
            auto transport_stats = transport_->get_stats();
            std::cout << "\nTransport Statistics:" << std::endl;
            std::cout << "Packets Sent: " << transport_stats.packets_sent << std::endl;
            std::cout << "Packets Received: " << transport_stats.packets_received << std::endl;
            std::cout << "Bytes Sent: " << transport_stats.bytes_sent << std::endl;
            std::cout << "Bytes Received: " << transport_stats.bytes_received << std::endl;
            std::cout << "Send Errors: " << transport_stats.send_errors << std::endl;
            std::cout << "Receive Errors: " << transport_stats.receive_errors << std::endl;
            std::cout << "Socket Errors: " << transport_stats.socket_errors << std::endl;
        }
        
        std::cout << std::endl;
    }
};

// Signal handling for graceful shutdown
std::atomic<bool> shutdown_requested{false};
DTLSServer* global_server_instance = nullptr;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    shutdown_requested = true;
    if (global_server_instance) {
        global_server_instance->stop();
    }
}

int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments
        std::string bind_address = "0.0.0.0";
        uint16_t bind_port = 4433;
        
        if (argc >= 2) {
            bind_address = argv[1];
        }
        if (argc >= 3) {
            bind_port = static_cast<uint16_t>(std::stoi(argv[2]));
        }
        
        std::cout << "DTLS v1.3 Server Example" << std::endl;
        std::cout << "========================" << std::endl;
        
        // Install signal handlers for graceful shutdown
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        
        // Create and start server
        DTLSServer server;
        global_server_instance = &server;
        
        if (!server.start(bind_address, bind_port)) {
            std::cerr << "Failed to start DTLS server" << std::endl;
            return 1;
        }
        
        // Run server until shutdown is requested
        while (!shutdown_requested) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "Server shutdown completed." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}