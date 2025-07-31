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
            // Create crypto provider
            auto crypto_provider_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!crypto_provider_result) {
                std::cerr << "Failed to create crypto provider: " << crypto_provider_result.error() << std::endl;
                return false;
            }
            auto crypto_provider = std::move(crypto_provider_result.value());
            
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
            
            // Initialize connection manager
            connection_manager_ = std::make_unique<ConnectionManager>();
            
            // Set up transport event callback to handle incoming connections
            transport_->set_event_callback([this](transport::TransportEvent event, 
                                                  const transport::NetworkEndpoint& endpoint, 
                                                  const std::vector<uint8_t>& data) {
                handle_transport_event(event, endpoint, data);
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
    
    void handle_transport_event(transport::TransportEvent event, 
                               const transport::NetworkEndpoint& endpoint, 
                               const std::vector<uint8_t>& data) {
        switch (event) {
            case transport::TransportEvent::PACKET_RECEIVED: {
                // Handle incoming packet - check if it's a new connection or existing one
                std::string endpoint_key = endpoint.to_string();
                
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = active_connections_.find(endpoint_key);
                
                if (it == active_connections_.end()) {
                    // New connection attempt - create server connection
                    auto crypto_provider_result = crypto::ProviderFactory::instance().create_default_provider();
                    if (!crypto_provider_result) {
                        std::cerr << "Failed to create crypto provider for new connection" << std::endl;
                        return;
                    }
                    
                    auto connection_result = Connection::create_server(
                        config_,
                        std::move(crypto_provider_result.value()),
                        NetworkAddress{endpoint.address, endpoint.port},
                        [this, endpoint_key](ConnectionEvent event, const std::vector<uint8_t>& data) {
                            handle_connection_event(endpoint_key, event, data);
                        }
                    );
                    
                    if (!connection_result) {
                        std::cerr << "Failed to create server connection: " << connection_result.error() << std::endl;
                        return;
                    }
                    
                    auto connection = std::move(connection_result.value());
                    
                    // Initialize the connection
                    auto init_result = connection->initialize();
                    if (!init_result) {
                        std::cerr << "Failed to initialize server connection: " << init_result.error() << std::endl;
                        return;
                    }
                    
                    // Process the incoming data
                    memory::ZeroCopyBuffer buffer(data);
                    auto process_result = connection->process_incoming_data(buffer);
                    if (!process_result) {
                        std::cerr << "Failed to process incoming data: " << process_result.error() << std::endl;
                        return;
                    }
                    
                    // Store the connection
                    active_connections_[endpoint_key] = std::move(connection);
                    total_connections_++;
                    active_connection_count_++;
                    
                    std::cout << "[SERVER] New client connection from: " << endpoint_key << std::endl;
                } else {
                    // Existing connection - process data
                    memory::ZeroCopyBuffer buffer(data);
                    auto process_result = it->second->process_incoming_data(buffer);
                    if (!process_result) {
                        std::cerr << "Failed to process data for " << endpoint_key << ": " << process_result.error() << std::endl;
                    }
                }
                break;
            }
            default:
                break;
        }
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
        memory::ZeroCopyBuffer response_buffer(response_data);
        
        // Find and send response through the connection
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = active_connections_.find(endpoint);
            if (it != active_connections_.end() && it->second) {
                auto send_result = it->second->send_application_data(response_buffer);
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
                if (connection->get_state() == ConnectionState::FAILED) {
                    std::cout << "[" << endpoint << "] Connection has failed, will be cleaned up" << std::endl;
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
        
        std::cout << "
=== Connection Information [" << endpoint << "] ===" << std::endl;
        
        // Display connection state
        std::cout << "Connection State: ";
        switch (connection->get_state()) {
            case ConnectionState::IDLE: std::cout << "IDLE"; break;
            case ConnectionState::CONNECTING: std::cout << "CONNECTING"; break;
            case ConnectionState::CONNECTED: std::cout << "CONNECTED"; break;
            case ConnectionState::CLOSING: std::cout << "CLOSING"; break;
            case ConnectionState::CLOSED: std::cout << "CLOSED"; break;
            case ConnectionState::FAILED: std::cout << "FAILED"; break;
            default: std::cout << "UNKNOWN"; break;
        }
        std::cout << std::endl;
        
        // Display peer address
        std::cout << "Peer Address: " << connection->get_peer_address().to_string() << std::endl;
        std::cout << "Server Mode: " << (connection->is_server() ? "Yes" : "No") << std::endl;
        
        // Try to get connection IDs if available
        auto local_id_result = connection->get_local_connection_id();
        if (local_id_result && !local_id_result.value().empty()) {
            std::cout << "Local Connection ID: ";
            for (uint8_t byte : local_id_result.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        auto peer_id_result = connection->get_peer_connection_id();
        if (peer_id_result && !peer_id_result.value().empty()) {
            std::cout << "Peer Connection ID: ";
            for (uint8_t byte : peer_id_result.value()) {
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