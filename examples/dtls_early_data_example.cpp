/**
 * DTLS v1.3 Early Data (0-RTT) Example
 * 
 * Demonstrates early data functionality for reduced connection establishment time:
 * - Session resumption with Pre-Shared Key (PSK)
 * - 0-RTT data transmission during handshake
 * - Early data validation and replay protection
 * - Performance comparison with full handshake
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
#include <atomic>

using namespace dtls::v13;

class EarlyDataDemo {
private:
    std::unique_ptr<Connection> client_connection_;
    std::unique_ptr<Connection> server_connection_;
    std::unique_ptr<transport::UDPTransport> client_transport_;
    std::unique_ptr<transport::UDPTransport> server_transport_;
    std::unique_ptr<ConnectionManager> server_manager_;
    
    ConnectionConfig client_config_;
    ConnectionConfig server_config_;
    
    // PSK for session resumption
    std::vector<uint8_t> pre_shared_key_;
    std::string psk_identity_;
    
    std::atomic<bool> demo_running_{true};

public:
    EarlyDataDemo() {
        setup_configurations();
        setup_psk();
    }
    
    void setup_configurations() {
        // Client configuration with early data enabled
        client_config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        
        client_config_.supported_groups = {
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        
        client_config_.supported_signatures = {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::ED25519
        };
        
        // Enable early data and session resumption
        client_config_.enable_early_data = true;
        client_config_.enable_session_resumption = true;
        client_config_.max_early_data_size = 16384; // 16KB early data limit
        client_config_.enable_connection_id = true;
        client_config_.connection_id_length = 8;
        
        client_config_.handshake_timeout = std::chrono::seconds(30);
        client_config_.retransmission_timeout = std::chrono::milliseconds(1000);
        client_config_.max_retransmissions = 6;
        
        // Server configuration (similar to client)
        server_config_ = client_config_;
        server_config_.enable_early_data = true;
        server_config_.max_early_data_size = 16384;
        server_config_.early_data_timeout = std::chrono::milliseconds(10000); // 10 second timeout
    }
    
    void setup_psk() {
        // Generate a PSK for demonstration (in practice, this would be exchanged securely)
        psk_identity_ = "dtls_early_data_demo_client";
        
        // Generate 32-byte PSK (for AES-256)
        pre_shared_key_ = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
            0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
        };
        
        std::cout << "PSK Identity: " << psk_identity_ << std::endl;
        std::cout << "PSK Length: " << pre_shared_key_.size() << " bytes" << std::endl;
    }
    
    bool setup_transport_and_connections() {
        std::cout << "\n=== Setting Up Transport and Connections ===" << std::endl;
        
        try {
            // Create crypto providers for server and client  
            auto server_crypto_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!server_crypto_result) {
                std::cerr << "Failed to create server crypto provider: " << server_crypto_result.error() << std::endl;
                return false;
            }
            auto server_crypto_provider = std::move(server_crypto_result.value());
            
            auto client_crypto_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!client_crypto_result) {
                std::cerr << "Failed to create client crypto provider: " << client_crypto_result.error() << std::endl;
                return false;
            }
            auto client_crypto_provider = std::move(client_crypto_result.value());
            
            // Setup server transport
            transport::TransportConfig server_transport_config;
            server_transport_config.receive_buffer_size = 16384;
            server_transport_config.send_buffer_size = 16384;
            server_transport_config.worker_threads = 2;
            server_transport_config.reuse_address = true;
            
            server_transport_ = std::make_unique<transport::UDPTransport>(server_transport_config);
            
            if (!server_transport_->initialize()) {
                std::cerr << "Failed to initialize server transport" << std::endl;
                return false;
            }
            
            transport::NetworkEndpoint server_endpoint("127.0.0.1", 5555);
            if (!server_transport_->bind(server_endpoint)) {
                std::cerr << "Failed to bind server transport" << std::endl;
                return false;
            }
            
            if (!server_transport_->start()) {
                std::cerr << "Failed to start server transport" << std::endl;
                return false;
            }
            
            std::cout << "Server bound to: 127.0.0.1:5555" << std::endl;
            
            // Create server connection manager with PSK
            server_manager_ = ConnectionManager::create_server_manager(server_config_, server_transport_.get());
            if (!server_manager_) {
                std::cerr << "Failed to create server connection manager" << std::endl;
                return false;
            }
            
            // Configure PSK on server
            auto psk_result = server_manager_->add_pre_shared_key(psk_identity_, pre_shared_key_);
            if (!psk_result) {
                std::cerr << "Failed to configure PSK on server: " << psk_result.error() << std::endl;
                return false;
            }
            
            // Setup client transport
            transport::TransportConfig client_transport_config;
            client_transport_config.receive_buffer_size = 16384;
            client_transport_config.send_buffer_size = 16384;
            client_transport_config.worker_threads = 1;
            
            client_transport_ = std::make_unique<transport::UDPTransport>(client_transport_config);
            
            if (!client_transport_->initialize()) {
                std::cerr << "Failed to initialize client transport" << std::endl;
                return false;
            }
            
            transport::NetworkEndpoint client_endpoint("127.0.0.1", 0);
            if (!client_transport_->bind(client_endpoint)) {
                std::cerr << "Failed to bind client transport" << std::endl;
                return false;
            }
            
            if (!client_transport_->start()) {
                std::cerr << "Failed to start client transport" << std::endl;
                return false;
            }
            
            auto actual_client_endpoint = client_transport_->get_local_endpoint();
            if (actual_client_endpoint) {
                std::cout << "Client bound to: " << actual_client_endpoint.value().to_string() << std::endl;
            }
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Setup error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool perform_initial_handshake() {
        std::cout << "\n=== Performing Initial Full Handshake ===" << std::endl;
        
        // Create client connection
        client_connection_ = Connection::create_client_connection(client_config_, client_transport_.get());
        if (!client_connection_) {
            std::cerr << "Failed to create client connection" << std::endl;
            return false;
        }
        
        // Setup event callbacks
        client_connection_->set_event_callback([this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            handle_client_event(event, data);
        });
        
        server_manager_->set_new_connection_callback([this](std::unique_ptr<Connection> connection) {
            handle_new_server_connection(std::move(connection));
        });
        
        // Measure handshake time
        auto handshake_start = std::chrono::high_resolution_clock::now();
        
        // Initiate handshake
        transport::NetworkEndpoint server_endpoint("127.0.0.1", 5555);
        auto connect_result = client_connection_->connect(server_endpoint);
        if (!connect_result) {
            std::cerr << "Failed to initiate handshake: " << connect_result.error() << std::endl;
            return false;
        }
        
        // Wait for handshake completion
        std::cout << "Performing initial DTLS handshake..." << std::endl;
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = client_config_.handshake_timeout;
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            server_manager_->process_events();
            
            if (client_connection_->is_connected() && server_connection_ && server_connection_->is_connected()) {
                auto handshake_end = std::chrono::high_resolution_clock::now();
                auto handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(handshake_end - handshake_start);
                
                std::cout << "Initial handshake completed successfully!" << std::endl;
                std::cout << "Initial handshake time: " << handshake_duration.count() << " ms" << std::endl;
                
                return true;
            }
            
            if (client_connection_->has_error()) {
                std::cerr << "Client connection error during handshake" << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cerr << "Initial handshake timeout" << std::endl;
        return false;
    }
    
    bool test_regular_data_transfer() {
        std::cout << "\n=== Testing Regular Data Transfer ===" << std::endl;
        
        // Send some regular application data
        std::vector<std::string> test_messages = {
            "Initial connection message 1",
            "Initial connection message 2",
            "Initial connection message 3"
        };
        
        for (const auto& message : test_messages) {
            std::vector<uint8_t> data(message.begin(), message.end());
            
            std::cout << "Sending: \"" << message << "\"" << std::endl;
            auto send_result = client_connection_->send(data);
            if (!send_result) {
                std::cerr << "Failed to send message: " << send_result.error() << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            server_manager_->process_events();
        }
        
        std::cout << "Regular data transfer completed!" << std::endl;
        return true;
    }
    
    bool store_session_for_resumption() {
        std::cout << "\n=== Storing Session for Resumption ===" << std::endl;
        
        // Export session ticket for resumption
        auto session_result = client_connection_->export_session();
        if (!session_result) {
            std::cerr << "Failed to export session: " << session_result.error() << std::endl;
            return false;
        }
        
        std::cout << "Session exported successfully for future resumption" << std::endl;
        std::cout << "Session ticket size: " << session_result.value().size() << " bytes" << std::endl;
        
        return true;
    }
    
    bool close_initial_connection() {
        std::cout << "\n=== Closing Initial Connection ===" << std::endl;
        
        if (client_connection_) {
            client_connection_->close();
        }
        
        if (server_connection_) {
            server_connection_->close();
        }
        
        // Brief pause to allow cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        std::cout << "Initial connection closed" << std::endl;
        return true;
    }
    
    bool perform_early_data_handshake() {
        std::cout << "\n=== Performing Early Data (0-RTT) Handshake ===" << std::endl;
        
        // Create new client connection with PSK
        client_connection_ = Connection::create_client_connection(client_config_, client_transport_.get());
        if (!client_connection_) {
            std::cerr << "Failed to create client connection for early data" << std::endl;
            return false;
        }
        
        // Configure PSK on client
        auto psk_result = client_connection_->add_pre_shared_key(psk_identity_, pre_shared_key_);
        if (!psk_result) {
            std::cerr << "Failed to configure PSK on client: " << psk_result.error() << std::endl;
            return false;
        }
        
        // Setup event callbacks
        client_connection_->set_event_callback([this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            handle_client_event(event, data);
        });
        
        // Reset server connection
        server_connection_.reset();
        
        // Measure early data connection time
        auto early_handshake_start = std::chrono::high_resolution_clock::now();
        
        // Prepare early data
        std::vector<std::string> early_data_messages = {
            "Early data message 1 (0-RTT)",
            "Early data message 2 (0-RTT)",
            "Critical early application data"
        };
        
        // Initiate handshake with early data
        transport::NetworkEndpoint server_endpoint("127.0.0.1", 5555);
        auto connect_result = client_connection_->connect_with_early_data(server_endpoint);
        if (!connect_result) {
            std::cerr << "Failed to initiate early data handshake: " << connect_result.error() << std::endl;
            return false;
        }
        
        std::cout << "Early data handshake initiated..." << std::endl;
        
        // Send early data immediately (0-RTT)
        for (const auto& message : early_data_messages) {
            std::vector<uint8_t> data(message.begin(), message.end());
            
            std::cout << "Sending early data: \"" << message << "\"" << std::endl;
            auto send_result = client_connection_->send_early_data(data);
            if (!send_result) {
                std::cerr << "Failed to send early data: " << send_result.error() << std::endl;
                // Continue with regular handshake
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        // Wait for handshake completion
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = client_config_.handshake_timeout;
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            server_manager_->process_events();
            
            if (client_connection_->is_connected() && server_connection_ && server_connection_->is_connected()) {
                auto early_handshake_end = std::chrono::high_resolution_clock::now();
                auto early_handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    early_handshake_end - early_handshake_start);
                
                std::cout << "Early data handshake completed successfully!" << std::endl;
                std::cout << "Early data handshake time: " << early_handshake_duration.count() << " ms" << std::endl;
                
                // Check early data acceptance
                auto early_data_status = client_connection_->get_early_data_status();
                if (early_data_status) {
                    switch (early_data_status.value()) {
                    case EarlyDataStatus::ACCEPTED:
                        std::cout << "Early data was ACCEPTED by server" << std::endl;
                        break;
                    case EarlyDataStatus::REJECTED:
                        std::cout << "Early data was REJECTED by server" << std::endl;
                        break;
                    case EarlyDataStatus::UNKNOWN:
                        std::cout << "Early data status is UNKNOWN" << std::endl;
                        break;
                    }
                }
                
                return true;
            }
            
            if (client_connection_->has_error()) {
                std::cerr << "Client connection error during early data handshake" << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cerr << "Early data handshake timeout" << std::endl;
        return false;
    }
    
    bool test_post_handshake_data() {
        std::cout << "\n=== Testing Post-Handshake Data ===" << std::endl;
        
        // Send regular application data after handshake completion
        std::vector<std::string> post_handshake_messages = {
            "Post-handshake message 1",
            "Post-handshake message 2",
            "Final test message"
        };
        
        for (const auto& message : post_handshake_messages) {
            std::vector<uint8_t> data(message.begin(), message.end());
            
            std::cout << "Sending: \"" << message << "\"" << std::endl;
            auto send_result = client_connection_->send(data);
            if (!send_result) {
                std::cerr << "Failed to send post-handshake message: " << send_result.error() << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            server_manager_->process_events();
        }
        
        std::cout << "Post-handshake data transfer completed!" << std::endl;
        return true;
    }
    
    void display_performance_comparison() {
        std::cout << "\n=== Performance Comparison ===" << std::endl;
        
        if (!client_connection_) return;
        
        auto stats = client_connection_->get_statistics();
        
        std::cout << "Connection Statistics:" << std::endl;
        std::cout << "  Handshake Duration: " << stats.handshake_duration.count() << " ms" << std::endl;
        std::cout << "  Early Data Sent: " << stats.early_data_bytes_sent << " bytes" << std::endl;
        std::cout << "  Early Data Accepted: " << (stats.early_data_accepted ? "Yes" : "No") << std::endl;
        std::cout << "  Total Bytes Sent: " << stats.bytes_sent << std::endl;
        std::cout << "  Total Bytes Received: " << stats.bytes_received << std::endl;
        std::cout << "  Records Sent: " << stats.records_sent << std::endl;
        std::cout << "  Records Received: " << stats.records_received << std::endl;
        
        // Calculate potential time savings
        if (stats.early_data_accepted && stats.early_data_bytes_sent > 0) {
            std::cout << "\nEarly Data Benefits:" << std::endl;
            std::cout << "  Reduced round-trips for initial data transmission" << std::endl;
            std::cout << "  Faster application startup time" << std::endl;
            std::cout << "  Improved user experience for repeated connections" << std::endl;
        }
    }
    
    void cleanup() {
        std::cout << "\n=== Early Data Demo Cleanup ===" << std::endl;
        
        demo_running_ = false;
        
        if (client_connection_) {
            client_connection_->close();
        }
        
        if (server_connection_) {
            server_connection_->close();
        }
        
        if (client_transport_) {
            client_transport_->stop();
        }
        
        if (server_transport_) {
            server_transport_->stop();
        }
        
        std::cout << "Cleanup completed." << std::endl;
    }

private:
    void handle_client_event(ConnectionEvent event, const std::vector<uint8_t>& data) {
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                std::cout << "[CLIENT] Handshake started" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "[CLIENT] Handshake completed" << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                std::cout << "[CLIENT] Handshake failed" << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_ACCEPTED:
                std::cout << "[CLIENT] Early data accepted by server" << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_REJECTED:
                std::cout << "[CLIENT] Early data rejected by server" << std::endl;
                break;
            case ConnectionEvent::DATA_RECEIVED:
                if (!data.empty()) {
                    std::string message(data.begin(), data.end());
                    std::cout << "[CLIENT] Received: \"" << message << "\"" << std::endl;
                }
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "[CLIENT] Connection closed" << std::endl;
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                std::cout << "[CLIENT] Error occurred" << std::endl;
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                std::cout << "[CLIENT] Alert received" << std::endl;
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                std::cout << "[CLIENT] Key update completed" << std::endl;
                break;
        }
    }
    
    void handle_new_server_connection(std::unique_ptr<Connection> connection) {
        if (!connection) return;
        
        auto remote_endpoint = connection->get_remote_endpoint();
        std::string endpoint_str = remote_endpoint ? remote_endpoint.value().to_string() : "unknown";
        
        std::cout << "[SERVER] New connection from: " << endpoint_str << std::endl;
        
        connection->set_event_callback([this, endpoint_str](ConnectionEvent event, const std::vector<uint8_t>& data) {
            handle_server_event(endpoint_str, event, data);
        });
        
        server_connection_ = std::move(connection);
    }
    
    void handle_server_event(const std::string& endpoint, ConnectionEvent event, const std::vector<uint8_t>& data) {
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                std::cout << "[SERVER] Handshake started with " << endpoint << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                std::cout << "[SERVER] Handshake completed with " << endpoint << std::endl;
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                std::cout << "[SERVER] Handshake failed with " << endpoint << std::endl;
                break;
            case ConnectionEvent::EARLY_DATA_RECEIVED:
                if (!data.empty()) {
                    std::string message(data.begin(), data.end());
                    std::cout << "[SERVER] Received early data from " << endpoint << ": \"" << message << "\"" << std::endl;
                }
                break;
            case ConnectionEvent::DATA_RECEIVED:
                if (!data.empty()) {
                    std::string message(data.begin(), data.end());
                    std::cout << "[SERVER] Received from " << endpoint << ": \"" << message << "\"" << std::endl;
                    
                    // Echo response
                    std::string response = "Echo: " + message;
                    std::vector<uint8_t> response_data(response.begin(), response.end());
                    
                    if (server_connection_) {
                        auto send_result = server_connection_->send(response_data);
                        if (send_result) {
                            std::cout << "[SERVER] Sent echo to " << endpoint << std::endl;
                        }
                    }
                }
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                std::cout << "[SERVER] Connection closed with " << endpoint << std::endl;
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                std::cout << "[SERVER] Error occurred with " << endpoint << std::endl;
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                std::cout << "[SERVER] Alert received from " << endpoint << std::endl;
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                std::cout << "[SERVER] Key update completed with " << endpoint << std::endl;
                break;
        }
    }
};

int main() {
    try {
        std::cout << "DTLS v1.3 Early Data (0-RTT) Example" << std::endl;
        std::cout << "====================================" << std::endl;
        
        EarlyDataDemo demo;
        
        // Setup transport and connections
        if (!demo.setup_transport_and_connections()) {
            std::cerr << "Failed to setup transport and connections" << std::endl;
            return 1;
        }
        
        // Perform initial handshake to establish session
        if (!demo.perform_initial_handshake()) {
            std::cerr << "Failed to perform initial handshake" << std::endl;
            return 1;
        }
        
        // Test regular data transfer
        if (!demo.test_regular_data_transfer()) {
            std::cerr << "Failed to test regular data transfer" << std::endl;
            return 1;
        }
        
        // Store session for resumption
        if (!demo.store_session_for_resumption()) {
            std::cerr << "Failed to store session for resumption" << std::endl;
            return 1;
        }
        
        // Close initial connection
        if (!demo.close_initial_connection()) {
            std::cerr << "Failed to close initial connection" << std::endl;
            return 1;
        }
        
        // Perform early data handshake
        if (!demo.perform_early_data_handshake()) {
            std::cerr << "Failed to perform early data handshake" << std::endl;
            return 1;
        }
        
        // Test post-handshake data
        if (!demo.test_post_handshake_data()) {
            std::cerr << "Failed to test post-handshake data" << std::endl;
            return 1;
        }
        
        // Display performance comparison
        demo.display_performance_comparison();
        
        std::cout << "\n=== Early Data Demo Completed Successfully! ===" << std::endl;
        std::cout << "Key features demonstrated:" << std::endl;
        std::cout << "- Session resumption with Pre-Shared Key (PSK)" << std::endl;
        std::cout << "- 0-RTT data transmission during handshake" << std::endl;
        std::cout << "- Early data validation and acceptance/rejection" << std::endl;
        std::cout << "- Performance benefits of reduced round-trips" << std::endl;
        
        // Cleanup
        demo.cleanup();
        
    } catch (const std::exception& e) {
        std::cerr << "Early data demo error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}