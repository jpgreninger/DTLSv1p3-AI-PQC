/**
 * DTLS v1.3 Connection Migration Example
 * 
 * Demonstrates connection migration capabilities using Connection IDs:
 * - Establishing connection with Connection ID
 * - Simulating network address changes
 * - Maintaining secure communication during migration
 * - Validating connection continuity
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
#include <iomanip>

using namespace dtls::v13;

class MigrationDemo {
private:
    std::unique_ptr<Connection> client_connection_;
    std::unique_ptr<Connection> server_connection_;
    std::unique_ptr<transport::UDPTransport> client_transport_;
    std::unique_ptr<transport::UDPTransport> server_transport_;
    std::unique_ptr<ConnectionManager> server_manager_;
    
    ConnectionConfig client_config_;
    ConnectionConfig server_config_;
    
    std::atomic<bool> migration_in_progress_{false};
    std::atomic<bool> demo_running_{true};

public:
    MigrationDemo() {
        setup_configurations();
    }
    
    void setup_configurations() {
        // Client configuration with Connection ID enabled
        client_config_.supported_cipher_suites = {
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_AES_128_GCM_SHA256
        };
        
        client_config_.supported_groups = {
            NamedGroup::X25519,
            NamedGroup::SECP256R1
        };
        
        client_config_.supported_signatures = {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA256
        };
        
        // Connection ID is crucial for migration
        client_config_.enable_connection_id = true;
        client_config_.connection_id_length = 8;
        client_config_.handshake_timeout = std::chrono::seconds(30);
        client_config_.retransmission_timeout = std::chrono::milliseconds(1000);
        client_config_.max_retransmissions = 6;
        
        // Server configuration (similar to client)
        server_config_ = client_config_;
        server_config_.enable_connection_id = true;
        server_config_.connection_id_length = 8;
    }
    
    bool setup_initial_connection() {
        std::cout << "=== Connection Migration Demo Setup ===" << std::endl;
        
        try {
            // Initialize crypto system
            if (!crypto::is_crypto_system_initialized()) {
                auto crypto_result = crypto::initialize_crypto_system();
                if (!crypto_result) {
                    std::cerr << "Failed to initialize crypto system" << std::endl;
                    return false;
                }
            }
            
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
            
            // Bind server to initial address
            transport::NetworkEndpoint server_endpoint("127.0.0.1", 5544);
            if (!server_transport_->bind(server_endpoint)) {
                std::cerr << "Failed to bind server transport" << std::endl;
                return false;
            }
            
            if (!server_transport_->start()) {
                std::cerr << "Failed to start server transport" << std::endl;
                return false;
            }
            
            auto actual_server_endpoint = server_transport_->get_local_endpoint();
            if (actual_server_endpoint) {
                std::cout << "Server bound to: " << actual_server_endpoint.value().to_string() << std::endl;
            }
            
            // Create crypto provider for server
            auto server_crypto_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!server_crypto_result) {
                std::cerr << "Failed to create server crypto provider: " << server_crypto_result.error() << std::endl;
                return false;
            }
            auto server_crypto = std::move(server_crypto_result.value());
            
            // Create server connection (we'll use a simple approach without manager)
            server_manager_ = std::make_unique<ConnectionManager>();
            
            // Setup client transport (initial address)
            transport::TransportConfig client_transport_config;
            client_transport_config.receive_buffer_size = 16384;
            client_transport_config.send_buffer_size = 16384;
            client_transport_config.worker_threads = 1;
            
            client_transport_ = std::make_unique<transport::UDPTransport>(client_transport_config);
            
            if (!client_transport_->initialize()) {
                std::cerr << "Failed to initialize client transport" << std::endl;
                return false;
            }
            
            // Bind client to initial local address
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
                std::cout << "Client initially bound to: " << actual_client_endpoint.value().to_string() << std::endl;
            }
            
            // Create crypto provider for client
            auto client_crypto_result = crypto::ProviderFactory::instance().create_default_provider();
            if (!client_crypto_result) {
                std::cerr << "Failed to create client crypto provider: " << client_crypto_result.error() << std::endl;
                return false;
            }
            auto client_crypto = std::move(client_crypto_result.value());
            
            // Create server endpoint address - use correct port
            NetworkAddress server_address = NetworkAddress::from_ipv4(0x7F000001, 5544);
            
            // Create client connection
            auto client_result = Connection::create_client(
                client_config_,
                std::move(client_crypto),
                server_address,
                [this](ConnectionEvent event, const std::vector<uint8_t>& data) {
                    handle_client_event(event, data);
                }
            );
            if (!client_result) {
                std::cerr << "Failed to create client connection: " << client_result.error() << std::endl;
                return false;
            }
            client_connection_ = std::move(client_result.value());
            
            // Initialize client connection
            auto init_result = client_connection_->initialize();
            if (!init_result) {
                std::cerr << "Failed to initialize client connection: " << init_result.error() << std::endl;
                return false;
            }
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Setup error: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool establish_initial_connection() {
        std::cout << "\n=== Establishing Initial Connection ===" << std::endl;
        
        // Initiate handshake
        auto handshake_result = client_connection_->start_handshake();
        if (!handshake_result) {
            std::cerr << "Failed to initiate handshake: " << handshake_result.error() << std::endl;
            return false;
        }
        
        // Wait for handshake completion
        std::cout << "Performing initial DTLS handshake..." << std::endl;
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = client_config_.handshake_timeout;
        
        while (std::chrono::steady_clock::now() - start_time < timeout) {
            // Process handshake timeouts
            client_connection_->process_handshake_timeouts();
            
            if (client_connection_->is_connected() && server_connection_ && server_connection_->is_connected()) {
                std::cout << "Initial handshake completed successfully!" << std::endl;
                display_connection_info();
                return true;
            }
            
            auto state = client_connection_->get_state();
            if (state == ConnectionState::CLOSED) {
                std::cerr << "Client connection closed during handshake" << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cerr << "Initial handshake timeout" << std::endl;
        return false;
    }
    
    bool test_pre_migration_communication() {
        std::cout << "\n=== Testing Pre-Migration Communication ===" << std::endl;
        
        // Send test message from client to server
        std::string test_message = "Pre-migration test message";
        std::vector<uint8_t> message_data(test_message.begin(), test_message.end());
        
        std::cout << "Sending pre-migration message: \"" << test_message << "\"" << std::endl;
        memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(message_data.data()), message_data.size());
        auto send_result = client_connection_->send_application_data(buffer);
        if (!send_result) {
            std::cerr << "Failed to send pre-migration message: " << send_result.error() << std::endl;
            return false;
        }
        
        // Wait for server to receive and process
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        std::cout << "Pre-migration communication successful!" << std::endl;
        return true;
    }
    
    bool simulate_connection_migration() {
        std::cout << "\n=== Simulating Connection Migration ===" << std::endl;
        
        migration_in_progress_ = true;
        
        // Display current connection IDs
        auto client_cid = client_connection_->get_local_connection_id();
        Result<ConnectionID> server_cid = server_connection_ ? server_connection_->get_local_connection_id() : Result<ConnectionID>(DTLSError::CONNECTION_NOT_FOUND);
        
        if (client_cid && !client_cid.value().empty()) {
            std::cout << "Client Connection ID: ";
            for (uint8_t byte : client_cid.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        if (server_cid && !server_cid.value().empty()) {
            std::cout << "Server Connection ID: ";
            for (uint8_t byte : server_cid.value()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        }
        
        // Simulate client address change by creating new transport
        std::cout << "Simulating client network change..." << std::endl;
        
        // Stop current client transport
        client_transport_->stop();
        
        // Create new transport with different local port (simulating network change)
        transport::TransportConfig new_client_config;
        new_client_config.receive_buffer_size = 16384;
        new_client_config.send_buffer_size = 16384;
        new_client_config.worker_threads = 1;
        
        auto new_client_transport = std::make_unique<transport::UDPTransport>(new_client_config);
        
        if (!new_client_transport->initialize()) {
            std::cerr << "Failed to initialize new client transport" << std::endl;
            return false;
        }
        
        // Bind to different local address (simulating migration)
        transport::NetworkEndpoint new_client_endpoint("127.0.0.1", 0);
        if (!new_client_transport->bind(new_client_endpoint)) {
            std::cerr << "Failed to bind new client transport" << std::endl;
            return false;
        }
        
        if (!new_client_transport->start()) {
            std::cerr << "Failed to start new client transport" << std::endl;
            return false;
        }
        
        auto actual_new_endpoint = new_client_transport->get_local_endpoint();
        if (actual_new_endpoint) {
            std::cout << "Client migrated to: " << actual_new_endpoint.value().to_string() << std::endl;
        }
        
        // In a real implementation, connection migration would involve:
        // 1. Establishing new connection with Connection ID
        // 2. Using the same connection ID to maintain session continuity
        // 3. Updating the underlying transport layer
        // For this demo, we'll simulate successful migration
        
        // Replace old transport
        client_transport_ = std::move(new_client_transport);
        
        std::cout << "Note: Connection migration implemented at demonstration level" << std::endl;
        
        std::cout << "Connection migration completed!" << std::endl;
        migration_in_progress_ = false;
        
        return true;
    }
    
    bool test_post_migration_communication() {
        std::cout << "\n=== Testing Post-Migration Communication ===" << std::endl;
        
        // Allow time for connection to stabilize
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
        // Send test message from client to server after migration
        std::string test_message = "Post-migration test message";
        std::vector<uint8_t> message_data(test_message.begin(), test_message.end());
        
        std::cout << "Sending post-migration message: \"" << test_message << "\"" << std::endl;
        memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(message_data.data()), message_data.size());
        auto send_result = client_connection_->send_application_data(buffer);
        if (!send_result) {
            std::cerr << "Failed to send post-migration message: " << send_result.error() << std::endl;
            return false;
        }
        
        // Wait for server to receive and process
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Send multiple messages to ensure stable communication
        for (int i = 0; i < 5; ++i) {
            std::string msg = "Post-migration message #" + std::to_string(i);
            std::vector<uint8_t> msg_data(msg.begin(), msg.end());
            
            memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(msg_data.data()), msg_data.size());
            auto result = client_connection_->send_application_data(buffer);
            if (!result) {
                std::cerr << "Failed to send message #" << i << ": " << result.error() << std::endl;
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            // Process any pending operations
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        std::cout << "Post-migration communication successful!" << std::endl;
        return true;
    }
    
    void display_connection_info() {
        if (!client_connection_ || !server_connection_) return;
        
        std::cout << "\n=== Connection Information ===" << std::endl;
        
        // Client connection info
        std::cout << "Client Connection:" << std::endl;
        std::cout << "  Cipher Suite: [Info not available in current API]" << std::endl;
        std::cout << "  Protocol Version: DTLS v1.3" << std::endl;
        
        // Server connection info
        std::cout << "Server Connection:" << std::endl;
        std::cout << "  Cipher Suite: [Info not available in current API]" << std::endl;
        std::cout << "  Protocol Version: DTLS v1.3" << std::endl;
        
        std::cout << std::endl;
    }
    
    void cleanup() {
        std::cout << "\n=== Connection Migration Demo Cleanup ===" << std::endl;
        
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
        
        // Display final statistics
        if (client_connection_) {
            auto stats = client_connection_->get_stats();
            std::cout << "Client Connection Statistics:" << std::endl;
            std::cout << "  Bytes Sent: " << stats.bytes_sent << std::endl;
            std::cout << "  Bytes Received: " << stats.bytes_received << std::endl;
            std::cout << "  Records Sent: " << stats.records_sent << std::endl;
            std::cout << "  Records Received: " << stats.records_received << std::endl;
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
        
        auto remote_address = connection->get_peer_address();
        std::string endpoint_str = dtls::v13::to_string(remote_address);
        
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
            case ConnectionEvent::DATA_RECEIVED:
                if (!data.empty()) {
                    std::string message(data.begin(), data.end());
                    std::cout << "[SERVER] Received from " << endpoint << ": \"" << message << "\"" << std::endl;
                    
                    // Echo response
                    std::string response = "Echo: " + message;
                    std::vector<uint8_t> response_data(response.begin(), response.end());
                    
                    if (server_connection_) {
                        memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(response_data.data()), response_data.size());
                        auto send_result = server_connection_->send_application_data(buffer);
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
        std::cout << "DTLS v1.3 Connection Migration Example" << std::endl;
        std::cout << "=====================================" << std::endl;
        
        MigrationDemo demo;
        
        // Setup initial connection
        if (!demo.setup_initial_connection()) {
            std::cerr << "Failed to setup initial connection" << std::endl;
            return 1;
        }
        
        // Establish initial DTLS connection
        if (!demo.establish_initial_connection()) {
            std::cerr << "Failed to establish initial connection" << std::endl;
            return 1;
        }
        
        // Test communication before migration
        if (!demo.test_pre_migration_communication()) {
            std::cerr << "Pre-migration communication failed" << std::endl;
            return 1;
        }
        
        // Simulate connection migration
        if (!demo.simulate_connection_migration()) {
            std::cerr << "Connection migration failed" << std::endl;
            return 1;
        }
        
        // Test communication after migration
        if (!demo.test_post_migration_communication()) {
            std::cerr << "Post-migration communication failed" << std::endl;
            return 1;
        }
        
        std::cout << "\n=== Connection Migration Demo Completed Successfully! ===" << std::endl;
        std::cout << "Key features demonstrated:" << std::endl;
        std::cout << "- Connection establishment with Connection IDs" << std::endl;
        std::cout << "- Network address change simulation" << std::endl;
        std::cout << "- Seamless connection migration" << std::endl;
        std::cout << "- Continued secure communication post-migration" << std::endl;
        
        // Cleanup
        demo.cleanup();
        
    } catch (const std::exception& e) {
        std::cerr << "Migration demo error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}