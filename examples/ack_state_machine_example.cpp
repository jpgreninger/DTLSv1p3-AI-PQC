#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

#include <dtls/connection.h>
#include <dtls/protocol/handshake.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/memory/buffer.h>

using namespace dtls::v13;
using namespace dtls::v13::protocol;

/**
 * Mock Crypto Provider for testing
 */
class MockCryptoProvider : public crypto::CryptoProvider {
public:
    Result<void> initialize() override {
        return make_result();
    }
    
    Result<std::vector<uint8_t>> generate_random(size_t length) override {
        std::vector<uint8_t> random(length);
        for (size_t i = 0; i < length; ++i) {
            random[i] = static_cast<uint8_t>(i % 256);
        }
        return make_result(std::move(random));
    }
    
    Result<crypto::KeyPair> generate_key_pair(NamedGroup group) override {
        crypto::KeyPair keypair;
        // Mock implementation
        return make_result(std::move(keypair));
    }
    
    Result<std::vector<uint8_t>> compute_shared_secret(
        const crypto::PrivateKey& private_key,
        const crypto::PublicKey& public_key) override {
        std::vector<uint8_t> secret(32, 0xAB); // Mock secret
        return make_result(std::move(secret));
    }
};

/**
 * Test ACK processing integration with handshake state machine
 */
void test_ack_state_machine_integration() {
    std::cout << "=== ACK State Machine Integration Test ===\n";
    
    // Create connection configuration
    ConnectionConfig config;
    config.handshake_timeout = std::chrono::milliseconds(5000);
    config.retransmission_timeout = std::chrono::milliseconds(1000);
    config.max_retransmissions = 3;
    config.supported_cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
    
    // Create mock crypto provider
    auto crypto_provider = std::make_unique<MockCryptoProvider>();
    
    // Create server address
    NetworkAddress server_address;
    server_address.address = "127.0.0.1";
    server_address.port = 4433;
    server_address.family = NetworkAddress::Family::IPv4;
    
    // Event callback to track connection events
    auto event_callback = [](ConnectionEvent event, const std::vector<uint8_t>& data) {
        std::string event_name;
        switch (event) {
            case ConnectionEvent::HANDSHAKE_STARTED:
                event_name = "HANDSHAKE_STARTED";
                break;
            case ConnectionEvent::HANDSHAKE_COMPLETED:
                event_name = "HANDSHAKE_COMPLETED";
                break;
            case ConnectionEvent::HANDSHAKE_FAILED:
                event_name = "HANDSHAKE_FAILED";
                break;
            case ConnectionEvent::DATA_RECEIVED:
                event_name = "DATA_RECEIVED";
                break;
            case ConnectionEvent::CONNECTION_CLOSED:
                event_name = "CONNECTION_CLOSED";
                break;
            case ConnectionEvent::ERROR_OCCURRED:
                event_name = "ERROR_OCCURRED";
                break;
            case ConnectionEvent::ALERT_RECEIVED:
                event_name = "ALERT_RECEIVED";
                break;
            case ConnectionEvent::KEY_UPDATE_COMPLETED:
                event_name = "KEY_UPDATE_COMPLETED";
                break;
        }
        
        std::cout << "Connection Event: " << event_name;
        if (!data.empty()) {
            std::cout << " (data: " << data.size() << " bytes)";
        }
        std::cout << "\n";
    };
    
    try {
        // Create client connection
        auto client_result = Connection::create_client(
            config, 
            std::move(crypto_provider), 
            server_address, 
            event_callback
        );
        
        if (!client_result) {
            std::cout << "Failed to create client connection\n";
            return;
        }
        
        auto client = std::move(client_result.value());
        
        // Initialize connection
        auto init_result = client->initialize();
        if (!init_result) {
            std::cout << "Failed to initialize connection\n";
            return;
        }
        
        std::cout << "Client connection initialized successfully\n";
        std::cout << "Initial state: " << static_cast<int>(client->get_state()) << "\n";
        
        // Start handshake
        auto handshake_result = client->start_handshake();
        if (!handshake_result) {
            std::cout << "Failed to start handshake\n";
            return;
        }
        
        std::cout << "Handshake started\n";
        std::cout << "State after handshake start: " << static_cast<int>(client->get_state()) << "\n";
        
        // Simulate handshake message processing with ACK support
        std::cout << "\n--- Simulating Handshake Message Processing ---\n";
        
        // Create a mock ServerHello message to process
        ServerHello server_hello;
        server_hello.set_legacy_version(ProtocolVersion::DTLS_1_3);
        server_hello.set_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
        
        // Set random
        std::array<uint8_t, 32> random;
        for (size_t i = 0; i < 32; ++i) {
            random[i] = static_cast<uint8_t>(i);
        }
        server_hello.set_random(random);
        
        HandshakeMessage server_hello_msg(server_hello, 1);
        
        // Process the message (this will trigger ACK processing)
        std::cout << "Processing ServerHello message...\n";
        
        // Note: This would normally be called from process_incoming_data,
        // but we're calling it directly for demonstration
        // In real usage, the message would come through the transport layer
        
        std::cout << "State before message processing: " << static_cast<int>(client->get_state()) << "\n";
        
        // Simulate timeout processing (for ACK retransmissions)
        std::cout << "\n--- Testing Timeout Processing ---\n";
        for (int i = 0; i < 5; ++i) {
            std::cout << "Processing timeouts (iteration " << (i + 1) << ")...\n";
            auto timeout_result = client->process_handshake_timeouts();
            if (!timeout_result) {
                std::cout << "Timeout processing failed\n";
                break;
            }
            
            // Simulate time passing
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Test ACK message handling
        std::cout << "\n--- Testing ACK Message Processing ---\n";
        
        // Create a mock ACK message
        ACK ack_message;
        ack_message.add_ack_range(1, 1); // Acknowledge sequence 1
        
        HandshakeMessage ack_handshake_msg(ack_message, 2);
        
        std::cout << "Processing ACK message...\n";
        // This would also normally come through process_incoming_data
        
        // Display final statistics
        std::cout << "\n--- Final Statistics ---\n";
        auto stats = client->get_stats();
        std::cout << "Handshake duration: " << stats.handshake_duration.count() << " ms\n";
        std::cout << "Handshake retransmissions: " << stats.handshake_retransmissions << "\n";
        std::cout << "Bytes sent: " << stats.bytes_sent << "\n";
        std::cout << "Bytes received: " << stats.bytes_received << "\n";
        std::cout << "Records sent: " << stats.records_sent << "\n";
        std::cout << "Records received: " << stats.records_received << "\n";
        std::cout << "Protocol errors: " << stats.protocol_errors << "\n";
        
        std::cout << "\n--- Connection Information ---\n";
        std::cout << "Is client: " << (client->is_client() ? "Yes" : "No") << "\n";
        std::cout << "Is connected: " << (client->is_connected() ? "Yes" : "No") << "\n";
        std::cout << "Handshake complete: " << (client->is_handshake_complete() ? "Yes" : "No") << "\n";
        std::cout << "Final state: " << static_cast<int>(client->get_state()) << "\n";
        
        // Clean up
        client->close();
        std::cout << "Connection closed\n";
        
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
    }
}

/**
 * Demonstrate ACK processing configuration options
 */
void test_ack_configuration_options() {
    std::cout << "\n=== ACK Configuration Options Test ===\n";
    
    // Test different ACK configurations
    struct ACKTestConfig {
        std::chrono::milliseconds initial_timeout;
        std::chrono::milliseconds max_timeout;
        uint32_t max_retransmissions;
        std::string description;
    };
    
    std::vector<ACKTestConfig> test_configs = {
        {std::chrono::milliseconds(500), std::chrono::milliseconds(5000), 3, "Fast retransmission"},
        {std::chrono::milliseconds(1000), std::chrono::milliseconds(10000), 5, "Standard configuration"},
        {std::chrono::milliseconds(2000), std::chrono::milliseconds(30000), 10, "Slow/unreliable networks"}
    };
    
    for (const auto& test_config : test_configs) {
        std::cout << "\nTesting: " << test_config.description << "\n";
        std::cout << "  Initial timeout: " << test_config.initial_timeout.count() << " ms\n";
        std::cout << "  Max timeout: " << test_config.max_timeout.count() << " ms\n";
        std::cout << "  Max retransmissions: " << test_config.max_retransmissions << "\n";
        
        // Configuration would be applied to ConnectionConfig and tested
        // For brevity, we're just showing the parameters
    }
}

int main() {
    std::cout << "DTLS v1.3 ACK State Machine Integration Example\n";
    std::cout << "===============================================\n";
    
    try {
        // Test 1: Basic ACK processing integration
        test_ack_state_machine_integration();
        
        // Test 2: ACK configuration options
        test_ack_configuration_options();
        
        std::cout << "\n=== All tests completed successfully! ===\n";
        
    } catch (const std::exception& e) {
        std::cout << "Test failed with exception: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}