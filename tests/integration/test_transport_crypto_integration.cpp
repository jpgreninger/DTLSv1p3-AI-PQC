/**
 * @file test_transport_crypto_integration.cpp
 * @brief Integration tests between transport and crypto layers
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>

#include "dtls/transport/udp_transport.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory/buffer.h"

using namespace dtls::v13;
using namespace dtls::v13::transport;
using namespace dtls::v13::crypto;
using namespace dtls::v13::memory;
using namespace std::chrono_literals;

class TransportCryptoIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register crypto providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            builtin::register_null_provider();
            builtin::register_openssl_provider();
            builtin::register_botan_provider();
        }
        
        // Set up transport configuration
        transport_config_.worker_threads = 1;
        transport_config_.receive_buffer_size = 32768;
        transport_config_.send_buffer_size = 32768;
        transport_config_.max_connections = 100;
        transport_config_.send_timeout = 1000ms;
        transport_config_.receive_timeout = 1000ms;
        transport_config_.idle_timeout = 300000ms;
        transport_config_.max_send_queue_size = 50;
        transport_config_.max_receive_queue_size = 50;
        transport_config_.enable_nonblocking = true;
        transport_config_.enable_fast_path = true;
        transport_config_.poll_timeout_ms = 50;
        transport_config_.reuse_address = true;
        transport_config_.reuse_port = false;
        
        // Set up endpoints
        server_endpoint_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        client_endpoint_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        
        // Set up test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<uint8_t>(i % 256);
        }
        
        encrypted_data_marker_ = {0xDE, 0xAD, 0xBE, 0xEF};
    }
    
    void TearDown() override {
        if (server_transport_) {
            server_transport_->stop();
            server_transport_->force_stop();
        }
        if (client_transport_) {
            client_transport_->stop();
            client_transport_->force_stop();
        }
        
        ProviderFactory::instance().reset_all_stats();
    }
    
    TransportConfig transport_config_;
    NetworkEndpoint server_endpoint_, client_endpoint_;
    std::unique_ptr<UDPTransport> server_transport_, client_transport_;
    std::vector<uint8_t> test_data_;
    std::vector<uint8_t> encrypted_data_marker_;
};

// Test basic transport and crypto integration
TEST_F(TransportCryptoIntegrationTest, BasicIntegration) {
    // Create crypto provider
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = std::move(provider_result.value());
    auto init_result = provider->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Create transport
    server_transport_ = std::make_unique<UDPTransport>(transport_config_);
    auto transport_init = server_transport_->initialize();
    ASSERT_TRUE(transport_init.is_ok());
    
    auto bind_result = server_transport_->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = server_transport_->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Test that both crypto and transport are functional
    EXPECT_TRUE(provider->is_available());
    EXPECT_TRUE(server_transport_->is_running());
    
    // Test crypto operations
    RandomParams random_params;
    random_params.length = 32;
    random_params.cryptographically_secure = true;
    
    auto random_result = provider->generate_random(random_params);
    ASSERT_TRUE(random_result.is_ok());
    auto random_data = random_result.value();
    EXPECT_EQ(random_data.size(), 32);
    
    // Test transport operations
    auto local_endpoint = server_transport_->get_local_endpoint();
    ASSERT_TRUE(local_endpoint.is_ok());
    EXPECT_GT(local_endpoint.value().port, 0);
}

// Test transport of crypto-generated data
TEST_F(TransportCryptoIntegrationTest, TransportCryptoData) {
    // Create crypto provider
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = std::move(provider_result.value());
    auto init_result = provider->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Create server transport
    server_transport_ = std::make_unique<UDPTransport>(transport_config_);
    auto server_init = server_transport_->initialize();
    ASSERT_TRUE(server_init.is_ok());
    
    auto server_bind = server_transport_->bind(server_endpoint_);
    ASSERT_TRUE(server_bind.is_ok());
    
    auto server_start = server_transport_->start();
    ASSERT_TRUE(server_start.is_ok());
    
    auto actual_server_endpoint = server_transport_->get_local_endpoint().value();
    
    // Create client transport
    client_transport_ = std::make_unique<UDPTransport>(transport_config_);
    auto client_init = client_transport_->initialize();
    ASSERT_TRUE(client_init.is_ok());
    
    auto client_bind = client_transport_->bind(client_endpoint_);
    ASSERT_TRUE(client_bind.is_ok());
    
    auto client_start = client_transport_->start();
    ASSERT_TRUE(client_start.is_ok());
    
    // Generate crypto data
    RandomParams crypto_params;
    crypto_params.length = 256;
    crypto_params.cryptographically_secure = true;
    
    auto crypto_result = provider->generate_random(crypto_params);
    ASSERT_TRUE(crypto_result.is_ok());
    auto crypto_data = crypto_result.value();
    
    // Create buffer with crypto data and marker
    std::vector<uint8_t> transport_data;
    transport_data.insert(transport_data.end(), encrypted_data_marker_.begin(), encrypted_data_marker_.end());
    transport_data.insert(transport_data.end(), crypto_data.begin(), crypto_data.end());
    
    // Send crypto data via transport
    ZeroCopyBuffer send_buffer(transport_data.data(), transport_data.size());
    auto send_result = client_transport_->send_packet(actual_server_endpoint, send_buffer);
    ASSERT_TRUE(send_result.is_ok());
    
    // Wait for transmission
    std::this_thread::sleep_for(100ms);
    
    // Receive on server
    auto receive_result = server_transport_->receive_packet();
    if (receive_result.is_ok()) {
        auto packet = receive_result.value();
        EXPECT_GE(packet.data.size(), encrypted_data_marker_.size() + crypto_data.size());
        
        // Verify marker
        bool marker_found = std::equal(
            encrypted_data_marker_.begin(), encrypted_data_marker_.end(),
            packet.data.data()
        );
        EXPECT_TRUE(marker_found);
        
        // Verify crypto data
        if (packet.data.size() >= encrypted_data_marker_.size() + crypto_data.size()) {
            const uint8_t* received_crypto = packet.data.data() + encrypted_data_marker_.size();
            bool crypto_data_matches = std::equal(
                crypto_data.begin(), crypto_data.end(),
                received_crypto
            );
            EXPECT_TRUE(crypto_data_matches);
        }
    }
}

// Test concurrent crypto operations with transport
TEST_F(TransportCryptoIntegrationTest, ConcurrentCryptoTransport) {
    // Create crypto provider
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider("openssl");
    ASSERT_TRUE(provider_result.is_ok());
    
    auto provider = std::move(provider_result.value());
    auto init_result = provider->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Create transport
    server_transport_ = std::make_unique<UDPTransport>(transport_config_);
    auto transport_init = server_transport_->initialize();
    ASSERT_TRUE(transport_init.is_ok());
    
    auto bind_result = server_transport_->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = server_transport_->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Test concurrent operations
    std::vector<std::future<bool>> futures;
    
    // Test concurrent crypto operations
    for (int i = 0; i < 5; ++i) {
        futures.push_back(std::async(std::launch::async, [&provider]() {
            RandomParams params;
            params.length = 64;
            params.cryptographically_secure = true;
            
            auto result = provider->generate_random(params);
            return result.is_ok() && result.value().size() == 64;
        }));
    }
    
    // Test concurrent transport operations
    for (int i = 0; i < 5; ++i) {
        futures.push_back(std::async(std::launch::async, [this]() {
            auto stats = server_transport_->get_stats();
            auto config = server_transport_->get_config();
            return config.worker_threads > 0;
        }));
    }
    
    // Wait for all operations
    bool all_success = true;
    for (auto& future : futures) {
        all_success &= future.get();
    }
    
    EXPECT_TRUE(all_success);
}

// Test transport with different crypto providers
TEST_F(TransportCryptoIntegrationTest, MultiProviderTransport) {
    auto& factory = ProviderFactory::instance();
    
    // Try different providers
    std::vector<std::string> providers_to_test = {"openssl", "botan"};
    
    for (const auto& provider_name : providers_to_test) {
        if (!factory.is_provider_available(provider_name)) {
            continue; // Skip unavailable providers
        }
        
        auto provider_result = factory.create_provider(provider_name);
        if (!provider_result.is_ok()) {
            continue;
        }
        
        auto provider = std::move(provider_result.value());
        auto init_result = provider->initialize();
        if (!init_result.is_ok()) {
            continue;
        }
        
        // Create fresh transport for each provider
        auto transport = std::make_unique<UDPTransport>(transport_config_);
        auto transport_init = transport->initialize();
        ASSERT_TRUE(transport_init.is_ok());
        
        NetworkEndpoint test_endpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        auto bind_result = transport->bind(test_endpoint);
        ASSERT_TRUE(bind_result.is_ok());
        
        auto start_result = transport->start();
        ASSERT_TRUE(start_result.is_ok());
        
        // Test crypto with this provider
        RandomParams params;
        params.length = 128;
        params.cryptographically_secure = true;
        
        auto crypto_result = provider->generate_random(params);
        if (crypto_result.is_ok()) {
            auto crypto_data = crypto_result.value();
            EXPECT_EQ(crypto_data.size(), 128);
            
            // Test transport functionality
            auto local_endpoint = transport->get_local_endpoint();
            EXPECT_TRUE(local_endpoint.is_ok());
            EXPECT_TRUE(transport->is_running());
        }
        
        transport->stop();
        provider->cleanup();
    }
}

// Test error handling in integration scenarios
TEST_F(TransportCryptoIntegrationTest, ErrorHandlingIntegration) {
    auto& factory = ProviderFactory::instance();
    
    // Test with invalid provider
    auto invalid_provider_result = factory.create_provider("invalid_provider");
    EXPECT_TRUE(invalid_provider_result.is_error());
    
    // Test with valid provider but invalid transport config
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto provider = std::move(provider_result.value());
        auto init_result = provider->initialize();
        
        if (init_result.is_ok()) {
            // Test crypto error handling
            RandomParams invalid_params;
            invalid_params.length = 0; // Invalid
            invalid_params.cryptographically_secure = true;
            
            auto invalid_crypto_result = provider->generate_random(invalid_params);
            EXPECT_TRUE(invalid_crypto_result.is_error());
            
            // Test transport error handling
            server_transport_ = std::make_unique<UDPTransport>(transport_config_);
            auto transport_init = server_transport_->initialize();
            ASSERT_TRUE(transport_init.is_ok());
            
            // Try to start without binding
            auto invalid_start = server_transport_->start();
            EXPECT_TRUE(invalid_start.is_error());
        }
    }
}

// Test memory management in integration scenarios
TEST_F(TransportCryptoIntegrationTest, MemoryManagementIntegration) {
    auto& factory = ProviderFactory::instance();
    
    // Test repeated creation and destruction
    for (int i = 0; i < 20; ++i) {
        auto provider_result = factory.create_provider("openssl");
        if (provider_result.is_ok()) {
            auto provider = std::move(provider_result.value());
            auto init_result = provider->initialize();
            
            if (init_result.is_ok()) {
                // Generate some crypto data
                RandomParams params;
                params.length = 64;
                params.cryptographically_secure = true;
                
                auto crypto_result = provider->generate_random(params);
                if (crypto_result.is_ok()) {
                    auto crypto_data = crypto_result.value();
                    EXPECT_EQ(crypto_data.size(), 64);
                }
            }
            
            provider->cleanup();
        }
        
        // Create and destroy transport
        auto transport = std::make_unique<UDPTransport>(transport_config_);
        auto transport_init = transport->initialize();
        if (transport_init.is_ok()) {
            NetworkEndpoint test_endpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
            auto bind_result = transport->bind(test_endpoint);
            if (bind_result.is_ok()) {
                auto start_result = transport->start();
                if (start_result.is_ok()) {
                    EXPECT_TRUE(transport->is_running());
                }
                transport->stop();
            }
        }
    }
}

// Test provider selection with transport requirements
TEST_F(TransportCryptoIntegrationTest, ProviderSelectionWithTransport) {
    auto& factory = ProviderFactory::instance();
    
    // Create transport first
    server_transport_ = std::make_unique<UDPTransport>(transport_config_);
    auto transport_init = server_transport_->initialize();
    ASSERT_TRUE(transport_init.is_ok());
    
    auto bind_result = server_transport_->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = server_transport_->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Select crypto provider based on requirements
    ProviderSelection criteria;
    criteria.require_hardware_acceleration = false;
    criteria.require_fips_compliance = false;
    criteria.allow_software_fallback = true;
    criteria.minimum_security_level = SecurityLevel::MEDIUM;
    criteria.require_thread_safety = true; // Important for transport threading
    
    auto best_provider_result = factory.create_best_provider(criteria);
    ASSERT_TRUE(best_provider_result.is_ok());
    
    auto provider = std::move(best_provider_result.value());
    auto init_result = provider->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Test that selected provider works with transport
    RandomParams params;
    params.length = 32;
    params.cryptographically_secure = true;
    
    auto crypto_result = provider->generate_random(params);
    ASSERT_TRUE(crypto_result.is_ok());
    
    auto crypto_data = crypto_result.value();
    EXPECT_EQ(crypto_data.size(), 32);
    
    // Test transport stats
    auto stats = server_transport_->get_stats();
    EXPECT_EQ(stats.packets_sent, 0); // No packets sent yet
    EXPECT_EQ(stats.packets_received, 0); // No packets received yet
    
    // Verify both systems are operational
    EXPECT_TRUE(server_transport_->is_running());
    EXPECT_TRUE(provider->is_available());
}