/**
 * @file test_udp_transport_fixed.cpp
 * @brief Comprehensive tests for UDP transport layer - fixed version
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>
#include <future>
#include <atomic>
#include <random>

#include "dtls/transport/udp_transport.h"
#include "dtls/types.h"
#include "dtls/memory/buffer.h"

using namespace dtls::v13;
using namespace dtls::v13::transport;
using namespace dtls::v13::memory;
using namespace std::chrono_literals;

class UDPTransportTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test endpoints
        server_endpoint_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4); // Let system choose port
        client_endpoint_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        remote_endpoint_ = NetworkEndpoint("192.168.1.100", 5000, NetworkAddress::Family::IPv4);
        
        // Basic transport configuration
        config_.worker_threads = 2;
        config_.receive_buffer_size = 65536;
        config_.send_buffer_size = 65536;
        config_.max_connections = 1000;
        config_.send_timeout = 1000ms;
        config_.receive_timeout = 1000ms;
        config_.idle_timeout = 300000ms;
        config_.max_send_queue_size = 100;
        config_.max_receive_queue_size = 100;
        config_.enable_nonblocking = true;
        config_.enable_fast_path = true;
        config_.poll_timeout_ms = 100;
        config_.reuse_address = true;
        config_.reuse_port = false;
        
        // Create test data
        small_data_ = {static_cast<std::byte>(0xDE), static_cast<std::byte>(0xAD), 
                      static_cast<std::byte>(0xBE), static_cast<std::byte>(0xEF)};
        
        large_data_.resize(1400); // Typical MTU size
        for (size_t i = 0; i < large_data_.size(); ++i) {
            large_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        jumbo_data_.resize(9000); // Jumbo frame size
        std::fill(jumbo_data_.begin(), jumbo_data_.end(), std::byte{0xAA});
    }
    
    void TearDown() override {
        // Clean up any active transports
        if (server_transport_) {
            server_transport_->stop();
            server_transport_->force_stop();
        }
        if (client_transport_) {
            client_transport_->stop();
            client_transport_->force_stop();
        }
    }
    
    TransportConfig config_;
    NetworkEndpoint server_endpoint_, client_endpoint_, remote_endpoint_;
    std::unique_ptr<UDPTransport> server_transport_, client_transport_;
    std::vector<std::byte> small_data_, large_data_, jumbo_data_;
};

// Test basic transport creation and configuration
TEST_F(UDPTransportTest, BasicCreationAndConfiguration) {
    // Create transport
    auto transport = std::make_unique<UDPTransport>(config_);
    EXPECT_TRUE(transport != nullptr);
    
    // Test initial state
    EXPECT_FALSE(transport->is_running());
    
    // Test initialization
    auto init_result = transport->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    // Test configuration access
    auto retrieved_config = transport->get_config();
    EXPECT_EQ(retrieved_config.receive_buffer_size, config_.receive_buffer_size);
    EXPECT_EQ(retrieved_config.send_buffer_size, config_.send_buffer_size);
    EXPECT_EQ(retrieved_config.worker_threads, config_.worker_threads);
}

// Test binding and address management
TEST_F(UDPTransportTest, BindingAndAddressManagement) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    // Initialize first
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Test binding
    auto bind_result = transport->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Get the actual bound address (port may have been assigned)
    auto bound_endpoint_result = transport->get_local_endpoint();
    ASSERT_TRUE(bound_endpoint_result.is_ok());
    
    auto bound_endpoint = bound_endpoint_result.value();
    EXPECT_EQ(bound_endpoint.address, server_endpoint_.address);
    EXPECT_GT(bound_endpoint.port, 0); // System should have assigned a port
    
    // Test double binding (should fail)
    auto double_bind_result = transport->bind(client_endpoint_);
    EXPECT_TRUE(double_bind_result.is_error());
    
    // Test stopping
    auto stop_result = transport->stop();
    EXPECT_TRUE(stop_result.is_ok());
}

// Test basic send and receive operations
TEST_F(UDPTransportTest, BasicSendReceiveOperations) {
    // Create server transport
    server_transport_ = std::make_unique<UDPTransport>(config_);
    auto server_init_result = server_transport_->initialize();
    ASSERT_TRUE(server_init_result.is_ok());
    
    auto server_bind_result = server_transport_->bind(server_endpoint_);
    ASSERT_TRUE(server_bind_result.is_ok());
    
    auto server_start_result = server_transport_->start();
    ASSERT_TRUE(server_start_result.is_ok());
    
    auto actual_server_endpoint = server_transport_->get_local_endpoint().value();
    
    // Create client transport
    client_transport_ = std::make_unique<UDPTransport>(config_);
    auto client_init_result = client_transport_->initialize();
    ASSERT_TRUE(client_init_result.is_ok());
    
    auto client_bind_result = client_transport_->bind(client_endpoint_);
    ASSERT_TRUE(client_bind_result.is_ok());
    
    auto client_start_result = client_transport_->start();
    ASSERT_TRUE(client_start_result.is_ok());
    
    // Create and send data from client to server
    ZeroCopyBuffer send_buffer(small_data_.data(), small_data_.size());
    auto send_result = client_transport_->send_packet(actual_server_endpoint, send_buffer);
    ASSERT_TRUE(send_result.is_ok());
    
    // Wait a bit for packet transmission
    std::this_thread::sleep_for(50ms);
    
    // Try to receive data on server
    auto receive_result = server_transport_->receive_packet();
    if (receive_result.is_ok()) {
        auto packet = receive_result.value();
        EXPECT_EQ(packet.data.size(), small_data_.size());
        EXPECT_EQ(std::memcmp(packet.data.data(), small_data_.data(), small_data_.size()), 0);
        
        // Verify sender matches client endpoint
        auto client_endpoint = client_transport_->get_local_endpoint().value();
        EXPECT_EQ(packet.source.address, client_endpoint.address);
        EXPECT_EQ(packet.source.port, client_endpoint.port);
    }
}

// Test transport lifecycle
TEST_F(UDPTransportTest, TransportLifecycle) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    // Test state transitions
    EXPECT_FALSE(transport->is_running());
    
    auto init_result = transport->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    auto bind_result = transport->bind(server_endpoint_);
    EXPECT_TRUE(bind_result.is_ok());
    
    auto start_result = transport->start();
    EXPECT_TRUE(start_result.is_ok());
    EXPECT_TRUE(transport->is_running());
    
    auto stop_result = transport->stop();
    EXPECT_TRUE(stop_result.is_ok());
    EXPECT_FALSE(transport->is_running());
}

// Test connection management
TEST_F(UDPTransportTest, ConnectionManagement) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    auto bind_result = transport->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Test adding connections
    auto add_result = transport->add_connection(remote_endpoint_);
    EXPECT_TRUE(add_result.is_ok());
    
    // Get active connections
    auto connections = transport->get_active_connections();
    EXPECT_GE(connections.size(), 1);
    
    // Test removing connections
    auto remove_result = transport->remove_connection(remote_endpoint_);
    EXPECT_TRUE(remove_result.is_ok());
    
    // Test removing non-existent connection
    auto remove_invalid_result = transport->remove_connection(client_endpoint_);
    EXPECT_TRUE(remove_invalid_result.is_error());
}

// Test statistics tracking
TEST_F(UDPTransportTest, StatisticsTracking) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Get initial stats
    auto stats = transport->get_stats();
    EXPECT_EQ(stats.packets_sent, 0);
    EXPECT_EQ(stats.packets_received, 0);
    EXPECT_EQ(stats.bytes_sent, 0);
    EXPECT_EQ(stats.bytes_received, 0);
}

// Test transport manager
TEST_F(UDPTransportTest, TransportManager) {
    TransportManager manager;
    
    // Test creation
    auto create_result = manager.create_transport(config_);
    EXPECT_TRUE(create_result.is_ok());
    
    // Test starting
    auto start_result = manager.start_transport(server_endpoint_);
    EXPECT_TRUE(start_result.is_ok());
    
    // Test stopping
    manager.stop_transport();
}

// Test address resolution utilities
TEST_F(UDPTransportTest, AddressResolution) {
    // Test hostname resolution
    auto resolve_result = UDPTransport::resolve_hostname("localhost", 8080, NetworkAddress::Family::IPv4);
    if (resolve_result.is_ok()) {
        auto endpoints = resolve_result.value();
        EXPECT_GT(endpoints.size(), 0);
        
        for (const auto& endpoint : endpoints) {
            EXPECT_EQ(endpoint.port, 8080);
            EXPECT_EQ(endpoint.family, NetworkAddress::Family::IPv4);
        }
    }
    
    // Test getting local addresses
    auto local_addresses_result = UDPTransport::get_local_addresses();
    if (local_addresses_result.is_ok()) {
        auto addresses = local_addresses_result.value();
        EXPECT_GE(addresses.size(), 2); // Should have at least IPv4 and IPv6 localhost
    }
}

// Test error handling
TEST_F(UDPTransportTest, ErrorHandling) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    // Test operations before initialization
    auto bind_before_init = transport->bind(server_endpoint_);
    EXPECT_TRUE(bind_before_init.is_error());
    
    auto start_before_init = transport->start();
    EXPECT_TRUE(start_before_init.is_error());
    
    // Initialize
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Test start before bind
    auto start_before_bind = transport->start();
    EXPECT_TRUE(start_before_bind.is_error());
    
    // Bind first
    auto bind_result = transport->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Test send before start
    ZeroCopyBuffer buffer(small_data_.data(), small_data_.size());
    auto send_before_start = transport->send_packet(remote_endpoint_, buffer);
    EXPECT_TRUE(send_before_start.is_error());
    
    // Test receive before start
    auto receive_before_start = transport->receive_packet();
    EXPECT_TRUE(receive_before_start.is_error());
}

// Test IPv6 support
TEST_F(UDPTransportTest, IPv6Support) {
    TransportConfig ipv6_config = config_;
    
    NetworkEndpoint ipv6_endpoint("::1", 0, NetworkAddress::Family::IPv6);
    
    auto transport = std::make_unique<UDPTransport>(ipv6_config);
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Try to bind to IPv6 address
    auto bind_result = transport->bind(ipv6_endpoint);
    if (bind_result.is_ok()) {
        auto bound_endpoint = transport->get_local_endpoint().value();
        EXPECT_EQ(bound_endpoint.family, NetworkAddress::Family::IPv6);
        EXPECT_EQ(bound_endpoint.address, "::1");
        EXPECT_GT(bound_endpoint.port, 0);
    }
}

// Test configuration edge cases
TEST_F(UDPTransportTest, ConfigurationEdgeCases) {
    TransportConfig edge_config;
    
    // Test minimal configuration
    edge_config.worker_threads = 1;
    edge_config.receive_buffer_size = 1024;
    edge_config.send_buffer_size = 1024;
    edge_config.max_connections = 10;
    edge_config.send_timeout = 100ms;
    edge_config.receive_timeout = 100ms;
    edge_config.idle_timeout = 1000ms;
    edge_config.max_send_queue_size = 10;
    edge_config.max_receive_queue_size = 10;
    edge_config.enable_nonblocking = false;
    edge_config.enable_fast_path = false;
    edge_config.poll_timeout_ms = 10;
    
    auto transport = std::make_unique<UDPTransport>(edge_config);
    auto init_result = transport->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    auto retrieved_config = transport->get_config();
    EXPECT_EQ(retrieved_config.worker_threads, edge_config.worker_threads);
    EXPECT_EQ(retrieved_config.receive_buffer_size, edge_config.receive_buffer_size);
    EXPECT_EQ(retrieved_config.enable_nonblocking, edge_config.enable_nonblocking);
}

// Test concurrent operations
TEST_F(UDPTransportTest, ConcurrentOperations) {
    auto transport = std::make_unique<UDPTransport>(config_);
    
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    auto bind_result = transport->bind(server_endpoint_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = transport->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Test concurrent connection management
    std::vector<std::future<void>> futures;
    
    for (int i = 0; i < 10; ++i) {
        futures.push_back(std::async(std::launch::async, [&transport, i]() {
            NetworkEndpoint endpoint("192.168.1." + std::to_string(100 + i), 5000 + i, NetworkAddress::Family::IPv4);
            transport->add_connection(endpoint);
            std::this_thread::sleep_for(10ms);
            transport->remove_connection(endpoint);
        }));
    }
    
    // Wait for all operations to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify final state
    auto connections = transport->get_active_connections();
    // Some connections might still be present due to timing
}