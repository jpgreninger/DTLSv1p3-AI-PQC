/**
 * @file test_udp_transport.cpp
 * @brief Comprehensive tests for UDP transport layer
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

// Test large packet handling
TEST_F(UDPTransportTest, LargePacketHandling) {
    auto server_result = UDPTransport::create(config_);
    ASSERT_TRUE(server_result.is_ok());
    server_transport_ = server_result.value();
    
    auto server_bind_result = server_transport_->bind(server_addr_);
    ASSERT_TRUE(server_bind_result.is_ok());
    auto actual_server_addr = server_transport_->get_local_address().value();
    
    auto client_result = UDPTransport::create(config_);
    ASSERT_TRUE(client_result.is_ok());
    client_transport_ = client_result.value();
    
    auto client_bind_result = client_transport_->bind(client_addr_);
    ASSERT_TRUE(client_bind_result.is_ok());
    
    // Test sending large data
    ZeroCopyBuffer large_send_buffer(large_data_.data(), large_data_.size());
    auto send_result = client_transport_->send_to(large_send_buffer, actual_server_addr);
    ASSERT_TRUE(send_result.is_ok());
    EXPECT_EQ(send_result.value(), large_data_.size());
    
    // Receive large data
    ZeroCopyBuffer large_receive_buffer(2048);
    auto receive_result = server_transport_->receive_from(large_receive_buffer);
    ASSERT_TRUE(receive_result.is_ok());
    
    auto [bytes_received, sender_addr] = receive_result.value();
    EXPECT_EQ(bytes_received, large_data_.size());
    EXPECT_EQ(std::memcmp(large_receive_buffer.data(), large_data_.data(), large_data_.size()), 0);
}

// Test packet size limits and fragmentation
TEST_F(UDPTransportTest, PacketSizeLimitsAndFragmentation) {
    UDPTransportConfig small_packet_config = config_;
    small_packet_config.max_packet_size = 512; // Small limit
    
    auto transport_result = UDPTransport::create(small_packet_config);
    ASSERT_TRUE(transport_result.is_ok());
    auto transport = transport_result.value();
    
    auto bind_result = transport->bind(server_addr_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Try to send packet larger than limit
    ZeroCopyBuffer oversized_buffer(large_data_.data(), large_data_.size());
    auto send_result = transport->send_to(oversized_buffer, remote_addr_);
    
    // Should either succeed with truncation or fail with appropriate error
    if (send_result.is_error()) {
        // Verify it's the right kind of error
        auto error = send_result.error();
        EXPECT_TRUE(error == DTLSError::MESSAGE_TOO_LARGE || 
                   error == DTLSError::BUFFER_TOO_SMALL);
    } else {
        // If it succeeded, should have sent at most max_packet_size bytes
        EXPECT_LE(send_result.value(), small_packet_config.max_packet_size);
    }
}

// Test timeout and non-blocking operations
TEST_F(UDPTransportTest, TimeoutAndNonBlockingOperations) {
    UDPTransportConfig timeout_config = config_;
    timeout_config.socket_timeout_ms = 100; // Short timeout
    timeout_config.enable_non_blocking = true;
    
    auto transport_result = UDPTransport::create(timeout_config);
    ASSERT_TRUE(transport_result.is_ok());
    auto transport = transport_result.value();
    
    auto bind_result = transport->bind(server_addr_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Try to receive when no data is available
    ZeroCopyBuffer receive_buffer(1024);
    auto start_time = std::chrono::high_resolution_clock::now();
    
    auto receive_result = transport->receive_from(receive_buffer);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Should timeout or return immediately (non-blocking)
    if (timeout_config.enable_non_blocking) {
        EXPECT_LT(duration.count(), 50); // Should return quickly
        if (receive_result.is_error()) {
            EXPECT_TRUE(receive_result.error() == DTLSError::WOULD_BLOCK ||
                       receive_result.error() == DTLSError::TIMEOUT);
        }
    } else {
        // Should respect timeout
        EXPECT_GE(duration.count(), timeout_config.socket_timeout_ms - 50);
        EXPECT_LE(duration.count(), timeout_config.socket_timeout_ms + 50);
        EXPECT_TRUE(receive_result.is_error());
        EXPECT_EQ(receive_result.error(), DTLSError::TIMEOUT);
    }
}

// Test connection-oriented UDP operations
TEST_F(UDPTransportTest, ConnectionOrientedOperations) {
    auto server_result = UDPTransport::create(config_);
    ASSERT_TRUE(server_result.is_ok());
    server_transport_ = server_result.value();
    
    auto server_bind_result = server_transport_->bind(server_addr_);
    ASSERT_TRUE(server_bind_result.is_ok());
    auto actual_server_addr = server_transport_->get_local_address().value();
    
    auto client_result = UDPTransport::create(config_);
    ASSERT_TRUE(client_result.is_ok());
    client_transport_ = client_result.value();
    
    // Connect client to server
    auto connect_result = client_transport_->connect(actual_server_addr);
    if (connect_result.is_ok()) { // UDP connect may not be supported on all platforms
        EXPECT_TRUE(client_transport_->is_connected());
        
        // Test connected send (no destination address needed)
        ZeroCopyBuffer send_buffer(small_data_.data(), small_data_.size());
        auto send_result = client_transport_->send(send_buffer);
        ASSERT_TRUE(send_result.is_ok());
        EXPECT_EQ(send_result.value(), small_data_.size());
        
        // Receive on server
        ZeroCopyBuffer receive_buffer(1024);
        auto receive_result = server_transport_->receive_from(receive_buffer);
        ASSERT_TRUE(receive_result.is_ok());
        
        auto [bytes_received, sender_addr] = receive_result.value();
        EXPECT_EQ(bytes_received, small_data_.size());
        
        // Test disconnection
        auto disconnect_result = client_transport_->disconnect();
        EXPECT_TRUE(disconnect_result.is_ok());
        EXPECT_FALSE(client_transport_->is_connected());
    }
}

// Test multicast operations
TEST_F(UDPTransportTest, MulticastOperations) {
    UDPTransportConfig multicast_config = config_;
    multicast_config.enable_multicast = true;
    multicast_config.multicast_ttl = 2;
    multicast_config.enable_multicast_loop = true;
    
    auto transport_result = UDPTransport::create(multicast_config);
    ASSERT_TRUE(transport_result.is_ok());
    auto transport = transport_result.value();
    
    auto bind_result = transport->bind(NetworkAddress::from_string("0.0.0.0:0").value());
    ASSERT_TRUE(bind_result.is_ok());
    
    // Test joining multicast group
    auto multicast_addr = NetworkAddress::from_string("224.0.0.1:0").value();
    auto join_result = transport->join_multicast_group(multicast_addr);
    
    if (join_result.is_ok()) {
        // Test sending to multicast group
        ZeroCopyBuffer multicast_data(small_data_.data(), small_data_.size());
        auto send_result = transport->send_to(multicast_data, 
            NetworkAddress::from_string("224.0.0.1:12345").value());
        
        // May succeed or fail depending on system configuration
        // Main goal is to test the API without errors
        
        // Test leaving multicast group
        auto leave_result = transport->leave_multicast_group(multicast_addr);
        EXPECT_TRUE(leave_result.is_ok() || leave_result.error() == DTLSError::NOT_SUPPORTED);
    }
}

// Test socket options and advanced configuration
TEST_F(UDPTransportTest, SocketOptionsAndAdvancedConfiguration) {
    UDPTransportConfig advanced_config = config_;
    advanced_config.enable_broadcast = true;
    advanced_config.enable_reuse_address = true;
    advanced_config.enable_reuse_port = true;
    advanced_config.dscp_value = 46; // Expedited Forwarding
    advanced_config.priority = 7;
    
    auto transport_result = UDPTransport::create(advanced_config);
    ASSERT_TRUE(transport_result.is_ok());
    auto transport = transport_result.value();
    
    auto bind_result = transport->bind(server_addr_);
    ASSERT_TRUE(bind_result.is_ok());
    
    // Test getting socket options
    auto socket_info = transport->get_socket_info();
    EXPECT_GT(socket_info.socket_fd, 0);
    EXPECT_GT(socket_info.socket_family, 0);
    
    // Test broadcast (if enabled)
    if (advanced_config.enable_broadcast) {
        auto broadcast_addr = NetworkAddress::from_string("255.255.255.255:12345").value();
        ZeroCopyBuffer broadcast_data(small_data_.data(), small_data_.size());
        
        auto broadcast_result = transport->send_to(broadcast_data, broadcast_addr);
        // May succeed or fail depending on network configuration
        // Main goal is to test API without crashes
    }
}

// Test error handling and edge cases
TEST_F(UDPTransportTest, ErrorHandlingAndEdgeCases) {
    auto transport_result = UDPTransport::create(config_);
    ASSERT_TRUE(transport_result.is_ok());
    auto transport = transport_result.value();
    
    // Test operations on unbound socket
    ZeroCopyBuffer test_buffer(small_data_.data(), small_data_.size());
    auto send_result = transport->send_to(test_buffer, remote_addr_);
    EXPECT_TRUE(send_result.is_error());
    
    ZeroCopyBuffer receive_buffer(1024);
    auto receive_result = transport->receive_from(receive_buffer);
    EXPECT_TRUE(receive_result.is_error());
    
    // Test binding to invalid address
    auto invalid_addr = NetworkAddress::from_string("999.999.999.999:0").value();
    auto bind_result = transport->bind(invalid_addr);
    EXPECT_TRUE(bind_result.is_error());
    
    // Test sending to invalid address
    auto bind_valid = transport->bind(server_addr_);
    ASSERT_TRUE(bind_valid.is_ok());
    
    auto invalid_send = transport->send_to(test_buffer, invalid_addr);
    EXPECT_TRUE(invalid_send.is_error());
    
    // Test sending empty buffer
    ZeroCopyBuffer empty_buffer;
    auto empty_send = transport->send_to(empty_buffer, remote_addr_);
    // Should either succeed (0 bytes) or fail appropriately
    if (empty_send.is_ok()) {
        EXPECT_EQ(empty_send.value(), 0);
    }
    
    // Test receiving into too-small buffer
    ZeroCopyBuffer tiny_buffer(1);
    // This test would require actual data to receive, skip for now
}

// Test statistics and monitoring
TEST_F(UDPTransportTest, StatisticsAndMonitoring) {
    auto server_result = UDPTransport::create(config_);
    ASSERT_TRUE(server_result.is_ok());
    server_transport_ = server_result.value();
    
    auto server_bind_result = server_transport_->bind(server_addr_);
    ASSERT_TRUE(server_bind_result.is_ok());
    auto actual_server_addr = server_transport_->get_local_address().value();
    
    auto client_result = UDPTransport::create(config_);
    ASSERT_TRUE(client_result.is_ok());
    client_transport_ = client_result.value();
    
    auto client_bind_result = client_transport_->bind(client_addr_);
    ASSERT_TRUE(client_bind_result.is_ok());
    
    // Generate some traffic
    for (int i = 0; i < 10; ++i) {
        ZeroCopyBuffer send_buffer(small_data_.data(), small_data_.size());
        auto send_result = client_transport_->send_to(send_buffer, actual_server_addr);
        ASSERT_TRUE(send_result.is_ok());
        
        ZeroCopyBuffer receive_buffer(1024);
        auto receive_result = server_transport_->receive_from(receive_buffer);
        ASSERT_TRUE(receive_result.is_ok());
    }
    
    // Check client statistics
    auto client_stats = client_transport_->get_statistics();
    EXPECT_EQ(client_stats.packets_sent, 10);
    EXPECT_EQ(client_stats.bytes_sent, 10 * small_data_.size());
    EXPECT_GE(client_stats.total_send_calls, 10);
    
    // Check server statistics
    auto server_stats = server_transport_->get_statistics();
    EXPECT_EQ(server_stats.packets_received, 10);
    EXPECT_EQ(server_stats.bytes_received, 10 * small_data_.size());
    EXPECT_GE(server_stats.total_receive_calls, 10);
    
    // Test statistics reset
    client_transport_->reset_statistics();
    auto reset_stats = client_transport_->get_statistics();
    EXPECT_EQ(reset_stats.packets_sent, 0);
    EXPECT_EQ(reset_stats.bytes_sent, 0);
}

// Test concurrent operations and thread safety
TEST_F(UDPTransportTest, ConcurrentOperationsAndThreadSafety) {
    auto server_result = UDPTransport::create(config_);
    ASSERT_TRUE(server_result.is_ok());
    server_transport_ = server_result.value();
    
    auto server_bind_result = server_transport_->bind(server_addr_);
    ASSERT_TRUE(server_bind_result.is_ok());
    auto actual_server_addr = server_transport_->get_local_address().value();
    
    auto client_result = UDPTransport::create(config_);
    ASSERT_TRUE(client_result.is_ok());
    client_transport_ = client_result.value();
    
    auto client_bind_result = client_transport_->bind(client_addr_);
    ASSERT_TRUE(client_bind_result.is_ok());
    
    constexpr int num_sender_threads = 3;
    constexpr int num_receiver_threads = 2;
    constexpr int packets_per_sender = 20;
    
    std::atomic<int> packets_sent{0};
    std::atomic<int> packets_received{0};
    std::atomic<int> send_errors{0};
    std::atomic<int> receive_errors{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch sender threads
    for (int t = 0; t < num_sender_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(10, 100);
            
            for (int i = 0; i < packets_per_sender; ++i) {
                // Create variable-sized data
                size_t data_size = size_dis(gen);
                std::vector<std::byte> data(data_size);
                std::fill(data.begin(), data.end(), static_cast<std::byte>(t));
                
                ZeroCopyBuffer send_buffer(data.data(), data.size());
                auto result = client_transport_->send_to(send_buffer, actual_server_addr);
                
                if (result.is_ok()) {
                    packets_sent.fetch_add(1);
                } else {
                    send_errors.fetch_add(1);
                }
                
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }));
    }
    
    // Launch receiver threads
    for (int t = 0; t < num_receiver_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&]() {
            while (packets_received.load() < num_sender_threads * packets_per_sender) {
                ZeroCopyBuffer receive_buffer(1024);
                auto result = server_transport_->receive_from(receive_buffer);
                
                if (result.is_ok()) {
                    packets_received.fetch_add(1);
                } else {
                    receive_errors.fetch_add(1);
                    if (result.error() == DTLSError::TIMEOUT) {
                        // Expected timeout, not a real error
                        receive_errors.fetch_sub(1);
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify results
    EXPECT_EQ(packets_sent.load(), num_sender_threads * packets_per_sender);
    EXPECT_EQ(packets_received.load(), packets_sent.load());
    EXPECT_EQ(send_errors.load(), 0);
    EXPECT_LT(receive_errors.load(), 5); // Allow some timeout errors
}

// Test performance characteristics
TEST_F(UDPTransportTest, PerformanceCharacteristics) {
    UDPTransportConfig perf_config = config_;
    perf_config.receive_buffer_size = 1024 * 1024; // 1MB
    perf_config.send_buffer_size = 1024 * 1024;    // 1MB
    
    auto server_result = UDPTransport::create(perf_config);
    ASSERT_TRUE(server_result.is_ok());
    server_transport_ = server_result.value();
    
    auto server_bind_result = server_transport_->bind(server_addr_);
    ASSERT_TRUE(server_bind_result.is_ok());
    auto actual_server_addr = server_transport_->get_local_address().value();
    
    auto client_result = UDPTransport::create(perf_config);
    ASSERT_TRUE(client_result.is_ok());
    client_transport_ = client_result.value();
    
    auto client_bind_result = client_transport_->bind(client_addr_);
    ASSERT_TRUE(client_bind_result.is_ok());
    
    constexpr int num_packets = 1000;
    constexpr size_t packet_size = 1400; // Typical MTU payload
    
    std::vector<std::byte> perf_data(packet_size);
    std::iota(perf_data.begin(), perf_data.end(), std::byte{0});
    
    // Measure send performance
    auto start_send = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_packets; ++i) {
        ZeroCopyBuffer send_buffer(perf_data.data(), perf_data.size());
        auto result = client_transport_->send_to(send_buffer, actual_server_addr);
        ASSERT_TRUE(result.is_ok());
    }
    
    auto end_send = std::chrono::high_resolution_clock::now();
    auto send_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_send - start_send);
    
    // Measure receive performance
    auto start_receive = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_packets; ++i) {
        ZeroCopyBuffer receive_buffer(packet_size + 100);
        auto result = server_transport_->receive_from(receive_buffer);
        ASSERT_TRUE(result.is_ok());
    }
    
    auto end_receive = std::chrono::high_resolution_clock::now();
    auto receive_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_receive - start_receive);
    
    // Calculate performance metrics
    double send_packets_per_second = (num_packets * 1000000.0) / send_duration.count();
    double receive_packets_per_second = (num_packets * 1000000.0) / receive_duration.count();
    double send_mbps = (send_packets_per_second * packet_size * 8) / (1000 * 1000);
    double receive_mbps = (receive_packets_per_second * packet_size * 8) / (1000 * 1000);
    
    // Performance expectations (adjust based on hardware)
    EXPECT_GT(send_packets_per_second, 10000);    // At least 10k packets/sec
    EXPECT_GT(receive_packets_per_second, 10000); // At least 10k packets/sec
    EXPECT_GT(send_mbps, 100);                    // At least 100 Mbps
    EXPECT_GT(receive_mbps, 100);                 // At least 100 Mbps
    
    std::cout << "Send performance: " << send_packets_per_second << " pps, " << send_mbps << " Mbps" << std::endl;
    std::cout << "Receive performance: " << receive_packets_per_second << " pps, " << receive_mbps << " Mbps" << std::endl;
}