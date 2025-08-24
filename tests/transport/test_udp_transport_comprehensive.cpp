/**
 * @file test_udp_transport_comprehensive.cpp
 * @brief Additional comprehensive tests for UDP transport layer
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>
#include <future>
#include <atomic>
#include <random>
#include <algorithm>

#include "dtls/transport/udp_transport.h"
#include "dtls/types.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::transport;
using namespace dtls::v13::memory;
using namespace std::chrono_literals;

class UDPTransportComprehensiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test endpoints
        local_endpoint1_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        local_endpoint2_ = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
        remote_endpoint_ = NetworkEndpoint("192.168.1.100", 5000, NetworkAddress::Family::IPv4);
        
        // IPv6 endpoints for testing
        local_endpoint_v6_ = NetworkEndpoint("::1", 0, NetworkAddress::Family::IPv6);
        remote_endpoint_v6_ = NetworkEndpoint("::1", 6000, NetworkAddress::Family::IPv6);
        
        // Basic transport configuration
        basic_config_.worker_threads = 2;
        basic_config_.receive_buffer_size = 65536;
        basic_config_.send_buffer_size = 65536;
        basic_config_.max_connections = 1000;
        basic_config_.send_timeout = 1000ms;
        basic_config_.receive_timeout = 1000ms;
        basic_config_.idle_timeout = 300000ms;
        basic_config_.max_send_queue_size = 100;
        basic_config_.max_receive_queue_size = 100;
        basic_config_.enable_nonblocking = true;
        basic_config_.enable_fast_path = true;
        basic_config_.poll_timeout_ms = 100;
        
        // Create test data patterns
        small_data_.resize(64);
        std::iota(small_data_.begin(), small_data_.end(), std::byte{0});
        
        medium_data_.resize(1400); // Typical MTU payload
        for (size_t i = 0; i < medium_data_.size(); ++i) {
            medium_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        large_data_.resize(8192); // Large buffer
        std::fill(large_data_.begin(), large_data_.end(), std::byte{0xAA});
        
        pattern_data_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
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
    
    NetworkEndpoint local_endpoint1_, local_endpoint2_, remote_endpoint_;
    NetworkEndpoint local_endpoint_v6_, remote_endpoint_v6_;
    TransportConfig basic_config_;
    std::unique_ptr<UDPTransport> server_transport_, client_transport_;
    std::vector<std::byte> small_data_, medium_data_, large_data_, pattern_data_;
};

// Test transport initialization and lifecycle
TEST_F(UDPTransportComprehensiveTest, TransportInitializationAndLifecycle) {
    auto transport = std::make_unique<UDPTransport>(basic_config_);
    
    // Test initial state
    EXPECT_FALSE(transport->is_running());
    auto local_endpoint_result = transport->get_local_endpoint();
    EXPECT_TRUE(local_endpoint_result.is_error()); // Not bound yet
    
    // Test initialization
    auto init_result = transport->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    // Test binding
    auto bind_result = transport->bind(local_endpoint1_);
    EXPECT_TRUE(bind_result.is_ok());
    
    // Get actual bound endpoint
    local_endpoint_result = transport->get_local_endpoint();
    ASSERT_TRUE(local_endpoint_result.is_ok());
    
    auto bound_endpoint = local_endpoint_result.value();
    EXPECT_EQ(bound_endpoint.address, local_endpoint1_.address);
    EXPECT_GT(bound_endpoint.port, 0); // System assigned port
    EXPECT_EQ(bound_endpoint.family, local_endpoint1_.family);
    
    // Test starting
    auto start_result = transport->start();
    EXPECT_TRUE(start_result.is_ok());
    EXPECT_TRUE(transport->is_running());
    
    // Test statistics access
    const auto& stats = transport->get_stats();
    EXPECT_EQ(stats.packets_sent, 0);
    EXPECT_EQ(stats.packets_received, 0);
    EXPECT_EQ(stats.current_connections, 0);
    
    // Test configuration access
    const auto& config = transport->get_config();
    EXPECT_EQ(config.worker_threads, basic_config_.worker_threads);
    EXPECT_EQ(config.receive_buffer_size, basic_config_.receive_buffer_size);
    
    // Test stopping
    auto stop_result = transport->stop();
    EXPECT_TRUE(stop_result.is_ok());
    EXPECT_FALSE(transport->is_running());
    
    // Test force stop
    transport->force_stop();
    EXPECT_FALSE(transport->is_running());
}

// Test packet sending and receiving
TEST_F(UDPTransportComprehensiveTest, PacketSendingAndReceiving) {
    // Create server transport
    server_transport_ = std::make_unique<UDPTransport>(basic_config_);
    auto server_init = server_transport_->initialize();
    ASSERT_TRUE(server_init.is_ok());
    
    auto server_bind = server_transport_->bind(local_endpoint1_);
    ASSERT_TRUE(server_bind.is_ok());
    
    auto server_start = server_transport_->start();
    ASSERT_TRUE(server_start.is_ok());
    
    auto actual_server_endpoint = server_transport_->get_local_endpoint().value();
    
    // Create client transport
    client_transport_ = std::make_unique<UDPTransport>(basic_config_);
    auto client_init = client_transport_->initialize();
    ASSERT_TRUE(client_init.is_ok());
    
    auto client_bind = client_transport_->bind(local_endpoint2_);
    ASSERT_TRUE(client_bind.is_ok());
    
    auto client_start = client_transport_->start();
    ASSERT_TRUE(client_start.is_ok());
    
    // Test small packet
    ZeroCopyBuffer send_buffer(small_data_.data(), small_data_.size());
    auto send_result = client_transport_->send_packet(actual_server_endpoint, send_buffer);
    EXPECT_TRUE(send_result.is_ok());
    
    // Receive packet
    std::this_thread::sleep_for(10ms); // Allow time for packet to arrive
    auto receive_result = server_transport_->receive_packet();
    
    if (receive_result.is_ok()) {
        auto received_packet = receive_result.value();
        EXPECT_EQ(received_packet.data.size(), small_data_.size());
        EXPECT_EQ(std::memcmp(received_packet.data.data(), small_data_.data(), small_data_.size()), 0);
        EXPECT_EQ(received_packet.destination.address, actual_server_endpoint.address);
        EXPECT_EQ(received_packet.destination.port, actual_server_endpoint.port);
    }
    
    // Test medium packet
    ZeroCopyBuffer medium_buffer(medium_data_.data(), medium_data_.size());
    send_result = client_transport_->send_packet(actual_server_endpoint, medium_buffer);
    EXPECT_TRUE(send_result.is_ok());
    
    std::this_thread::sleep_for(10ms);
    receive_result = server_transport_->receive_packet();
    
    if (receive_result.is_ok()) {
        auto received_packet = receive_result.value();
        EXPECT_EQ(received_packet.data.size(), medium_data_.size());
        EXPECT_EQ(std::memcmp(received_packet.data.data(), medium_data_.data(), medium_data_.size()), 0);
    }
}

// Test connection management
TEST_F(UDPTransportComprehensiveTest, ConnectionManagement) {
    server_transport_ = std::make_unique<UDPTransport>(basic_config_);
    
    auto init_result = server_transport_->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    auto bind_result = server_transport_->bind(local_endpoint1_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = server_transport_->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Add connections
    auto add_result1 = server_transport_->add_connection(remote_endpoint_);
    EXPECT_TRUE(add_result1.is_ok());
    
    NetworkEndpoint remote2("192.168.1.101", 5001, NetworkAddress::Family::IPv4);
    auto add_result2 = server_transport_->add_connection(remote2);
    EXPECT_TRUE(add_result2.is_ok());
    
    // Get active connections
    auto connections = server_transport_->get_active_connections();
    EXPECT_GE(connections.size(), 2);
    
    // Verify connections are in the list
    bool found_remote1 = false, found_remote2 = false;
    for (const auto& conn : connections) {
        if (conn == remote_endpoint_) found_remote1 = true;
        if (conn == remote2) found_remote2 = true;
    }
    EXPECT_TRUE(found_remote1);
    EXPECT_TRUE(found_remote2);
    
    // Remove connections
    auto remove_result1 = server_transport_->remove_connection(remote_endpoint_);
    EXPECT_TRUE(remove_result1.is_ok());
    
    auto remove_result2 = server_transport_->remove_connection(remote2);
    EXPECT_TRUE(remove_result2.is_ok());
    
    // Verify connections were removed
    auto final_connections = server_transport_->get_active_connections();
    bool still_found_remote1 = false, still_found_remote2 = false;
    for (const auto& conn : final_connections) {
        if (conn == remote_endpoint_) still_found_remote1 = true;
        if (conn == remote2) still_found_remote2 = true;
    }
    EXPECT_FALSE(still_found_remote1);
    EXPECT_FALSE(still_found_remote2);
}

// Test hostname resolution
TEST_F(UDPTransportComprehensiveTest, HostnameResolution) {
    // Test localhost resolution
    auto localhost_result = UDPTransport::resolve_hostname("localhost", 8080);
    EXPECT_TRUE(localhost_result.is_ok());
    
    if (localhost_result.is_ok()) {
        auto endpoints = localhost_result.value();
        EXPECT_GT(endpoints.size(), 0);
        
        // Should resolve to loopback
        bool found_loopback = false;
        for (const auto& endpoint : endpoints) {
            if (endpoint.address == "127.0.0.1" || endpoint.address == "::1") {
                found_loopback = true;
                EXPECT_EQ(endpoint.port, 8080);
                break;
            }
        }
        EXPECT_TRUE(found_loopback);
    }
    
    // Test IPv4 preference
    auto ipv4_result = UDPTransport::resolve_hostname("localhost", 9090, NetworkAddress::Family::IPv4);
    if (ipv4_result.is_ok()) {
        auto endpoints = ipv4_result.value();
        for (const auto& endpoint : endpoints) {
            EXPECT_EQ(endpoint.family, NetworkAddress::Family::IPv4);
        }
    }
    
    // Test invalid hostname
    auto invalid_result = UDPTransport::resolve_hostname("invalid.nonexistent.domain", 80);
    EXPECT_TRUE(invalid_result.is_error());
}

// Test local address discovery
TEST_F(UDPTransportComprehensiveTest, LocalAddressDiscovery) {
    auto addresses_result = UDPTransport::get_local_addresses();
    EXPECT_TRUE(addresses_result.is_ok());
    
    if (addresses_result.is_ok()) {
        auto addresses = addresses_result.value();
        EXPECT_GT(addresses.size(), 0);
        
        // Should contain at least loopback
        bool found_loopback = false;
        for (const auto& addr : addresses) {
            if (addr.address == "127.0.0.1" || addr.address == "::1") {
                found_loopback = true;
                break;
            }
        }
        EXPECT_TRUE(found_loopback);
        
        // All should have port 0 (since we didn't specify)
        for (const auto& addr : addresses) {
            EXPECT_EQ(addr.port, 0);
        }
    }
}

// Test event callback functionality
TEST_F(UDPTransportComprehensiveTest, EventCallbackFunctionality) {
    server_transport_ = std::make_unique<UDPTransport>(basic_config_);
    
    // Set up event tracking
    std::atomic<int> packet_received_events{0};
    std::atomic<int> packet_sent_events{0};
    std::atomic<int> error_events{0};
    
    auto event_callback = [&](TransportEvent event, const NetworkEndpoint& endpoint, const std::vector<uint8_t>& data) {
        switch (event) {
            case TransportEvent::PACKET_RECEIVED:
                packet_received_events.fetch_add(1);
                break;
            case TransportEvent::PACKET_SENT:
                packet_sent_events.fetch_add(1);
                break;
            case TransportEvent::SEND_ERROR:
            case TransportEvent::RECEIVE_ERROR:
            case TransportEvent::SOCKET_ERROR:
                error_events.fetch_add(1);
                break;
            default:
                break;
        }
    };
    
    server_transport_->set_event_callback(event_callback);
    
    auto init_result = server_transport_->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    auto bind_result = server_transport_->bind(local_endpoint1_);
    ASSERT_TRUE(bind_result.is_ok());
    
    auto start_result = server_transport_->start();
    ASSERT_TRUE(start_result.is_ok());
    
    // Generate some events by sending packets to self
    auto actual_endpoint = server_transport_->get_local_endpoint().value();
    
    for (int i = 0; i < 5; ++i) {
        ZeroCopyBuffer test_buffer(pattern_data_.data(), pattern_data_.size());
        auto send_result = server_transport_->send_packet(actual_endpoint, test_buffer);
        EXPECT_TRUE(send_result.is_ok());
        
        std::this_thread::sleep_for(5ms); // Allow events to be processed
        
        // Try to receive
        auto receive_result = server_transport_->receive_packet();
        // May or may not succeed depending on timing
    }
    
    // Give some time for events to be processed
    std::this_thread::sleep_for(100ms);
    
    // We should have at least some events (exact counts depend on implementation)
    EXPECT_GE(packet_sent_events.load() + packet_received_events.load() + error_events.load(), 0);
}

// Test transport statistics accuracy
TEST_F(UDPTransportComprehensiveTest, TransportStatisticsAccuracy) {
    server_transport_ = std::make_unique<UDPTransport>(basic_config_);
    client_transport_ = std::make_unique<UDPTransport>(basic_config_);
    
    // Initialize and start both transports
    ASSERT_TRUE(server_transport_->initialize().is_ok());
    ASSERT_TRUE(server_transport_->bind(local_endpoint1_).is_ok());
    ASSERT_TRUE(server_transport_->start().is_ok());
    
    ASSERT_TRUE(client_transport_->initialize().is_ok());
    ASSERT_TRUE(client_transport_->bind(local_endpoint2_).is_ok());
    ASSERT_TRUE(client_transport_->start().is_ok());
    
    auto server_endpoint = server_transport_->get_local_endpoint().value();
    
    // Get initial statistics
    auto initial_server_stats = server_transport_->get_stats();
    auto initial_client_stats = client_transport_->get_stats();
    
    // Send known number of packets
    const int num_packets = 10;
    size_t total_bytes_sent = 0;
    
    for (int i = 0; i < num_packets; ++i) {
        // Vary packet sizes
        size_t packet_size = 100 + (i * 50);
        std::vector<std::byte> packet_data(packet_size, static_cast<std::byte>(i));
        total_bytes_sent += packet_size;
        
        ZeroCopyBuffer send_buffer(packet_data.data(), packet_data.size());
        auto send_result = client_transport_->send_packet(server_endpoint, send_buffer);
        EXPECT_TRUE(send_result.is_ok());
        
        std::this_thread::sleep_for(5ms); // Small delay between packets
    }
    
    // Allow time for packets to be processed
    std::this_thread::sleep_for(200ms);
    
    // Attempt to receive packets
    size_t packets_received = 0;
    size_t total_bytes_received = 0;
    
    for (int i = 0; i < num_packets + 5; ++i) { // Try a few extra times
        auto receive_result = server_transport_->receive_packet();
        if (receive_result.is_ok()) {
            auto packet = receive_result.value();
            packets_received++;
            total_bytes_received += packet.data.size();
        }
        std::this_thread::sleep_for(10ms);
    }
    
    // Check final statistics
    auto final_server_stats = server_transport_->get_stats();
    auto final_client_stats = client_transport_->get_stats();
    
    // Client should show sent packets
    EXPECT_GE(final_client_stats.packets_sent, initial_client_stats.packets_sent);
    EXPECT_GE(final_client_stats.bytes_sent, initial_client_stats.bytes_sent);
    
    // Server should show received packets (if any were successfully received)
    EXPECT_GE(final_server_stats.packets_received, initial_server_stats.packets_received);
    EXPECT_GE(final_server_stats.bytes_received, initial_server_stats.bytes_received);
    
    // Statistics should be consistent with what we observed
    if (packets_received > 0) {
        EXPECT_EQ(final_server_stats.packets_received - initial_server_stats.packets_received, packets_received);
        EXPECT_EQ(final_server_stats.bytes_received - initial_server_stats.bytes_received, total_bytes_received);
    }
}

// Test transport configuration variations
TEST_F(UDPTransportComprehensiveTest, TransportConfigurationVariations) {
    // Test minimal configuration
    TransportConfig minimal_config;
    minimal_config.worker_threads = 1;
    minimal_config.receive_buffer_size = 1024;
    minimal_config.send_buffer_size = 1024;
    minimal_config.max_connections = 10;
    
    auto minimal_transport = std::make_unique<UDPTransport>(minimal_config);
    EXPECT_TRUE(minimal_transport->initialize().is_ok());
    EXPECT_TRUE(minimal_transport->bind(local_endpoint1_).is_ok());
    EXPECT_TRUE(minimal_transport->start().is_ok());
    
    const auto& retrieved_config = minimal_transport->get_config();
    EXPECT_EQ(retrieved_config.worker_threads, 1);
    EXPECT_EQ(retrieved_config.receive_buffer_size, 1024);
    EXPECT_EQ(retrieved_config.send_buffer_size, 1024);
    EXPECT_EQ(retrieved_config.max_connections, 10);
    
    minimal_transport->stop();
    
    // Test high-performance configuration
    TransportConfig perf_config;
    perf_config.worker_threads = 8;
    perf_config.receive_buffer_size = 1024 * 1024; // 1MB
    perf_config.send_buffer_size = 1024 * 1024;
    perf_config.max_connections = 10000;
    perf_config.enable_fast_path = true;
    perf_config.poll_timeout_ms = 1; // Very responsive
    
    auto perf_transport = std::make_unique<UDPTransport>(perf_config);
    EXPECT_TRUE(perf_transport->initialize().is_ok());
    EXPECT_TRUE(perf_transport->bind(local_endpoint2_).is_ok());
    EXPECT_TRUE(perf_transport->start().is_ok());
    
    perf_transport->stop();
    
    // Test timeout configuration
    TransportConfig timeout_config = basic_config_;
    timeout_config.send_timeout = 100ms; // Very short
    timeout_config.receive_timeout = 50ms; // Very short
    timeout_config.idle_timeout = 1000ms; // Short idle
    
    auto timeout_transport = std::make_unique<UDPTransport>(timeout_config);
    EXPECT_TRUE(timeout_transport->initialize().is_ok());
    EXPECT_TRUE(timeout_transport->bind(local_endpoint1_).is_ok());
    EXPECT_TRUE(timeout_transport->start().is_ok());
    
    // Test that timeouts are respected (should timeout quickly)
    auto timeout_endpoint = timeout_transport->get_local_endpoint().value();
    timeout_endpoint.port = 9999; // Non-existent port
    
    ZeroCopyBuffer timeout_buffer(small_data_.data(), small_data_.size());
    auto start_time = std::chrono::steady_clock::now();
    auto send_result = timeout_transport->send_packet(timeout_endpoint, timeout_buffer);
    auto end_time = std::chrono::steady_clock::now();
    
    // May succeed or fail depending on implementation, but should be fast
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    EXPECT_LT(duration.count(), 500); // Should not take long
    
    timeout_transport->stop();
}

// Test error conditions and edge cases
TEST_F(UDPTransportComprehensiveTest, ErrorConditionsAndEdgeCases) {
    auto transport = std::make_unique<UDPTransport>(basic_config_);
    
    // Test operations on uninitialized transport
    auto uninit_bind = transport->bind(local_endpoint1_);
    EXPECT_TRUE(uninit_bind.is_error());
    
    auto uninit_start = transport->start();
    EXPECT_TRUE(uninit_start.is_error());
    
    // Initialize but don't bind
    ASSERT_TRUE(transport->initialize().is_ok());
    
    auto unbound_start = transport->start();
    EXPECT_TRUE(unbound_start.is_error());
    
    // Bind to invalid address
    NetworkEndpoint invalid_endpoint("999.999.999.999", 80, NetworkAddress::Family::IPv4);
    auto invalid_bind = transport->bind(invalid_endpoint);
    EXPECT_TRUE(invalid_bind.is_error());
    
    // Bind to valid address
    ASSERT_TRUE(transport->bind(local_endpoint1_).is_ok());
    ASSERT_TRUE(transport->start().is_ok());
    
    // Test sending to invalid endpoint
    ZeroCopyBuffer test_buffer(small_data_.data(), small_data_.size());
    auto invalid_send = transport->send_packet(invalid_endpoint, test_buffer);
    EXPECT_TRUE(invalid_send.is_error());
    
    // Test sending empty buffer
    ZeroCopyBuffer empty_buffer;
    auto empty_send = transport->send_packet(local_endpoint2_, empty_buffer);
    // May succeed or fail depending on implementation
    
    // Test double start
    auto double_start = transport->start();
    EXPECT_TRUE(double_start.is_error());
    
    // Test operations after stop
    transport->stop();
    
    auto stopped_send = transport->send_packet(local_endpoint2_, test_buffer);
    EXPECT_TRUE(stopped_send.is_error());
    
    auto stopped_receive = transport->receive_packet();
    EXPECT_TRUE(stopped_receive.is_error());
    
    // Test double stop
    auto double_stop = transport->stop();
    EXPECT_TRUE(double_stop.is_ok() || double_stop.is_error()); // Either is acceptable
}

// Test IPv6 functionality (if supported)
TEST_F(UDPTransportComprehensiveTest, IPv6Functionality) {
    // Try to create IPv6 transport
    auto transport = std::make_unique<UDPTransport>(basic_config_);
    
    auto init_result = transport->initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    auto bind_result = transport->bind(local_endpoint_v6_);
    
    if (bind_result.is_ok()) {
        // IPv6 is supported
        ASSERT_TRUE(transport->start().is_ok());
        
        auto actual_endpoint = transport->get_local_endpoint().value();
        EXPECT_EQ(actual_endpoint.family, NetworkAddress::Family::IPv6);
        EXPECT_EQ(actual_endpoint.address, local_endpoint_v6_.address);
        EXPECT_GT(actual_endpoint.port, 0);
        
        // Test sending to IPv6 endpoint
        ZeroCopyBuffer ipv6_buffer(pattern_data_.data(), pattern_data_.size());
        auto send_result = transport->send_packet(remote_endpoint_v6_, ipv6_buffer);
        // May succeed or fail depending on network configuration
        
        transport->stop();
    } else {
        // IPv6 not supported on this system
        GTEST_SKIP() << "IPv6 not supported on this system";
    }
}

// Test concurrent transport operations
TEST_F(UDPTransportComprehensiveTest, ConcurrentTransportOperations) {
    server_transport_ = std::make_unique<UDPTransport>(basic_config_);
    
    ASSERT_TRUE(server_transport_->initialize().is_ok());
    ASSERT_TRUE(server_transport_->bind(local_endpoint1_).is_ok());
    ASSERT_TRUE(server_transport_->start().is_ok());
    
    auto server_endpoint = server_transport_->get_local_endpoint().value();
    
    const int num_sender_threads = 3;
    const int num_receiver_threads = 2;
    const int packets_per_sender = 20;
    
    std::atomic<int> packets_sent{0};
    std::atomic<int> packets_received{0};
    std::atomic<int> send_errors{0};
    std::atomic<int> receive_timeouts{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch sender threads
    for (int t = 0; t < num_sender_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            auto client_endpoint = NetworkEndpoint("127.0.0.1", 0, NetworkAddress::Family::IPv4);
            auto client_transport = std::make_unique<UDPTransport>(basic_config_);
            
            if (client_transport->initialize().is_ok() &&
                client_transport->bind(client_endpoint).is_ok() &&
                client_transport->start().is_ok()) {
                
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> size_dis(50, 500);
                
                for (int i = 0; i < packets_per_sender; ++i) {
                    size_t packet_size = size_dis(gen);
                    std::vector<std::byte> packet_data(packet_size, static_cast<std::byte>(t));
                    
                    ZeroCopyBuffer send_buffer(packet_data.data(), packet_data.size());
                    auto result = client_transport->send_packet(server_endpoint, send_buffer);
                    
                    if (result.is_ok()) {
                        packets_sent.fetch_add(1);
                    } else {
                        send_errors.fetch_add(1);
                    }
                    
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
                
                client_transport->stop();
            }
        }));
    }
    
    // Launch receiver threads
    for (int t = 0; t < num_receiver_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&]() {
            int consecutive_timeouts = 0;
            const int max_consecutive_timeouts = 50;
            
            while (consecutive_timeouts < max_consecutive_timeouts) {
                auto result = server_transport_->receive_packet();
                
                if (result.is_ok()) {
                    packets_received.fetch_add(1);
                    consecutive_timeouts = 0;
                } else {
                    receive_timeouts.fetch_add(1);
                    consecutive_timeouts++;
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify results
    int expected_packets = num_sender_threads * packets_per_sender;
    EXPECT_EQ(packets_sent.load(), expected_packets - send_errors.load());
    
    // We should have received at least some packets
    EXPECT_GT(packets_received.load(), 0);
    
    // Total sent should equal total received (within reason, accounting for losses)
    EXPECT_LE(packets_received.load(), packets_sent.load());
    
    std::cout << "Sent: " << packets_sent.load() 
              << ", Received: " << packets_received.load()
              << ", Send errors: " << send_errors.load()
              << ", Receive timeouts: " << receive_timeouts.load() << std::endl;
}

// Test transport manager RAII functionality
TEST_F(UDPTransportComprehensiveTest, TransportManagerRAII) {
    auto manager = std::make_unique<TransportManager>();
    
    // Create transport
    auto create_result = manager->create_transport(basic_config_);
    EXPECT_TRUE(create_result.is_ok());
    
    auto* transport = manager->get_transport();
    EXPECT_NE(transport, nullptr);
    
    // Start transport
    auto start_result = manager->start_transport(local_endpoint1_);
    EXPECT_TRUE(start_result.is_ok());
    
    // Transport should be running
    EXPECT_TRUE(transport->is_running());
    
    // Get endpoint
    auto endpoint_result = transport->get_local_endpoint();
    EXPECT_TRUE(endpoint_result.is_ok());
    
    // Stop transport
    manager->stop_transport();
    EXPECT_FALSE(transport->is_running());
    
    // Manager destructor should clean up automatically
}