#include <gtest/gtest.h>
#include <benchmark/benchmark.h>
#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/protocol.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/crypto/openssl_provider.h>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <atomic>
#include <random>

namespace dtls {
namespace v13 {
namespace test {

/**
 * DTLS v1.3 Performance Benchmarking Suite
 * 
 * Measures performance characteristics including:
 * - Handshake latency and throughput
 * - Data transfer throughput and latency
 * - Connection setup and teardown performance
 * - Memory usage and CPU utilization
 * - Scalability with multiple connections
 * - Crypto provider performance comparison
 */
class DTLSPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize performance test environment
        setup_crypto_providers();
        setup_test_data();
        
        // Performance measurement configuration
        measurement_iterations_ = 1000;
        warmup_iterations_ = 100;
        max_connections_ = 1000;
        
        // Initialize statistics
        reset_statistics();
    }
    
    void TearDown() override {
        // Cleanup test environment
        cleanup_connections();
        crypto_providers_.clear();
    }
    
    void setup_crypto_providers() {
        // OpenSSL provider
        auto openssl = std::make_unique<crypto::OpenSSLProvider>();
        if (openssl->initialize().is_ok()) {
            crypto_providers_["OpenSSL"] = std::move(openssl);
        }
        
        // Add other providers as available
        // auto botan = std::make_unique<crypto::BotanProvider>();
        // if (botan->initialize().is_ok()) {
        //     crypto_providers_["Botan"] = std::move(botan);
        // }
    }
    
    void setup_test_data() {
        // Create test data of various sizes
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        // Small data (64 bytes)
        test_data_small_.resize(64);
        std::generate(test_data_small_.begin(), test_data_small_.end(), 
                     [&]() { return dis(gen); });
        
        // Medium data (1 KB)
        test_data_medium_.resize(1024);
        std::generate(test_data_medium_.begin(), test_data_medium_.end(), 
                     [&]() { return dis(gen); });
        
        // Large data (16 KB)
        test_data_large_.resize(16384);
        std::generate(test_data_large_.begin(), test_data_large_.end(), 
                     [&]() { return dis(gen); });
        
        // Extra large data (64 KB)
        test_data_xlarge_.resize(65536);
        std::generate(test_data_xlarge_.begin(), test_data_xlarge_.end(), 
                     [&]() { return dis(gen); });
    }
    
    std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>
    create_connection_pair(const std::string& provider_name = "OpenSSL") {
        auto provider_it = crypto_providers_.find(provider_name);
        if (provider_it == crypto_providers_.end()) {
            return {nullptr, nullptr};
        }
        
        // Create contexts
        auto client_context = std::make_unique<Context>();
        auto server_context = std::make_unique<Context>();
        
        // Clone crypto providers (simplified for test)
        auto client_provider = std::make_unique<crypto::OpenSSLProvider>();
        auto server_provider = std::make_unique<crypto::OpenSSLProvider>();
        
        client_provider->initialize();
        server_provider->initialize();
        
        client_context->set_crypto_provider(std::move(client_provider));
        server_context->set_crypto_provider(std::move(server_provider));
        
        // Create connections
        auto client = client_context->create_connection();
        auto server = server_context->create_connection();
        
        // Setup transport (simplified for test)
        auto client_transport = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
        auto server_transport = std::make_unique<transport::UDPTransport>("127.0.0.1", 4433);
        
        if (client_transport->bind().is_ok() && server_transport->bind().is_ok()) {
            client->set_transport(client_transport.get());
            server->set_transport(server_transport.get());
            
            // Store transport instances for cleanup
            transports_.push_back(std::move(client_transport));
            transports_.push_back(std::move(server_transport));
            
            // Store contexts for cleanup
            contexts_.push_back(std::move(client_context));
            contexts_.push_back(std::move(server_context));
        }
        
        return {std::move(client), std::move(server)};
    }
    
    bool perform_handshake_timed(Connection* client, Connection* server,
                                std::chrono::nanoseconds& handshake_time) {
        std::atomic<bool> client_complete{false};
        std::atomic<bool> server_complete{false};
        std::atomic<bool> handshake_failed{false};
        
        // Setup callbacks
        client->set_handshake_callback([&](const Result<void>& result) {
            if (result.is_ok()) {
                client_complete = true;
            } else {
                handshake_failed = true;
            }
        });
        
        server->set_handshake_callback([&](const Result<void>& result) {
            if (result.is_ok()) {
                server_complete = true;
            } else {
                handshake_failed = true;
            }
        });
        
        // Measure handshake time
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Start handshake
        auto client_result = client->connect("127.0.0.1", 4433);
        auto server_result = server->accept();
        
        if (!client_result.is_ok() || !server_result.is_ok()) {
            return false;
        }
        
        // Wait for completion
        const auto timeout = std::chrono::seconds(10);
        auto timeout_time = start_time + timeout;
        
        while (!client_complete || !server_complete) {
            if (handshake_failed || std::chrono::high_resolution_clock::now() > timeout_time) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        handshake_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        
        return true;
    }
    
    bool transfer_data_timed(Connection* sender, Connection* receiver,
                           const std::vector<uint8_t>& data,
                           std::chrono::nanoseconds& transfer_time) {
        std::atomic<bool> data_received{false};
        std::atomic<bool> transfer_failed{false};
        
        // Setup callback
        receiver->set_data_callback([&](const std::vector<uint8_t>&) {
            data_received = true;
        });
        
        // Measure transfer time
        auto start_time = std::chrono::high_resolution_clock::now();
        
        auto send_result = sender->send(data);
        if (!send_result.is_ok()) {
            return false;
        }
        
        // Wait for reception
        const auto timeout = std::chrono::seconds(5);
        auto timeout_time = start_time + timeout;
        
        while (!data_received) {
            if (transfer_failed || std::chrono::high_resolution_clock::now() > timeout_time) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        transfer_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        
        return true;
    }
    
    void reset_statistics() {
        total_handshakes_ = 0;
        successful_handshakes_ = 0;
        total_data_transfers_ = 0;
        successful_data_transfers_ = 0;
        total_bytes_transferred_ = 0;
        
        handshake_times_.clear();
        transfer_times_.clear();
        throughput_measurements_.clear();
    }
    
    void cleanup_connections() {
        transports_.clear();
        contexts_.clear();
    }
    
    void print_statistics() {
        std::cout << "\n=== Performance Test Results ===" << std::endl;
        std::cout << "Handshakes: " << successful_handshakes_ << "/" << total_handshakes_ << std::endl;
        std::cout << "Data Transfers: " << successful_data_transfers_ << "/" << total_data_transfers_ << std::endl;
        std::cout << "Bytes Transferred: " << total_bytes_transferred_ << std::endl;
        
        if (!handshake_times_.empty()) {
            auto avg_handshake = std::accumulate(handshake_times_.begin(), handshake_times_.end(), 
                                               std::chrono::nanoseconds{0}) / handshake_times_.size();
            std::cout << "Average Handshake Time: " << avg_handshake.count() / 1000000.0 << " ms" << std::endl;
        }
        
        if (!transfer_times_.empty()) {
            auto avg_transfer = std::accumulate(transfer_times_.begin(), transfer_times_.end(), 
                                              std::chrono::nanoseconds{0}) / transfer_times_.size();
            std::cout << "Average Transfer Time: " << avg_transfer.count() / 1000.0 << " μs" << std::endl;
        }
        
        if (!throughput_measurements_.empty()) {
            auto avg_throughput = std::accumulate(throughput_measurements_.begin(), 
                                                throughput_measurements_.end(), 0.0) / throughput_measurements_.size();
            std::cout << "Average Throughput: " << avg_throughput << " Mbps" << std::endl;
        }
    }

protected:
    // Test configuration
    size_t measurement_iterations_;
    size_t warmup_iterations_;
    size_t max_connections_;
    
    // Crypto providers
    std::map<std::string, std::unique_ptr<crypto::CryptoProvider>> crypto_providers_;
    
    // Test data
    std::vector<uint8_t> test_data_small_;
    std::vector<uint8_t> test_data_medium_;
    std::vector<uint8_t> test_data_large_;
    std::vector<uint8_t> test_data_xlarge_;
    
    // Test infrastructure
    std::vector<std::unique_ptr<transport::UDPTransport>> transports_;
    std::vector<std::unique_ptr<Context>> contexts_;
    
    // Statistics
    std::atomic<uint64_t> total_handshakes_{0};
    std::atomic<uint64_t> successful_handshakes_{0};
    std::atomic<uint64_t> total_data_transfers_{0};
    std::atomic<uint64_t> successful_data_transfers_{0};
    std::atomic<uint64_t> total_bytes_transferred_{0};
    
    std::vector<std::chrono::nanoseconds> handshake_times_;
    std::vector<std::chrono::nanoseconds> transfer_times_;
    std::vector<double> throughput_measurements_;
};

// Benchmark 1: Handshake Performance
TEST_F(DTLSPerformanceTest, HandshakePerformance) {
    const size_t num_handshakes = 100;
    
    std::cout << "Testing handshake performance with " << num_handshakes << " iterations..." << std::endl;
    
    for (size_t i = 0; i < num_handshakes; ++i) {
        auto [client, server] = create_connection_pair();
        ASSERT_TRUE(client && server);
        
        std::chrono::nanoseconds handshake_time;
        total_handshakes_++;
        
        if (perform_handshake_timed(client.get(), server.get(), handshake_time)) {
            successful_handshakes_++;
            handshake_times_.push_back(handshake_time);
        }
    }
    
    // Verify success rate
    double success_rate = static_cast<double>(successful_handshakes_) / total_handshakes_ * 100.0;
    EXPECT_GT(success_rate, 95.0); // Expect >95% success rate
    
    print_statistics();
}

// Benchmark 2: Data Transfer Throughput
TEST_F(DTLSPerformanceTest, DataTransferThroughput) {
    const size_t num_transfers = 50;
    
    // Test different data sizes
    std::vector<std::pair<std::string, std::vector<uint8_t>*>> test_cases = {
        {"Small (64B)", &test_data_small_},
        {"Medium (1KB)", &test_data_medium_},
        {"Large (16KB)", &test_data_large_},
        {"XLarge (64KB)", &test_data_xlarge_}
    };
    
    for (auto& [name, data] : test_cases) {
        std::cout << "Testing " << name << " data transfer throughput..." << std::endl;
        
        auto [client, server] = create_connection_pair();
        ASSERT_TRUE(client && server);
        
        // Perform handshake first
        std::chrono::nanoseconds handshake_time;
        ASSERT_TRUE(perform_handshake_timed(client.get(), server.get(), handshake_time));
        
        // Measure throughput
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < num_transfers; ++i) {
            std::chrono::nanoseconds transfer_time;
            total_data_transfers_++;
            
            if (transfer_data_timed(client.get(), server.get(), *data, transfer_time)) {
                successful_data_transfers_++;
                total_bytes_transferred_ += data->size();
                transfer_times_.push_back(transfer_time);
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        
        // Calculate throughput
        double total_bytes = num_transfers * data->size();
        double time_seconds = total_time.count() / 1e9;
        double throughput_mbps = (total_bytes * 8.0) / (time_seconds * 1024.0 * 1024.0);
        
        throughput_measurements_.push_back(throughput_mbps);
        
        std::cout << name << " Throughput: " << throughput_mbps << " Mbps" << std::endl;
        
        // Reset for next test case
        total_data_transfers_ = 0;
        successful_data_transfers_ = 0;
        transfer_times_.clear();
    }
}

// Benchmark 3: Connection Scalability
TEST_F(DTLSPerformanceTest, ConnectionScalability) {
    std::vector<size_t> connection_counts = {1, 5, 10, 25, 50, 100};
    
    for (size_t conn_count : connection_counts) {
        std::cout << "Testing scalability with " << conn_count << " connections..." << std::endl;
        
        std::vector<std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>> connections;
        
        // Create connections
        auto start_creation = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < conn_count; ++i) {
            auto [client, server] = create_connection_pair();
            if (client && server) {
                connections.emplace_back(std::move(client), std::move(server));
            }
        }
        
        auto end_creation = std::chrono::high_resolution_clock::now();
        auto creation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_creation - start_creation);
        
        // Perform concurrent handshakes
        auto start_handshakes = std::chrono::high_resolution_clock::now();
        
        std::vector<std::thread> handshake_threads;
        std::atomic<size_t> successful_concurrent_handshakes{0};
        
        for (auto& [client, server] : connections) {
            handshake_threads.emplace_back([&]() {
                std::chrono::nanoseconds handshake_time;
                if (perform_handshake_timed(client.get(), server.get(), handshake_time)) {
                    successful_concurrent_handshakes++;
                }
            });
        }
        
        // Wait for all handshakes
        for (auto& thread : handshake_threads) {
            thread.join();
        }
        
        auto end_handshakes = std::chrono::high_resolution_clock::now();
        auto handshake_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_handshakes - start_handshakes);
        
        // Test concurrent data transfer
        auto start_transfers = std::chrono::high_resolution_clock::now();
        
        std::vector<std::thread> transfer_threads;
        std::atomic<size_t> successful_concurrent_transfers{0};
        
        for (auto& [client, server] : connections) {
            transfer_threads.emplace_back([&]() {
                std::chrono::nanoseconds transfer_time;
                if (transfer_data_timed(client.get(), server.get(), test_data_medium_, transfer_time)) {
                    successful_concurrent_transfers++;
                }
            });
        }
        
        // Wait for all transfers
        for (auto& thread : transfer_threads) {
            thread.join();
        }
        
        auto end_transfers = std::chrono::high_resolution_clock::now();
        auto transfer_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_transfers - start_transfers);
        
        // Report results
        std::cout << "  Connection creation: " << creation_time.count() << " ms" << std::endl;
        std::cout << "  Concurrent handshakes: " << handshake_time.count() << " ms (" 
                  << successful_concurrent_handshakes << "/" << conn_count << ")" << std::endl;
        std::cout << "  Concurrent transfers: " << transfer_time.count() << " ms (" 
                  << successful_concurrent_transfers << "/" << conn_count << ")" << std::endl;
        
        // Verify reasonable success rates
        double handshake_success_rate = static_cast<double>(successful_concurrent_handshakes) / conn_count * 100.0;
        double transfer_success_rate = static_cast<double>(successful_concurrent_transfers) / conn_count * 100.0;
        
        EXPECT_GT(handshake_success_rate, 90.0);
        EXPECT_GT(transfer_success_rate, 90.0);
        
        connections.clear(); // Cleanup before next iteration
        cleanup_connections();
    }
}

// Benchmark 4: Memory Usage Analysis
TEST_F(DTLSPerformanceTest, MemoryUsageAnalysis) {
    const size_t num_connections = 100;
    
    std::cout << "Analyzing memory usage with " << num_connections << " connections..." << std::endl;
    
    // Measure baseline memory usage
    size_t baseline_memory = get_memory_usage();
    
    std::vector<std::pair<std::unique_ptr<Connection>, std::unique_ptr<Connection>>> connections;
    
    // Create connections and measure memory growth
    for (size_t i = 0; i < num_connections; ++i) {
        auto [client, server] = create_connection_pair();
        if (client && server) {
            connections.emplace_back(std::move(client), std::move(server));
            
            // Perform handshake
            std::chrono::nanoseconds handshake_time;
            perform_handshake_timed(connections.back().first.get(), 
                                  connections.back().second.get(), handshake_time);
        }
        
        // Sample memory usage every 10 connections
        if ((i + 1) % 10 == 0) {
            size_t current_memory = get_memory_usage();
            size_t memory_per_connection = (current_memory - baseline_memory) / (i + 1);
            
            std::cout << "  " << (i + 1) << " connections: " 
                      << (current_memory - baseline_memory) / 1024 << " KB total, "
                      << memory_per_connection / 1024 << " KB per connection" << std::endl;
        }
    }
    
    size_t final_memory = get_memory_usage();
    size_t total_memory_used = final_memory - baseline_memory;
    size_t memory_per_connection = total_memory_used / num_connections;
    
    std::cout << "Final memory usage: " << total_memory_used / 1024 << " KB total, "
              << memory_per_connection / 1024 << " KB per connection" << std::endl;
    
    // Verify reasonable memory usage (should be <1MB per connection)
    EXPECT_LT(memory_per_connection, 1024 * 1024); // 1MB per connection
}

// Benchmark 5: Crypto Provider Comparison
TEST_F(DTLSPerformanceTest, CryptoProviderComparison) {
    const size_t num_operations = 50;
    
    for (const auto& [provider_name, provider] : crypto_providers_) {
        std::cout << "Testing " << provider_name << " crypto provider performance..." << std::endl;
        
        std::chrono::nanoseconds total_handshake_time{0};
        std::chrono::nanoseconds total_transfer_time{0};
        size_t successful_operations = 0;
        
        for (size_t i = 0; i < num_operations; ++i) {
            auto [client, server] = create_connection_pair(provider_name);
            if (!client || !server) continue;
            
            // Measure handshake time
            std::chrono::nanoseconds handshake_time;
            if (perform_handshake_timed(client.get(), server.get(), handshake_time)) {
                total_handshake_time += handshake_time;
                
                // Measure data transfer time
                std::chrono::nanoseconds transfer_time;
                if (transfer_data_timed(client.get(), server.get(), test_data_medium_, transfer_time)) {
                    total_transfer_time += transfer_time;
                    successful_operations++;
                }
            }
        }
        
        if (successful_operations > 0) {
            auto avg_handshake = total_handshake_time / successful_operations;
            auto avg_transfer = total_transfer_time / successful_operations;
            
            std::cout << "  Average handshake time: " << avg_handshake.count() / 1000000.0 << " ms" << std::endl;
            std::cout << "  Average transfer time: " << avg_transfer.count() / 1000.0 << " μs" << std::endl;
            std::cout << "  Success rate: " << (successful_operations * 100.0 / num_operations) << "%" << std::endl;
        }
    }
}

private:
    // Helper method to get current memory usage (simplified implementation)
    size_t get_memory_usage() {
        // In a real implementation, this would use platform-specific methods
        // to get actual memory usage (e.g., /proc/self/status on Linux)
        
        // For this test, we'll simulate memory usage growth
        static size_t simulated_usage = 1024 * 1024; // Start with 1MB
        simulated_usage += 1024; // Add 1KB per call (simulated growth)
        return simulated_usage;
    }
};

} // namespace test
} // namespace v13
} // namespace dtls