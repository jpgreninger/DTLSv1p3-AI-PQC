/*
 * DTLS v1.3 Throughput Performance Benchmarks
 * Task 10: Performance Benchmarking - Throughput and Data Transfer Tests
 */

#include "benchmark_framework.h"
#include <dtls/connection/connection_manager.h>
#include <dtls/protocol/dtls_records.h>
#include "../test_infrastructure/test_certificates.h"
#include "../test_infrastructure/mock_transport.h"
#include <chrono>
#include <thread>
#include <future>
#include <numeric>

namespace dtls::v13::test::performance {

// ============================================================================
// ThroughputBenchmark Implementation
// ============================================================================

class ThroughputBenchmark::Impl {
public:
    BenchmarkConfig config_;
    bool encryption_enabled_ = true;
    bool compression_enabled_ = false;
    double packet_loss_rate_ = 0.0;
    
    std::unique_ptr<test::infrastructure::TestCertificates> test_certs_;
    std::unique_ptr<test::infrastructure::MockTransport> mock_transport_;
    
    Impl(const BenchmarkConfig& config) : config_(config) {
        setup_test_infrastructure();
    }
    
    void setup_test_infrastructure() {
        test_certs_ = std::make_unique<test::infrastructure::TestCertificates>();
        mock_transport_ = std::make_unique<test::infrastructure::MockTransport>();
        
        // Configure mock transport for throughput testing
        mock_transport_->set_packet_loss_rate(packet_loss_rate_);
        mock_transport_->set_network_delay(std::chrono::microseconds(50)); // Minimal delay
        mock_transport_->set_bandwidth_limit(0); // No artificial bandwidth limit
        mock_transport_->set_mtu(1400); // Typical MTU
    }
    
    BenchmarkResult benchmark_application_data_throughput_impl(size_t data_size) {
        BenchmarkRunner runner(config_);
        
        std::vector<uint8_t> test_data = generate_test_data(data_size);
        size_t bytes_transferred = 0;
        
        runner.register_benchmark("Throughput_" + std::to_string(data_size) + "_bytes", 
        [this, &test_data, &bytes_transferred]() {
            bytes_transferred += transfer_application_data(test_data);
        }, [this]() {
            setup_connection_pair();
        }, [this]() {
            cleanup_connections();
        });
        
        auto results = runner.run_all_benchmarks();
        if (!results.empty()) {
            auto& result = results[0];
            
            // Calculate throughput metrics
            double total_time_seconds = result.mean_time_ms / 1000.0;
            double total_mb = static_cast<double>(bytes_transferred * config_.iterations) / (1024.0 * 1024.0);
            
            result.throughput_mbps = total_mb / total_time_seconds * 8.0; // Convert MB/s to Mbps
            result.total_bytes_processed = bytes_transferred * config_.iterations;
            
            // PRD compliance: Should achieve >90% of UDP throughput
            double udp_baseline = measure_udp_baseline_throughput(test_data.size());
            result.meets_throughput_requirement = (result.throughput_mbps / udp_baseline) >= 0.90;
            
            return result;
        }
        
        return BenchmarkResult{};
    }
    
    BenchmarkResult benchmark_concurrent_connections_impl(size_t connection_count) {
        BenchmarkRunner runner(config_);
        
        std::vector<std::pair<std::shared_ptr<connection::Connection>, 
                             std::shared_ptr<connection::Connection>>> connections;
        std::vector<uint8_t> test_data = generate_test_data(1024); // 1KB per connection
        
        runner.register_benchmark("Concurrent_" + std::to_string(connection_count) + "_connections",
        [this, &connections, &test_data]() {
            transfer_data_concurrent(connections, test_data);
        }, [this, &connections, connection_count]() {
            connections = setup_multiple_connections(connection_count);
        }, [this, &connections]() {
            cleanup_multiple_connections(connections);
        });
        
        auto results = runner.run_all_benchmarks();
        if (!results.empty()) {
            auto& result = results[0];
            
            // Calculate aggregate throughput
            double total_time_seconds = result.mean_time_ms / 1000.0;
            size_t total_bytes = test_data.size() * connection_count * config_.iterations;
            double total_mb = static_cast<double>(total_bytes) / (1024.0 * 1024.0);
            
            result.throughput_mbps = total_mb / total_time_seconds * 8.0;
            result.total_bytes_processed = total_bytes;
            
            return result;
        }
        
        return BenchmarkResult{};
    }
    
    BenchmarkResult benchmark_streaming_throughput_impl(size_t stream_duration_ms) {
        BenchmarkRunner runner(config_);
        
        size_t bytes_streamed = 0;
        std::vector<uint8_t> chunk_data = generate_test_data(4096); // 4KB chunks
        
        runner.register_benchmark("Streaming_" + std::to_string(stream_duration_ms) + "ms",
        [this, &bytes_streamed, &chunk_data, stream_duration_ms]() {
            bytes_streamed += perform_streaming_transfer(chunk_data, stream_duration_ms);
        }, [this]() {
            setup_connection_pair();
        }, [this]() {
            cleanup_connections();
        });
        
        auto results = runner.run_all_benchmarks();
        if (!results.empty()) {
            auto& result = results[0];
            
            // Calculate streaming throughput
            double total_time_seconds = result.mean_time_ms / 1000.0;
            double total_mb = static_cast<double>(bytes_streamed * config_.iterations) / (1024.0 * 1024.0);
            
            result.throughput_mbps = total_mb / total_time_seconds * 8.0;
            result.total_bytes_processed = bytes_streamed * config_.iterations;
            
            return result;
        }
        
        return BenchmarkResult{};
    }
    
    BenchmarkResult benchmark_udp_comparison_impl(size_t data_size) {
        // First measure DTLS throughput
        auto dtls_result = benchmark_application_data_throughput_impl(data_size);
        
        // Then measure plain UDP throughput
        double udp_throughput = measure_udp_baseline_throughput(data_size);
        
        // Calculate overhead
        double overhead_percent = 0.0;
        if (udp_throughput > 0) {
            overhead_percent = ((udp_throughput - dtls_result.throughput_mbps) / udp_throughput) * 100.0;
        }
        
        dtls_result.name = "DTLS_vs_UDP_" + std::to_string(data_size) + "_bytes";
        dtls_result.custom_metrics["udp_throughput_mbps"] = udp_throughput;
        dtls_result.custom_metrics["overhead_percent"] = overhead_percent;
        
        // PRD compliance: <5% overhead vs plain UDP
        dtls_result.meets_throughput_requirement = overhead_percent < 5.0;
        
        return dtls_result;
    }
    
private:
    std::shared_ptr<connection::Connection> client_connection_;
    std::shared_ptr<connection::Connection> server_connection_;
    
    void setup_connection_pair() {
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        connection::ConnectionManager client_manager(client_config);
        connection::ConnectionManager server_manager(server_config);
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        client_connection_ = client_manager.create_connection(client_endpoint);
        server_connection_ = server_manager.accept_connection(server_endpoint);
        
        // Complete handshake
        complete_handshake(client_connection_, server_connection_);
    }
    
    void cleanup_connections() {
        if (client_connection_) {
            client_connection_->close();
            client_connection_.reset();
        }
        if (server_connection_) {
            server_connection_->close();
            server_connection_.reset();
        }
        mock_transport_->reset();
    }
    
    std::vector<std::pair<std::shared_ptr<connection::Connection>, 
                         std::shared_ptr<connection::Connection>>> 
    setup_multiple_connections(size_t count) {
        std::vector<std::pair<std::shared_ptr<connection::Connection>, 
                             std::shared_ptr<connection::Connection>>> connections;
        
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        for (size_t i = 0; i < count; ++i) {
            connection::ConnectionManager client_manager(client_config);
            connection::ConnectionManager server_manager(server_config);
            
            std::string client_name = "client_" + std::to_string(i);
            std::string server_name = "server_" + std::to_string(i);
            
            auto client_endpoint = mock_transport_->create_endpoint(client_name);
            auto server_endpoint = mock_transport_->create_endpoint(server_name);
            mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
            
            auto client_conn = client_manager.create_connection(client_endpoint);
            auto server_conn = server_manager.accept_connection(server_endpoint);
            
            // Complete handshake for each connection
            complete_handshake(client_conn, server_conn);
            
            connections.push_back({client_conn, server_conn});
        }
        
        return connections;
    }
    
    void cleanup_multiple_connections(std::vector<std::pair<std::shared_ptr<connection::Connection>, 
                                                           std::shared_ptr<connection::Connection>>>& connections) {
        for (auto& [client, server] : connections) {
            if (client) client->close();
            if (server) server->close();
        }
        connections.clear();
        mock_transport_->reset();
    }
    
    size_t transfer_application_data(const std::vector<uint8_t>& data) {
        if (!client_connection_ || !server_connection_) {
            throw std::runtime_error("Connections not established");
        }
        
        // Send data from client to server
        size_t bytes_sent = client_connection_->send_application_data(data);
        
        // Process network messages
        mock_transport_->process_pending_messages();
        
        // Receive data on server side
        server_connection_->process_incoming_data();
        auto received_data = server_connection_->receive_application_data();
        
        if (received_data.size() != data.size()) {
            throw std::runtime_error("Data transfer incomplete: sent " + 
                                   std::to_string(data.size()) + ", received " + 
                                   std::to_string(received_data.size()));
        }
        
        return bytes_sent;
    }
    
    void transfer_data_concurrent(const std::vector<std::pair<std::shared_ptr<connection::Connection>, 
                                                             std::shared_ptr<connection::Connection>>>& connections,
                                 const std::vector<uint8_t>& data) {
        
        std::vector<std::future<void>> futures;
        
        for (const auto& [client, server] : connections) {
            futures.push_back(std::async(std::launch::async, [client, server, &data]() {
                client->send_application_data(data);
                server->process_incoming_data();
                auto received = server->receive_application_data();
                if (received.size() != data.size()) {
                    throw std::runtime_error("Concurrent transfer failed");
                }
            }));
        }
        
        // Process network messages
        mock_transport_->process_pending_messages();
        
        // Wait for all transfers to complete
        for (auto& future : futures) {
            future.get();
        }
    }
    
    size_t perform_streaming_transfer(const std::vector<uint8_t>& chunk_data, size_t duration_ms) {
        if (!client_connection_ || !server_connection_) {
            throw std::runtime_error("Connections not established");
        }
        
        size_t total_bytes = 0;
        auto start_time = std::chrono::high_resolution_clock::now();
        auto end_time = start_time + std::chrono::milliseconds(duration_ms);
        
        while (std::chrono::high_resolution_clock::now() < end_time) {
            // Send chunk
            size_t bytes_sent = client_connection_->send_application_data(chunk_data);
            total_bytes += bytes_sent;
            
            // Process network and receive
            mock_transport_->process_pending_messages();
            server_connection_->process_incoming_data();
            server_connection_->receive_application_data();
            
            // Small delay to prevent overwhelming
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        return total_bytes;
    }
    
    double measure_udp_baseline_throughput(size_t data_size) {
        // Create a plain UDP transport for baseline measurement
        auto udp_transport = std::make_unique<test::infrastructure::MockTransport>();
        udp_transport->set_encryption_enabled(false); // Plain UDP
        
        auto client_endpoint = udp_transport->create_endpoint("udp_client");
        auto server_endpoint = udp_transport->create_endpoint("udp_server");
        udp_transport->connect_endpoints(client_endpoint, server_endpoint);
        
        std::vector<uint8_t> test_data = generate_test_data(data_size);
        
        HighResolutionTimer timer;
        timer.start();
        
        // Perform UDP transfers
        for (size_t i = 0; i < config_.iterations; ++i) {
            client_endpoint->send_data(test_data);
            udp_transport->process_pending_messages();
            auto received = server_endpoint->receive_data();
            
            if (received.size() != test_data.size()) {
                throw std::runtime_error("UDP baseline transfer failed");
            }
        }
        
        timer.stop();
        
        // Calculate UDP throughput
        double total_time_seconds = timer.elapsed_milliseconds() / 1000.0;
        double total_mb = static_cast<double>(data_size * config_.iterations) / (1024.0 * 1024.0);
        
        return total_mb / total_time_seconds * 8.0; // Mbps
    }
    
    void complete_handshake(std::shared_ptr<connection::Connection> client,
                           std::shared_ptr<connection::Connection> server) {
        const size_t max_iterations = 20;
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            mock_transport_->process_pending_messages();
            client->process_incoming_data();
            server->process_incoming_data();
            
            iteration++;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (!client->is_handshake_complete() || !server->is_handshake_complete()) {
            throw std::runtime_error("Handshake failed to complete for throughput test");
        }
    }
    
    connection::ClientConfig create_client_config() {
        connection::ClientConfig config;
        config.protocol_version = protocol::ProtocolVersion::DTLS_1_3;
        config.cipher_suites = {0x1301}; // TLS_AES_128_GCM_SHA256 for performance
        config.supported_groups = {"secp256r1"};
        config.verify_certificate = false;
        config.enable_compression = compression_enabled_;
        return config;
    }
    
    connection::ServerConfig create_server_config() {
        connection::ServerConfig config;
        config.protocol_version = protocol::ProtocolVersion::DTLS_1_3;
        config.cipher_suites = {0x1301};
        config.supported_groups = {"secp256r1"};
        config.certificate_chain = test_certs_->get_certificate_chain(1);
        config.private_key = test_certs_->get_private_key();
        config.enable_compression = compression_enabled_;
        return config;
    }
};

// ============================================================================
// Public ThroughputBenchmark Interface
// ============================================================================

ThroughputBenchmark::ThroughputBenchmark(const BenchmarkConfig& config) 
    : pimpl_(std::make_unique<Impl>(config)) {}

BenchmarkResult ThroughputBenchmark::benchmark_application_data_throughput(size_t data_size) {
    return pimpl_->benchmark_application_data_throughput_impl(data_size);
}

BenchmarkResult ThroughputBenchmark::benchmark_concurrent_connections(size_t connection_count) {
    return pimpl_->benchmark_concurrent_connections_impl(connection_count);
}

BenchmarkResult ThroughputBenchmark::benchmark_streaming_throughput(size_t stream_duration_ms) {
    return pimpl_->benchmark_streaming_throughput_impl(stream_duration_ms);
}

BenchmarkResult ThroughputBenchmark::benchmark_udp_comparison(size_t data_size) {
    return pimpl_->benchmark_udp_comparison_impl(data_size);
}

void ThroughputBenchmark::set_encryption_enabled(bool enabled) {
    pimpl_->encryption_enabled_ = enabled;
}

void ThroughputBenchmark::set_compression_enabled(bool enabled) {
    pimpl_->compression_enabled_ = enabled;
}

void ThroughputBenchmark::set_packet_loss_rate(double loss_rate) {
    pimpl_->packet_loss_rate_ = loss_rate;
}

// ============================================================================
// Comprehensive Throughput Performance Test Suite
// ============================================================================

class ThroughputPerformanceTestSuite {
public:
    explicit ThroughputPerformanceTestSuite(const BenchmarkConfig& config = BenchmarkConfig{}) 
        : config_(config), throughput_benchmark_(config) {}
    
    std::vector<BenchmarkResult> run_all_throughput_benchmarks() {
        std::vector<BenchmarkResult> results;
        
        // Basic throughput tests with different data sizes
        std::cout << "Running throughput benchmarks for different data sizes..." << std::endl;
        for (size_t data_size : config_.data_sizes) {
            auto result = throughput_benchmark_.benchmark_application_data_throughput(data_size);
            results.push_back(result);
        }
        
        // UDP comparison tests
        std::cout << "Running DTLS vs UDP comparison..." << std::endl;
        for (size_t data_size : {1024, 4096, 16384}) {
            auto result = throughput_benchmark_.benchmark_udp_comparison(data_size);
            results.push_back(result);
        }
        
        // Concurrent connection tests
        std::cout << "Running concurrent connection benchmarks..." << std::endl;
        for (size_t conn_count : {1, 10, 50, 100}) {
            if (conn_count <= config_.max_connections) {
                auto result = throughput_benchmark_.benchmark_concurrent_connections(conn_count);
                results.push_back(result);
            }
        }
        
        // Streaming throughput tests
        std::cout << "Running streaming throughput benchmarks..." << std::endl;
        for (size_t duration : {1000, 5000, 10000}) { // 1s, 5s, 10s
            auto result = throughput_benchmark_.benchmark_streaming_throughput(duration);
            results.push_back(result);
        }
        
        // Test with different configurations
        std::cout << "Running configuration variation tests..." << std::endl;
        results.append_range(benchmark_configuration_variations());
        
        return results;
    }
    
    std::vector<BenchmarkResult> benchmark_configuration_variations() {
        std::vector<BenchmarkResult> results;
        
        // Test with compression enabled
        throughput_benchmark_.set_compression_enabled(true);
        auto compression_result = throughput_benchmark_.benchmark_application_data_throughput(4096);
        compression_result.name += "_with_compression";
        results.push_back(compression_result);
        throughput_benchmark_.set_compression_enabled(false);
        
        // Test with different packet loss rates
        for (double loss_rate : {0.01, 0.05, 0.1}) { // 1%, 5%, 10%
            throughput_benchmark_.set_packet_loss_rate(loss_rate);
            auto loss_result = throughput_benchmark_.benchmark_application_data_throughput(4096);
            loss_result.name += "_loss_" + std::to_string(static_cast<int>(loss_rate * 100)) + "pct";
            results.push_back(loss_result);
        }
        throughput_benchmark_.set_packet_loss_rate(0.0);
        
        return results;
    }
    
    void generate_throughput_summary(const std::vector<BenchmarkResult>& results, std::ostream& output) {
        output << "\nThroughput Performance Summary\n";
        output << "=============================\n\n";
        
        // Find peak throughput
        auto max_throughput_it = std::max_element(results.begin(), results.end(),
            [](const BenchmarkResult& a, const BenchmarkResult& b) {
                return a.throughput_mbps < b.throughput_mbps;
            });
        
        if (max_throughput_it != results.end()) {
            output << "Peak Throughput: " << max_throughput_it->throughput_mbps 
                   << " Mbps (" << max_throughput_it->name << ")\n";
        }
        
        // Calculate average throughput
        double total_throughput = std::accumulate(results.begin(), results.end(), 0.0,
            [](double sum, const BenchmarkResult& result) {
                return sum + result.throughput_mbps;
            });
        
        double avg_throughput = results.empty() ? 0.0 : total_throughput / results.size();
        output << "Average Throughput: " << avg_throughput << " Mbps\n";
        
        // PRD compliance summary
        size_t compliant_tests = std::count_if(results.begin(), results.end(),
            [](const BenchmarkResult& result) {
                return result.meets_throughput_requirement;
            });
        
        double compliance_rate = results.empty() ? 0.0 : 
            static_cast<double>(compliant_tests) / results.size() * 100.0;
        
        output << "PRD Compliance Rate: " << compliance_rate << "% (" 
               << compliant_tests << "/" << results.size() << " tests)\n";
        
        // Data size analysis
        output << "\nThroughput by Data Size:\n";
        std::map<size_t, double> throughput_by_size;
        for (const auto& result : results) {
            // Extract data size from name if possible
            if (result.total_bytes_processed > 0) {
                size_t data_size = result.total_bytes_processed / config_.iterations;
                throughput_by_size[data_size] = std::max(throughput_by_size[data_size], result.throughput_mbps);
            }
        }
        
        for (const auto& [size, throughput] : throughput_by_size) {
            output << "  " << size << " bytes: " << throughput << " Mbps\n";
        }
    }
    
private:
    BenchmarkConfig config_;
    ThroughputBenchmark throughput_benchmark_;
};

} // namespace dtls::v13::test::performance