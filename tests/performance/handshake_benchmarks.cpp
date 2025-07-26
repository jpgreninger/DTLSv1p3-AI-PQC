/*
 * DTLS v1.3 Handshake Performance Benchmarks
 * Task 10: Performance Benchmarking - Handshake Latency Tests
 */

#include "benchmark_framework.h"
#include <dtls/protocol/handshake.h>
#include <dtls/connection/connection_manager.h>
#include <dtls/crypto/cipher_suites.h>
#include "../test_infrastructure/test_certificates.h"
#include "../test_infrastructure/mock_transport.h"
#include <memory>
#include <vector>
#include <future>

namespace dtls::v13::test::performance {

// ============================================================================
// HandshakeBenchmark Implementation
// ============================================================================

class HandshakeBenchmark::Impl {
public:
    BenchmarkConfig config_;
    size_t certificate_chain_length_ = 1;
    std::string key_exchange_group_ = "secp256r1";
    uint16_t cipher_suite_ = 0x1301; // TLS_AES_128_GCM_SHA256
    
    std::unique_ptr<test::infrastructure::TestCertificates> test_certs_;
    std::unique_ptr<test::infrastructure::MockTransport> mock_transport_;
    
    Impl(const BenchmarkConfig& config) : config_(config) {
        setup_test_infrastructure();
    }
    
    void setup_test_infrastructure() {
        test_certs_ = std::make_unique<test::infrastructure::TestCertificates>();
        mock_transport_ = std::make_unique<test::infrastructure::MockTransport>();
        
        // Configure mock transport for performance testing
        mock_transport_->set_packet_loss_rate(0.0); // No packet loss for clean measurements
        mock_transport_->set_network_delay(std::chrono::microseconds(100)); // Minimal network delay
        mock_transport_->set_bandwidth_limit(0); // No bandwidth limit
    }
    
    BenchmarkResult benchmark_full_handshake_impl() {
        BenchmarkRunner runner(config_);
        
        runner.register_benchmark("Full Handshake", [this]() {
            perform_full_handshake();
        }, [this]() {
            setup_test_infrastructure();
        }, [this]() {
            cleanup_test_infrastructure();
        });
        
        auto results = runner.run_all_benchmarks();
        return results.empty() ? BenchmarkResult{} : results[0];
    }
    
    BenchmarkResult benchmark_handshake_with_retry_impl() {
        BenchmarkRunner runner(config_);
        
        runner.register_benchmark("Handshake with Retry", [this]() {
            perform_handshake_with_retry();
        }, [this]() {
            setup_test_infrastructure();
            // Simulate 10% packet loss for retry scenarios
            mock_transport_->set_packet_loss_rate(0.1);
        }, [this]() {
            cleanup_test_infrastructure();
        });
        
        auto results = runner.run_all_benchmarks();
        return results.empty() ? BenchmarkResult{} : results[0];
    }
    
    BenchmarkResult benchmark_handshake_with_fragmentation_impl() {
        BenchmarkRunner runner(config_);
        
        runner.register_benchmark("Handshake with Fragmentation", [this]() {
            perform_handshake_with_fragmentation();
        }, [this]() {
            setup_test_infrastructure();
            // Set small MTU to force fragmentation
            mock_transport_->set_mtu(512);
            // Use longer certificate chain to trigger fragmentation
            certificate_chain_length_ = 3;
        }, [this]() {
            certificate_chain_length_ = 1;
            cleanup_test_infrastructure();
        });
        
        auto results = runner.run_all_benchmarks();
        return results.empty() ? BenchmarkResult{} : results[0];
    }
    
    BenchmarkResult benchmark_resumption_handshake_impl() {
        BenchmarkRunner runner(config_);
        
        runner.register_benchmark("Resumption Handshake", [this]() {
            perform_resumption_handshake();
        }, [this]() {
            setup_test_infrastructure();
            // Pre-establish a session for resumption
            establish_session_for_resumption();
        }, [this]() {
            cleanup_test_infrastructure();
        });
        
        auto results = runner.run_all_benchmarks();
        return results.empty() ? BenchmarkResult{} : results[0];
    }
    
    BenchmarkResult benchmark_early_data_handshake_impl() {
        BenchmarkRunner runner(config_);
        
        runner.register_benchmark("Early Data Handshake", [this]() {
            perform_early_data_handshake();
        }, [this]() {
            setup_test_infrastructure();
            // Setup for 0-RTT early data
            setup_early_data_context();
        }, [this]() {
            cleanup_test_infrastructure();
        });
        
        auto results = runner.run_all_benchmarks();
        return results.empty() ? BenchmarkResult{} : results[0];
    }
    
private:
    void perform_full_handshake() {
        // Create client and server connection managers
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        connection::ConnectionManager client_manager(client_config);
        connection::ConnectionManager server_manager(server_config);
        
        // Setup mock transport connection
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Perform handshake
        auto client_connection = client_manager.create_connection(client_endpoint);
        auto server_connection = server_manager.accept_connection(server_endpoint);
        
        // Execute handshake protocol
        execute_handshake_exchange(client_connection, server_connection);
        
        // Verify successful completion
        if (!client_connection->is_handshake_complete() || 
            !server_connection->is_handshake_complete()) {
            throw std::runtime_error("Handshake failed to complete");
        }
    }
    
    void perform_handshake_with_retry() {
        // Similar to full handshake but with packet loss simulation
        perform_full_handshake();
    }
    
    void perform_handshake_with_fragmentation() {
        // Use longer certificate chain and small MTU
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        // Configure longer certificate chain
        server_config.certificate_chain = test_certs_->get_certificate_chain(certificate_chain_length_);
        
        connection::ConnectionManager client_manager(client_config);
        connection::ConnectionManager server_manager(server_config);
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        auto client_connection = client_manager.create_connection(client_endpoint);
        auto server_connection = server_manager.accept_connection(server_endpoint);
        
        execute_handshake_exchange(client_connection, server_connection);
        
        if (!client_connection->is_handshake_complete() || 
            !server_connection->is_handshake_complete()) {
            throw std::runtime_error("Fragmented handshake failed to complete");
        }
    }
    
    void perform_resumption_handshake() {
        // Perform session resumption handshake
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        // Enable session resumption
        client_config.enable_session_resumption = true;
        server_config.enable_session_resumption = true;
        
        connection::ConnectionManager client_manager(client_config);
        connection::ConnectionManager server_manager(server_config);
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Use existing session ticket for resumption
        auto client_connection = client_manager.resume_connection(client_endpoint, get_session_ticket());
        auto server_connection = server_manager.accept_connection(server_endpoint);
        
        execute_resumption_exchange(client_connection, server_connection);
        
        if (!client_connection->is_handshake_complete() || 
            !server_connection->is_handshake_complete()) {
            throw std::runtime_error("Resumption handshake failed to complete");
        }
    }
    
    void perform_early_data_handshake() {
        // Perform 0-RTT early data handshake
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        // Enable early data support
        client_config.enable_early_data = true;
        server_config.enable_early_data = true;
        server_config.max_early_data_size = 16384;
        
        connection::ConnectionManager client_manager(client_config);
        connection::ConnectionManager server_manager(server_config);
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Initiate connection with early data
        auto client_connection = client_manager.create_connection_with_early_data(
            client_endpoint, get_early_data_context());
        auto server_connection = server_manager.accept_connection(server_endpoint);
        
        // Send early data immediately
        std::vector<uint8_t> early_data = {0x01, 0x02, 0x03, 0x04};
        client_connection->send_early_data(early_data);
        
        execute_early_data_exchange(client_connection, server_connection);
        
        if (!client_connection->is_handshake_complete() || 
            !server_connection->is_handshake_complete()) {
            throw std::runtime_error("Early data handshake failed to complete");
        }
    }
    
    connection::ClientConfig create_client_config() {
        connection::ClientConfig config;
        config.protocol_version = protocol::ProtocolVersion::DTLS_1_3;
        config.cipher_suites = {cipher_suite_};
        config.supported_groups = {key_exchange_group_};
        config.signature_algorithms = {"rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"};
        config.verify_certificate = false; // Disable for performance testing
        return config;
    }
    
    connection::ServerConfig create_server_config() {
        connection::ServerConfig config;
        config.protocol_version = protocol::ProtocolVersion::DTLS_1_3;
        config.cipher_suites = {cipher_suite_};
        config.supported_groups = {key_exchange_group_};
        config.signature_algorithms = {"rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"};
        config.certificate_chain = test_certs_->get_certificate_chain(certificate_chain_length_);
        config.private_key = test_certs_->get_private_key();
        return config;
    }
    
    void execute_handshake_exchange(std::shared_ptr<connection::Connection> client,
                                   std::shared_ptr<connection::Connection> server) {
        // Simulate the handshake message exchange
        const size_t max_iterations = 20; // Prevent infinite loops
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            // Process any pending messages
            mock_transport_->process_pending_messages();
            
            // Let connections process received data
            client->process_incoming_data();
            server->process_incoming_data();
            
            iteration++;
            
            // Small delay to prevent busy waiting
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (iteration >= max_iterations) {
            throw std::runtime_error("Handshake did not complete within expected iterations");
        }
    }
    
    void execute_resumption_exchange(std::shared_ptr<connection::Connection> client,
                                   std::shared_ptr<connection::Connection> server) {
        // Resumption handshake should be faster
        const size_t max_iterations = 10;
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            mock_transport_->process_pending_messages();
            client->process_incoming_data();
            server->process_incoming_data();
            
            iteration++;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (iteration >= max_iterations) {
            throw std::runtime_error("Resumption handshake did not complete within expected iterations");
        }
    }
    
    void execute_early_data_exchange(std::shared_ptr<connection::Connection> client,
                                   std::shared_ptr<connection::Connection> server) {
        // 0-RTT handshake processing
        const size_t max_iterations = 15;
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            mock_transport_->process_pending_messages();
            client->process_incoming_data();
            server->process_incoming_data();
            
            // Check for early data acceptance
            if (server->has_early_data()) {
                auto early_data = server->receive_early_data();
                // Validate early data was received correctly
                if (early_data.empty()) {
                    throw std::runtime_error("Early data not received");
                }
            }
            
            iteration++;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (iteration >= max_iterations) {
            throw std::runtime_error("Early data handshake did not complete within expected iterations");
        }
    }
    
    void establish_session_for_resumption() {
        // Pre-establish a session that can be resumed
        perform_full_handshake();
        // Session ticket would be stored in the session cache
    }
    
    void setup_early_data_context() {
        // Setup PSK and early data context
        establish_session_for_resumption();
    }
    
    std::vector<uint8_t> get_session_ticket() {
        // Return a mock session ticket for testing
        return {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    }
    
    std::vector<uint8_t> get_early_data_context() {
        // Return early data context for 0-RTT
        return {0x10, 0x20, 0x30, 0x40};
    }
    
    void cleanup_test_infrastructure() {
        mock_transport_->reset();
    }
};

// ============================================================================
// Public HandshakeBenchmark Interface
// ============================================================================

HandshakeBenchmark::HandshakeBenchmark(const BenchmarkConfig& config) 
    : pimpl_(std::make_unique<Impl>(config)) {}

BenchmarkResult HandshakeBenchmark::benchmark_full_handshake() {
    return pimpl_->benchmark_full_handshake_impl();
}

BenchmarkResult HandshakeBenchmark::benchmark_handshake_with_retry() {
    return pimpl_->benchmark_handshake_with_retry_impl();
}

BenchmarkResult HandshakeBenchmark::benchmark_handshake_with_fragmentation() {
    return pimpl_->benchmark_handshake_with_fragmentation_impl();
}

BenchmarkResult HandshakeBenchmark::benchmark_resumption_handshake() {
    return pimpl_->benchmark_resumption_handshake_impl();
}

BenchmarkResult HandshakeBenchmark::benchmark_early_data_handshake() {
    return pimpl_->benchmark_early_data_handshake_impl();
}

void HandshakeBenchmark::set_certificate_chain_length(size_t length) {
    pimpl_->certificate_chain_length_ = length;
}

void HandshakeBenchmark::set_key_exchange_group(const std::string& group) {
    pimpl_->key_exchange_group_ = group;
}

void HandshakeBenchmark::set_cipher_suite(uint16_t cipher_suite) {
    pimpl_->cipher_suite_ = cipher_suite;
}

// ============================================================================
// Comprehensive Handshake Performance Test Suite
// ============================================================================

class HandshakePerformanceTestSuite {
public:
    explicit HandshakePerformanceTestSuite(const BenchmarkConfig& config = BenchmarkConfig{}) 
        : config_(config), handshake_benchmark_(config) {}
    
    std::vector<BenchmarkResult> run_all_handshake_benchmarks() {
        std::vector<BenchmarkResult> results;
        
        // Basic handshake performance
        std::cout << "Running full handshake benchmark..." << std::endl;
        results.push_back(handshake_benchmark_.benchmark_full_handshake());
        
        // Handshake with network issues
        std::cout << "Running handshake with retry benchmark..." << std::endl;
        results.push_back(handshake_benchmark_.benchmark_handshake_with_retry());
        
        // Fragmentation scenarios
        std::cout << "Running handshake with fragmentation benchmark..." << std::endl;
        results.push_back(handshake_benchmark_.benchmark_handshake_with_fragmentation());
        
        // Session resumption
        std::cout << "Running resumption handshake benchmark..." << std::endl;
        results.push_back(handshake_benchmark_.benchmark_resumption_handshake());
        
        // 0-RTT early data
        std::cout << "Running early data handshake benchmark..." << std::endl;
        results.push_back(handshake_benchmark_.benchmark_early_data_handshake());
        
        // Different cipher suites
        std::cout << "Running cipher suite variations..." << std::endl;
        results.append_range(benchmark_cipher_suite_variations());
        
        // Different key exchange groups
        std::cout << "Running key exchange variations..." << std::endl;
        results.append_range(benchmark_key_exchange_variations());
        
        return results;
    }
    
    std::vector<BenchmarkResult> benchmark_cipher_suite_variations() {
        std::vector<BenchmarkResult> results;
        
        std::vector<uint16_t> cipher_suites = {
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1304, // TLS_AES_128_CCM_SHA256
            0x1305  // TLS_AES_128_CCM_8_SHA256
        };
        
        for (uint16_t suite : cipher_suites) {
            handshake_benchmark_.set_cipher_suite(suite);
            auto result = handshake_benchmark_.benchmark_full_handshake();
            result.name += "_cipher_" + std::to_string(suite);
            results.push_back(result);
        }
        
        return results;
    }
    
    std::vector<BenchmarkResult> benchmark_key_exchange_variations() {
        std::vector<BenchmarkResult> results;
        
        std::vector<std::string> key_groups = {
            "secp256r1",
            "secp384r1",
            "secp521r1",
            "x25519",
            "x448"
        };
        
        for (const auto& group : key_groups) {
            handshake_benchmark_.set_key_exchange_group(group);
            auto result = handshake_benchmark_.benchmark_full_handshake();
            result.name += "_keygroup_" + group;
            results.push_back(result);
        }
        
        return results;
    }
    
private:
    BenchmarkConfig config_;
    HandshakeBenchmark handshake_benchmark_;
};

} // namespace dtls::v13::test::performance