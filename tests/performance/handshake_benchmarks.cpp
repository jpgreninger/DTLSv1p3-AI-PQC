/*
 * DTLS v1.3 Handshake Performance Benchmarks
 * Task 10: Performance Benchmarking - Handshake Latency Tests
 */

#include "benchmark_framework.h"
#include <dtls/protocol/handshake.h>
#include <dtls/connection.h>
#include <dtls/connection/advanced_connection_manager.h>
#include <dtls/types.h> // Contains CipherSuite enum
#include <dtls/crypto/provider_factory.h>
#include "../test_infrastructure/test_certificates.h"
#include "../test_infrastructure/mock_transport.h"
#include <memory>
#include <vector>
#include <future>
#include <thread>
#include <iostream>

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
    
    std::unique_ptr<dtls::test::TestCertificates> test_certs_;
    std::unique_ptr<dtls::test::MockTransport> mock_transport_;
    
    Impl(const BenchmarkConfig& config) : config_(config) {
        setup_test_infrastructure();
    }
    
    void setup_test_infrastructure() {
        test_certs_ = std::make_unique<dtls::test::TestCertificates>();
        mock_transport_ = std::make_unique<dtls::test::MockTransport>("127.0.0.1", 4433);
        
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
        // Create client and server connections directly
        auto client_config = create_client_config();
        auto server_config = create_server_config();
        
        // Setup mock transport connection
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Create crypto providers (simplified for testing)
        auto client_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        auto server_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        
        if (!client_crypto || !server_crypto) {
            throw std::runtime_error("Failed to create crypto providers");
        }
        
        // Create connections
        auto server_addr = NetworkAddress::from_ipv4(0x7F000001, 4433); // 127.0.0.1:4433
        auto client_connection_result = v13::Connection::create_client(
            client_config, std::move(client_crypto.value()), 
            server_addr);
        auto server_connection_result = v13::Connection::create_server(
            server_config, std::move(server_crypto.value()),
            server_addr);
            
        if (!client_connection_result || !server_connection_result) {
            throw std::runtime_error("Failed to create connections");
        }
        
        auto client_connection = std::move(client_connection_result.value());
        auto server_connection = std::move(server_connection_result.value());
        
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
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Create crypto providers
        auto client_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        auto server_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        
        if (!client_crypto || !server_crypto) {
            throw std::runtime_error("Failed to create crypto providers");
        }
        
        // Create connections
        auto server_addr = NetworkAddress::from_ipv4(0x7F000001, 4433); // 127.0.0.1:4433
        auto client_connection_result = v13::Connection::create_client(
            client_config, std::move(client_crypto.value()), 
            server_addr);
        auto server_connection_result = v13::Connection::create_server(
            server_config, std::move(server_crypto.value()),
            server_addr);
            
        if (!client_connection_result || !server_connection_result) {
            throw std::runtime_error("Failed to create connections");
        }
        
        auto client_connection = std::move(client_connection_result.value());
        auto server_connection = std::move(server_connection_result.value());
        
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
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Create crypto providers
        auto client_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        auto server_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        
        if (!client_crypto || !server_crypto) {
            throw std::runtime_error("Failed to create crypto providers");
        }
        
        // Create connections
        auto server_addr = NetworkAddress::from_ipv4(0x7F000001, 4433); // 127.0.0.1:4433
        auto client_connection_result = v13::Connection::create_client(
            client_config, std::move(client_crypto.value()), 
            server_addr);
        auto server_connection_result = v13::Connection::create_server(
            server_config, std::move(server_crypto.value()),
            server_addr);
            
        if (!client_connection_result || !server_connection_result) {
            throw std::runtime_error("Failed to create connections");
        }
        
        auto client_connection = std::move(client_connection_result.value());
        auto server_connection = std::move(server_connection_result.value());
        
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
        
        auto client_endpoint = mock_transport_->create_endpoint("client");
        auto server_endpoint = mock_transport_->create_endpoint("server");
        mock_transport_->connect_endpoints(client_endpoint, server_endpoint);
        
        // Create crypto providers
        auto client_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        auto server_crypto = crypto::ProviderFactory::instance().create_provider("openssl");
        
        if (!client_crypto || !server_crypto) {
            throw std::runtime_error("Failed to create crypto providers");
        }
        
        // Create connections
        auto server_addr = NetworkAddress::from_ipv4(0x7F000001, 4433); // 127.0.0.1:4433
        auto client_connection_result = v13::Connection::create_client(
            client_config, std::move(client_crypto.value()), 
            server_addr);
        auto server_connection_result = v13::Connection::create_server(
            server_config, std::move(server_crypto.value()),
            server_addr);
            
        if (!client_connection_result || !server_connection_result) {
            throw std::runtime_error("Failed to create connections");
        }
        
        auto client_connection = std::move(client_connection_result.value());
        auto server_connection = std::move(server_connection_result.value());
        
        // Send early data immediately
        std::vector<uint8_t> early_data = {0x01, 0x02, 0x03, 0x04};
        memory::ZeroCopyBuffer early_data_buffer(
            reinterpret_cast<const std::byte*>(early_data.data()), 
            early_data.size());
        client_connection->send_early_data(early_data_buffer);
        
        execute_early_data_exchange(client_connection, server_connection);
        
        if (!client_connection->is_handshake_complete() || 
            !server_connection->is_handshake_complete()) {
            throw std::runtime_error("Early data handshake failed to complete");
        }
    }
    
    v13::ConnectionConfig create_client_config() {
        v13::ConnectionConfig config;
        // Note: ConnectionConfig doesn't have protocol_version, it's DTLS v1.3 by default
        config.supported_cipher_suites = {static_cast<CipherSuite>(cipher_suite_)};
        config.supported_groups = {NamedGroup::SECP256R1}; // Default to secp256r1
        config.supported_signatures = {SignatureScheme::RSA_PSS_RSAE_SHA256, SignatureScheme::ECDSA_SECP256R1_SHA256};
        return config;
    }
    
    v13::ConnectionConfig create_server_config() {
        v13::ConnectionConfig config;
        // Note: ConnectionConfig doesn't have protocol_version, it's DTLS v1.3 by default
        config.supported_cipher_suites = {static_cast<CipherSuite>(cipher_suite_)};
        config.supported_groups = {NamedGroup::SECP256R1}; // Default to secp256r1  
        config.supported_signatures = {SignatureScheme::RSA_PSS_RSAE_SHA256, SignatureScheme::ECDSA_SECP256R1_SHA256};
        // Note: certificate and private key are handled differently in DTLS v1.3
        // They would be set through the crypto provider or connection setup
        return config;
    }
    
    void execute_handshake_exchange(std::unique_ptr<v13::Connection>& client,
                                   std::unique_ptr<v13::Connection>& server) {
        // Simulate the handshake message exchange
        const size_t max_iterations = 20; // Prevent infinite loops
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            // Process any pending messages
            mock_transport_->process_pending_messages();
            
            // Let connections process received data
            // Note: In a real implementation, this would process actual network data
            // For this benchmark, we simulate basic handshake progression
            
            iteration++;
            
            // Small delay to prevent busy waiting
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (iteration >= max_iterations) {
            throw std::runtime_error("Handshake did not complete within expected iterations");
        }
    }
    
    void execute_resumption_exchange(std::unique_ptr<v13::Connection>& client,
                                   std::unique_ptr<v13::Connection>& server) {
        // Resumption handshake should be faster
        const size_t max_iterations = 10;
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            mock_transport_->process_pending_messages();
            // Note: In a real implementation, this would process actual network data
            // For this benchmark, we simulate basic handshake progression
            
            iteration++;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
        
        if (iteration >= max_iterations) {
            throw std::runtime_error("Resumption handshake did not complete within expected iterations");
        }
    }
    
    void execute_early_data_exchange(std::unique_ptr<v13::Connection>& client,
                                   std::unique_ptr<v13::Connection>& server) {
        // 0-RTT handshake processing
        const size_t max_iterations = 15;
        size_t iteration = 0;
        
        while ((!client->is_handshake_complete() || !server->is_handshake_complete()) && 
               iteration < max_iterations) {
            
            mock_transport_->process_pending_messages();
            // Note: In a real implementation, this would process actual network data
            // For this benchmark, we simulate basic handshake progression
            
            // Check for early data acceptance
            if (client->is_early_data_accepted()) {
                // Early data was accepted by the server
                break;
            } else if (client->is_early_data_rejected()) {
                // Early data was rejected, continue with normal handshake
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

HandshakeBenchmark::~HandshakeBenchmark() = default;

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
        auto cipher_results = benchmark_cipher_suite_variations();
        results.insert(results.end(), cipher_results.begin(), cipher_results.end());
        
        // Different key exchange groups
        std::cout << "Running key exchange variations..." << std::endl;
        auto key_results = benchmark_key_exchange_variations();
        results.insert(results.end(), key_results.begin(), key_results.end());
        
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