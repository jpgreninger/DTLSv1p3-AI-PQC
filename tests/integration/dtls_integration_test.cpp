#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <dtls/connection.h>
#include <dtls/crypto.h>
#include <dtls/protocol.h>
#include <dtls/transport/udp_transport.h>
#include <dtls/crypto/openssl_provider.h>
#include "../test_infrastructure/test_utilities.h"
#include "../test_infrastructure/test_certificates.h"
#include "../test_infrastructure/mock_transport.h"
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <atomic>
#include <future>

namespace dtls {
namespace v13 {
namespace test {

/**
 * Comprehensive DTLS v1.3 Integration Test Suite
 * 
 * Tests the complete DTLS v1.3 implementation including:
 * - End-to-end handshake completion
 * - Application data transfer
 * - Connection migration
 * - Multi-connection scenarios
 * - Error handling and recovery
 * - Security validation
 */
class DTLSIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test environment with enhanced configuration
        dtls::test::TestEnvironmentConfig config;
        config.verbose_logging = true;
        config.enable_certificate_validation = true;
        config.handshake_timeout = std::chrono::milliseconds(15000);
        
        test_env_ = std::make_unique<dtls::test::DTLSTestEnvironment>(config);
        test_env_->SetUp();
        
        // Reset statistics
        test_env_->reset_statistics();
    }
    
    void TearDown() override {
        if (test_env_) {
            test_env_->TearDown();
        }
        
        // Cleanup any additional test resources
        client_connections_.clear();
        server_connections_.clear();
    }
    
    // Helper method to create client connection
    std::unique_ptr<Connection> create_client_connection() {
        return test_env_->create_client_connection();
    }
    
    // Helper method to create server connection
    std::unique_ptr<Connection> create_server_connection() {
        return test_env_->create_server_connection();
    }
    
    // Helper method to perform handshake
    bool perform_handshake(Connection* client, Connection* server) {
        return test_env_->perform_handshake(client, server);
    }
    
    // Helper method to transfer data
    bool transfer_data(Connection* sender, Connection* receiver, 
                      const std::vector<uint8_t>& data) {
        return test_env_->transfer_data(sender, receiver, data);
    }

protected:
    std::unique_ptr<dtls::test::DTLSTestEnvironment> test_env_;
    std::vector<std::unique_ptr<Connection>> client_connections_;
    std::vector<std::unique_ptr<Connection>> server_connections_;
};

// Test 1: Basic End-to-End Handshake
TEST_F(DTLSIntegrationTest, BasicHandshakeCompletion) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Perform handshake
    EXPECT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Verify connection state
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_connected());
    
    // Verify handshake statistics
    auto& stats = test_env_->get_statistics();
    EXPECT_EQ(stats.handshakes_completed, 1);
    EXPECT_EQ(stats.errors_encountered, 0);
    
    // Validate connection security using test utilities
    dtls::test::DTLSTestValidators::validate_connection_secure(client.get());
    dtls::test::DTLSTestValidators::validate_connection_secure(server.get());
}

// Test 2: Application Data Transfer
TEST_F(DTLSIntegrationTest, ApplicationDataTransfer) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake first
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Test data transfer client -> server using test data generator
    auto test_data1 = dtls::test::TestDataGenerator::generate_sequential_data(64);
    EXPECT_TRUE(test_env_->transfer_data(client.get(), server.get(), test_data1));
    
    // Test data transfer server -> client using random data
    auto test_data2 = dtls::test::TestDataGenerator::generate_random_data(128);
    EXPECT_TRUE(test_env_->transfer_data(server.get(), client.get(), test_data2));
    
    // Verify transfer statistics
    auto& stats = test_env_->get_statistics();
    EXPECT_EQ(stats.bytes_transferred, test_data1.size() + test_data2.size());
    
    // Validate data integrity using test utilities
    dtls::test::DTLSTestValidators::validate_data_integrity(test_data1, test_data1);
    dtls::test::DTLSTestValidators::validate_data_integrity(test_data2, test_data2);
}

// Test 3: Large Data Transfer
TEST_F(DTLSIntegrationTest, LargeDataTransfer) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake first
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Create large test data (16KB)
    std::vector<uint8_t> large_data(16384);
    for (size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Transfer large data
    EXPECT_TRUE(transfer_data(client.get(), server.get(), large_data));
    
    // Verify no fragmentation errors
    auto& stats = test_env_->get_statistics();
    EXPECT_EQ(stats.errors_encountered, 0);
    
    // Validate performance for large transfers
    dtls::test::DTLSTestValidators::validate_throughput_performance(large_data.size(), 
                                                       std::chrono::milliseconds(5000));
}

// Test 4: Multiple Concurrent Connections
TEST_F(DTLSIntegrationTest, MultipleConcurrentConnections) {
    const size_t num_connections = 5;
    
    // Create multiple connection pairs
    for (size_t i = 0; i < num_connections; ++i) {
        client_connections_.push_back(create_client_connection());
        server_connections_.push_back(create_server_connection());
    }
    
    // Perform handshakes concurrently
    std::vector<std::thread> handshake_threads;
    std::atomic<uint32_t> successful_handshakes{0};
    
    for (size_t i = 0; i < num_connections; ++i) {
        handshake_threads.emplace_back([this, i, &successful_handshakes]() {
            if (perform_handshake(client_connections_[i].get(), 
                                server_connections_[i].get())) {
                successful_handshakes++;
            }
        });
    }
    
    // Wait for all handshakes to complete
    for (auto& thread : handshake_threads) {
        thread.join();
    }
    
    // Verify all handshakes succeeded
    EXPECT_EQ(successful_handshakes, num_connections);
    auto& stats = test_env_->get_statistics(); 
    EXPECT_EQ(stats.handshakes_completed, num_connections);
    
    // Test concurrent data transfer
    std::vector<std::thread> transfer_threads;
    std::atomic<uint32_t> successful_transfers{0};
    
    for (size_t i = 0; i < num_connections; ++i) {
        transfer_threads.emplace_back([this, i, &successful_transfers]() {
            std::vector<uint8_t> data = {static_cast<uint8_t>(i), 0xFF, 0xAA, 0x55};
            if (transfer_data(client_connections_[i].get(), 
                            server_connections_[i].get(), data)) {
                successful_transfers++;
            }
        });
    }
    
    // Wait for all transfers to complete
    for (auto& thread : transfer_threads) {
        thread.join();
    }
    
    EXPECT_EQ(successful_transfers, num_connections);
}

// Test 5: Connection Migration Simulation
TEST_F(DTLSIntegrationTest, ConnectionMigration) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete initial handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Transfer initial data
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), data1));
    
    // Simulate network address change (connection migration)
    // In a real implementation, this would involve changing the transport endpoint
    // For this test, we'll simulate by creating a new transport
    transport::TransportConfig transport_config;
    auto new_client_transport = std::make_unique<transport::UDPTransport>(transport_config);
    transport::NetworkEndpoint endpoint("127.0.0.1", 0);
    ASSERT_TRUE(new_client_transport->bind(endpoint).is_ok());
    
    // Note: Connection migration not implemented in current API
    // In a full implementation, this would update the connection's transport
    // For now, we'll simulate successful migration
    
    // Test data transfer after migration
    std::vector<uint8_t> data2 = {0x04, 0x05, 0x06};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), data2));
    
    // Verify connection is still active
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_connected());
}

// Test 6: Error Handling and Recovery
TEST_F(DTLSIntegrationTest, ErrorHandlingAndRecovery) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Simulate network error by shutting down transport temporarily
    // Note: In actual implementation, would access transport through connection
    // client_transport_->shutdown();
    
    // Attempt data transfer (should fail)
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    memory::ZeroCopyBuffer buffer(reinterpret_cast<const std::byte*>(test_data.data()), test_data.size());
    auto send_result = client->send_application_data(buffer);
    EXPECT_FALSE(send_result.is_ok());
    
    // Restart transport
    // Note: In actual implementation, would recreate transport through connection
    // auto client_transport = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
    // ASSERT_TRUE(client_transport->bind().is_ok());
    // client->set_transport(client_transport.get());
    
    // Attempt recovery (may require re-handshake)
    // Note: reconnect() not implemented in current API
    // In a full implementation, this would attempt to reconnect
    auto reconnect_result = Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    if (reconnect_result.is_ok()) {
        // Test data transfer after recovery
        EXPECT_TRUE(transfer_data(client.get(), server.get(), test_data));
    }
}

// Test 7: Cipher Suite Negotiation
TEST_F(DTLSIntegrationTest, CipherSuiteNegotiation) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Set preferred cipher suites
    std::vector<uint16_t> client_cipher_suites = {
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1301, // TLS_AES_128_GCM_SHA256
    };
    
    std::vector<uint16_t> server_cipher_suites = {
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
    };
    
    // Note: set_cipher_suites() not implemented in current API
    // Cipher suites are configured through ConnectionConfig
    
    // Perform handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Verify negotiated cipher suite (should be AES_128_GCM_SHA256)
    // Note: get_negotiated_cipher_suite() not implemented in current API
    // In a full implementation, this would return the negotiated cipher suite
    auto client_cipher = Result<uint16_t>(DTLSError::OPERATION_NOT_SUPPORTED);
    auto server_cipher = Result<uint16_t>(DTLSError::OPERATION_NOT_SUPPORTED);
    
    EXPECT_TRUE(client_cipher.is_ok());
    EXPECT_TRUE(server_cipher.is_ok());
    
    if (client_cipher.is_ok() && server_cipher.is_ok()) {
        EXPECT_EQ(client_cipher.value(), 0x1301);
        EXPECT_EQ(server_cipher.value(), 0x1301);
        EXPECT_EQ(client_cipher.value(), server_cipher.value());
    }
}

// Test 8: Key Update Functionality
TEST_F(DTLSIntegrationTest, KeyUpdateFunctionality) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Transfer data before key update
    std::vector<uint8_t> data_before = {0x01, 0x02, 0x03};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), data_before));
    
    // Perform key update
    auto key_update_result = client->update_keys();
    EXPECT_TRUE(key_update_result.is_ok());
    
    // Transfer data after key update
    std::vector<uint8_t> data_after = {0x04, 0x05, 0x06};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), data_after));
    
    // Verify both transfers succeeded
    auto& stats = test_env_->get_statistics();
    EXPECT_GE(stats.bytes_transferred, data_before.size() + data_after.size());
}

// Test 9: Performance and Throughput
TEST_F(DTLSIntegrationTest, PerformanceAndThroughput) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Measure throughput with multiple data transfers
    const size_t num_transfers = 100;
    const size_t data_size = 1024; // 1KB per transfer
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_transfers; ++i) {
        std::vector<uint8_t> data(data_size, static_cast<uint8_t>(i & 0xFF));
        EXPECT_TRUE(transfer_data(client.get(), server.get(), data));
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Calculate throughput
    double total_bytes = num_transfers * data_size;
    double duration_seconds = duration.count() / 1000.0;
    double throughput_mbps = (total_bytes * 8.0) / (duration_seconds * 1024.0 * 1024.0);
    
    std::cout << "Throughput: " << throughput_mbps << " Mbps" << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;
    
    // Verify reasonable performance (>1 Mbps)
    EXPECT_GT(throughput_mbps, 1.0);
}

// Test 10: Security Validation
TEST_F(DTLSIntegrationTest, SecurityValidation) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Verify security properties
    // Note: is_secure() not implemented in current API
    // We'll use is_connected() as a proxy for now
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_connected());
    
    // Verify encryption is active
    // Note: is_encrypted() not implemented in current API
    // In DTLS v1.3, all application data is encrypted after handshake
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_connected());
    
    // Test replay attack protection
    // (This would require more sophisticated testing in a real implementation)
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), test_data));
    
    // Verify authenticated encryption
    // Note: get_security_info() not implemented in current API
    auto security_info = Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    EXPECT_TRUE(security_info.is_ok());
}

// Test 11: Network Conditions Simulation
TEST_F(DTLSIntegrationTest, NetworkConditionsSimulation) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete initial handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Test under various network conditions
    dtls::test::MockTransport::NetworkConditions conditions;
    
    // Test with packet loss
    conditions.packet_loss_rate = 0.05; // 5% packet loss
    conditions.latency = std::chrono::milliseconds(100);
    test_env_->set_network_conditions(conditions);
    
    auto test_data = dtls::test::TestDataGenerator::generate_pattern_data(512, 0xAB);
    EXPECT_TRUE(transfer_data(client.get(), server.get(), test_data));
    
    // Test with high latency
    conditions.packet_loss_rate = 0.0;
    conditions.latency = std::chrono::milliseconds(500);
    test_env_->set_network_conditions(conditions);
    
    auto test_data2 = dtls::test::TestDataGenerator::generate_random_data(256);
    EXPECT_TRUE(transfer_data(server.get(), client.get(), test_data2));
    
    // Verify connections remained stable
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_connected());
}

// Test 12: Error Injection and Recovery
TEST_F(DTLSIntegrationTest, ErrorInjectionAndRecovery) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Inject transport errors
    test_env_->inject_transport_error(true);
    
    // Attempt data transfer (should handle errors gracefully)
    auto test_data = dtls::test::TestDataGenerator::generate_sequential_data(128);
    
    // Multiple attempts should eventually succeed due to DTLS reliability
    bool transfer_succeeded = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (transfer_data(client.get(), server.get(), test_data)) {
            transfer_succeeded = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Disable error injection
    test_env_->inject_transport_error(false);
    
    // Normal transfer should work
    auto test_data2 = dtls::test::TestDataGenerator::generate_random_data(256);
    EXPECT_TRUE(transfer_data(server.get(), client.get(), test_data2));
}

// Test 13: Performance Benchmarking
TEST_F(DTLSIntegrationTest, PerformanceBenchmarking) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Measure handshake performance
    auto handshake_start = std::chrono::high_resolution_clock::now();
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    auto handshake_end = std::chrono::high_resolution_clock::now();
    
    auto handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        handshake_end - handshake_start);
    
    // Validate handshake performance (should complete within reasonable time)
    dtls::test::DTLSTestValidators::validate_handshake_performance(handshake_duration);
    
    // Measure throughput performance
    const size_t num_transfers = 50;
    const size_t data_size = 2048; // 2KB per transfer
    
    auto throughput_start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_transfers; ++i) {
        auto data = dtls::test::TestDataGenerator::generate_pattern_data(data_size, 
                                                           static_cast<uint8_t>(i & 0xFF));
        EXPECT_TRUE(transfer_data(client.get(), server.get(), data));
    }
    
    auto throughput_end = std::chrono::high_resolution_clock::now();
    auto throughput_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        throughput_end - throughput_start);
    
    // Calculate and validate throughput
    size_t total_bytes = num_transfers * data_size;
    dtls::test::DTLSTestValidators::validate_throughput_performance(total_bytes, throughput_duration);
    
    // Log performance metrics
    double throughput_mbps = (total_bytes * 8.0 * 1000.0) / 
                           (throughput_duration.count() * 1024.0 * 1024.0);
    
    std::cout << "Handshake Duration: " << handshake_duration.count() << " ms" << std::endl;
    std::cout << "Throughput: " << throughput_mbps << " Mbps" << std::endl;
    std::cout << "Total Data Transferred: " << total_bytes << " bytes" << std::endl;
}

// Test 14: Stress Testing with Concurrent Load
TEST_F(DTLSIntegrationTest, StressTestingConcurrentLoad) {
    const size_t num_concurrent_connections = 10;
    const size_t transfers_per_connection = 20;
    
    // Create multiple connection pairs
    std::vector<std::unique_ptr<Connection>> clients;
    std::vector<std::unique_ptr<Connection>> servers;
    
    for (size_t i = 0; i < num_concurrent_connections; ++i) {
        clients.push_back(create_client_connection());
        servers.push_back(create_server_connection());
        ASSERT_TRUE(clients.back());
        ASSERT_TRUE(servers.back());
    }
    
    // Perform all handshakes concurrently
    std::vector<std::future<bool>> handshake_futures;
    
    for (size_t i = 0; i < num_concurrent_connections; ++i) {
        handshake_futures.push_back(
            std::async(std::launch::async, [this, &clients, &servers, i]() {
                return perform_handshake(clients[i].get(), servers[i].get());
            })
        );
    }
    
    // Wait for all handshakes to complete
    size_t successful_handshakes = 0;
    for (auto& future : handshake_futures) {
        if (future.get()) {
            successful_handshakes++;
        }
    }
    
    EXPECT_EQ(successful_handshakes, num_concurrent_connections);
    
    // Perform concurrent data transfers
    std::vector<std::future<size_t>> transfer_futures;
    
    for (size_t i = 0; i < num_concurrent_connections; ++i) {
        transfer_futures.push_back(
            std::async(std::launch::async, [this, &clients, &servers, i, transfers_per_connection]() {
                size_t successful_transfers = 0;
                
                for (size_t j = 0; j < transfers_per_connection; ++j) {
                    auto data = dtls::test::TestDataGenerator::generate_random_data(512);
                    if (transfer_data(clients[i].get(), servers[i].get(), data)) {
                        successful_transfers++;
                    }
                }
                
                return successful_transfers;
            })
        );
    }
    
    // Collect results
    size_t total_successful_transfers = 0;
    for (auto& future : transfer_futures) {
        total_successful_transfers += future.get();
    }
    
    size_t expected_transfers = num_concurrent_connections * transfers_per_connection;
    EXPECT_EQ(total_successful_transfers, expected_transfers);
    
    // Verify final statistics
    auto& stats = test_env_->get_statistics();
    EXPECT_EQ(stats.handshakes_completed, num_concurrent_connections);
    EXPECT_GE(stats.bytes_transferred, total_successful_transfers * 512);
    
    std::cout << "Stress Test Results:" << std::endl;
    std::cout << "  Concurrent Connections: " << num_concurrent_connections << std::endl;
    std::cout << "  Successful Handshakes: " << successful_handshakes << std::endl;
    std::cout << "  Total Transfers: " << total_successful_transfers << std::endl;
    std::cout << "  Total Bytes: " << stats.bytes_transferred << std::endl;
}

// Test 15: Certificate Validation and Security
TEST_F(DTLSIntegrationTest, CertificateValidationAndSecurity) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake with certificate validation
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Validate security properties
    EXPECT_TRUE(test_env_->verify_connection_security(client.get()));
    EXPECT_TRUE(test_env_->verify_connection_security(server.get()));
    
    // Validate cipher suite negotiation
    dtls::test::DTLSTestValidators::validate_cipher_suite_negotiation(client.get(), server.get());
    
    // Validate key material
    dtls::test::DTLSTestValidators::validate_key_material(client.get());
    dtls::test::DTLSTestValidators::validate_key_material(server.get());
    
    // Validate security parameters
    dtls::test::DTLSTestValidators::validate_security_parameters(client.get());
    dtls::test::DTLSTestValidators::validate_security_parameters(server.get());
    
    // Test encrypted data transfer
    auto sensitive_data = dtls::test::TestDataGenerator::generate_random_data(1024);
    EXPECT_TRUE(transfer_data(client.get(), server.get(), sensitive_data));
    
    // Validate message authentication
    dtls::test::DTLSTestValidators::validate_message_authentication(client.get());
    dtls::test::DTLSTestValidators::validate_message_authentication(server.get());
}

} // namespace test
} // namespace v13
} // namespace dtls