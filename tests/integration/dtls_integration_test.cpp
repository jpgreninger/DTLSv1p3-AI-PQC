#include <gtest/gtest.h>
#include <gmock/gmock.h>
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
        // Initialize crypto providers
        auto openssl_provider = std::make_unique<crypto::OpenSSLProvider>();
        ASSERT_TRUE(openssl_provider->initialize().is_ok());
        
        // Create client and server contexts
        client_context_ = std::make_unique<Context>();
        server_context_ = std::make_unique<Context>();
        
        // Configure contexts
        client_context_->set_crypto_provider(std::move(openssl_provider));
        
        auto server_openssl = std::make_unique<crypto::OpenSSLProvider>();
        ASSERT_TRUE(server_openssl->initialize().is_ok());
        server_context_->set_crypto_provider(std::move(server_openssl));
        
        // Setup transport
        client_transport_ = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
        server_transport_ = std::make_unique<transport::UDPTransport>("127.0.0.1", 4433);
        
        ASSERT_TRUE(client_transport_->bind().is_ok());
        ASSERT_TRUE(server_transport_->bind().is_ok());
        
        // Reset statistics
        handshakes_completed_ = 0;
        bytes_transferred_ = 0;
        errors_encountered_ = 0;
    }
    
    void TearDown() override {
        // Cleanup connections
        client_connections_.clear();
        server_connections_.clear();
        
        // Shutdown transport
        if (client_transport_) {
            client_transport_->shutdown();
        }
        if (server_transport_) {
            server_transport_->shutdown();
        }
    }
    
    // Helper method to create client connection
    std::unique_ptr<Connection> create_client_connection() {
        auto connection = client_context_->create_connection();
        EXPECT_TRUE(connection);
        if (connection) {
            connection->set_transport(client_transport_.get());
        }
        return connection;
    }
    
    // Helper method to create server connection
    std::unique_ptr<Connection> create_server_connection() {
        auto connection = server_context_->create_connection();
        EXPECT_TRUE(connection);
        if (connection) {
            connection->set_transport(server_transport_.get());
        }
        return connection;
    }
    
    // Helper method to perform handshake
    bool perform_handshake(Connection* client, Connection* server) {
        std::atomic<bool> client_complete{false};
        std::atomic<bool> server_complete{false};
        std::atomic<bool> handshake_failed{false};
        
        // Setup handshake completion callbacks
        client->set_handshake_callback([&](const Result<void>& result) {
            if (result.is_ok()) {
                client_complete = true;
                handshakes_completed_++;
            } else {
                handshake_failed = true;
                errors_encountered_++;
            }
        });
        
        server->set_handshake_callback([&](const Result<void>& result) {
            if (result.is_ok()) {
                server_complete = true;
            } else {
                handshake_failed = true;
                errors_encountered_++;
            }
        });
        
        // Start handshake
        auto client_result = client->connect("127.0.0.1", 4433);
        EXPECT_TRUE(client_result.is_ok());
        
        auto server_result = server->accept();
        EXPECT_TRUE(server_result.is_ok());
        
        // Wait for handshake completion (with timeout)
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(10);
        
        while (!client_complete || !server_complete) {
            if (handshake_failed) {
                return false;
            }
            
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > timeout) {
                ADD_FAILURE() << "Handshake timeout";
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        return true;
    }
    
    // Helper method to transfer data
    bool transfer_data(Connection* sender, Connection* receiver, 
                      const std::vector<uint8_t>& data) {
        std::atomic<bool> data_received{false};
        std::atomic<bool> transfer_failed{false};
        std::vector<uint8_t> received_data;
        
        // Setup data reception callback
        receiver->set_data_callback([&](const std::vector<uint8_t>& recv_data) {
            received_data = recv_data;
            data_received = true;
            bytes_transferred_ += recv_data.size();
        });
        
        // Send data
        auto send_result = sender->send(data);
        EXPECT_TRUE(send_result.is_ok());
        if (!send_result.is_ok()) {
            transfer_failed = true;
            errors_encountered_++;
            return false;
        }
        
        // Wait for data reception (with timeout)
        auto start_time = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(5);
        
        while (!data_received) {
            if (transfer_failed) {
                return false;
            }
            
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > timeout) {
                ADD_FAILURE() << "Data transfer timeout";
                return false;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Verify data integrity
        EXPECT_EQ(data, received_data);
        return data == received_data;
    }

protected:
    std::unique_ptr<Context> client_context_;
    std::unique_ptr<Context> server_context_;
    std::unique_ptr<transport::UDPTransport> client_transport_;
    std::unique_ptr<transport::UDPTransport> server_transport_;
    
    std::vector<std::unique_ptr<Connection>> client_connections_;
    std::vector<std::unique_ptr<Connection>> server_connections_;
    
    // Test statistics
    std::atomic<uint32_t> handshakes_completed_{0};
    std::atomic<uint64_t> bytes_transferred_{0};
    std::atomic<uint32_t> errors_encountered_{0};
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
    EXPECT_EQ(handshakes_completed_, 1);
    EXPECT_EQ(errors_encountered_, 0);
}

// Test 2: Application Data Transfer
TEST_F(DTLSIntegrationTest, ApplicationDataTransfer) {
    auto client = create_client_connection();
    auto server = create_server_connection();
    
    ASSERT_TRUE(client);
    ASSERT_TRUE(server);
    
    // Complete handshake first
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Test data transfer client -> server
    std::vector<uint8_t> test_data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), test_data1));
    
    // Test data transfer server -> client
    std::vector<uint8_t> test_data2 = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    EXPECT_TRUE(transfer_data(server.get(), client.get(), test_data2));
    
    // Verify transfer statistics
    EXPECT_EQ(bytes_transferred_, test_data1.size() + test_data2.size());
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
    EXPECT_EQ(errors_encountered_, 0);
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
    EXPECT_EQ(handshakes_completed_, num_connections);
    
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
    auto new_client_transport = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
    ASSERT_TRUE(new_client_transport->bind().is_ok());
    
    // Update client connection transport
    client->set_transport(new_client_transport.get());
    
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
    client_transport_->shutdown();
    
    // Attempt data transfer (should fail)
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    auto send_result = client->send(test_data);
    EXPECT_FALSE(send_result.is_ok());
    
    // Restart transport
    client_transport_ = std::make_unique<transport::UDPTransport>("127.0.0.1", 0);
    ASSERT_TRUE(client_transport_->bind().is_ok());
    client->set_transport(client_transport_.get());
    
    // Attempt recovery (may require re-handshake)
    auto reconnect_result = client->reconnect();
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
    
    client->set_cipher_suites(client_cipher_suites);
    server->set_cipher_suites(server_cipher_suites);
    
    // Perform handshake
    ASSERT_TRUE(perform_handshake(client.get(), server.get()));
    
    // Verify negotiated cipher suite (should be AES_128_GCM_SHA256)
    auto client_cipher = client->get_negotiated_cipher_suite();
    auto server_cipher = server->get_negotiated_cipher_suite();
    
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
    EXPECT_EQ(bytes_transferred_, data_before.size() + data_after.size());
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
    EXPECT_TRUE(client->is_secure());
    EXPECT_TRUE(server->is_secure());
    
    // Verify encryption is active
    EXPECT_TRUE(client->is_encrypted());
    EXPECT_TRUE(server->is_encrypted());
    
    // Test replay attack protection
    // (This would require more sophisticated testing in a real implementation)
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    EXPECT_TRUE(transfer_data(client.get(), server.get(), test_data));
    
    // Verify authenticated encryption
    auto security_info = client->get_security_info();
    EXPECT_TRUE(security_info.is_ok());
}

} // namespace test
} // namespace v13
} // namespace dtls