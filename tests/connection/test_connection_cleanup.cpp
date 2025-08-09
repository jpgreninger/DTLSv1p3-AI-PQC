#include <gtest/gtest.h>
#include <dtls/connection.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/transport/udp_transport.h>
#include <chrono>
#include <thread>
#include <iostream>

using namespace dtls::v13;

class ConnectionCleanupTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up basic connection configuration
        config_.supported_cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
        config_.handshake_timeout = std::chrono::milliseconds(5000);
        config_.retransmission_timeout = std::chrono::milliseconds(1000);
        config_.max_retransmissions = 3;
        
        // Disable error recovery for tests to prevent timeouts
        config_.error_recovery.enable_automatic_recovery = false;
        
        // Create test network address
        test_address_.family = NetworkAddress::Family::IPv4;
        test_address_.port = 4433;
        // Set IPv4 address for 127.0.0.1
        test_address_.address[0] = 127;
        test_address_.address[1] = 0;
        test_address_.address[2] = 0;
        test_address_.address[3] = 1;
    }
    
    ConnectionConfig config_;
    NetworkAddress test_address_;
};

TEST_F(ConnectionCleanupTest, BasicConnectionCleanup) {
    // Create connection
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    auto connection_result = Connection::create_client(
        config_, 
        std::move(crypto_provider), 
        test_address_
    );
    
    ASSERT_TRUE(connection_result.is_success());
    auto connection = std::move(connection_result.value());
    
    // Verify initial state
    EXPECT_EQ(connection->get_state(), ConnectionState::INITIAL);
    EXPECT_FALSE(connection->is_connected());
    
    // Close connection normally
    auto close_result = connection->close();
    EXPECT_TRUE(close_result.is_success());
    
    // Verify closed state
    EXPECT_EQ(connection->get_state(), ConnectionState::CLOSED);
    EXPECT_FALSE(connection->is_connected());
}

TEST_F(ConnectionCleanupTest, ForceCloseConnection) {
    // Create connection
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    auto connection_result = Connection::create_client(
        config_, 
        std::move(crypto_provider), 
        test_address_
    );
    
    ASSERT_TRUE(connection_result.is_success());
    auto connection = std::move(connection_result.value());
    
    // Force close connection
    connection->force_close();
    
    // Verify closed state
    EXPECT_EQ(connection->get_state(), ConnectionState::CLOSED);
    EXPECT_FALSE(connection->is_connected());
    
    // Verify operations are rejected after force close
    memory::ZeroCopyBuffer test_data(100);
    auto send_result = connection->send_application_data(test_data);
    EXPECT_FALSE(send_result.is_success());
    EXPECT_EQ(send_result.error(), DTLSError::CONNECTION_CLOSED);
}

TEST_F(ConnectionCleanupTest, OperationsAfterClose) {
    // Create connection
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    auto connection_result = Connection::create_client(
        config_, 
        std::move(crypto_provider), 
        test_address_
    );
    
    ASSERT_TRUE(connection_result.is_success());
    auto connection = std::move(connection_result.value());
    
    // Close connection
    auto close_result = connection->close();
    EXPECT_TRUE(close_result.is_success());
    
    // Verify all operations are rejected after close
    memory::ZeroCopyBuffer test_data(100);
    
    auto send_result = connection->send_application_data(test_data);
    EXPECT_FALSE(send_result.is_success());
    EXPECT_EQ(send_result.error(), DTLSError::CONNECTION_CLOSED);
    
    auto update_result = connection->update_keys();
    EXPECT_FALSE(update_result.is_success());
    EXPECT_EQ(update_result.error(), DTLSError::CONNECTION_CLOSED);
    
    // Close should be idempotent
    auto second_close = connection->close();
    if (!second_close.is_success()) {
        std::cout << "Second close failed with error: " << static_cast<int>(second_close.error()) << std::endl;
    }
    EXPECT_TRUE(second_close.is_success());
}

TEST_F(ConnectionCleanupTest, ConnectionStats) {
    // Create connection
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    auto connection_result = Connection::create_client(
        config_, 
        std::move(crypto_provider), 
        test_address_
    );
    
    ASSERT_TRUE(connection_result.is_success());
    auto connection = std::move(connection_result.value());
    
    // Check initial stats
    auto initial_stats = connection->get_stats();
    EXPECT_EQ(initial_stats.bytes_sent, 0);
    EXPECT_EQ(initial_stats.bytes_received, 0);
    EXPECT_EQ(initial_stats.key_updates_performed, 0);
    
    // Close connection
    connection->close();
    
    // Stats should still be accessible after close
    auto final_stats = connection->get_stats();
    EXPECT_EQ(final_stats.bytes_sent, 0);
    EXPECT_EQ(final_stats.bytes_received, 0);
}

TEST_F(ConnectionCleanupTest, DestructorCleanup) {
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    // Test that destructor properly cleans up connection
    {
        auto connection_result = Connection::create_client(
            config_, 
            std::move(crypto_provider), 
            test_address_
        );
        
        ASSERT_TRUE(connection_result.is_success());
        auto connection = std::move(connection_result.value());
        
        // Connection will be destroyed when leaving scope
        // Destructor should call force_close() automatically
    }
    
    // If we reach here without crashes, destructor cleanup worked
    SUCCEED();
}

TEST_F(ConnectionCleanupTest, ConnectionValidityCheck) {
    auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
    ASSERT_TRUE(crypto_provider->initialize().is_success());
    
    auto connection_result = Connection::create_client(
        config_, 
        std::move(crypto_provider), 
        test_address_
    );
    
    ASSERT_TRUE(connection_result.is_success());
    auto connection = std::move(connection_result.value());
    
    // Initially valid (though not connected)
    EXPECT_EQ(connection->get_state(), ConnectionState::INITIAL);
    
    // After force close, should be invalid
    connection->force_close();
    EXPECT_EQ(connection->get_state(), ConnectionState::CLOSED);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}