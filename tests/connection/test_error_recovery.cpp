#include <gtest/gtest.h>
#include <dtls/connection.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/transport/udp_transport.h>
#include <chrono>
#include <thread>
#include <iostream>

using namespace dtls::v13;

class ErrorRecoveryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up basic connection configuration with error recovery enabled
        config_.supported_cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
        config_.handshake_timeout = std::chrono::milliseconds(5000);
        config_.retransmission_timeout = std::chrono::milliseconds(1000);
        config_.max_retransmissions = 3;
        
        // Configure error recovery settings
        config_.error_recovery.max_retries = 3;
        config_.error_recovery.initial_retry_delay = std::chrono::milliseconds(100);
        config_.error_recovery.max_retry_delay = std::chrono::milliseconds(5000);
        config_.error_recovery.backoff_multiplier = 2.0;
        config_.error_recovery.max_consecutive_errors = 5;
        config_.error_recovery.max_errors_per_minute = 20;
        config_.error_recovery.degraded_mode_threshold = 0.5;
        config_.error_recovery.enable_automatic_recovery = true;
        
        // Create test network address
        test_address_.family = NetworkAddress::Family::IPv4;
        test_address_.port = 4433;
        // Set IPv4 address for 127.0.0.1
        test_address_.address[0] = 127;
        test_address_.address[1] = 0;
        test_address_.address[2] = 0;
        test_address_.address[3] = 1;
        
        // Track events
        events_received_.clear();
        event_callback_ = [this](ConnectionEvent event, const std::vector<uint8_t>& data) {
            events_received_.push_back(event);
        };
    }
    
    std::unique_ptr<Connection> create_test_connection() {
        auto crypto_provider = std::make_unique<crypto::OpenSSLProvider>();
        EXPECT_TRUE(crypto_provider->initialize().is_success());
        
        auto connection_result = Connection::create_client(
            config_, 
            std::move(crypto_provider), 
            test_address_,
            event_callback_
        );
        
        EXPECT_TRUE(connection_result.is_success());
        return std::move(connection_result.value());
    }
    
    ConnectionConfig config_;
    NetworkAddress test_address_;
    ConnectionEventCallback event_callback_;
    std::vector<ConnectionEvent> events_received_;
};

TEST_F(ErrorRecoveryTest, InitialHealthStatus) {
    auto connection = create_test_connection();
    
    // Initially, connection should be healthy
    EXPECT_EQ(connection->get_health_status(), ConnectionHealth::HEALTHY);
    
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.consecutive_errors, 0);
    EXPECT_EQ(recovery_state.total_recovery_attempts, 0);
    EXPECT_FALSE(recovery_state.recovery_in_progress);
    EXPECT_EQ(recovery_state.current_strategy, RecoveryStrategy::NONE);
}

TEST_F(ErrorRecoveryTest, ErrorRecording) {
    auto connection = create_test_connection();
    
    // Simulate a network error
    auto result = connection->recover_from_error(DTLSError::NETWORK_ERROR, "Test network error");
    EXPECT_TRUE(result.is_success());
    
    // Check that error was recorded
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.last_error_code, DTLSError::NETWORK_ERROR);
    EXPECT_EQ(recovery_state.last_error_message, "Test network error");
    EXPECT_EQ(recovery_state.consecutive_errors, 1);
    EXPECT_EQ(recovery_state.total_recovery_attempts, 1);
    
    // Check that recovery events were fired
    EXPECT_GE(events_received_.size(), 2);
    EXPECT_EQ(events_received_[0], ConnectionEvent::RECOVERY_STARTED);
    EXPECT_EQ(events_received_[1], ConnectionEvent::RECOVERY_SUCCEEDED);
}

TEST_F(ErrorRecoveryTest, RetryableErrorRecovery) {
    auto connection = create_test_connection();
    
    // Test network error (retryable)
    auto result = connection->recover_from_error(DTLSError::NETWORK_ERROR, "Network timeout");
    EXPECT_TRUE(result.is_success());
    
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, RecoveryStrategy::RETRY_WITH_BACKOFF);
    EXPECT_EQ(recovery_state.successful_recoveries, 1);
}

TEST_F(ErrorRecoveryTest, NonRetryableErrorRecovery) {
    auto connection = create_test_connection();
    
    // Test certificate error (non-retryable)
    auto result = connection->recover_from_error(DTLSError::CERTIFICATE_VERIFY_FAILED, "Certificate validation failed");
    EXPECT_TRUE(result.is_success());
    
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, RecoveryStrategy::GRACEFUL_DEGRADATION);
    EXPECT_EQ(recovery_state.successful_recoveries, 1);
}

TEST_F(ErrorRecoveryTest, ConsecutiveErrorHandling) {
    auto connection = create_test_connection();
    
    // Simulate multiple consecutive errors
    for (int i = 0; i < 3; ++i) {
        auto result = connection->recover_from_error(DTLSError::TIMEOUT, "Timeout error " + std::to_string(i));
        EXPECT_TRUE(result.is_success());
    }
    
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.consecutive_errors, 3);
    EXPECT_EQ(recovery_state.total_recovery_attempts, 3);
    
    // Health status should degrade with consecutive errors
    EXPECT_NE(connection->get_health_status(), ConnectionHealth::HEALTHY);
}

TEST_F(ErrorRecoveryTest, DegradedModeEntry) {
    auto connection = create_test_connection();
    
    // Simulate enough errors to trigger degraded mode
    for (int i = 0; i < 10; ++i) {
        connection->recover_from_error(DTLSError::NETWORK_ERROR, "Error " + std::to_string(i));
        // Small delay to spread errors over time
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    EXPECT_TRUE(connection->is_in_degraded_mode());
    EXPECT_EQ(connection->get_health_status(), ConnectionHealth::DEGRADED);
    
    // Check that degraded mode event was fired
    bool degraded_event_fired = false;
    for (const auto& event : events_received_) {
        if (event == ConnectionEvent::CONNECTION_DEGRADED) {
            degraded_event_fired = true;
            break;
        }
    }
    EXPECT_TRUE(degraded_event_fired);
}

TEST_F(ErrorRecoveryTest, ErrorRateCalculation) {
    auto connection = create_test_connection();
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Generate errors at a specific rate
    for (int i = 0; i < 5; ++i) {
        connection->recover_from_error(DTLSError::TIMEOUT, "Rate test error");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    
    auto elapsed = std::chrono::steady_clock::now() - start_time;
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    
    double error_rate = connection->get_error_rate(elapsed_seconds);
    
    // Should have approximately 5 errors per elapsed time
    EXPECT_GT(error_rate, 0.0);
    EXPECT_LT(error_rate, 10.0); // Reasonable upper bound
}

TEST_F(ErrorRecoveryTest, HealthCheckFunctionality) {
    auto connection = create_test_connection();
    
    // Initial health check should succeed
    auto health_result = connection->perform_health_check();
    EXPECT_TRUE(health_result.is_success());
    EXPECT_EQ(connection->get_health_status(), ConnectionHealth::HEALTHY);
    
    // Simulate some errors
    for (int i = 0; i < 2; ++i) {
        connection->recover_from_error(DTLSError::NETWORK_ERROR, "Health check test error");
    }
    
    // Health check should still work but may show degraded status
    health_result = connection->perform_health_check();
    EXPECT_TRUE(health_result.is_success());
}

TEST_F(ErrorRecoveryTest, RecoveryStateReset) {
    auto connection = create_test_connection();
    
    // Generate some errors
    for (int i = 0; i < 3; ++i) {
        connection->recover_from_error(DTLSError::TIMEOUT, "Reset test error");
    }
    
    // Check that state has errors
    auto recovery_state = connection->get_recovery_state();
    EXPECT_GT(recovery_state.consecutive_errors, 0);
    EXPECT_GT(recovery_state.total_recovery_attempts, 0);
    
    // Reset state
    connection->reset_recovery_state();
    
    // Check that state is reset
    recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.consecutive_errors, 0);
    EXPECT_EQ(recovery_state.total_recovery_attempts, 0);
    EXPECT_EQ(recovery_state.successful_recoveries, 0);
    EXPECT_EQ(recovery_state.failed_recoveries, 0);
    EXPECT_EQ(recovery_state.health_status, ConnectionHealth::HEALTHY);
}

TEST_F(ErrorRecoveryTest, MaxRetryLimitEnforcement) {
    auto connection = create_test_connection();
    
    // Configure for low retry limit
    config_.error_recovery.max_retries = 2;
    config_.error_recovery.max_consecutive_errors = 2;
    
    // Create new connection with updated config
    connection = create_test_connection();
    
    // Exceed retry limit
    for (int i = 0; i < 5; ++i) {
        auto result = connection->recover_from_error(DTLSError::NETWORK_ERROR, "Retry limit test");
        if (i < 2) {
            EXPECT_TRUE(result.is_success());
        } else {
            // Should start failing after max retries
            EXPECT_FALSE(result.is_success());
        }
    }
    
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.health_status, ConnectionHealth::FAILED);
}

TEST_F(ErrorRecoveryTest, StrategySelectionForDifferentErrors) {
    auto connection = create_test_connection();
    
    // Test handshake error strategy
    connection->recover_from_error(DTLSError::HANDSHAKE_FAILURE, "Handshake test");
    auto recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, config_.error_recovery.handshake_error_strategy);
    
    // Reset and test crypto error strategy
    connection->reset_recovery_state();
    connection->recover_from_error(DTLSError::DECRYPT_ERROR, "Crypto test");
    recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, config_.error_recovery.crypto_error_strategy);
    
    // Reset and test network error strategy
    connection->reset_recovery_state();
    connection->recover_from_error(DTLSError::NETWORK_ERROR, "Network test");
    recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, config_.error_recovery.network_error_strategy);
    
    // Reset and test protocol error strategy
    connection->reset_recovery_state();
    connection->recover_from_error(DTLSError::STATE_MACHINE_ERROR, "Protocol test");
    recovery_state = connection->get_recovery_state();
    EXPECT_EQ(recovery_state.current_strategy, config_.error_recovery.protocol_error_strategy);
}

TEST_F(ErrorRecoveryTest, BackoffDelayCalculation) {
    auto connection = create_test_connection();
    
    // Access private method through recovery functionality
    // We'll test this indirectly by checking retry attempts
    
    connection->recover_from_error(DTLSError::TIMEOUT, "Backoff test 1");
    auto recovery_state = connection->get_recovery_state();
    uint32_t first_attempt = recovery_state.retry_attempt;
    
    connection->recover_from_error(DTLSError::TIMEOUT, "Backoff test 2");
    recovery_state = connection->get_recovery_state();
    uint32_t second_attempt = recovery_state.retry_attempt;
    
    // Retry attempts should increase with backoff strategy
    EXPECT_GT(second_attempt, first_attempt);
}

TEST_F(ErrorRecoveryTest, AutomaticRecoveryDisabling) {
    // Configure with automatic recovery disabled
    config_.error_recovery.enable_automatic_recovery = false;
    
    auto connection = create_test_connection();
    
    // Try to trigger recovery
    auto result = connection->recover_from_error(DTLSError::NETWORK_ERROR, "Auto recovery disabled test");
    
    // Should fail because automatic recovery is disabled
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::RESOURCE_EXHAUSTED);
}

TEST_F(ErrorRecoveryTest, ConnectionValidityAfterErrors) {
    auto connection = create_test_connection();
    
    // Connection should be valid initially
    EXPECT_EQ(connection->get_state(), ConnectionState::INITIAL);
    
    // Simulate recoverable error
    auto result = connection->recover_from_error(DTLSError::TIMEOUT, "Validity test");
    EXPECT_TRUE(result.is_success());
    
    // Connection should still be valid after recoverable error
    EXPECT_NE(connection->get_state(), ConnectionState::CLOSED);
    
    // Simulate fatal error with abort strategy
    config_.error_recovery.crypto_error_strategy = RecoveryStrategy::ABORT_CONNECTION;
    connection = create_test_connection();
    
    result = connection->recover_from_error(DTLSError::DECRYPT_ERROR, "Fatal error test");
    EXPECT_FALSE(result.is_success());
    
    // Connection should be closed after abort strategy
    EXPECT_EQ(connection->get_state(), ConnectionState::CLOSED);
}

// Main function is provided by dtls_connection_test suite