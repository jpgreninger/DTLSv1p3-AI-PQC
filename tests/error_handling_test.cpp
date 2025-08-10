#include <gtest/gtest.h>
#include <dtls/error_handler.h>
#include <dtls/error_context.h>
#include <dtls/alert_manager.h>
#include <dtls/error_reporter.h>
#include <memory>
#include <chrono>
#include <thread>
#include <algorithm>

namespace dtls {
namespace v13 {
namespace test {

// Helper function for error equivalence testing
bool is_equivalent_error(DTLSError error1, DTLSError error2) {
    // Define groups of equivalent errors
    std::vector<std::vector<DTLSError>> equivalent_groups = {
        {DTLSError::CERTIFICATE_VERIFY_FAILED, DTLSError::CERTIFICATE_UNKNOWN},
        {DTLSError::TIMEOUT, DTLSError::CONNECTION_TIMEOUT},
        {DTLSError::NETWORK_ERROR, DTLSError::TRANSPORT_ERROR}
    };
    
    for (const auto& group : equivalent_groups) {
        bool found1 = std::find(group.begin(), group.end(), error1) != group.end();
        bool found2 = std::find(group.begin(), group.end(), error2) != group.end();
        if (found1 && found2) {
            return true;
        }
    }
    
    return error1 == error2;
}

class ErrorHandlingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Configure error handler for testing
        ErrorHandler::Configuration config;
        config.transport_type = ErrorHandler::Transport::UDP;
        config.security_level = ErrorHandler::SecurityLevel::STANDARD;
        config.generate_alerts_on_invalid_records = false; // Per RFC 9147 for UDP
        config.log_invalid_records = true;
        config.max_auth_failures_per_epoch = 5;
        config.max_invalid_records_per_second = 10;
        
        error_handler_ = std::make_unique<ErrorHandler>(config);
        
        // Configure alert manager
        AlertManager::AlertPolicy alert_policy;
        alert_policy.transport_security = AlertManager::TransportSecurity::INSECURE; // UDP
        alert_policy.generate_alerts_for_invalid_records = false;
        alert_policy.generate_alerts_for_auth_failures = false;
        
        alert_manager_ = std::make_shared<AlertManager>(alert_policy);
        
        // Configure error reporter for testing
        ErrorReporter::ReportingConfig reporter_config;
        reporter_config.minimum_level = ErrorReporter::LogLevel::DEBUG;
        reporter_config.format = ErrorReporter::OutputFormat::JSON;
        reporter_config.log_network_addresses = false; // Privacy test
        reporter_config.log_connection_ids = false;
        reporter_config.max_reports_per_second = 1000; // High for testing
        
        error_reporter_ = std::make_shared<ErrorReporter>(reporter_config);
        
        // Wire up components
        error_handler_->set_alert_manager(alert_manager_);
        error_handler_->set_error_reporter(error_reporter_);
    }
    
    void TearDown() override {
        error_handler_.reset();
        alert_manager_.reset();
        error_reporter_.reset();
    }
    
    std::unique_ptr<ErrorHandler> error_handler_;
    std::shared_ptr<AlertManager> alert_manager_;
    std::shared_ptr<ErrorReporter> error_reporter_;
};

// Test RFC 9147 Section 4.2.1 - Invalid records should be silently discarded
TEST_F(ErrorHandlingTest, InvalidRecordsSilentlyDiscarded) {
    auto context = error_handler_->create_error_context("test_conn_1");
    
    // Test that invalid records are silently discarded
    auto result = error_handler_->handle_invalid_record(
        ContentType::APPLICATION_DATA, context);
    
    EXPECT_TRUE(result.is_success());
    
    // Check that error was logged for diagnostic purposes
    EXPECT_GT(context->get_total_error_count(), 0);
    
    // Verify no alert was generated for UDP transport
    const auto& stats = error_handler_->get_error_statistics();
    EXPECT_EQ(stats.alerts_generated, 0);
    
    // Verify invalid record counter was incremented
    EXPECT_GT(stats.invalid_records_discarded, 0);
}

// Test RFC 9147 authentication failure tracking
TEST_F(ErrorHandlingTest, AuthenticationFailureTracking) {
    auto context = error_handler_->create_error_context("test_conn_2");
    Epoch test_epoch = 1;
    
    // Test normal authentication failures (should continue)
    for (int i = 0; i < 3; ++i) {
        auto result = error_handler_->handle_authentication_failure(test_epoch, context);
        EXPECT_TRUE(result.is_success());
        EXPECT_TRUE(result.value()); // Connection should continue
    }
    
    // Test excessive authentication failures (should terminate)
    for (int i = 0; i < 5; ++i) {
        error_handler_->handle_authentication_failure(test_epoch, context);
    }
    
    auto result = error_handler_->handle_authentication_failure(test_epoch, context);
    EXPECT_TRUE(result.is_success());
    EXPECT_FALSE(result.value()); // Connection should terminate
    
    // Verify DoS attack detection
    const auto& stats = error_handler_->get_error_statistics();
    EXPECT_GT(stats.dos_attacks_detected, 0);
}

// Test transport-specific alert generation policies
TEST_F(ErrorHandlingTest, TransportSpecificAlertPolicy) {
    auto context = error_handler_->create_error_context("test_conn_3");
    
    // For UDP transport, should NOT generate alerts for most errors
    auto alert_result = error_handler_->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    EXPECT_FALSE(alert_result.is_success()); // Should fail for UDP transport
    EXPECT_EQ(alert_result.error(), DTLSError::OPERATION_NOT_SUPPORTED);
    
    // Change to secure transport and test again
    ErrorHandler::Configuration secure_config;
    secure_config.transport_type = ErrorHandler::Transport::DTLS_OVER_SCTP;
    error_handler_->update_configuration(secure_config);
    
    // Now alerts should be generated for secure transport
    alert_result = error_handler_->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    // Should succeed for secure transport
    EXPECT_TRUE(alert_result.is_success());
    EXPECT_GT(alert_result.value().size(), 0);
}

// Test error context creation and management
TEST_F(ErrorHandlingTest, ErrorContextManagement) {
    // Convert IP address 192.168.1.100 to uint32_t (network byte order)
    uint32_t ip_addr = (192U << 24) | (168U << 16) | (1U << 8) | 100U;
    NetworkAddress peer_addr = NetworkAddress::from_ipv4(ip_addr, 443);
    auto context = error_handler_->create_error_context("test_conn_4", peer_addr);
    
    EXPECT_NE(context, nullptr);
    EXPECT_EQ(context->get_total_error_count(), 0);
    EXPECT_FALSE(context->has_security_errors());
    
    // Record various types of errors
    context->record_error(DTLSError::HANDSHAKE_FAILURE, "handshake", 
                         "Test handshake error", false);
    context->record_security_error(DTLSError::AUTHENTICATION_FAILED,
                                  "brute_force", 0.8);
    
    EXPECT_EQ(context->get_total_error_count(), 2);
    EXPECT_TRUE(context->has_security_errors());
    
    // Test error pattern detection
    double confidence = context->detect_attack_patterns();
    EXPECT_GT(confidence, 0.0);
    EXPECT_LE(confidence, 1.0);
}

// Test error rate detection for DoS protection
TEST_F(ErrorHandlingTest, ErrorRateDetection) {
    auto context = error_handler_->create_error_context("test_conn_5");
    
    // Generate errors rapidly to trigger rate detection
    for (int i = 0; i < 15; ++i) {
        error_handler_->handle_invalid_record(ContentType::HANDSHAKE, context);
    }
    
    // Check if DoS attack was detected
    const auto& stats = error_handler_->get_error_statistics();
    EXPECT_GT(stats.dos_attacks_detected, 0);
    
    // Verify error context rate detection
    bool excessive_rate = context->is_error_rate_excessive(
        std::chrono::seconds(1), 10);
    EXPECT_TRUE(excessive_rate);
}

// Test security-conscious error reporting
TEST_F(ErrorHandlingTest, SecurityConsciousReporting) {
    auto context = error_handler_->create_error_context("sensitive_conn");
    
    // Report various types of errors
    error_reporter_->report_error(
        ErrorReporter::LogLevel::WARNING,
        DTLSError::CERTIFICATE_VERIFY_FAILED,
        "certificate_validation",
        "Certificate verification failed",
        context
    );
    
    error_reporter_->report_security_incident(
        DTLSError::REPLAY_ATTACK_DETECTED,
        "replay_attack",
        0.9,
        context
    );
    
    const auto& stats = error_reporter_->get_statistics();
    EXPECT_GT(stats.total_reports, 0);
    EXPECT_GT(stats.security_incidents, 0);
    
    // Verify no sensitive data is exposed in safe descriptions
    std::string safe_desc = ErrorReporter::error_to_safe_description(
        DTLSError::DECRYPT_ERROR);
    EXPECT_FALSE(safe_desc.empty());
    EXPECT_EQ(safe_desc.find("key"), std::string::npos); // No key material
    EXPECT_EQ(safe_desc.find("plaintext"), std::string::npos); // No plaintext
}

// Test alert generation and serialization
TEST_F(ErrorHandlingTest, AlertGenerationAndSerialization) {
    // Test alert serialization
    auto alert_data = AlertManager::serialize_alert(
        AlertLevel::FATAL, AlertDescription::HANDSHAKE_FAILURE);
    
    EXPECT_EQ(alert_data.size(), 2); // Alert should be 2 bytes
    EXPECT_EQ(alert_data[0], static_cast<uint8_t>(AlertLevel::FATAL));
    EXPECT_EQ(alert_data[1], static_cast<uint8_t>(AlertDescription::HANDSHAKE_FAILURE));
    
    // Test alert parsing
    auto parse_result = AlertManager::parse_alert(alert_data);
    EXPECT_TRUE(parse_result.is_success());
    
    auto [level, description] = parse_result.value();
    EXPECT_EQ(level, AlertLevel::FATAL);
    EXPECT_EQ(description, AlertDescription::HANDSHAKE_FAILURE);
}

// Test error-to-alert mapping compliance
TEST_F(ErrorHandlingTest, ErrorToAlertMappingCompliance) {
    // Test standard RFC 9147 error-to-alert mappings
    struct ErrorAlertMapping {
        DTLSError error;
        AlertDescription expected_alert;
    } mappings[] = {
        {DTLSError::HANDSHAKE_FAILURE, AlertDescription::HANDSHAKE_FAILURE},
        {DTLSError::BAD_RECORD_MAC, AlertDescription::BAD_RECORD_MAC},
        {DTLSError::DECRYPT_ERROR, AlertDescription::DECRYPT_ERROR},
        {DTLSError::ILLEGAL_PARAMETER, AlertDescription::ILLEGAL_PARAMETER},
        {DTLSError::CERTIFICATE_VERIFY_FAILED, AlertDescription::BAD_CERTIFICATE},
        {DTLSError::UNKNOWN_CA, AlertDescription::UNKNOWN_CA},
        {DTLSError::ACCESS_DENIED, AlertDescription::ACCESS_DENIED}
    };
    
    for (const auto& mapping : mappings) {
        AlertDescription alert = error_to_alert(mapping.error);
        EXPECT_EQ(alert, mapping.expected_alert) 
            << "Error " << static_cast<int>(mapping.error) 
            << " should map to alert " << static_cast<int>(mapping.expected_alert);
        
        // Test reverse mapping
        DTLSError reverse_error = alert_to_error(alert);
        EXPECT_TRUE(reverse_error == mapping.error || 
                   is_equivalent_error(reverse_error, mapping.error))
            << "Alert " << static_cast<int>(alert)
            << " should reverse-map to compatible error";
    }
}

// Test thread safety of error handling
TEST_F(ErrorHandlingTest, ThreadSafety) {
    const int NUM_THREADS = 10;
    const int OPERATIONS_PER_THREAD = 100;
    std::vector<std::thread> threads;
    
    // Create multiple contexts for concurrent testing
    std::vector<std::shared_ptr<ErrorContext>> contexts;
    for (int i = 0; i < NUM_THREADS; ++i) {
        contexts.push_back(
            error_handler_->create_error_context("thread_conn_" + std::to_string(i))
        );
    }
    
    // Launch threads that concurrently perform error operations
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([this, t, &contexts, OPERATIONS_PER_THREAD]() {
            for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                // Mix different types of operations
                if (i % 3 == 0) {
                    error_handler_->handle_invalid_record(
                        ContentType::APPLICATION_DATA, contexts[t]);
                } else if (i % 3 == 1) {
                    error_handler_->handle_authentication_failure(1, contexts[t]);
                } else {
                    error_handler_->process_error(DTLSError::TIMEOUT, contexts[t]);
                }
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify that operations completed successfully
    const auto& stats = error_handler_->get_error_statistics();
    EXPECT_GT(stats.total_errors, 0);
    
    // Verify each context has recorded errors
    for (const auto& context : contexts) {
        EXPECT_GT(context->get_total_error_count(), 0);
    }
}

// Test error context expiration and cleanup
TEST_F(ErrorHandlingTest, ErrorContextExpiration) {
    ErrorContextManager manager;
    
    // Create contexts with different characteristics
    auto context1 = manager.create_context("short_lived");
    auto context2 = manager.create_context("long_lived");
    
    // Add many errors to context1 to trigger event-based expiration
    for (int i = 0; i < 1100; ++i) { // Exceed default max_events limit
        context1->record_error(DTLSError::TIMEOUT, "test", "test error");
    }
    
    // Test expiration criteria
    EXPECT_TRUE(context1->should_expire(std::chrono::seconds(10), 1000));
    EXPECT_FALSE(context2->should_expire(std::chrono::hours(1), 2000));
    
    // Test cleanup
    size_t cleaned = manager.cleanup_expired_contexts(
        std::chrono::seconds(1), 1000);
    EXPECT_GT(cleaned, 0);
}

// Test error reporting rate limiting
TEST_F(ErrorHandlingTest, ErrorReportingRateLimiting) {
    // Configure strict rate limiting
    ErrorReporter::ReportingConfig config;
    config.max_reports_per_second = 5;
    config.max_reports_per_minute = 20;
    error_reporter_->update_configuration(config);
    
    auto context = error_handler_->create_error_context("rate_limited_conn");
    
    // Generate reports rapidly
    int successful_reports = 0;
    for (int i = 0; i < 30; ++i) {
        auto result = error_reporter_->report_error(
            ErrorReporter::LogLevel::INFO,
            DTLSError::TIMEOUT,
            "test",
            "Rate limiting test",
            context
        );
        
        if (result.is_success()) {
            successful_reports++;
        }
    }
    
    // Should have been rate limited
    EXPECT_LT(successful_reports, 30);
    
    const auto& stats = error_reporter_->get_statistics();
    EXPECT_GT(stats.rate_limited_reports, 0);
}

// Test RFC 9147 Connection ID error handling
TEST_F(ErrorHandlingTest, ConnectionIDErrorHandling) {
    auto context = error_handler_->create_error_context("cid_test_conn");
    
    // Test too many CID requests error mapping
    DTLSError cid_error = DTLSError::CONNECTION_ID_MISMATCH;
    AlertDescription expected_alert = error_to_alert(cid_error);
    
    EXPECT_EQ(expected_alert, AlertDescription::TOO_MANY_CIDS_REQUESTED);
    
    // Test reverse mapping
    DTLSError reverse_error = alert_to_error(AlertDescription::TOO_MANY_CIDS_REQUESTED);
    EXPECT_EQ(reverse_error, DTLSError::CONNECTION_ID_MISMATCH);
}


} // namespace test
} // namespace v13
} // namespace dtls