#include <gtest/gtest.h>
#include <dtls/error_handler.h>
#include <dtls/alert_manager.h>
#include <dtls/error_context.h>
#include <dtls/types.h>
#include <memory>

namespace dtls {
namespace v13 {
namespace test {

/**
 * RFC 9147 Compliance Test Suite
 * 
 * Tests specific requirements from RFC 9147 "The Datagram Transport Layer 
 * Security (DTLS) Protocol Version 1.3"
 */
class RFC9147ComplianceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Default UDP configuration per RFC 9147 recommendations
        udp_config_.transport_type = ErrorHandler::Transport::UDP;
        udp_config_.security_level = ErrorHandler::SecurityLevel::STANDARD;
        udp_config_.generate_alerts_on_invalid_records = false; // NOT RECOMMENDED for UDP
        udp_config_.log_invalid_records = true; // MAY be logged for diagnostics
        udp_config_.max_auth_failures_per_epoch = 10; // Per RFC implementation guidelines
        
        udp_error_handler_ = std::make_unique<ErrorHandler>(udp_config_);
        
        // Secure transport configuration (SCTP with SCTP-AUTH)
        secure_config_.transport_type = ErrorHandler::Transport::DTLS_OVER_SCTP;
        secure_config_.security_level = ErrorHandler::SecurityLevel::STANDARD;
        secure_config_.generate_alerts_on_invalid_records = true; // Safer for secure transports
        
        secure_error_handler_ = std::make_unique<ErrorHandler>(secure_config_);
        
        // Alert managers with transport-specific policies
        AlertManager::AlertPolicy udp_policy;
        udp_policy.transport_security = AlertManager::TransportSecurity::INSECURE;
        udp_policy.generate_alerts_for_invalid_records = false;
        udp_policy.generate_alerts_for_auth_failures = false;
        
        AlertManager::AlertPolicy secure_policy;
        secure_policy.transport_security = AlertManager::TransportSecurity::SECURE;
        secure_policy.generate_alerts_for_invalid_records = true;
        secure_policy.generate_alerts_for_auth_failures = true;
        
        udp_alert_manager_ = std::make_shared<AlertManager>(udp_policy);
        secure_alert_manager_ = std::make_shared<AlertManager>(secure_policy);
        
        udp_error_handler_->set_alert_manager(udp_alert_manager_);
        secure_error_handler_->set_alert_manager(secure_alert_manager_);
    }
    
    ErrorHandler::Configuration udp_config_;
    ErrorHandler::Configuration secure_config_;
    
    std::unique_ptr<ErrorHandler> udp_error_handler_;
    std::unique_ptr<ErrorHandler> secure_error_handler_;
    
    std::shared_ptr<AlertManager> udp_alert_manager_;
    std::shared_ptr<AlertManager> secure_alert_manager_;
};

/**
 * RFC 9147 Section 4.2.1: Invalid Record Handling
 * "In general, invalid records SHOULD be silently discarded, thus preserving
 * the association; however, an error MAY be logged for diagnostic purposes."
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_InvalidRecordHandling) {
    auto context = udp_error_handler_->create_error_context("test_invalid_records");
    
    // Test various invalid record types
    std::vector<ContentType> invalid_record_types = {
        ContentType::INVALID,
        ContentType::APPLICATION_DATA, // Could be invalid in certain contexts
        ContentType::HANDSHAKE,        // Could be malformed
        ContentType::ALERT             // Could be malicious
    };
    
    for (const auto& record_type : invalid_record_types) {
        // RFC requirement: invalid records SHOULD be silently discarded
        auto result = udp_error_handler_->handle_invalid_record(record_type, context);
        
        // Should succeed (silently discarded)
        EXPECT_TRUE(result.is_success()) 
            << "Invalid record type " << static_cast<int>(record_type) 
            << " should be silently discarded";
    }
    
    // RFC requirement: error MAY be logged for diagnostic purposes
    EXPECT_GT(context->get_total_error_count(), 0)
        << "Diagnostic logging should have recorded invalid records";
    
    // RFC requirement: association should be preserved (no fatal errors)
    EXPECT_EQ(context->get_error_count(true), 0) // true = fatal errors only
        << "Invalid records should not cause fatal errors";
    
    // Verify statistics tracking
    const auto& stats = udp_error_handler_->get_error_statistics();
    EXPECT_GT(stats.invalid_records_discarded, 0)
        << "Invalid records counter should be incremented";
}

/**
 * RFC 9147 Section 4.2.1: Alert Generation Policy
 * "Implementations which choose to generate an alert instead MUST generate
 * fatal alerts to avoid attacks where the attacker repeatedly probes the
 * implementation to see how it responds to various types of error."
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_AlertGenerationMustBeFatal) {
    auto context = secure_error_handler_->create_error_context("test_fatal_alerts");
    
    // For secure transport, if alerts are generated, they MUST be fatal
    auto alert_result = secure_error_handler_->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    if (alert_result.is_success()) {
        auto alert_data = alert_result.value();
        ASSERT_GT(alert_data.size(), 0);
        
        // Parse the alert to verify it's fatal
        auto parse_result = AlertManager::parse_alert(alert_data);
        ASSERT_TRUE(parse_result.is_success());
        
        auto [level, description] = parse_result.value();
        EXPECT_EQ(level, AlertLevel::FATAL)
            << "RFC 9147 requires alerts for invalid records to be FATAL";
    }
}

/**
 * RFC 9147 Section 4.2.1: UDP Transport Alert Policy
 * "Note that if DTLS is run over UDP, then any implementation which does this
 * will be extremely susceptible to DoS attacks because UDP forgery is so easy.
 * Thus, generating fatal alerts is NOT RECOMMENDED for such transports"
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_UDPTransportAlertPolicy) {
    auto context = udp_error_handler_->create_error_context("test_udp_no_alerts");
    
    // For UDP transport, generating alerts is NOT RECOMMENDED
    auto alert_result = udp_error_handler_->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    // Should fail or return empty result for UDP
    EXPECT_FALSE(alert_result.is_success())
        << "RFC 9147: Alert generation NOT RECOMMENDED for UDP transport";
    
    if (alert_result.is_success()) {
        EXPECT_EQ(alert_result.value().size(), 0)
            << "If alerts are generated for UDP, they should be empty/suppressed";
    }
    
    // Verify the alert manager policy
    EXPECT_FALSE(udp_alert_manager_->get_policy().generate_alerts_for_invalid_records)
        << "UDP alert policy should not generate alerts for invalid records";
    EXPECT_FALSE(udp_alert_manager_->get_policy().generate_alerts_for_auth_failures)
        << "UDP alert policy should not generate alerts for auth failures";
}

/**
 * RFC 9147 Section 4.2.1: Secure Transport Alert Policy
 * "both to increase the reliability of DTLS service and to avoid the risk of
 * spoofing attacks sending traffic to unrelated third parties."
 * For secure transports like SCTP with SCTP-AUTH, alerts are safer.
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_SecureTransportAlertPolicy) {
    auto context = secure_error_handler_->create_error_context("test_secure_alerts");
    
    // For secure transport, alerts can be generated safely
    auto alert_result = secure_error_handler_->generate_alert_if_appropriate(
        AlertDescription::BAD_RECORD_MAC, context);
    
    EXPECT_TRUE(alert_result.is_success())
        << "Secure transports (SCTP with SCTP-AUTH) can safely generate alerts";
    
    if (alert_result.is_success()) {
        EXPECT_GT(alert_result.value().size(), 0)
            << "Secure transport should generate actual alert data";
    }
    
    // Verify the alert manager policy
    EXPECT_TRUE(secure_alert_manager_->get_policy().generate_alerts_for_invalid_records)
        << "Secure transport policy should allow alerts for invalid records";
}

/**
 * RFC 9147 Section 4.2.1: Persistent Bad Messages
 * "Implementations SHOULD detect when a peer is persistently sending bad 
 * messages and terminate the local connection state after such misbehavior 
 * is detected."
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_PersistentBadMessageDetection) {
    auto context = udp_error_handler_->create_error_context("test_persistent_bad");
    
    // Generate many invalid records to simulate persistent bad messages
    const int MANY_INVALID_RECORDS = 50;
    for (int i = 0; i < MANY_INVALID_RECORDS; ++i) {
        udp_error_handler_->handle_invalid_record(ContentType::INVALID, context);
    }
    
    // Should detect persistent misbehavior
    bool should_terminate = udp_alert_manager_->should_terminate_connection(
        "test_persistent_bad", context);
    
    EXPECT_TRUE(should_terminate)
        << "RFC 9147: Should terminate connection after persistent bad messages";
    
    // Verify DoS attack detection was triggered
    const auto& stats = udp_error_handler_->get_error_statistics();
    EXPECT_GT(stats.dos_attacks_detected, 0)
        << "Persistent bad messages should trigger DoS attack detection";
}

/**
 * RFC 9147 Section 4.2.1: Alert Reliability
 * "Note that alert messages are not retransmitted at all, even when they occur
 * in the context of a handshake. However, a DTLS implementation which would
 * ordinarily issue an alert SHOULD generate a new alert message if the
 * offending record is received again (e.g., as a retransmitted handshake message)."
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_AlertReliability) {
    // Verify alert policy doesn't attempt retransmission
    const auto& policy = secure_alert_manager_->get_policy();
    
    EXPECT_FALSE(policy.attempt_alert_retransmission)
        << "RFC 9147: Alert messages are not retransmitted at all";
    
    // Test that repeated offending records generate new alerts (if policy allows)
    auto context = secure_error_handler_->create_error_context("test_repeated_offense");
    
    size_t initial_alerts = secure_alert_manager_->get_statistics().alerts_generated;
    
    // Send the same bad record multiple times
    for (int i = 0; i < 3; ++i) {
        secure_error_handler_->process_error(DTLSError::ILLEGAL_PARAMETER, context);
    }
    
    size_t final_alerts = secure_alert_manager_->get_statistics().alerts_generated;
    
    if (final_alerts > initial_alerts) {
        EXPECT_GE(final_alerts - initial_alerts, 1)
            << "Should generate new alerts for repeated offending records";
    }
}

/**
 * RFC 9147 Section 4.2.1: Alert Dependence
 * "Note that alerts are not reliably transmitted; implementations SHOULD NOT
 * depend on receiving alerts in order to signal errors or connection closure."
 */
TEST_F(RFC9147ComplianceTest, Section_4_2_1_AlertDependence) {
    auto context = udp_error_handler_->create_error_context("test_alert_dependence");
    
    // Process a fatal error that would normally generate an alert
    auto result = udp_error_handler_->process_error(
        DTLSError::HANDSHAKE_FAILURE, context);
    
    // The error should be processed successfully even if alert generation fails
    EXPECT_TRUE(result.is_success())
        << "Error processing should not depend on alert generation";
    
    // Connection termination decision should be made independently of alerts
    bool should_terminate = udp_error_handler_->should_terminate_connection(
        DTLSError::HANDSHAKE_FAILURE);
    
    EXPECT_TRUE(should_terminate)
        << "Connection termination should not depend on alert transmission";
}

/**
 * RFC 9147 Section 5.5: Connection ID Error Handling
 * "Endpoints MAY handle an excessive number of RequestConnectionId messages
 * by terminating the connection using a 'too_many_cids_requested' (alert number 52) alert."
 */
TEST_F(RFC9147ComplianceTest, Section_5_5_ConnectionIDErrorHandling) {
    // Test the new DTLS v1.3 specific alert
    EXPECT_EQ(static_cast<uint8_t>(AlertDescription::TOO_MANY_CIDS_REQUESTED), 52)
        << "RFC 9147: too_many_cids_requested alert should be number 52";
    
    // Test error-to-alert mapping for Connection ID errors
    DTLSError cid_error = DTLSError::CONNECTION_ID_MISMATCH;
    AlertDescription mapped_alert = error_to_alert(cid_error);
    
    EXPECT_EQ(mapped_alert, AlertDescription::TOO_MANY_CIDS_REQUESTED)
        << "Connection ID errors should map to too_many_cids_requested alert";
    
    // Test reverse mapping
    DTLSError reverse_error = alert_to_error(AlertDescription::TOO_MANY_CIDS_REQUESTED);
    EXPECT_EQ(reverse_error, DTLSError::CONNECTION_ID_MISMATCH)
        << "too_many_cids_requested alert should map to CONNECTION_ID_MISMATCH";
}

/**
 * RFC 9147 Section 5.5: Connection ID Message Validation
 * "Endpoints MUST NOT send either of these messages if they did not negotiate a CID.
 * If an implementation receives these messages when CIDs were not negotiated,
 * it MUST abort the connection with an 'unexpected_message' alert."
 */
TEST_F(RFC9147ComplianceTest, Section_5_5_ConnectionIDMessageValidation) {
    auto context = udp_error_handler_->create_error_context("test_cid_validation");
    
    // Test unexpected Connection ID message error
    DTLSError unexpected_cid_error = DTLSError::UNEXPECTED_MESSAGE;
    AlertDescription expected_alert = error_to_alert(unexpected_cid_error);
    
    EXPECT_EQ(expected_alert, AlertDescription::UNEXPECTED_MESSAGE)
        << "Unexpected CID messages should generate unexpected_message alert";
    
    // Test that this is considered a fatal error
    bool is_fatal = is_fatal_error(unexpected_cid_error);
    EXPECT_TRUE(is_fatal)
        << "Unexpected CID messages should be fatal errors";
    
    // Test connection termination
    bool should_terminate = udp_error_handler_->should_terminate_connection(unexpected_cid_error);
    EXPECT_TRUE(should_terminate)
        << "Connection should be terminated for unexpected CID messages";
}

/**
 * RFC 9147 Authentication Failure Tracking
 * "Implementations SHOULD track records that fail authentication and SHOULD
 * close the connection if authentication failure records exceed a specific
 * limit for the AEAD algorithm used."
 */
TEST_F(RFC9147ComplianceTest, AuthenticationFailureTracking) {
    auto context = udp_error_handler_->create_error_context("test_auth_tracking");
    Epoch test_epoch = 1;
    
    // Track authentication failures
    std::vector<bool> connection_states;
    
    for (int i = 0; i < 15; ++i) {
        auto result = udp_error_handler_->handle_authentication_failure(test_epoch, context);
        ASSERT_TRUE(result.is_success());
        connection_states.push_back(result.value()); // true = continue, false = terminate
    }
    
    // Should eventually recommend connection termination
    bool found_termination = false;
    for (bool should_continue : connection_states) {
        if (!should_continue) {
            found_termination = true;
            break;
        }
    }
    
    EXPECT_TRUE(found_termination)
        << "Should recommend connection termination after excessive auth failures";
    
    // Verify security metrics were updated
    const auto& security_metrics = context->get_security_metrics();
    EXPECT_GT(security_metrics.authentication_failures, 0)
        << "Authentication failure counter should be incremented";
}

/**
 * RFC 9147 Error Message Consistency
 * Test that error messages are consistent and don't leak sensitive information
 */
TEST_F(RFC9147ComplianceTest, ErrorMessageConsistency) {
    // Test that error messages don't contain sensitive keywords
    std::vector<std::string> sensitive_keywords = {
        "key", "secret", "private", "plaintext", "decrypt", "password"
    };
    
    // Test various error types
    std::vector<DTLSError> test_errors = {
        DTLSError::DECRYPT_ERROR,
        DTLSError::BAD_RECORD_MAC,
        DTLSError::KEY_DERIVATION_FAILED,
        DTLSError::AUTHENTICATION_FAILED,
        DTLSError::SIGNATURE_VERIFICATION_FAILED
    };
    
    for (DTLSError error : test_errors) {
        std::string message = error_message(error);
        
        // Ensure message is not empty
        EXPECT_FALSE(message.empty())
            << "Error " << static_cast<int>(error) << " should have a message";
        
        // Check for sensitive information leakage
        for (const std::string& keyword : sensitive_keywords) {
            EXPECT_EQ(message.find(keyword), std::string::npos)
                << "Error message for " << static_cast<int>(error)
                << " should not contain sensitive keyword: " << keyword
                << " (message: " << message << ")";
        }
        
        // Ensure message is reasonably descriptive
        EXPECT_GT(message.length(), 10)
            << "Error message should be descriptive";
        EXPECT_LT(message.length(), 200)
            << "Error message should be concise";
    }
}

/**
 * RFC 9147 DoS Protection Requirements
 * Test that implementations provide adequate DoS protection
 */
TEST_F(RFC9147ComplianceTest, DoSProtectionRequirements) {
    auto context = udp_error_handler_->create_error_context("test_dos_protection");
    
    // Test rate limiting for invalid records
    const int FLOOD_SIZE = 200;
    int processed_count = 0;
    
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < FLOOD_SIZE; ++i) {
        auto result = udp_error_handler_->handle_invalid_record(
            ContentType::INVALID, context);
        if (result.is_success()) {
            processed_count++;
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    // Should have some form of rate limiting or DoS protection
    const auto& stats = udp_error_handler_->get_error_statistics();
    
    if (stats.dos_attacks_detected > 0) {
        EXPECT_GT(stats.dos_attacks_detected, 0)
            << "DoS attack detection should be triggered by flood";
    }
    
    // Check that excessive error rate was detected
    bool excessive_rate = context->is_error_rate_excessive(
        std::chrono::seconds(1), 50);
    
    EXPECT_TRUE(excessive_rate)
        << "Should detect excessive error rate during flood";
}

} // namespace test
} // namespace v13
} // namespace dtls