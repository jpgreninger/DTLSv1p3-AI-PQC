#include <gtest/gtest.h>
#include <dtls/error.h>
#include <dtls/types.h>
#include <system_error>
#include <string>

using namespace dtls::v13;

class DTLSErrorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup common test data
    }

    void TearDown() override {
        // Cleanup
    }
};

// Test DTLSError enum values and ranges
TEST_F(DTLSErrorTest, ErrorCodeValues) {
    // Test success
    EXPECT_EQ(static_cast<int>(DTLSError::SUCCESS), 0);
    
    // Test general errors are in expected range (1-19)
    EXPECT_EQ(static_cast<int>(DTLSError::INVALID_PARAMETER), 1);
    EXPECT_EQ(static_cast<int>(DTLSError::INSUFFICIENT_BUFFER), 2);
    EXPECT_EQ(static_cast<int>(DTLSError::OUT_OF_MEMORY), 4);
    EXPECT_EQ(static_cast<int>(DTLSError::TIMEOUT), 5);
    EXPECT_EQ(static_cast<int>(DTLSError::INTERNAL_ERROR), 11);
    
    // Test protocol errors are in expected range (20-49)
    EXPECT_EQ(static_cast<int>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED), 21);
    EXPECT_EQ(static_cast<int>(DTLSError::INVALID_MESSAGE_FORMAT), 22);
    EXPECT_EQ(static_cast<int>(DTLSError::UNEXPECTED_MESSAGE), 23);
    
    // Test handshake errors are in expected range (51-80)
    EXPECT_EQ(static_cast<int>(DTLSError::HANDSHAKE_FAILURE), 51);
    EXPECT_EQ(static_cast<int>(DTLSError::CERTIFICATE_VERIFY_FAILED), 52);
    
    // Test crypto errors are in expected range (92-111)
    EXPECT_EQ(static_cast<int>(DTLSError::DECRYPT_ERROR), 92);
    EXPECT_EQ(static_cast<int>(DTLSError::BAD_RECORD_MAC), 93);
    EXPECT_EQ(static_cast<int>(DTLSError::CRYPTO_PROVIDER_ERROR), 97);
    
    // Test connection errors are in expected range (112-131)
    EXPECT_EQ(static_cast<int>(DTLSError::CONNECTION_CLOSED), 112);
    EXPECT_EQ(static_cast<int>(DTLSError::CONNECTION_RESET), 113);
    
    // Test network errors are in expected range (132-151)
    EXPECT_EQ(static_cast<int>(DTLSError::NETWORK_ERROR), 132);
    EXPECT_EQ(static_cast<int>(DTLSError::SOCKET_ERROR), 134);
    
    // Test security errors are in expected range (152-171)
    EXPECT_EQ(static_cast<int>(DTLSError::REPLAY_ATTACK_DETECTED), 152);
    EXPECT_EQ(static_cast<int>(DTLSError::SECURITY_POLICY_VIOLATION), 154);
}

// Test DTLSErrorCategory functionality
TEST_F(DTLSErrorTest, ErrorCategory) {
    const DTLSErrorCategory& category = DTLSErrorCategory::instance();
    
    // Test category name
    EXPECT_STREQ(category.name(), "dtls");
    
    // Test that instance returns same object (singleton pattern)
    const DTLSErrorCategory& category2 = DTLSErrorCategory::instance();
    EXPECT_EQ(&category, &category2);
}

TEST_F(DTLSErrorTest, ErrorCategoryMessage) {
    const DTLSErrorCategory& category = DTLSErrorCategory::instance();
    
    // Test that messages are provided for common errors
    std::string success_msg = category.message(static_cast<int>(DTLSError::SUCCESS));
    EXPECT_FALSE(success_msg.empty());
    
    std::string invalid_param_msg = category.message(static_cast<int>(DTLSError::INVALID_PARAMETER));
    EXPECT_FALSE(invalid_param_msg.empty());
    EXPECT_NE(invalid_param_msg, success_msg);
    
    std::string handshake_failure_msg = category.message(static_cast<int>(DTLSError::HANDSHAKE_FAILURE));
    EXPECT_FALSE(handshake_failure_msg.empty());
    
    std::string decrypt_error_msg = category.message(static_cast<int>(DTLSError::DECRYPT_ERROR));
    EXPECT_FALSE(decrypt_error_msg.empty());
    
    // Test unknown error code
    std::string unknown_msg = category.message(99999);
    EXPECT_FALSE(unknown_msg.empty());
    EXPECT_TRUE(unknown_msg.find("Unknown") != std::string::npos || 
                unknown_msg.find("unknown") != std::string::npos);
}

TEST_F(DTLSErrorTest, ErrorCategoryEquivalent) {
    const DTLSErrorCategory& category = DTLSErrorCategory::instance();
    
    // Test equivalent function with same category
    std::error_code dtls_code = make_error_code(DTLSError::HANDSHAKE_FAILURE);
    EXPECT_TRUE(category.equivalent(dtls_code, static_cast<int>(DTLSError::HANDSHAKE_FAILURE)));
    EXPECT_FALSE(category.equivalent(dtls_code, static_cast<int>(DTLSError::DECRYPT_ERROR)));
    
    // Test with different category
    std::error_code generic_code(static_cast<int>(DTLSError::HANDSHAKE_FAILURE), std::generic_category());
    EXPECT_FALSE(category.equivalent(generic_code, static_cast<int>(DTLSError::HANDSHAKE_FAILURE)));
}

// Test make_error_code function
TEST_F(DTLSErrorTest, MakeErrorCode) {
    std::error_code code = make_error_code(DTLSError::INVALID_PARAMETER);
    
    EXPECT_EQ(code.value(), static_cast<int>(DTLSError::INVALID_PARAMETER));
    EXPECT_EQ(&code.category(), &DTLSErrorCategory::instance());
    EXPECT_FALSE(code.message().empty());
    
    // Test success code
    std::error_code success_code = make_error_code(DTLSError::SUCCESS);
    EXPECT_EQ(success_code.value(), 0);
    EXPECT_FALSE(success_code); // Should evaluate to false for success
    
    // Test non-success code
    std::error_code error_code = make_error_code(DTLSError::HANDSHAKE_FAILURE);
    EXPECT_NE(error_code.value(), 0);
    EXPECT_TRUE(error_code); // Should evaluate to true for error
}

// Test DTLSException functionality
TEST_F(DTLSErrorTest, DTLSExceptionBasic) {
    DTLSException ex(DTLSError::HANDSHAKE_FAILURE);
    
    EXPECT_EQ(ex.dtls_error(), DTLSError::HANDSHAKE_FAILURE);
    EXPECT_EQ(ex.code().value(), static_cast<int>(DTLSError::HANDSHAKE_FAILURE));
    EXPECT_EQ(&ex.code().category(), &DTLSErrorCategory::instance());
    EXPECT_FALSE(std::string(ex.what()).empty());
}

TEST_F(DTLSErrorTest, DTLSExceptionWithMessage) {
    const std::string custom_message = "Custom handshake failure message";
    DTLSException ex(DTLSError::HANDSHAKE_FAILURE, custom_message);
    
    EXPECT_EQ(ex.dtls_error(), DTLSError::HANDSHAKE_FAILURE);
    EXPECT_EQ(ex.code().value(), static_cast<int>(DTLSError::HANDSHAKE_FAILURE));
    
    std::string what_str(ex.what());
    EXPECT_TRUE(what_str.find(custom_message) != std::string::npos);
}

TEST_F(DTLSErrorTest, DTLSExceptionWithCString) {
    const char* custom_message = "C-style error message";
    DTLSException ex(DTLSError::DECRYPT_ERROR, custom_message);
    
    EXPECT_EQ(ex.dtls_error(), DTLSError::DECRYPT_ERROR);
    
    std::string what_str(ex.what());
    EXPECT_TRUE(what_str.find(custom_message) != std::string::npos);
}

TEST_F(DTLSErrorTest, DTLSExceptionInheritance) {
    DTLSException ex(DTLSError::CERTIFICATE_VERIFY_FAILED);
    
    // Test that it can be caught as system_error
    try {
        throw ex;
    } catch (const std::system_error& sys_ex) {
        EXPECT_EQ(sys_ex.code().value(), static_cast<int>(DTLSError::CERTIFICATE_VERIFY_FAILED));
        EXPECT_EQ(&sys_ex.code().category(), &DTLSErrorCategory::instance());
    } catch (...) {
        FAIL() << "DTLSException should be catchable as system_error";
    }
    
    // Test that it can be caught as std::exception
    try {
        throw ex;
    } catch (const std::exception& std_ex) {
        EXPECT_FALSE(std::string(std_ex.what()).empty());
    } catch (...) {
        FAIL() << "DTLSException should be catchable as std::exception";
    }
}

// Test utility functions
TEST_F(DTLSErrorTest, ErrorMessageFunction) {
    // Test that error_message function provides meaningful messages
    std::string success_msg = error_message(DTLSError::SUCCESS);
    EXPECT_FALSE(success_msg.empty());
    
    std::string handshake_msg = error_message(DTLSError::HANDSHAKE_FAILURE);
    EXPECT_FALSE(handshake_msg.empty());
    EXPECT_NE(handshake_msg, success_msg);
    
    std::string crypto_msg = error_message(DTLSError::DECRYPT_ERROR);
    EXPECT_FALSE(crypto_msg.empty());
    EXPECT_NE(crypto_msg, handshake_msg);
    
    // Messages should be descriptive
    EXPECT_GT(handshake_msg.length(), 5); // At least some description
    EXPECT_GT(crypto_msg.length(), 5);
}

TEST_F(DTLSErrorTest, IsFatalError) {
    // Test that fatal errors are correctly identified
    EXPECT_FALSE(is_fatal_error(DTLSError::SUCCESS));
    EXPECT_FALSE(is_fatal_error(DTLSError::TIMEOUT)); // Generally retryable
    
    // These should typically be fatal
    EXPECT_TRUE(is_fatal_error(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED));
    EXPECT_TRUE(is_fatal_error(DTLSError::CERTIFICATE_VERIFY_FAILED));
    EXPECT_TRUE(is_fatal_error(DTLSError::DECRYPT_ERROR));
    EXPECT_TRUE(is_fatal_error(DTLSError::BAD_RECORD_MAC));
    EXPECT_TRUE(is_fatal_error(DTLSError::HANDSHAKE_FAILURE));
    EXPECT_TRUE(is_fatal_error(DTLSError::INTERNAL_ERROR));
    
    // Security errors should be fatal
    EXPECT_TRUE(is_fatal_error(DTLSError::REPLAY_ATTACK_DETECTED));
    EXPECT_TRUE(is_fatal_error(DTLSError::TAMPERING_DETECTED));
    EXPECT_TRUE(is_fatal_error(DTLSError::SECURITY_POLICY_VIOLATION));
}

TEST_F(DTLSErrorTest, IsRetryableError) {
    // Test that retryable errors are correctly identified
    EXPECT_FALSE(is_retryable_error(DTLSError::SUCCESS)); // No need to retry success
    
    // These should be retryable
    EXPECT_TRUE(is_retryable_error(DTLSError::TIMEOUT));
    EXPECT_TRUE(is_retryable_error(DTLSError::NETWORK_ERROR));
    EXPECT_TRUE(is_retryable_error(DTLSError::SOCKET_ERROR));
    EXPECT_TRUE(is_retryable_error(DTLSError::SEND_ERROR));
    EXPECT_TRUE(is_retryable_error(DTLSError::RECEIVE_ERROR));
    EXPECT_TRUE(is_retryable_error(DTLSError::RESOURCE_UNAVAILABLE));
    
    // These should NOT be retryable
    EXPECT_FALSE(is_retryable_error(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED));
    EXPECT_FALSE(is_retryable_error(DTLSError::CERTIFICATE_VERIFY_FAILED));
    EXPECT_FALSE(is_retryable_error(DTLSError::DECRYPT_ERROR));
    EXPECT_FALSE(is_retryable_error(DTLSError::BAD_RECORD_MAC));
    EXPECT_FALSE(is_retryable_error(DTLSError::INVALID_PARAMETER));
    
    // Security errors should not be retryable
    EXPECT_FALSE(is_retryable_error(DTLSError::REPLAY_ATTACK_DETECTED));
    EXPECT_FALSE(is_retryable_error(DTLSError::TAMPERING_DETECTED));
}

TEST_F(DTLSErrorTest, ErrorToAlert) {
    // Test conversion from DTLS errors to alert descriptions
    EXPECT_EQ(error_to_alert(DTLSError::HANDSHAKE_FAILURE), AlertDescription::HANDSHAKE_FAILURE);
    EXPECT_EQ(error_to_alert(DTLSError::CERTIFICATE_VERIFY_FAILED), AlertDescription::BAD_CERTIFICATE);
    EXPECT_EQ(error_to_alert(DTLSError::CERTIFICATE_EXPIRED), AlertDescription::CERTIFICATE_EXPIRED);
    EXPECT_EQ(error_to_alert(DTLSError::UNKNOWN_CA), AlertDescription::UNKNOWN_CA);
    EXPECT_EQ(error_to_alert(DTLSError::DECODE_ERROR), AlertDescription::DECODE_ERROR);
    EXPECT_EQ(error_to_alert(DTLSError::DECRYPT_ERROR), AlertDescription::DECRYPT_ERROR);
    EXPECT_EQ(error_to_alert(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED), AlertDescription::PROTOCOL_VERSION);
    EXPECT_EQ(error_to_alert(DTLSError::INSUFFICIENT_SECURITY), AlertDescription::INSUFFICIENT_SECURITY);
    EXPECT_EQ(error_to_alert(DTLSError::INTERNAL_ERROR), AlertDescription::INTERNAL_ERROR);
    EXPECT_EQ(error_to_alert(DTLSError::ACCESS_DENIED), AlertDescription::ACCESS_DENIED);
    EXPECT_EQ(error_to_alert(DTLSError::MISSING_EXTENSION), AlertDescription::MISSING_EXTENSION);
    EXPECT_EQ(error_to_alert(DTLSError::UNSUPPORTED_EXTENSION), AlertDescription::UNSUPPORTED_EXTENSION);
    EXPECT_EQ(error_to_alert(DTLSError::UNRECOGNIZED_NAME), AlertDescription::UNRECOGNIZED_NAME);
    EXPECT_EQ(error_to_alert(DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE), AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE);
    EXPECT_EQ(error_to_alert(DTLSError::CERTIFICATE_REQUIRED), AlertDescription::CERTIFICATE_REQUIRED);
    EXPECT_EQ(error_to_alert(DTLSError::NO_APPLICATION_PROTOCOL), AlertDescription::NO_APPLICATION_PROTOCOL);
    
    // Test that errors without direct alert mapping get INTERNAL_ERROR
    EXPECT_EQ(error_to_alert(DTLSError::TIMEOUT), AlertDescription::INTERNAL_ERROR);
    EXPECT_EQ(error_to_alert(DTLSError::OUT_OF_MEMORY), AlertDescription::INTERNAL_ERROR);
    EXPECT_EQ(error_to_alert(DTLSError::NETWORK_ERROR), AlertDescription::INTERNAL_ERROR);
}

TEST_F(DTLSErrorTest, AlertToError) {
    // Test conversion from alert descriptions to DTLS errors
    EXPECT_EQ(alert_to_error(AlertDescription::HANDSHAKE_FAILURE), DTLSError::HANDSHAKE_FAILURE);
    EXPECT_EQ(alert_to_error(AlertDescription::BAD_CERTIFICATE), DTLSError::CERTIFICATE_VERIFY_FAILED);
    EXPECT_EQ(alert_to_error(AlertDescription::CERTIFICATE_EXPIRED), DTLSError::CERTIFICATE_EXPIRED);
    EXPECT_EQ(alert_to_error(AlertDescription::UNKNOWN_CA), DTLSError::UNKNOWN_CA);
    EXPECT_EQ(alert_to_error(AlertDescription::DECODE_ERROR), DTLSError::DECODE_ERROR);
    EXPECT_EQ(alert_to_error(AlertDescription::DECRYPT_ERROR), DTLSError::DECRYPT_ERROR);
    EXPECT_EQ(alert_to_error(AlertDescription::PROTOCOL_VERSION), DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED);
    EXPECT_EQ(alert_to_error(AlertDescription::INSUFFICIENT_SECURITY), DTLSError::INSUFFICIENT_SECURITY);
    EXPECT_EQ(alert_to_error(AlertDescription::INTERNAL_ERROR), DTLSError::INTERNAL_ERROR);
    EXPECT_EQ(alert_to_error(AlertDescription::ACCESS_DENIED), DTLSError::ACCESS_DENIED);
    EXPECT_EQ(alert_to_error(AlertDescription::MISSING_EXTENSION), DTLSError::MISSING_EXTENSION);
    EXPECT_EQ(alert_to_error(AlertDescription::UNSUPPORTED_EXTENSION), DTLSError::UNSUPPORTED_EXTENSION);
    EXPECT_EQ(alert_to_error(AlertDescription::UNRECOGNIZED_NAME), DTLSError::UNRECOGNIZED_NAME);
    EXPECT_EQ(alert_to_error(AlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE), DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE);
    EXPECT_EQ(alert_to_error(AlertDescription::CERTIFICATE_REQUIRED), DTLSError::CERTIFICATE_REQUIRED);
    EXPECT_EQ(alert_to_error(AlertDescription::NO_APPLICATION_PROTOCOL), DTLSError::NO_APPLICATION_PROTOCOL);
    
    // Test close_notify and unexpected_message
    EXPECT_EQ(alert_to_error(AlertDescription::CLOSE_NOTIFY), DTLSError::CONNECTION_CLOSED);
    EXPECT_EQ(alert_to_error(AlertDescription::UNEXPECTED_MESSAGE), DTLSError::UNEXPECTED_MESSAGE);
}

// Test error conversion round-trip consistency
TEST_F(DTLSErrorTest, ErrorAlertRoundTrip) {
    // Test that errors that map to alerts can round-trip correctly
    std::vector<DTLSError> testable_errors = {
        DTLSError::HANDSHAKE_FAILURE,
        DTLSError::CERTIFICATE_VERIFY_FAILED,
        DTLSError::CERTIFICATE_EXPIRED,
        DTLSError::UNKNOWN_CA,
        DTLSError::DECODE_ERROR,
        DTLSError::DECRYPT_ERROR,
        DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED,
        DTLSError::INSUFFICIENT_SECURITY,
        DTLSError::INTERNAL_ERROR,
        DTLSError::ACCESS_DENIED,
        DTLSError::MISSING_EXTENSION,
        DTLSError::UNSUPPORTED_EXTENSION,
        DTLSError::UNRECOGNIZED_NAME,
        DTLSError::BAD_CERTIFICATE_STATUS_RESPONSE,
        DTLSError::CERTIFICATE_REQUIRED,
        DTLSError::NO_APPLICATION_PROTOCOL
    };
    
    for (DTLSError error : testable_errors) {
        AlertDescription alert = error_to_alert(error);
        DTLSError round_trip_error = alert_to_error(alert);
        
        // Some mappings might not be perfect round-trips due to many-to-one mappings
        // But the round-trip should at least be a reasonable error
        EXPECT_NE(round_trip_error, DTLSError::SUCCESS) << "Error " << static_cast<int>(error) << " round-trip failed";
    }
}

// Test macros (if they can be tested)
TEST_F(DTLSErrorTest, ErrorHandlingMacros) {
    // Test DTLS_THROW_IF_ERROR macro
    EXPECT_NO_THROW(DTLS_THROW_IF_ERROR(DTLSError::SUCCESS));
    
    EXPECT_THROW({
        DTLS_THROW_IF_ERROR(DTLSError::HANDSHAKE_FAILURE);
    }, DTLSException);
    
    try {
        DTLS_THROW_IF_ERROR(DTLSError::DECRYPT_ERROR);
        FAIL() << "Should have thrown DTLSException";
    } catch (const DTLSException& ex) {
        EXPECT_EQ(ex.dtls_error(), DTLSError::DECRYPT_ERROR);
    }
}

// Test std::error_code integration
TEST_F(DTLSErrorTest, StdErrorCodeIntegration) {
    // Test that DTLSError is properly integrated with std::error_code system
    static_assert(std::is_error_code_enum<DTLSError>::value, "DTLSError should be error_code_enum");
    
    // Test implicit conversion to error_code
    std::error_code code = DTLSError::HANDSHAKE_FAILURE;
    EXPECT_EQ(code.value(), static_cast<int>(DTLSError::HANDSHAKE_FAILURE));
    EXPECT_EQ(&code.category(), &DTLSErrorCategory::instance());
    
    // Test error_condition creation from error_code
    std::error_condition condition = code.default_error_condition();
    EXPECT_EQ(condition.value(), static_cast<int>(DTLSError::HANDSHAKE_FAILURE));
    EXPECT_EQ(&condition.category(), &DTLSErrorCategory::instance());
}

// Test error categorization
TEST_F(DTLSErrorTest, ErrorCategorization) {
    // Test that errors are properly categorized by their numeric ranges
    
    // General errors (1-19)
    EXPECT_LE(static_cast<int>(DTLSError::INVALID_PARAMETER), 19);
    EXPECT_LE(static_cast<int>(DTLSError::OUT_OF_MEMORY), 19);
    EXPECT_LE(static_cast<int>(DTLSError::INTERNAL_ERROR), 19);
    
    // Protocol errors (20-49)
    EXPECT_GE(static_cast<int>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED), 20);
    EXPECT_LE(static_cast<int>(DTLSError::PROTOCOL_VERSION_NOT_SUPPORTED), 49);
    
    // Handshake errors (51-80)
    EXPECT_GE(static_cast<int>(DTLSError::HANDSHAKE_FAILURE), 51);
    EXPECT_LE(static_cast<int>(DTLSError::HANDSHAKE_FAILURE), 80);
    
    // Crypto errors (92-111)
    EXPECT_GE(static_cast<int>(DTLSError::DECRYPT_ERROR), 92);
    EXPECT_LE(static_cast<int>(DTLSError::DECRYPT_ERROR), 111);
    
    // Connection errors (112-131)
    EXPECT_GE(static_cast<int>(DTLSError::CONNECTION_CLOSED), 112);
    EXPECT_LE(static_cast<int>(DTLSError::CONNECTION_CLOSED), 131);
    
    // Network errors (132-151)
    EXPECT_GE(static_cast<int>(DTLSError::NETWORK_ERROR), 132);
    EXPECT_LE(static_cast<int>(DTLSError::NETWORK_ERROR), 151);
    
    // Security errors (152-171)
    EXPECT_GE(static_cast<int>(DTLSError::REPLAY_ATTACK_DETECTED), 152);
    EXPECT_LE(static_cast<int>(DTLSError::REPLAY_ATTACK_DETECTED), 171);
}

// Test that error messages are appropriate length and content
TEST_F(DTLSErrorTest, ErrorMessageQuality) {
    const DTLSErrorCategory& category = DTLSErrorCategory::instance();
    
    std::vector<DTLSError> test_errors = {
        DTLSError::SUCCESS,
        DTLSError::INVALID_PARAMETER,
        DTLSError::HANDSHAKE_FAILURE,
        DTLSError::DECRYPT_ERROR,
        DTLSError::CONNECTION_CLOSED,
        DTLSError::NETWORK_ERROR,
        DTLSError::REPLAY_ATTACK_DETECTED
    };
    
    for (DTLSError error : test_errors) {
        std::string msg = category.message(static_cast<int>(error));
        
        // Message should not be empty
        EXPECT_FALSE(msg.empty()) << "Empty message for error " << static_cast<int>(error);
        
        // Message should be reasonable length (not too short, not too long)
        EXPECT_GE(msg.length(), 3) << "Message too short for error " << static_cast<int>(error);
        EXPECT_LE(msg.length(), 200) << "Message too long for error " << static_cast<int>(error);
        
        // Message should not contain control characters
        for (char c : msg) {
            EXPECT_FALSE(std::iscntrl(c) && c != '\n' && c != '\t') 
                << "Control character in message for error " << static_cast<int>(error);
        }
    }
}