#include <gtest/gtest.h>
#include "dtls/protocol.h"
#include "dtls/protocol/record.h"
#include "dtls/protocol/handshake.h"
#include "dtls/types.h"

using namespace dtls::v13;
using namespace dtls::v13::protocol;

/**
 * @brief Test suite for protocol utility functions in protocol.cpp
 * 
 * This test suite provides comprehensive coverage for the protocol utility
 * functions that validate versions, content types, and handshake types.
 * These are critical functions used throughout the DTLS v1.3 implementation.
 */
class ProtocolUtilitiesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No setup required for these utility functions
    }
};

/**
 * @brief Test suite for version validation functions
 */
class VersionValidationTest : public ProtocolUtilitiesTest {};

/**
 * @brief Test is_supported_version function with all valid versions
 */
TEST_F(VersionValidationTest, TestValidVersions) {
    // Test all supported DTLS versions
    EXPECT_TRUE(is_supported_version(dtls::v13::protocol::ProtocolVersion::DTLS_1_3));
    EXPECT_TRUE(is_supported_version(dtls::v13::protocol::ProtocolVersion::DTLS_1_2));
    EXPECT_TRUE(is_supported_version(dtls::v13::protocol::ProtocolVersion::DTLS_1_0));
}

/**
 * @brief Test is_supported_version function with invalid versions
 */
TEST_F(VersionValidationTest, TestInvalidVersions) {
    // Test with arbitrary invalid version values
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0000)));
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xFFFF)));
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x1234)));
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xABCD)));
    
    // Test with TLS versions (not DTLS)
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0301))); // TLS 1.0
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0303))); // TLS 1.2
    EXPECT_FALSE(is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0304))); // TLS 1.3
}

/**
 * @brief Test suite for content type validation functions
 */
class ContentTypeValidationTest : public ProtocolUtilitiesTest {};

/**
 * @brief Test is_valid_content_type function with all valid content types
 */
TEST_F(ContentTypeValidationTest, TestValidContentTypes) {
    EXPECT_TRUE(is_valid_content_type(ContentType::CHANGE_CIPHER_SPEC));
    EXPECT_TRUE(is_valid_content_type(ContentType::ALERT));
    EXPECT_TRUE(is_valid_content_type(ContentType::HANDSHAKE));
    EXPECT_TRUE(is_valid_content_type(ContentType::APPLICATION_DATA));
    EXPECT_TRUE(is_valid_content_type(ContentType::HEARTBEAT));
    EXPECT_TRUE(is_valid_content_type(ContentType::TLS12_CID));
}

/**
 * @brief Test is_valid_content_type function with invalid content types
 */
TEST_F(ContentTypeValidationTest, TestInvalidContentTypes) {
    EXPECT_FALSE(is_valid_content_type(ContentType::INVALID));
    
    // Test with arbitrary invalid values
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(255)));
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(100)));
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(1)));
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(19)));
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(27)));
}

/**
 * @brief Test is_handshake_content_type function
 */
TEST_F(ContentTypeValidationTest, TestHandshakeContentType) {
    // Only HANDSHAKE should return true
    EXPECT_TRUE(is_handshake_content_type(ContentType::HANDSHAKE));
    
    // All other content types should return false
    EXPECT_FALSE(is_handshake_content_type(ContentType::CHANGE_CIPHER_SPEC));
    EXPECT_FALSE(is_handshake_content_type(ContentType::ALERT));
    EXPECT_FALSE(is_handshake_content_type(ContentType::APPLICATION_DATA));
    EXPECT_FALSE(is_handshake_content_type(ContentType::HEARTBEAT));
    EXPECT_FALSE(is_handshake_content_type(ContentType::TLS12_CID));
    EXPECT_FALSE(is_handshake_content_type(ContentType::INVALID));
}

/**
 * @brief Test is_application_data_content_type function
 */
TEST_F(ContentTypeValidationTest, TestApplicationDataContentType) {
    // Only APPLICATION_DATA should return true
    EXPECT_TRUE(is_application_data_content_type(ContentType::APPLICATION_DATA));
    
    // All other content types should return false
    EXPECT_FALSE(is_application_data_content_type(ContentType::CHANGE_CIPHER_SPEC));
    EXPECT_FALSE(is_application_data_content_type(ContentType::ALERT));
    EXPECT_FALSE(is_application_data_content_type(ContentType::HANDSHAKE));
    EXPECT_FALSE(is_application_data_content_type(ContentType::HEARTBEAT));
    EXPECT_FALSE(is_application_data_content_type(ContentType::TLS12_CID));
    EXPECT_FALSE(is_application_data_content_type(ContentType::INVALID));
}

/**
 * @brief Test suite for handshake type validation functions
 */
class HandshakeTypeValidationTest : public ProtocolUtilitiesTest {};

/**
 * @brief Test is_valid_handshake_type function with all valid handshake types
 */
TEST_F(HandshakeTypeValidationTest, TestValidHandshakeTypes) {
    // Test all handshake types that should be valid
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CLIENT_HELLO));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::SERVER_HELLO));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::HELLO_VERIFY_REQUEST_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::NEW_SESSION_TICKET));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::END_OF_EARLY_DATA));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::HELLO_RETRY_REQUEST));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::ENCRYPTED_EXTENSIONS));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CERTIFICATE));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::SERVER_KEY_EXCHANGE_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CERTIFICATE_REQUEST));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::SERVER_HELLO_DONE_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CERTIFICATE_VERIFY));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::FINISHED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CERTIFICATE_URL_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::CERTIFICATE_STATUS_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::SUPPLEMENTAL_DATA_RESERVED));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::KEY_UPDATE));
    EXPECT_TRUE(is_valid_handshake_type(HandshakeType::MESSAGE_HASH));
}

/**
 * @brief Test is_valid_handshake_type function with invalid handshake types
 */
TEST_F(HandshakeTypeValidationTest, TestInvalidHandshakeTypes) {
    // Test with arbitrary invalid values (gaps in the enum)
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(7)));   // Gap between 6 and 8
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(9)));   // Gap between 8 and 11
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(10)));  // Gap between 8 and 11
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(17)));  // Gap between 16 and 20
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(18)));  // Gap between 16 and 20
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(19)));  // Gap between 16 and 20
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(25)));  // Gap between 24 and 26
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(27)));  // Above 26
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(100))); // Arbitrary high value
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(255))); // Max uint8_t value
    EXPECT_FALSE(is_valid_handshake_type(static_cast<HandshakeType>(253))); // Just below MESSAGE_HASH
}

/**
 * @brief Test is_client_handshake_message function
 */
TEST_F(HandshakeTypeValidationTest, TestClientHandshakeMessages) {
    // Messages that should be client-originated
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CLIENT_HELLO));
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::END_OF_EARLY_DATA));
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CERTIFICATE));
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CERTIFICATE_VERIFY));
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED));
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::FINISHED));
    
    // Messages that should NOT be client-originated
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::SERVER_HELLO));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::HELLO_VERIFY_REQUEST_RESERVED));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::NEW_SESSION_TICKET));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::HELLO_RETRY_REQUEST));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::ENCRYPTED_EXTENSIONS));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::SERVER_KEY_EXCHANGE_RESERVED));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::CERTIFICATE_REQUEST));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::SERVER_HELLO_DONE_RESERVED));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::CERTIFICATE_STATUS_RESERVED));
    EXPECT_FALSE(is_client_handshake_message(HandshakeType::KEY_UPDATE));
    
    // Test with invalid handshake types
    EXPECT_FALSE(is_client_handshake_message(static_cast<HandshakeType>(100)));
    EXPECT_FALSE(is_client_handshake_message(static_cast<HandshakeType>(255)));
}

/**
 * @brief Test is_server_handshake_message function  
 */
TEST_F(HandshakeTypeValidationTest, TestServerHandshakeMessages) {
    // Messages that should be server-originated
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::SERVER_HELLO));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::HELLO_VERIFY_REQUEST_RESERVED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::NEW_SESSION_TICKET));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::HELLO_RETRY_REQUEST));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::ENCRYPTED_EXTENSIONS));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::SERVER_KEY_EXCHANGE_RESERVED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE_REQUEST));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::SERVER_HELLO_DONE_RESERVED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE_VERIFY));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::FINISHED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE_STATUS_RESERVED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::KEY_UPDATE));
    
    // Messages that should NOT be server-originated (client-only)
    EXPECT_FALSE(is_server_handshake_message(HandshakeType::CLIENT_HELLO));
    EXPECT_FALSE(is_server_handshake_message(HandshakeType::END_OF_EARLY_DATA));
    EXPECT_FALSE(is_server_handshake_message(HandshakeType::CLIENT_KEY_EXCHANGE_RESERVED));
    
    // Test with invalid handshake types
    EXPECT_FALSE(is_server_handshake_message(static_cast<HandshakeType>(100)));
    EXPECT_FALSE(is_server_handshake_message(static_cast<HandshakeType>(255)));
}

/**
 * @brief Test edge cases and boundary conditions
 */
class ProtocolUtilitiesBoundaryTest : public ProtocolUtilitiesTest {};

/**
 * @brief Test boundary conditions for version validation
 */
TEST_F(ProtocolUtilitiesBoundaryTest, TestVersionBoundaries) {
    // Test versions just above and below valid ranges
    EXPECT_FALSE(is_supported_version(static_cast<ProtocolVersion>(0xFEFB))); // Below DTLS 1.3
    EXPECT_FALSE(is_supported_version(static_cast<ProtocolVersion>(0xFF00))); // Above DTLS 1.0
    
    // Test with exact boundary values
    EXPECT_TRUE(is_supported_version(static_cast<ProtocolVersion>(0xFEFC)));  // DTLS 1.3
    EXPECT_TRUE(is_supported_version(static_cast<ProtocolVersion>(0xFEFD)));  // DTLS 1.2
    EXPECT_TRUE(is_supported_version(static_cast<ProtocolVersion>(0xFEFF)));  // DTLS 1.0
}

/**
 * @brief Test edge cases for content type validation
 */
TEST_F(ProtocolUtilitiesBoundaryTest, TestContentTypeBoundaries) {
    // Test values around valid content types
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(19)));  // Below CHANGE_CIPHER_SPEC
    EXPECT_FALSE(is_valid_content_type(static_cast<ContentType>(26)));  // Above TLS12_CID
}

/**
 * @brief Test overlapping message types (both client and server can send)
 */
TEST_F(ProtocolUtilitiesBoundaryTest, TestOverlappingMessageTypes) {
    // CERTIFICATE, CERTIFICATE_VERIFY, and FINISHED can be sent by both client and server
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CERTIFICATE));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE));
    
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::CERTIFICATE_VERIFY));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::CERTIFICATE_VERIFY));
    
    EXPECT_TRUE(is_client_handshake_message(HandshakeType::FINISHED));
    EXPECT_TRUE(is_server_handshake_message(HandshakeType::FINISHED));
}

/**
 * @brief Performance test for utility functions (they should be fast)
 */
TEST_F(ProtocolUtilitiesBoundaryTest, TestPerformance) {
    // These functions should be extremely fast as they're called frequently
    // Test with a large number of calls to ensure no performance regression
    const int iterations = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        volatile bool result1 = is_supported_version(ProtocolVersion::DTLS_1_3);
        volatile bool result2 = is_valid_content_type(ContentType::HANDSHAKE);
        volatile bool result3 = is_valid_handshake_type(HandshakeType::CLIENT_HELLO);
        volatile bool result4 = is_client_handshake_message(HandshakeType::CLIENT_HELLO);
        volatile bool result5 = is_server_handshake_message(HandshakeType::SERVER_HELLO);
        (void)result1; (void)result2; (void)result3; (void)result4; (void)result5;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete very quickly (less than 10ms for 100k iterations)
    EXPECT_LT(duration.count(), 10000);
}