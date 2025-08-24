#include <gtest/gtest.h>
#include "dtls/protocol.h"

/**
 * @brief Simple test suite for protocol utility functions in protocol.cpp
 * 
 * This test suite provides targeted coverage for the protocol utility
 * functions to achieve high code coverage without type conflicts.
 */
class ProtocolUtilitiesSimpleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No setup required for these utility functions
    }
};

/**
 * @brief Test is_supported_version function with raw version values
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestSupportedVersionsWithRawValues) {
    // Test with actual DTLS version values (raw uint16_t values)
    EXPECT_TRUE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xfefc))); // DTLS 1.3
    EXPECT_TRUE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xfefd))); // DTLS 1.2  
    EXPECT_TRUE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xfeff))); // DTLS 1.0
    
    // Test invalid versions
    EXPECT_FALSE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0000)));
    EXPECT_FALSE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xFFFF)));
    EXPECT_FALSE(dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0x0301))); // TLS version
}

/**
 * @brief Test is_valid_content_type function with raw content type values
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestValidContentTypesWithRawValues) {
    // Test valid content types using raw values to avoid enum conflicts
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(20))); // CHANGE_CIPHER_SPEC
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(21))); // ALERT
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(22))); // HANDSHAKE
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(23))); // APPLICATION_DATA
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(24))); // HEARTBEAT
    EXPECT_TRUE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(25))); // TLS12_CID
    
    // Test invalid content types
    EXPECT_FALSE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(0)));  // INVALID
    EXPECT_FALSE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(19))); // Below valid range
    EXPECT_FALSE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(26))); // Above valid range
    EXPECT_FALSE(dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(255))); // Max value
}

/**
 * @brief Test is_handshake_content_type function
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestHandshakeContentTypeDetection) {
    // Only value 22 (HANDSHAKE) should return true
    EXPECT_TRUE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(22)));
    
    // All other values should return false
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(20))); // CHANGE_CIPHER_SPEC
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(21))); // ALERT
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(23))); // APPLICATION_DATA
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(24))); // HEARTBEAT
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(25))); // TLS12_CID
    EXPECT_FALSE(dtls::v13::protocol::is_handshake_content_type(static_cast<dtls::v13::protocol::ContentType>(0)));  // INVALID
}

/**
 * @brief Test is_application_data_content_type function
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestApplicationDataContentTypeDetection) {
    // Only value 23 (APPLICATION_DATA) should return true
    EXPECT_TRUE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(23)));
    
    // All other values should return false
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(20))); // CHANGE_CIPHER_SPEC
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(21))); // ALERT
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(22))); // HANDSHAKE
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(24))); // HEARTBEAT
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(25))); // TLS12_CID
    EXPECT_FALSE(dtls::v13::protocol::is_application_data_content_type(static_cast<dtls::v13::protocol::ContentType>(0)));  // INVALID
}

/**
 * @brief Test is_valid_handshake_type function with raw handshake type values
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestValidHandshakeTypesWithRawValues) {
    // Test valid handshake types using raw values
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(1)));   // CLIENT_HELLO
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(2)));   // SERVER_HELLO
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(3)));   // HELLO_VERIFY_REQUEST_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(4)));   // NEW_SESSION_TICKET
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(5)));   // END_OF_EARLY_DATA
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(6)));   // HELLO_RETRY_REQUEST
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(8)));   // ENCRYPTED_EXTENSIONS
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(11)));  // CERTIFICATE
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(12)));  // SERVER_KEY_EXCHANGE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(13)));  // CERTIFICATE_REQUEST
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(14)));  // SERVER_HELLO_DONE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(15)));  // CERTIFICATE_VERIFY
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(16)));  // CLIENT_KEY_EXCHANGE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(20)));  // FINISHED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(21)));  // CERTIFICATE_URL_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(22)));  // CERTIFICATE_STATUS_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(23)));  // SUPPLEMENTAL_DATA_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(24)));  // KEY_UPDATE
    EXPECT_TRUE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(254))); // MESSAGE_HASH
    
    // Test invalid handshake types (gaps in the enum)
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(0)));   // Not defined
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(7)));   // Gap between 6 and 8
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(9)));   // Gap between 8 and 11
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(10)));  // Gap between 8 and 11
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(17)));  // Gap between 16 and 20
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(18)));  // Gap between 16 and 20
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(19)));  // Gap between 16 and 20
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(25)));  // Gap between 24 and 254
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(100))); // Arbitrary invalid value
    EXPECT_FALSE(dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(255))); // Max uint8_t value
}

/**
 * @brief Test is_client_handshake_message function
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestClientHandshakeMessageClassification) {
    // Messages that should be client-originated
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(1)));  // CLIENT_HELLO
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(5)));  // END_OF_EARLY_DATA
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(11))); // CERTIFICATE
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(15))); // CERTIFICATE_VERIFY
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(16))); // CLIENT_KEY_EXCHANGE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(20))); // FINISHED
    
    // Messages that should NOT be client-originated
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(2)));  // SERVER_HELLO
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(3)));  // HELLO_VERIFY_REQUEST_RESERVED
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(4)));  // NEW_SESSION_TICKET
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(6)));  // HELLO_RETRY_REQUEST
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(8)));  // ENCRYPTED_EXTENSIONS
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(12))); // SERVER_KEY_EXCHANGE_RESERVED
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(13))); // CERTIFICATE_REQUEST
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(14))); // SERVER_HELLO_DONE_RESERVED
    
    // Test with invalid handshake types
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(0)));
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(100)));
    EXPECT_FALSE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(255)));
}

/**
 * @brief Test is_server_handshake_message function  
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestServerHandshakeMessageClassification) {
    // Messages that should be server-originated
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(2)));  // SERVER_HELLO
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(3)));  // HELLO_VERIFY_REQUEST_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(4)));  // NEW_SESSION_TICKET
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(6)));  // HELLO_RETRY_REQUEST
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(8)));  // ENCRYPTED_EXTENSIONS
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(11))); // CERTIFICATE
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(12))); // SERVER_KEY_EXCHANGE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(13))); // CERTIFICATE_REQUEST
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(14))); // SERVER_HELLO_DONE_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(15))); // CERTIFICATE_VERIFY
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(20))); // FINISHED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(22))); // CERTIFICATE_STATUS_RESERVED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(24))); // KEY_UPDATE
    
    // Messages that should NOT be server-originated (client-only)
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(1)));  // CLIENT_HELLO
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(5)));  // END_OF_EARLY_DATA
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(16))); // CLIENT_KEY_EXCHANGE_RESERVED
    
    // Test with invalid handshake types
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(0)));
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(100)));
    EXPECT_FALSE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(255)));
}

/**
 * @brief Test overlapping message types (both client and server can send)
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestOverlappingMessageTypes) {
    // CERTIFICATE, CERTIFICATE_VERIFY, and FINISHED can be sent by both client and server
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(11))); // CERTIFICATE
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(11))); // CERTIFICATE
    
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(15))); // CERTIFICATE_VERIFY
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(15))); // CERTIFICATE_VERIFY
    
    EXPECT_TRUE(dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(20))); // FINISHED
    EXPECT_TRUE(dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(20))); // FINISHED
}

/**
 * @brief Performance test for utility functions (they should be fast)
 */
TEST_F(ProtocolUtilitiesSimpleTest, TestPerformance) {
    // These functions should be extremely fast as they're called frequently
    const int iterations = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        volatile bool result1 = dtls::v13::protocol::is_supported_version(static_cast<dtls::v13::protocol::ProtocolVersion>(0xfefc));
        volatile bool result2 = dtls::v13::protocol::is_valid_content_type(static_cast<dtls::v13::protocol::ContentType>(22));
        volatile bool result3 = dtls::v13::protocol::is_valid_handshake_type(static_cast<dtls::v13::HandshakeType>(1));
        volatile bool result4 = dtls::v13::protocol::is_client_handshake_message(static_cast<dtls::v13::HandshakeType>(1));
        volatile bool result5 = dtls::v13::protocol::is_server_handshake_message(static_cast<dtls::v13::HandshakeType>(2));
        (void)result1; (void)result2; (void)result3; (void)result4; (void)result5;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete very quickly (less than 10ms for 100k iterations)
    EXPECT_LT(duration.count(), 10000);
}