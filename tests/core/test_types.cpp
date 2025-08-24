#include <gtest/gtest.h>
#include <dtls/types.h>
#include <dtls/error.h>
#include <sstream>
#include <unordered_set>

using namespace dtls::v13;

class DTLSTypesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup common test data
    }

    void TearDown() override {
        // Cleanup
    }
};

// Test enum to_string conversions
TEST_F(DTLSTypesTest, ContentTypeToString) {
    // Test all valid content types
    EXPECT_EQ(to_string(ContentType::INVALID), "INVALID");
    EXPECT_EQ(to_string(ContentType::CHANGE_CIPHER_SPEC), "CHANGE_CIPHER_SPEC");
    EXPECT_EQ(to_string(ContentType::ALERT), "ALERT");
    EXPECT_EQ(to_string(ContentType::HANDSHAKE), "HANDSHAKE");
    EXPECT_EQ(to_string(ContentType::APPLICATION_DATA), "APPLICATION_DATA");
    EXPECT_EQ(to_string(ContentType::HEARTBEAT), "HEARTBEAT");
    EXPECT_EQ(to_string(ContentType::TLS12_CID), "TLS12_CID");
    EXPECT_EQ(to_string(ContentType::ACK), "ACK");
    
    // Test unknown content type
    ContentType unknown = static_cast<ContentType>(99);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_CONTENT_TYPE(99)") != std::string::npos);
}

TEST_F(DTLSTypesTest, HandshakeTypeToString) {
    // Test key handshake types
    EXPECT_EQ(to_string(HandshakeType::CLIENT_HELLO), "CLIENT_HELLO");
    EXPECT_EQ(to_string(HandshakeType::SERVER_HELLO), "SERVER_HELLO");
    EXPECT_EQ(to_string(HandshakeType::HELLO_RETRY_REQUEST), "HELLO_RETRY_REQUEST");
    EXPECT_EQ(to_string(HandshakeType::ENCRYPTED_EXTENSIONS), "ENCRYPTED_EXTENSIONS");
    EXPECT_EQ(to_string(HandshakeType::CERTIFICATE), "CERTIFICATE");
    EXPECT_EQ(to_string(HandshakeType::CERTIFICATE_VERIFY), "CERTIFICATE_VERIFY");
    EXPECT_EQ(to_string(HandshakeType::FINISHED), "FINISHED");
    EXPECT_EQ(to_string(HandshakeType::KEY_UPDATE), "KEY_UPDATE");
    EXPECT_EQ(to_string(HandshakeType::END_OF_EARLY_DATA), "END_OF_EARLY_DATA");
    EXPECT_EQ(to_string(HandshakeType::ACK), "ACK");
    EXPECT_EQ(to_string(HandshakeType::MESSAGE_HASH), "MESSAGE_HASH");
    
    // Test unknown handshake type
    HandshakeType unknown = static_cast<HandshakeType>(199);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_HANDSHAKE_TYPE(199)") != std::string::npos);
}

TEST_F(DTLSTypesTest, AlertLevelToString) {
    EXPECT_EQ(to_string(AlertLevel::WARNING), "WARNING");
    EXPECT_EQ(to_string(AlertLevel::FATAL), "FATAL");
    
    // Test unknown alert level
    AlertLevel unknown = static_cast<AlertLevel>(99);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_ALERT_LEVEL(99)") != std::string::npos);
}

TEST_F(DTLSTypesTest, AlertDescriptionToString) {
    // Test common alert descriptions
    EXPECT_EQ(to_string(AlertDescription::CLOSE_NOTIFY), "CLOSE_NOTIFY");
    EXPECT_EQ(to_string(AlertDescription::UNEXPECTED_MESSAGE), "UNEXPECTED_MESSAGE");
    EXPECT_EQ(to_string(AlertDescription::BAD_RECORD_MAC), "BAD_RECORD_MAC");
    EXPECT_EQ(to_string(AlertDescription::HANDSHAKE_FAILURE), "HANDSHAKE_FAILURE");
    EXPECT_EQ(to_string(AlertDescription::BAD_CERTIFICATE), "BAD_CERTIFICATE");
    EXPECT_EQ(to_string(AlertDescription::CERTIFICATE_EXPIRED), "CERTIFICATE_EXPIRED");
    EXPECT_EQ(to_string(AlertDescription::UNKNOWN_CA), "UNKNOWN_CA");
    EXPECT_EQ(to_string(AlertDescription::DECODE_ERROR), "DECODE_ERROR");
    EXPECT_EQ(to_string(AlertDescription::DECRYPT_ERROR), "DECRYPT_ERROR");
    EXPECT_EQ(to_string(AlertDescription::PROTOCOL_VERSION), "PROTOCOL_VERSION");
    EXPECT_EQ(to_string(AlertDescription::INTERNAL_ERROR), "INTERNAL_ERROR");
    EXPECT_EQ(to_string(AlertDescription::MISSING_EXTENSION), "MISSING_EXTENSION");
    EXPECT_EQ(to_string(AlertDescription::UNSUPPORTED_EXTENSION), "UNSUPPORTED_EXTENSION");
    EXPECT_EQ(to_string(AlertDescription::CERTIFICATE_REQUIRED), "CERTIFICATE_REQUIRED");
    EXPECT_EQ(to_string(AlertDescription::NO_APPLICATION_PROTOCOL), "NO_APPLICATION_PROTOCOL");
    
    // Test unknown alert description
    AlertDescription unknown = static_cast<AlertDescription>(199);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_ALERT_DESC(199)") != std::string::npos);
}

TEST_F(DTLSTypesTest, CipherSuiteToString) {
    // Test all supported cipher suites
    EXPECT_EQ(to_string(CipherSuite::TLS_AES_128_GCM_SHA256), "TLS_AES_128_GCM_SHA256");
    EXPECT_EQ(to_string(CipherSuite::TLS_AES_256_GCM_SHA384), "TLS_AES_256_GCM_SHA384");
    EXPECT_EQ(to_string(CipherSuite::TLS_CHACHA20_POLY1305_SHA256), "TLS_CHACHA20_POLY1305_SHA256");
    EXPECT_EQ(to_string(CipherSuite::TLS_AES_128_CCM_SHA256), "TLS_AES_128_CCM_SHA256");
    EXPECT_EQ(to_string(CipherSuite::TLS_AES_128_CCM_8_SHA256), "TLS_AES_128_CCM_8_SHA256");
    
    // Test unknown cipher suite - should show hex format
    CipherSuite unknown = static_cast<CipherSuite>(0x9999);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_CIPHER_SUITE(0x9999)") != std::string::npos);
}

TEST_F(DTLSTypesTest, ConnectionStateToString) {
    // Test all connection states
    EXPECT_EQ(to_string(ConnectionState::INITIAL), "INITIAL");
    EXPECT_EQ(to_string(ConnectionState::WAIT_SERVER_HELLO), "WAIT_SERVER_HELLO");
    EXPECT_EQ(to_string(ConnectionState::WAIT_ENCRYPTED_EXTENSIONS), "WAIT_ENCRYPTED_EXTENSIONS");
    EXPECT_EQ(to_string(ConnectionState::WAIT_CERTIFICATE_OR_CERT_REQUEST), "WAIT_CERTIFICATE_OR_CERT_REQUEST");
    EXPECT_EQ(to_string(ConnectionState::WAIT_CERTIFICATE_VERIFY), "WAIT_CERTIFICATE_VERIFY");
    EXPECT_EQ(to_string(ConnectionState::WAIT_SERVER_FINISHED), "WAIT_SERVER_FINISHED");
    EXPECT_EQ(to_string(ConnectionState::WAIT_CLIENT_CERTIFICATE), "WAIT_CLIENT_CERTIFICATE");
    EXPECT_EQ(to_string(ConnectionState::WAIT_CLIENT_CERTIFICATE_VERIFY), "WAIT_CLIENT_CERTIFICATE_VERIFY");
    EXPECT_EQ(to_string(ConnectionState::WAIT_CLIENT_FINISHED), "WAIT_CLIENT_FINISHED");
    EXPECT_EQ(to_string(ConnectionState::CONNECTED), "CONNECTED");
    EXPECT_EQ(to_string(ConnectionState::CLOSED), "CLOSED");
    
    // Test unknown connection state
    ConnectionState unknown = static_cast<ConnectionState>(199);
    std::string result = to_string(unknown);
    EXPECT_TRUE(result.find("UNKNOWN_CONNECTION_STATE(199)") != std::string::npos);
}

// Test NetworkAddress functionality
TEST_F(DTLSTypesTest, NetworkAddressIPv4Construction) {
    // Test IPv4 from uint32_t
    uint32_t ipv4_addr = 0xC0A80001; // 192.168.0.1
    uint16_t port = 443;
    
    NetworkAddress addr = NetworkAddress::from_ipv4(ipv4_addr, port);
    
    EXPECT_TRUE(addr.is_ipv4());
    EXPECT_FALSE(addr.is_ipv6());
    EXPECT_EQ(addr.get_port(), port);
    EXPECT_EQ(addr.to_ipv4(), ipv4_addr);
}

TEST_F(DTLSTypesTest, NetworkAddressIPv6Construction) {
    // Test IPv6 construction
    std::array<uint8_t, 16> ipv6_addr = {
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
    };
    uint16_t port = 8443;
    
    NetworkAddress addr = NetworkAddress::from_ipv6(ipv6_addr, port);
    
    EXPECT_FALSE(addr.is_ipv4());
    EXPECT_TRUE(addr.is_ipv6());
    EXPECT_EQ(addr.get_port(), port);
    EXPECT_EQ(addr.to_ipv6(), ipv6_addr);
}

TEST_F(DTLSTypesTest, NetworkAddressStringConstruction) {
    // Test IPv4 string construction
    NetworkAddress ipv4_addr("192.168.1.100", 443);
    EXPECT_TRUE(ipv4_addr.is_ipv4());
    EXPECT_EQ(ipv4_addr.get_port(), 443);
    
    // Test IPv6 string construction (simplified)
    NetworkAddress ipv6_addr("2001:db8::1", 8443);
    EXPECT_TRUE(ipv6_addr.is_ipv6());
    EXPECT_EQ(ipv6_addr.get_port(), 8443);
}

TEST_F(DTLSTypesTest, NetworkAddressFromString) {
    // Test valid IPv4 address with port
    auto result = NetworkAddress::from_string("192.168.1.1:443");
    ASSERT_TRUE(result.is_success());
    
    NetworkAddress addr = result.value();
    EXPECT_TRUE(addr.is_ipv4());
    EXPECT_EQ(addr.get_port(), 443);
    
    // Test invalid format - no port
    auto invalid_result = NetworkAddress::from_string("192.168.1.1");
    EXPECT_TRUE(invalid_result.is_error());
    EXPECT_EQ(invalid_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test invalid port
    auto invalid_port = NetworkAddress::from_string("192.168.1.1:invalid");
    EXPECT_TRUE(invalid_port.is_error());
    EXPECT_EQ(invalid_port.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(DTLSTypesTest, NetworkAddressComparison) {
    NetworkAddress addr1 = NetworkAddress::from_ipv4(0xC0A80001, 443);
    NetworkAddress addr2 = NetworkAddress::from_ipv4(0xC0A80001, 443);
    NetworkAddress addr3 = NetworkAddress::from_ipv4(0xC0A80002, 443);
    NetworkAddress addr4 = NetworkAddress::from_ipv4(0xC0A80001, 8443);
    
    // Test equality
    EXPECT_TRUE(addr1 == addr2);
    EXPECT_FALSE(addr1 == addr3);
    EXPECT_FALSE(addr1 == addr4);
    
    // Test inequality
    EXPECT_FALSE(addr1 != addr2);
    EXPECT_TRUE(addr1 != addr3);
    EXPECT_TRUE(addr1 != addr4);
    
    // Test less than (for use in maps/sets)
    EXPECT_TRUE(addr1 < addr3); // Different IP
    EXPECT_TRUE(addr1 < addr4); // Different port
}

TEST_F(DTLSTypesTest, NetworkAddressToString) {
    // Test IPv4 toString
    NetworkAddress ipv4_addr = NetworkAddress::from_ipv4(0xC0A80001, 443);
    std::string ipv4_str = to_string(ipv4_addr);
    EXPECT_EQ(ipv4_str, "192.168.0.1:443");
    
    // Test IPv6 toString
    std::array<uint8_t, 16> ipv6_bytes = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    NetworkAddress ipv6_addr = NetworkAddress::from_ipv6(ipv6_bytes, 8443);
    std::string ipv6_str = to_string(ipv6_addr);
    EXPECT_TRUE(ipv6_str.find("[2001:db8:0:0:0:0:0:1]:8443") != std::string::npos);
}

TEST_F(DTLSTypesTest, NetworkAddressGetIP) {
    // Test IPv4 get_ip
    NetworkAddress ipv4_addr = NetworkAddress::from_ipv4(0xC0A80001, 443);
    EXPECT_EQ(ipv4_addr.get_ip(), "192.168.0.1");
    
    // Test IPv6 get_ip  
    std::array<uint8_t, 16> ipv6_bytes = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    NetworkAddress ipv6_addr = NetworkAddress::from_ipv6(ipv6_bytes, 8443);
    std::string ipv6_ip = ipv6_addr.get_ip();
    EXPECT_TRUE(ipv6_ip.find("2001") != std::string::npos);
}

// Test cipher suite utility functions (these functions are not in the header but are in the source)
class CipherSuiteUtilitiesTest : public ::testing::Test {
protected:
    void test_cipher_suite_properties(CipherSuite suite, AEADCipher expected_aead, 
                                     HashAlgorithm expected_hash, size_t expected_key_len,
                                     size_t expected_iv_len, size_t expected_tag_len,
                                     size_t expected_hash_len) {
        // Note: These functions are not declared in the header but are implemented in source
        // They would need to be declared in the header for proper testing
        // For now, we'll test what we can access
        
        // Test that the cipher suite has a valid string representation
        std::string suite_str = to_string(suite);
        EXPECT_FALSE(suite_str.empty());
        EXPECT_TRUE(suite_str.find("TLS_") == 0 || suite_str.find("UNKNOWN_") == 0);
    }
};

TEST_F(CipherSuiteUtilitiesTest, AES128GCMProperties) {
    test_cipher_suite_properties(
        CipherSuite::TLS_AES_128_GCM_SHA256,
        AEADCipher::AES_128_GCM,
        HashAlgorithm::SHA256,
        16, 12, 16, 32
    );
}

TEST_F(CipherSuiteUtilitiesTest, AES256GCMProperties) {
    test_cipher_suite_properties(
        CipherSuite::TLS_AES_256_GCM_SHA384,
        AEADCipher::AES_256_GCM,
        HashAlgorithm::SHA384,
        32, 12, 16, 48
    );
}

TEST_F(CipherSuiteUtilitiesTest, ChaCha20Poly1305Properties) {
    test_cipher_suite_properties(
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        AEADCipher::CHACHA20_POLY1305,
        HashAlgorithm::SHA256,
        32, 12, 16, 32
    );
}

// Test protocol version constants
TEST_F(DTLSTypesTest, ProtocolVersionConstants) {
    EXPECT_EQ(DTLS_V10, 0xFEFF);
    EXPECT_EQ(DTLS_V12, 0xFEFD);
    EXPECT_EQ(DTLS_V13, 0xFEFC);
    
    // Verify ordering (lower values = newer versions in DTLS)
    EXPECT_GT(DTLS_V10, DTLS_V12);
    EXPECT_GT(DTLS_V12, DTLS_V13);
}

// Test size constants
TEST_F(DTLSTypesTest, SizeConstants) {
    EXPECT_EQ(MAX_RECORD_LENGTH, 16384);
    EXPECT_EQ(MAX_HANDSHAKE_MESSAGE_LENGTH, 16777215);
    EXPECT_EQ(MAX_CONNECTION_ID_LENGTH, 20);
    EXPECT_EQ(MAX_COOKIE_LENGTH, 255);
    EXPECT_EQ(RANDOM_LENGTH, 32);
    EXPECT_EQ(MAX_SESSION_ID_LENGTH, 32);
}

// Test timing constants
TEST_F(DTLSTypesTest, TimingConstants) {
    EXPECT_EQ(DEFAULT_RETRANSMISSION_TIMEOUT.count(), 1000);
    EXPECT_EQ(MAX_RETRANSMISSION_TIMEOUT.count(), 60000);
    EXPECT_EQ(MAX_RETRANSMISSIONS, 3);
}

// Test type aliases and their usage
TEST_F(DTLSTypesTest, TypeAliasUsage) {
    // Test that type aliases compile and work correctly
    ProtocolVersion version = DTLS_V13;
    EXPECT_EQ(version, 0xFEFC);
    
    Epoch epoch = 1;
    EXPECT_EQ(epoch, 1);
    
    SequenceNumber seq_num = 0x123456789ABCDEF0ULL;
    EXPECT_EQ(seq_num, 0x123456789ABCDEF0ULL);
    
    Length length = 1234;
    EXPECT_EQ(length, 1234);
    
    // Test container types
    ConnectionID cid = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(cid.size(), 4);
    EXPECT_EQ(cid[0], 0x01);
    
    Random random;
    EXPECT_EQ(random.size(), 32);
    
    SessionID session_id = {0xAA, 0xBB, 0xCC};
    EXPECT_EQ(session_id.size(), 3);
    
    Cookie cookie = {0x11, 0x22, 0x33, 0x44, 0x55};
    EXPECT_EQ(cookie.size(), 5);
    
    KeyMaterial key_material = {0xFF, 0xEE, 0xDD};
    EXPECT_EQ(key_material.size(), 3);
    
    CertificateData cert_data = {0x30, 0x82, 0x01, 0x00}; // Start of typical DER certificate
    EXPECT_EQ(cert_data.size(), 4);
}

// Test NetworkAddress edge cases
TEST_F(DTLSTypesTest, NetworkAddressEdgeCases) {
    // Test maximum port number
    NetworkAddress max_port_addr = NetworkAddress::from_ipv4(0x7F000001, 65535);
    EXPECT_EQ(max_port_addr.get_port(), 65535);
    
    // Test port 0
    NetworkAddress zero_port_addr = NetworkAddress::from_ipv4(0x7F000001, 0);
    EXPECT_EQ(zero_port_addr.get_port(), 0);
    
    // Test all zeros IPv4
    NetworkAddress zero_ipv4 = NetworkAddress::from_ipv4(0, 80);
    EXPECT_TRUE(zero_ipv4.is_ipv4());
    EXPECT_EQ(zero_ipv4.get_ip(), "0.0.0.0");
    
    // Test all ones IPv4
    NetworkAddress broadcast_ipv4 = NetworkAddress::from_ipv4(0xFFFFFFFF, 80);
    EXPECT_TRUE(broadcast_ipv4.is_ipv4());
    EXPECT_EQ(broadcast_ipv4.get_ip(), "255.255.255.255");
    
    // Test default constructor
    NetworkAddress default_addr;
    EXPECT_EQ(default_addr.get_port(), 0);
}

// Test enum value ranges and completeness
TEST_F(DTLSTypesTest, EnumValueRanges) {
    // Test that enum values are within expected ranges and don't overlap unexpectedly
    
    // ContentType values should be in TLS/DTLS range
    EXPECT_GE(static_cast<uint8_t>(ContentType::CHANGE_CIPHER_SPEC), 20);
    EXPECT_LE(static_cast<uint8_t>(ContentType::ACK), 26);
    
    // AlertLevel values
    EXPECT_EQ(static_cast<uint8_t>(AlertLevel::WARNING), 1);
    EXPECT_EQ(static_cast<uint8_t>(AlertLevel::FATAL), 2);
    
    // CipherSuite values should be in TLS 1.3 range
    EXPECT_EQ(static_cast<uint16_t>(CipherSuite::TLS_AES_128_GCM_SHA256), 0x1301);
    EXPECT_EQ(static_cast<uint16_t>(CipherSuite::TLS_AES_256_GCM_SHA384), 0x1302);
    EXPECT_EQ(static_cast<uint16_t>(CipherSuite::TLS_CHACHA20_POLY1305_SHA256), 0x1303);
    EXPECT_EQ(static_cast<uint16_t>(CipherSuite::TLS_AES_128_CCM_SHA256), 0x1304);
    EXPECT_EQ(static_cast<uint16_t>(CipherSuite::TLS_AES_128_CCM_8_SHA256), 0x1305);
}

// Test thread safety of to_string functions (they use static maps)
TEST_F(DTLSTypesTest, ThreadSafetyBasic) {
    // Basic test that the functions can be called from multiple threads
    // Note: Full thread safety testing would require more complex setup
    
    std::vector<std::thread> threads;
    std::vector<std::string> results(10);
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&results, i]() {
            results[i] = to_string(ContentType::HANDSHAKE);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All results should be the same
    for (const auto& result : results) {
        EXPECT_EQ(result, "HANDSHAKE");
    }
}

// Test string representations are reasonable and consistent
TEST_F(DTLSTypesTest, StringRepresentationConsistency) {
    // Test that string representations follow consistent patterns
    
    // All enum string representations should be uppercase
    auto test_uppercase = [](const std::string& str) {
        for (char c : str) {
            if (std::isalpha(c)) {
                EXPECT_TRUE(std::isupper(c)) << "Non-uppercase character in: " << str;
            }
        }
    };
    
    test_uppercase(to_string(ContentType::HANDSHAKE));
    test_uppercase(to_string(HandshakeType::CLIENT_HELLO));
    test_uppercase(to_string(AlertLevel::FATAL));
    test_uppercase(to_string(AlertDescription::HANDSHAKE_FAILURE));
    test_uppercase(to_string(ConnectionState::CONNECTED));
    
    // Cipher suite names should start with "TLS_"
    std::string cipher_str = to_string(CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_TRUE(cipher_str.find("TLS_") == 0);
    
    // Unknown values should contain "UNKNOWN"
    std::string unknown_content = to_string(static_cast<ContentType>(99));
    EXPECT_TRUE(unknown_content.find("UNKNOWN") != std::string::npos);
}