#include <gtest/gtest.h>
#include <dtls/protocol/handshake.h>
#include <dtls/memory/buffer.h>
#include <vector>
#include <cstring>

using namespace dtls::v13::protocol;
using namespace dtls::v13::memory;

class HelloRetryRequestTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up common test data
        test_cookie_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        test_cookie = Buffer(test_cookie_data.size());
        test_cookie.resize(test_cookie_data.size());
        std::memcpy(test_cookie.mutable_data(), test_cookie_data.data(), test_cookie_data.size());
        
        selected_group = NamedGroup::SECP256R1;
    }
    
    std::vector<uint8_t> test_cookie_data;
    Buffer test_cookie;
    NamedGroup selected_group;
};

// Basic HelloRetryRequest Tests
TEST_F(HelloRetryRequestTest, ConstructorInitialization) {
    HelloRetryRequest hrr;
    
    // Check default values
    EXPECT_EQ(hrr.legacy_version(), ProtocolVersion::DTLS_1_2);
    EXPECT_EQ(hrr.cipher_suite(), CipherSuite::TLS_AES_128_GCM_SHA256);
    
    // Check that it uses the special HelloRetryRequest random value
    EXPECT_TRUE(HelloRetryRequest::is_hello_retry_request_random(hrr.random()));
    
    // Should not be valid without cookie extension
    EXPECT_FALSE(hrr.is_valid());
}

TEST_F(HelloRetryRequestTest, SpecialRandomValue) {
    HelloRetryRequest hrr;
    
    // Check that the random value matches the RFC-defined HelloRetryRequest random
    std::array<uint8_t, 32> expected_random = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };
    
    EXPECT_EQ(hrr.random(), expected_random);
    EXPECT_TRUE(HelloRetryRequest::is_hello_retry_request_random(hrr.random()));
    
    // Test with different random value
    std::array<uint8_t, 32> different_random;
    different_random.fill(0x00);
    EXPECT_FALSE(HelloRetryRequest::is_hello_retry_request_random(different_random));
}

TEST_F(HelloRetryRequestTest, CookieManagement) {
    HelloRetryRequest hrr;
    
    // Initially no cookie
    EXPECT_FALSE(hrr.get_cookie().has_value());
    EXPECT_FALSE(hrr.has_extension(ExtensionType::COOKIE));
    
    // Set cookie
    hrr.set_cookie(test_cookie);
    
    // Check cookie is set
    EXPECT_TRUE(hrr.has_extension(ExtensionType::COOKIE));
    auto retrieved_cookie = hrr.get_cookie();
    ASSERT_TRUE(retrieved_cookie.has_value());
    EXPECT_EQ(retrieved_cookie->size(), test_cookie.size());
    EXPECT_EQ(std::memcmp(retrieved_cookie->data(), test_cookie.data(), test_cookie.size()), 0);
    
    // Now should be valid
    EXPECT_TRUE(hrr.is_valid());
}

TEST_F(HelloRetryRequestTest, SelectedGroupManagement) {
    HelloRetryRequest hrr;
    hrr.set_cookie(test_cookie); // Make it valid
    
    // Initially no selected group
    EXPECT_FALSE(hrr.get_selected_group().has_value());
    EXPECT_FALSE(hrr.has_extension(ExtensionType::KEY_SHARE));
    
    // Set selected group
    hrr.set_selected_group(selected_group);
    
    // Check selected group is set
    EXPECT_TRUE(hrr.has_extension(ExtensionType::KEY_SHARE));
    auto retrieved_group = hrr.get_selected_group();
    ASSERT_TRUE(retrieved_group.has_value());
    EXPECT_EQ(retrieved_group.value(), selected_group);
    
    // Should still be valid
    EXPECT_TRUE(hrr.is_valid());
}

TEST_F(HelloRetryRequestTest, Serialization) {
    HelloRetryRequest hrr;
    hrr.set_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    hrr.set_cookie(test_cookie);
    hrr.set_selected_group(NamedGroup::SECP384R1);
    
    Buffer output_buffer;
    auto result = hrr.serialize(output_buffer);
    ASSERT_TRUE(result.is_success());
    
    size_t bytes_written = result.value();
    EXPECT_EQ(bytes_written, hrr.serialized_size());
    EXPECT_GT(bytes_written, 38); // Minimum size plus extensions
    
    // Check basic structure
    const uint8_t* data = reinterpret_cast<const uint8_t*>(output_buffer.data());
    
    // Check version
    uint16_t version = (data[0] << 8) | data[1];
    EXPECT_EQ(version, ProtocolVersion::DTLS_1_2);
    
    // Check random (should be the special HelloRetryRequest value)
    std::array<uint8_t, 32> random_from_buffer;
    std::memcpy(random_from_buffer.data(), &data[2], 32);
    EXPECT_TRUE(HelloRetryRequest::is_hello_retry_request_random(random_from_buffer));
    
    // Check cipher suite
    uint16_t cipher_suite = (data[35] << 8) | data[36]; // After version(2) + random(32) + session_id_len(1)
    EXPECT_EQ(cipher_suite, static_cast<uint16_t>(CipherSuite::TLS_AES_256_GCM_SHA384));
}

TEST_F(HelloRetryRequestTest, Deserialization) {
    // Create a HelloRetryRequest and serialize it
    HelloRetryRequest original;
    original.set_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    original.set_cookie(test_cookie);
    original.set_selected_group(NamedGroup::X25519);
    
    Buffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    // Deserialize it
    auto deserialize_result = HelloRetryRequest::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    HelloRetryRequest deserialized = deserialize_result.value();
    
    // Check all fields match
    EXPECT_EQ(deserialized.legacy_version(), original.legacy_version());
    EXPECT_EQ(deserialized.random(), original.random());
    EXPECT_EQ(deserialized.cipher_suite(), original.cipher_suite());
    EXPECT_TRUE(deserialized.is_valid());
    
    // Check cookie
    auto original_cookie = original.get_cookie();
    auto deserialized_cookie = deserialized.get_cookie();
    ASSERT_TRUE(original_cookie.has_value() && deserialized_cookie.has_value());
    EXPECT_EQ(original_cookie->size(), deserialized_cookie->size());
    EXPECT_EQ(std::memcmp(original_cookie->data(), deserialized_cookie->data(), original_cookie->size()), 0);
    
    // Check selected group
    auto original_group = original.get_selected_group();
    auto deserialized_group = deserialized.get_selected_group();
    ASSERT_TRUE(original_group.has_value() && deserialized_group.has_value());
    EXPECT_EQ(original_group.value(), deserialized_group.value());
}

TEST_F(HelloRetryRequestTest, RoundTrip) {
    HelloRetryRequest original;
    original.set_cipher_suite(CipherSuite::TLS_AES_128_CCM_SHA256);
    
    // Create a larger cookie
    std::vector<uint8_t> large_cookie_data(64);
    std::iota(large_cookie_data.begin(), large_cookie_data.end(), 0);
    Buffer large_cookie(large_cookie_data.size());
    large_cookie.resize(large_cookie_data.size());
    std::memcpy(large_cookie.mutable_data(), large_cookie_data.data(), large_cookie_data.size());
    
    original.set_cookie(large_cookie);
    original.set_selected_group(NamedGroup::FFDHE2048);
    
    // Set legacy session ID
    std::vector<uint8_t> session_id = {0xAA, 0xBB, 0xCC, 0xDD};
    Buffer session_id_buffer(session_id.size());
    session_id_buffer.resize(session_id.size());
    std::memcpy(session_id_buffer.mutable_data(), session_id.data(), session_id.size());
    original.set_legacy_session_id_echo(std::move(session_id_buffer));
    
    // Serialize
    Buffer serialized;
    auto serialize_result = original.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    // Deserialize
    auto deserialize_result = HelloRetryRequest::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    HelloRetryRequest deserialized = deserialize_result.value();
    
    // Verify all fields
    EXPECT_EQ(deserialized.legacy_version(), original.legacy_version());
    EXPECT_EQ(deserialized.cipher_suite(), original.cipher_suite());
    EXPECT_EQ(deserialized.legacy_session_id_echo().size(), original.legacy_session_id_echo().size());
    EXPECT_TRUE(deserialized.is_valid());
}

TEST_F(HelloRetryRequestTest, ValidationTests) {
    HelloRetryRequest hrr;
    
    // Invalid without cookie
    EXPECT_FALSE(hrr.is_valid());
    
    // Valid with cookie
    hrr.set_cookie(test_cookie);
    EXPECT_TRUE(hrr.is_valid());
    
    // Test session ID length validation
    Buffer large_session_id(33); // Too large
    large_session_id.resize(33);
    hrr.set_legacy_session_id_echo(std::move(large_session_id));
    EXPECT_FALSE(hrr.is_valid());
}

TEST_F(HelloRetryRequestTest, ErrorHandling) {
    // Test deserialization with insufficient buffer
    Buffer small_buffer(10);
    small_buffer.resize(10);
    
    auto result = HelloRetryRequest::deserialize(small_buffer);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::INSUFFICIENT_BUFFER_SIZE);
    
    // Test deserialization with wrong random value (not HelloRetryRequest)
    Buffer fake_hrr_buffer(40);
    fake_hrr_buffer.resize(40);
    std::memset(fake_hrr_buffer.mutable_data(), 0, 40);
    
    // Set version
    uint16_t version_net = htons(ProtocolVersion::DTLS_1_2);
    std::memcpy(fake_hrr_buffer.mutable_data(), &version_net, 2);
    
    auto fake_result = HelloRetryRequest::deserialize(fake_hrr_buffer);
    EXPECT_FALSE(fake_result.is_success());
    EXPECT_EQ(fake_result.error(), DTLSError::INVALID_MESSAGE_FORMAT);
}

// Extension utility function tests
TEST_F(HelloRetryRequestTest, CookieExtensionUtilities) {
    // Test create_cookie_extension
    auto cookie_ext_result = create_cookie_extension(test_cookie);
    ASSERT_TRUE(cookie_ext_result.is_success());
    
    Extension cookie_ext = cookie_ext_result.value();
    EXPECT_EQ(cookie_ext.type, ExtensionType::COOKIE);
    EXPECT_EQ(cookie_ext.data.size(), 2 + test_cookie.size());
    
    // Test extract_cookie_from_extension
    auto extracted_cookie_result = extract_cookie_from_extension(cookie_ext);
    ASSERT_TRUE(extracted_cookie_result.is_success());
    
    Buffer extracted_cookie = extracted_cookie_result.value();
    EXPECT_EQ(extracted_cookie.size(), test_cookie.size());
    EXPECT_EQ(std::memcmp(extracted_cookie.data(), test_cookie.data(), test_cookie.size()), 0);
}

TEST_F(HelloRetryRequestTest, KeyShareExtensionUtilities) {
    // Test create_key_share_hello_retry_request_extension
    auto key_share_ext_result = create_key_share_hello_retry_request_extension(selected_group);
    ASSERT_TRUE(key_share_ext_result.is_success());
    
    Extension key_share_ext = key_share_ext_result.value();
    EXPECT_EQ(key_share_ext.type, ExtensionType::KEY_SHARE);
    EXPECT_EQ(key_share_ext.data.size(), 2);
    
    // Test extract_selected_group_from_extension
    auto extracted_group_result = extract_selected_group_from_extension(key_share_ext);
    ASSERT_TRUE(extracted_group_result.is_success());
    
    EXPECT_EQ(extracted_group_result.value(), selected_group);
}

TEST_F(HelloRetryRequestTest, HandshakeMessageIntegration) {
    HelloRetryRequest hrr;
    hrr.set_cookie(test_cookie);
    hrr.set_selected_group(NamedGroup::SECP521R1);
    
    // Create HandshakeMessage
    HandshakeMessage handshake_msg(hrr, 42);
    
    // Check message type
    EXPECT_EQ(handshake_msg.message_type(), HandshakeType::HELLO_RETRY_REQUEST);
    EXPECT_TRUE(handshake_msg.holds<HelloRetryRequest>());
    
    // Check the contained message
    const HelloRetryRequest& contained_hrr = handshake_msg.get<HelloRetryRequest>();
    EXPECT_TRUE(contained_hrr.is_valid());
    EXPECT_TRUE(contained_hrr.has_extension(ExtensionType::COOKIE));
    EXPECT_TRUE(contained_hrr.has_extension(ExtensionType::KEY_SHARE));
    
    // Test serialization of HandshakeMessage
    Buffer handshake_serialized;
    auto serialize_result = handshake_msg.serialize(handshake_serialized);
    EXPECT_TRUE(serialize_result.is_success());
    
    // Test deserialization of HandshakeMessage
    auto deserialize_result = HandshakeMessage::deserialize(handshake_serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    HandshakeMessage deserialized_msg = deserialize_result.value();
    EXPECT_EQ(deserialized_msg.message_type(), HandshakeType::HELLO_RETRY_REQUEST);
    EXPECT_TRUE(deserialized_msg.holds<HelloRetryRequest>());
}

// Performance Tests
TEST_F(HelloRetryRequestTest, SerializationPerformance) {
    const int iterations = 1000;
    HelloRetryRequest hrr;
    hrr.set_cookie(test_cookie);
    hrr.set_selected_group(NamedGroup::SECP256R1);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        Buffer output;
        auto result = hrr.serialize(output);
        EXPECT_TRUE(result.is_success());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should be reasonably fast (less than 1ms per operation on average)
    EXPECT_LT(duration.count() / iterations, 1000);
    
    std::cout << "Average HelloRetryRequest serialization time: " 
              << (duration.count() / iterations) << " microseconds" << std::endl;
}

TEST_F(HelloRetryRequestTest, MaximumExtensions) {
    HelloRetryRequest hrr;
    hrr.set_cookie(test_cookie); // Required
    
    // Add multiple extensions to test extension handling
    hrr.set_selected_group(NamedGroup::SECP256R1);
    
    // Create a supported_versions extension manually and add it
    std::vector<ProtocolVersion> versions = {ProtocolVersion::DTLS_1_3};
    auto supported_versions_ext = create_supported_versions_extension(versions);
    if (supported_versions_ext.is_success()) {
        hrr.add_extension(std::move(supported_versions_ext.value()));
    }
    
    // Should still be valid
    EXPECT_TRUE(hrr.is_valid());
    
    // Should serialize and deserialize correctly
    Buffer serialized;
    auto serialize_result = hrr.serialize(serialized);
    ASSERT_TRUE(serialize_result.is_success());
    
    auto deserialize_result = HelloRetryRequest::deserialize(serialized);
    ASSERT_TRUE(deserialize_result.is_success());
    
    HelloRetryRequest deserialized = deserialize_result.value();
    EXPECT_TRUE(deserialized.is_valid());
    EXPECT_TRUE(deserialized.has_extension(ExtensionType::COOKIE));
    EXPECT_TRUE(deserialized.has_extension(ExtensionType::KEY_SHARE));
    EXPECT_TRUE(deserialized.has_extension(ExtensionType::SUPPORTED_VERSIONS));
}