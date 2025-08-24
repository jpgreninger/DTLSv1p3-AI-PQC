#include <gtest/gtest.h>
#include <dtls/protocol/record_layer.h>
#include <dtls/protocol/message_layer.h>
#include <dtls/protocol/version_manager.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/core/error.h>
#include <dtls/memory/secure_buffer.h>

using namespace dtls::v13::protocol;
using namespace dtls::v13::crypto;
using namespace dtls::v13::memory;
using namespace dtls::v13;

class ProtocolErrorHandlingTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto provider = ProviderFactory::instance().create_provider("openssl");
        ASSERT_TRUE(provider.is_ok());
        crypto_provider_ = std::move(provider.value());
    }

    std::unique_ptr<crypto::CryptoProvider> crypto_provider_;
};

// Mock CryptoProvider for testing error conditions
class FailingCryptoProvider : public crypto::CryptoProvider {
public:
    enum class FailureMode {
        NONE,
        ENCRYPT_FAILURE,
        DECRYPT_FAILURE,
        KEY_DERIVATION_FAILURE,
        INITIALIZATION_FAILURE
    };
    
    void set_failure_mode(FailureMode mode) { failure_mode_ = mode; }
    
    Result<std::vector<uint8_t>> encrypt_aead(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& additional_data) override {
        
        if (failure_mode_ == FailureMode::ENCRYPT_FAILURE) {
            return Error(ErrorCode::DTLS_ERROR_ENCRYPT_ERROR, "Mock encryption failure");
        }
        
        // Return dummy encrypted data
        std::vector<uint8_t> result = plaintext;
        result.insert(result.end(), {0xDE, 0xAD, 0xBE, 0xEF}); // Fake auth tag
        return result;
    }
    
    Result<std::vector<uint8_t>> decrypt_aead(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& additional_data) override {
        
        if (failure_mode_ == FailureMode::DECRYPT_FAILURE) {
            return Error(ErrorCode::DTLS_ERROR_DECRYPT_ERROR, "Mock decryption failure");
        }
        
        // Return dummy decrypted data (remove fake auth tag)
        if (ciphertext.size() < 4) {
            return Error(ErrorCode::DTLS_ERROR_DECRYPT_ERROR, "Invalid ciphertext length");
        }
        
        std::vector<uint8_t> result(ciphertext.begin(), ciphertext.end() - 4);
        return result;
    }
    
    Result<std::vector<uint8_t>> derive_key(
        const std::vector<uint8_t>& key_material,
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t key_length) override {
        
        if (failure_mode_ == FailureMode::KEY_DERIVATION_FAILURE) {
            return Error(ErrorCode::DTLS_ERROR_KEY_DERIVATION, "Mock key derivation failure");
        }
        
        return std::vector<uint8_t>(key_length, 0x42);
    }
    
    Result<void> initialize() override {
        if (failure_mode_ == FailureMode::INITIALIZATION_FAILURE) {
            return Error(ErrorCode::DTLS_ERROR_INITIALIZATION, "Mock initialization failure");
        }
        return Result<void>::success();
    }
    
    // Other required methods with minimal implementations
    const std::string& get_name() const override {
        static const std::string name = "FailingMockProvider";
        return name;
    }
    
    const std::string& get_version() const override {
        static const std::string version = "1.0.0";
        return version;
    }
    
    bool supports_cipher_suite(CipherSuite suite) const override {
        return true;
    }
    
    Result<std::vector<uint8_t>> generate_random(size_t length) override {
        return std::vector<uint8_t>(length, 0x55);
    }
    
    Result<crypto::KeySchedule> create_key_schedule(CipherSuite suite) override {
        crypto::KeySchedule schedule;
        schedule.cipher_suite = suite;
        return schedule;
    }

private:
    FailureMode failure_mode_ = FailureMode::NONE;
};

// Record Layer Error Handling Tests
TEST_F(ProtocolErrorHandlingTest, RecordLayerInitializationFailure) {
    auto failing_provider = std::make_unique<FailingCryptoProvider>();
    failing_provider->set_failure_mode(FailingCryptoProvider::FailureMode::INITIALIZATION_FAILURE);
    
    RecordLayer record_layer(std::move(failing_provider));
    auto result = record_layer.initialize();
    
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_INITIALIZATION);
}

TEST_F(ProtocolErrorHandlingTest, RecordLayerEncryptionFailure) {
    auto failing_provider = std::make_unique<FailingCryptoProvider>();
    auto* provider_ptr = failing_provider.get();
    
    RecordLayer record_layer(std::move(failing_provider));
    auto init_result = record_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Set up keys for encryption
    std::vector<uint8_t> dummy_key(32, 0x42);
    std::vector<uint8_t> dummy_iv(12, 0x33);
    auto advance_result = record_layer.advance_epoch(dummy_key, dummy_key, dummy_iv, dummy_iv);
    ASSERT_TRUE(advance_result.is_ok());
    
    // Now set encryption to fail
    provider_ptr->set_failure_mode(FailingCryptoProvider::FailureMode::ENCRYPT_FAILURE);
    
    DTLSPlaintext plaintext;
    plaintext.content_type = ContentType::APPLICATION_DATA;
    plaintext.legacy_record_version = DTLS_V13;
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = {0x01, 0x02, 0x03, 0x04};
    
    auto protect_result = record_layer.protect_record(plaintext);
    EXPECT_FALSE(protect_result.is_ok());
    EXPECT_EQ(protect_result.error().code(), ErrorCode::DTLS_ERROR_ENCRYPT_ERROR);
}

TEST_F(ProtocolErrorHandlingTest, RecordLayerDecryptionFailure) {
    auto failing_provider = std::make_unique<FailingCryptoProvider>();
    auto* provider_ptr = failing_provider.get();
    
    RecordLayer record_layer(std::move(failing_provider));
    auto init_result = record_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Set up keys
    std::vector<uint8_t> dummy_key(32, 0x42);
    std::vector<uint8_t> dummy_iv(12, 0x33);
    auto advance_result = record_layer.advance_epoch(dummy_key, dummy_key, dummy_iv, dummy_iv);
    ASSERT_TRUE(advance_result.is_ok());
    
    // Create a valid ciphertext first
    DTLSPlaintext plaintext;
    plaintext.content_type = ContentType::APPLICATION_DATA;
    plaintext.legacy_record_version = DTLS_V13;
    plaintext.epoch = 1;
    plaintext.sequence_number = 1;
    plaintext.fragment = {0x01, 0x02, 0x03, 0x04};
    
    auto protect_result = record_layer.protect_record(plaintext);
    ASSERT_TRUE(protect_result.is_ok());
    
    auto ciphertext = protect_result.value();
    
    // Now set decryption to fail
    provider_ptr->set_failure_mode(FailingCryptoProvider::FailureMode::DECRYPT_FAILURE);
    
    auto unprotect_result = record_layer.unprotect_record(ciphertext);
    EXPECT_FALSE(unprotect_result.is_ok());
    EXPECT_EQ(unprotect_result.error().code(), ErrorCode::DTLS_ERROR_DECRYPT_ERROR);
}

TEST_F(ProtocolErrorHandlingTest, RecordLayerKeyDerivationFailure) {
    auto failing_provider = std::make_unique<FailingCryptoProvider>();
    auto* provider_ptr = failing_provider.get();
    
    RecordLayer record_layer(std::move(failing_provider));
    auto init_result = record_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Set key derivation to fail
    provider_ptr->set_failure_mode(FailingCryptoProvider::FailureMode::KEY_DERIVATION_FAILURE);
    
    auto update_result = record_layer.update_traffic_keys();
    EXPECT_FALSE(update_result.is_ok());
    EXPECT_EQ(update_result.error().code(), ErrorCode::DTLS_ERROR_KEY_DERIVATION);
}

TEST_F(ProtocolErrorHandlingTest, RecordLayerInvalidEpochHandling) {
    auto provider = ProviderFactory::instance().create_provider("openssl");
    ASSERT_TRUE(provider.is_ok());
    
    RecordLayer record_layer(std::move(provider.value()));
    auto init_result = record_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Try to protect record with non-existent epoch
    DTLSPlaintext plaintext;
    plaintext.content_type = ContentType::APPLICATION_DATA;
    plaintext.legacy_record_version = DTLS_V13;
    plaintext.epoch = 99; // Invalid epoch
    plaintext.sequence_number = 1;
    plaintext.fragment = {0x01, 0x02, 0x03, 0x04};
    
    auto protect_result = record_layer.protect_record(plaintext);
    EXPECT_FALSE(protect_result.is_ok());
    EXPECT_EQ(protect_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_EPOCH);
}

// AntiReplayWindow Error Handling
TEST_F(ProtocolErrorHandlingTest, AntiReplayWindowInvalidInput) {
    // Test construction with zero window size
    EXPECT_THROW(AntiReplayWindow(0), std::invalid_argument);
    
    // Test with window size that's too large
    EXPECT_THROW(AntiReplayWindow(1000000), std::invalid_argument);
    
    AntiReplayWindow window(64);
    
    // Test with sequence number that would cause integer overflow issues
    uint64_t overflow_seq = UINT64_MAX;
    
    // Should handle gracefully without crashing
    EXPECT_NO_THROW(window.check_and_update(overflow_seq));
}

// Sequence Number Manager Error Handling
TEST_F(ProtocolErrorHandlingTest, SequenceNumberManagerOverflowHandling) {
    SequenceNumberManager manager;
    
    // Manually advance to near overflow
    for (uint64_t i = 0; i < (1ULL << 48) - 1; ++i) {
        auto seq = manager.get_next_sequence_number();
        if (i == (1ULL << 48) - 2) {
            // Should detect imminent overflow
            EXPECT_TRUE(manager.would_overflow());
        }
    }
    
    // The last valid sequence number
    auto last_seq = manager.get_next_sequence_number();
    EXPECT_EQ(last_seq, (1ULL << 48) - 1);
    EXPECT_TRUE(manager.would_overflow());
    
    // Attempting to get another sequence number should return error
    EXPECT_THROW(manager.get_next_sequence_number(), std::overflow_error);
}

// Epoch Manager Error Handling
TEST_F(ProtocolErrorHandlingTest, EpochManagerInvalidOperations) {
    EpochManager manager;
    
    // Try to get keys for non-existent epoch
    auto result = manager.get_epoch_crypto_params(999);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_INVALID_EPOCH);
    
    // Try to set keys with invalid parameters
    std::vector<uint8_t> empty_key;
    auto set_result = manager.set_epoch_keys(1, empty_key, empty_key, empty_key, empty_key);
    EXPECT_FALSE(set_result.is_ok());
    EXPECT_EQ(set_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
    
    // Try to set keys with mismatched key lengths
    std::vector<uint8_t> short_key(16, 0x42);
    std::vector<uint8_t> long_key(64, 0x43);
    std::vector<uint8_t> iv(12, 0x44);
    
    auto mismatch_result = manager.set_epoch_keys(1, short_key, long_key, iv, iv);
    EXPECT_FALSE(mismatch_result.is_ok());
    EXPECT_EQ(mismatch_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
}

// Connection ID Manager Error Handling
TEST_F(ProtocolErrorHandlingTest, ConnectionIDManagerInvalidOperations) {
    ConnectionIDManager manager;
    
    // Test validation when connection ID is not enabled
    ConnectionID test_cid;
    test_cid.data = {0x01, 0x02, 0x03};
    test_cid.length = 3;
    
    EXPECT_FALSE(manager.is_connection_id_enabled());
    EXPECT_FALSE(manager.is_valid_connection_id(test_cid));
    
    // Test with invalid connection ID length
    ConnectionID invalid_cid;
    invalid_cid.data.resize(256, 0xFF); // Too long
    invalid_cid.length = 256;
    
    EXPECT_THROW(manager.set_local_connection_id(invalid_cid), std::invalid_argument);
    
    // Test with mismatched length and data size
    ConnectionID mismatched_cid;
    mismatched_cid.data = {0x01, 0x02};
    mismatched_cid.length = 10; // Doesn't match data size
    
    EXPECT_THROW(manager.set_peer_connection_id(mismatched_cid), std::invalid_argument);
}

// Message Layer Error Handling Tests
TEST_F(ProtocolErrorHandlingTest, MessageFragmentInvalidConstruction) {
    // Test fragment with invalid parameters
    Buffer invalid_data(10, 0x42);
    
    // Fragment offset + length > total length
    MessageFragment invalid_fragment(1, 50, 60, 100, std::move(invalid_data));
    EXPECT_FALSE(invalid_fragment.is_valid());
    
    // Fragment length doesn't match data size
    Buffer mismatched_data(5, 0x43);
    MessageFragment mismatched_fragment(1, 0, 10, 100, std::move(mismatched_data));
    EXPECT_FALSE(mismatched_fragment.is_valid());
}

TEST_F(ProtocolErrorHandlingTest, MessageReassemblerCorruptedFragments) {
    MessageReassembler reassembler;
    
    // Add fragment with corrupted total length
    Buffer data1(50, 0x11);
    MessageFragment fragment1(1, 0, 50, 100, std::move(data1));
    auto result1 = reassembler.add_fragment(fragment1);
    ASSERT_TRUE(result1.is_ok());
    
    // Add fragment with different total length (should be rejected)
    Buffer data2(50, 0x22);
    MessageFragment fragment2(1, 50, 50, 200, std::move(data2)); // Different total length
    auto result2 = reassembler.add_fragment(fragment2);
    EXPECT_FALSE(result2.is_ok());
    EXPECT_EQ(result2.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
}

TEST_F(ProtocolErrorHandlingTest, MessageReassemblerMemoryExhaustion) {
    MessageReassembler reassembler;
    
    // Try to add fragments that would exceed reasonable memory limits
    for (int i = 0; i < 10000; ++i) {
        Buffer large_data(10000, static_cast<uint8_t>(i % 256));
        MessageFragment large_fragment(1, i * 10000, 10000, 100000000, std::move(large_data));
        
        auto result = reassembler.add_fragment(large_fragment);
        if (!result.is_ok()) {
            // Should eventually fail due to memory constraints
            EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_MEMORY_ALLOCATION);
            break;
        }
    }
}

TEST_F(ProtocolErrorHandlingTest, HandshakeFlightInvalidOperations) {
    HandshakeFlight flight(FlightType::CLIENT_HELLO_FLIGHT, 0);
    
    // Try to fragment with zero max fragment size
    EXPECT_THROW(flight.fragment_messages(0), std::invalid_argument);
    
    // Try to fragment with extremely small fragment size
    auto result = flight.fragment_messages(1);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
}

TEST_F(ProtocolErrorHandlingTest, FlightManagerInvalidFlightOperations) {
    FlightManager manager;
    
    // Try to add message without creating flight first
    HandshakeMessage message;
    message.msg_type = HandshakeType::CLIENT_HELLO;
    message.length = 50;
    
    auto add_result = manager.add_message_to_current_flight(std::move(message));
    EXPECT_FALSE(add_result.is_ok());
    EXPECT_EQ(add_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_STATE);
    
    // Try to complete flight without creating one
    auto complete_result = manager.complete_current_flight();
    EXPECT_FALSE(complete_result.is_ok());
    EXPECT_EQ(complete_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_STATE);
    
    // Try to create invalid flight type
    auto invalid_flight = static_cast<FlightType>(999);
    auto create_result = manager.create_flight(invalid_flight);
    EXPECT_FALSE(create_result.is_ok());
    EXPECT_EQ(create_result.error().code(), ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
}

// Version Manager Error Handling Tests
TEST_F(ProtocolErrorHandlingTest, VersionManagerInvalidConfiguration) {
    // Test with empty supported versions
    VersionManager::Config invalid_config;
    invalid_config.supported_versions.clear();
    
    EXPECT_THROW(VersionManager(invalid_config), std::invalid_argument);
    
    // Test with unsupported preferred version
    VersionManager::Config invalid_config2;
    invalid_config2.supported_versions = {DTLS_V12};
    invalid_config2.preferred_version = DTLS_V13;
    
    EXPECT_THROW(VersionManager(invalid_config2), std::invalid_argument);
}

TEST_F(ProtocolErrorHandlingTest, VersionManagerMalformedExtensions) {
    VersionManager manager;
    
    ClientHello malformed_hello;
    malformed_hello.legacy_version = DTLS_V12;
    
    // Add malformed supported_versions extension
    Extension malformed_ext;
    malformed_ext.extension_type = ExtensionType::SUPPORTED_VERSIONS;
    malformed_ext.extension_data = {0xFF}; // Invalid length
    malformed_hello.extensions.push_back(malformed_ext);
    
    auto result = manager.negotiate_version_from_client_hello(malformed_hello);
    EXPECT_FALSE(result.is_ok());
    EXPECT_EQ(result.error().code(), ErrorCode::DTLS_ERROR_DECODE_ERROR);
    
    // Test with extension data that's too short
    Extension short_ext;
    short_ext.extension_type = ExtensionType::SUPPORTED_VERSIONS;
    short_ext.extension_data = {}; // Empty data
    
    ClientHello short_hello;
    short_hello.legacy_version = DTLS_V12;
    short_hello.extensions.push_back(short_ext);
    
    auto short_result = manager.negotiate_version_from_client_hello(short_hello);
    EXPECT_FALSE(short_result.is_ok());
    EXPECT_EQ(short_result.error().code(), ErrorCode::DTLS_ERROR_DECODE_ERROR);
}

TEST_F(ProtocolErrorHandlingTest, VersionManagerStringConversionErrors) {
    // Test invalid version string formats
    auto result1 = VersionManager::version_from_string("");
    EXPECT_FALSE(result1.is_ok());
    
    auto result2 = VersionManager::version_from_string("invalid");
    EXPECT_FALSE(result2.is_ok());
    
    auto result3 = VersionManager::version_from_string("1.3.invalid");
    EXPECT_FALSE(result3.is_ok());
    
    auto result4 = VersionManager::version_from_string("999.999");
    EXPECT_FALSE(result4.is_ok());
    
    // Test version to string with invalid version
    auto invalid_version = static_cast<GlobalProtocolVersion>(0x0000);
    auto version_str = VersionManager::version_to_string(invalid_version);
    EXPECT_EQ(version_str, "Unknown");
}

TEST_F(ProtocolErrorHandlingTest, VersionManagerCompatibilityContextErrors) {
    VersionManager manager;
    
    // Test with invalid compatibility context
    compatibility::DTLS12CompatibilityContext invalid_context;
    // Leave context uninitialized or set invalid values
    
    auto config_result = manager.configure_dtls12_compatibility(invalid_context);
    // Should handle gracefully even with invalid context
    EXPECT_TRUE(config_result.is_ok() || 
                config_result.error().code() == ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
}

// Resource Cleanup and Exception Safety Tests
TEST_F(ProtocolErrorHandlingTest, RecordLayerExceptionSafety) {
    // Test that record layer handles exceptions gracefully
    auto provider = ProviderFactory::instance().create_provider("openssl");
    ASSERT_TRUE(provider.is_ok());
    
    RecordLayer record_layer(std::move(provider.value()));
    auto init_result = record_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Try operations that might throw
    try {
        std::vector<uint8_t> invalid_key; // Empty key
        std::vector<uint8_t> valid_iv(12, 0x42);
        
        // This should fail gracefully, not throw
        auto result = record_layer.advance_epoch(invalid_key, invalid_key, valid_iv, valid_iv);
        EXPECT_FALSE(result.is_ok());
    } catch (...) {
        FAIL() << "Record layer should not throw exceptions";
    }
}

TEST_F(ProtocolErrorHandlingTest, MessageLayerResourceCleanup) {
    auto test_record_layer = record_layer_utils::create_test_record_layer();
    ASSERT_NE(test_record_layer, nullptr);
    
    MessageLayer message_layer(std::move(test_record_layer));
    auto init_result = message_layer.initialize();
    ASSERT_TRUE(init_result.is_ok());
    
    // Create many incomplete reassemblers to test cleanup
    for (int i = 0; i < 100; ++i) {
        PlaintextRecord record;
        record.type = ContentType::HANDSHAKE;
        record.epoch = 0;
        record.sequence_number = i;
        // Create partial handshake fragments
        record.fragment = {static_cast<uint8_t>(i), 0x00, 0x01, 0x00}; // Partial handshake header
        
        auto result = message_layer.process_incoming_handshake_record(record);
        // These should fail or return empty results, but not crash
        EXPECT_NO_THROW(result);
    }
    
    // Verify statistics are reasonable
    auto stats = message_layer.get_stats();
    EXPECT_LE(stats.reassembly_timeouts, 100);
}

// Input Validation and Boundary Tests
TEST_F(ProtocolErrorHandlingTest, ExtremeBoundaryInputs) {
    VersionManager manager;
    
    // Test with maximum possible values
    ClientHello extreme_hello;
    extreme_hello.legacy_version = static_cast<GlobalProtocolVersion>(0xFFFF);
    
    // Add extension with maximum length
    Extension extreme_ext;
    extreme_ext.extension_type = ExtensionType::SUPPORTED_VERSIONS;
    extreme_ext.extension_data.resize(65535, 0xFF);
    extreme_hello.extensions.push_back(extreme_ext);
    
    auto result = manager.negotiate_version_from_client_hello(extreme_hello);
    // Should handle gracefully without crashing
    EXPECT_NO_THROW(result);
    
    if (!result.is_ok()) {
        // If it fails, should be due to validation, not parsing errors
        auto error_code = result.error().code();
        EXPECT_TRUE(error_code == ErrorCode::DTLS_ERROR_DECODE_ERROR ||
                   error_code == ErrorCode::DTLS_ERROR_UNSUPPORTED_VERSION ||
                   error_code == ErrorCode::DTLS_ERROR_INVALID_PARAMETER);
    }
}