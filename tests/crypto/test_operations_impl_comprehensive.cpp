/**
 * @file test_operations_impl_comprehensive.cpp
 * @brief Comprehensive tests for DTLS CryptoOperationsImpl implementation
 * 
 * This test suite covers all functionality in operations_impl.cpp to achieve >95% coverage.
 * Tests include all crypto operations, error handling, provider management, and edge cases.
 * Target: Cover all 1,044 lines of operations_impl.cpp for dramatic coverage improvement.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>
#include <random>

#include "dtls/crypto/operations_impl.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class CryptoOperationsImplTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto system if not already done
        if (!crypto::is_crypto_system_initialized()) {
            auto init_result = crypto::initialize_crypto_system();
            ASSERT_TRUE(init_result.is_success()) << "Failed to initialize crypto system";
        }
        
        // Clear any existing providers and register test providers
        auto& factory = ProviderFactory::instance();
        auto refresh_result = factory.refresh_availability();
        EXPECT_TRUE(refresh_result.is_success());
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    // Helper to create test keys
    std::vector<uint8_t> create_test_key(size_t length = 32) {
        std::vector<uint8_t> key(length);
        std::iota(key.begin(), key.end(), 0);
        return key;
    }
    
    // Helper to create test data
    std::vector<uint8_t> create_test_data(size_t length = 256) {
        std::vector<uint8_t> data(length);
        for (size_t i = 0; i < length; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        return data;
    }
    
    // Helper to verify random data quality
    bool verify_random_quality(const std::vector<uint8_t>& data) {
        if (data.size() < 32) return false;
        
        // Check for obvious patterns
        bool all_same = std::all_of(data.begin(), data.end(), 
            [&](uint8_t val) { return val == data[0]; });
        if (all_same) return false;
        
        // Basic entropy check
        std::unordered_set<uint8_t> unique_bytes(data.begin(), data.end());
        return unique_bytes.size() > data.size() / 4; // At least 25% unique
    }
};

// ==================== Constructor Tests ====================

TEST_F(CryptoOperationsImplTest, ConstructorWithValidProvider) {
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_default_provider();
    ASSERT_TRUE(provider_result.is_success());
    
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>(
        std::move(provider_result.value()));
    
    EXPECT_TRUE(crypto_ops->is_initialized());
    EXPECT_FALSE(crypto_ops->provider_name().empty());
}

TEST_F(CryptoOperationsImplTest, ConstructorWithNullProvider) {
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>(nullptr);
    EXPECT_FALSE(crypto_ops->is_initialized());
}

TEST_F(CryptoOperationsImplTest, ConstructorWithProviderName) {
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>("openssl");
    EXPECT_TRUE(crypto_ops->is_initialized());
    EXPECT_EQ(crypto_ops->provider_name(), "openssl");
}

TEST_F(CryptoOperationsImplTest, ConstructorWithInvalidProviderName) {
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>("invalid_provider");
    EXPECT_FALSE(crypto_ops->is_initialized());
}

TEST_F(CryptoOperationsImplTest, ConstructorWithEmptyProviderName) {
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>("");
    // Should use default provider
    EXPECT_TRUE(crypto_ops->is_initialized());
}

TEST_F(CryptoOperationsImplTest, ConstructorWithProviderSelection) {
    ProviderSelection criteria;
    criteria.preferred_provider = "openssl";
    criteria.require_hardware_acceleration = false;
    criteria.minimum_security_level = SecurityLevel::STANDARD;
    
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>(criteria);
    EXPECT_TRUE(crypto_ops->is_initialized());
}

TEST_F(CryptoOperationsImplTest, ConstructorWithStrictProviderSelection) {
    ProviderSelection criteria;
    criteria.preferred_provider = "nonexistent";
    criteria.require_hardware_acceleration = true;
    criteria.minimum_security_level = SecurityLevel::HIGH;
    
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>(criteria);
    // May or may not initialize depending on available providers
}

// ==================== Move Semantics Tests ====================

TEST_F(CryptoOperationsImplTest, MoveConstructor) {
    auto crypto_ops1 = std::make_unique<CryptoOperationsImpl>("openssl");
    ASSERT_TRUE(crypto_ops1->is_initialized());
    
    std::string original_provider = crypto_ops1->provider_name();
    
    auto crypto_ops2 = std::make_unique<CryptoOperationsImpl>(std::move(*crypto_ops1));
    
    EXPECT_TRUE(crypto_ops2->is_initialized());
    EXPECT_EQ(crypto_ops2->provider_name(), original_provider);
    EXPECT_FALSE(crypto_ops1->is_initialized()); // Moved-from object
}

TEST_F(CryptoOperationsImplTest, MoveAssignment) {
    auto crypto_ops1 = std::make_unique<CryptoOperationsImpl>("openssl");
    auto crypto_ops2 = std::make_unique<CryptoOperationsImpl>("openssl");
    
    ASSERT_TRUE(crypto_ops1->is_initialized());
    ASSERT_TRUE(crypto_ops2->is_initialized());
    
    std::string original_provider = crypto_ops1->provider_name();
    
    *crypto_ops2 = std::move(*crypto_ops1);
    
    EXPECT_TRUE(crypto_ops2->is_initialized());
    EXPECT_EQ(crypto_ops2->provider_name(), original_provider);
    EXPECT_FALSE(crypto_ops1->is_initialized()); // Moved-from object
}

TEST_F(CryptoOperationsImplTest, SelfMoveAssignment) {
    auto crypto_ops = std::make_unique<CryptoOperationsImpl>("openssl");
    ASSERT_TRUE(crypto_ops->is_initialized());
    
    std::string original_provider = crypto_ops->provider_name();
    
    // Self-assignment should be safe
    *crypto_ops = std::move(*crypto_ops);
    
    EXPECT_TRUE(crypto_ops->is_initialized());
    EXPECT_EQ(crypto_ops->provider_name(), original_provider);
}

// ==================== Random Number Generation Tests ====================

TEST_F(CryptoOperationsImplTest, GenerateRandomBasic) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_random(32);
    ASSERT_TRUE(result.is_success());
    
    const auto& random_data = result.value();
    EXPECT_EQ(random_data.size(), 32);
    EXPECT_TRUE(verify_random_quality(random_data));
}

TEST_F(CryptoOperationsImplTest, GenerateRandomWithAdditionalEntropy) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    std::vector<uint8_t> entropy = {0x01, 0x02, 0x03, 0x04};
    auto result = crypto_ops.generate_random(32, entropy);
    ASSERT_TRUE(result.is_success());
    
    const auto& random_data = result.value();
    EXPECT_EQ(random_data.size(), 32);
    EXPECT_TRUE(verify_random_quality(random_data));
}

TEST_F(CryptoOperationsImplTest, GenerateRandomZeroLength) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_random(0);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value().size(), 0);
}

TEST_F(CryptoOperationsImplTest, GenerateRandomLargeSize) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_random(1024);
    ASSERT_TRUE(result.is_success());
    
    const auto& random_data = result.value();
    EXPECT_EQ(random_data.size(), 1024);
    EXPECT_TRUE(verify_random_quality(random_data));
}

TEST_F(CryptoOperationsImplTest, GenerateRandomUninitializedProvider) {
    CryptoOperationsImpl crypto_ops(nullptr);
    ASSERT_FALSE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_random(32);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
}

TEST_F(CryptoOperationsImplTest, GenerateDTLSRandom) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_dtls_random();
    ASSERT_TRUE(result.is_success());
    
    const auto& dtls_random = result.value();
    EXPECT_EQ(dtls_random.size(), 32);
    
    // Verify it's not all zeros
    bool all_zero = std::all_of(dtls_random.begin(), dtls_random.end(),
        [](uint8_t val) { return val == 0; });
    EXPECT_FALSE(all_zero);
}

TEST_F(CryptoOperationsImplTest, GenerateSessionId) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_session_id(32);
    ASSERT_TRUE(result.is_success());
    
    const auto& session_id = result.value();
    EXPECT_EQ(session_id.size(), 32);
    EXPECT_TRUE(verify_random_quality(session_id));
}

TEST_F(CryptoOperationsImplTest, GenerateSessionIdDefaultLength) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_session_id();
    ASSERT_TRUE(result.is_success());
    
    const auto& session_id = result.value();
    EXPECT_EQ(session_id.size(), 32); // Default length
}

TEST_F(CryptoOperationsImplTest, GenerateConnectionId) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_connection_id(8);
    ASSERT_TRUE(result.is_success());
    
    const auto& connection_id = result.value();
    EXPECT_EQ(connection_id.size(), 8);
}

TEST_F(CryptoOperationsImplTest, GenerateConnectionIdInvalidLength) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Test zero length
    auto result1 = crypto_ops.generate_connection_id(0);
    EXPECT_FALSE(result1.is_success());
    EXPECT_EQ(result1.error(), DTLSError::INVALID_PARAMETER);
    
    // Test too large length
    auto result2 = crypto_ops.generate_connection_id(256);
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(CryptoOperationsImplTest, GenerateConnectionIdMaxLength) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto result = crypto_ops.generate_connection_id(255);
    ASSERT_TRUE(result.is_success());
    
    const auto& connection_id = result.value();
    EXPECT_EQ(connection_id.size(), 255);
}

// ==================== Key Derivation Tests ====================

TEST_F(CryptoOperationsImplTest, HKDFExpandLabelBasic) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto secret = create_test_key(32);
    auto context = create_test_data(16);
    
    auto result = crypto_ops.hkdf_expand_label(secret, "test label", context, 32);
    ASSERT_TRUE(result.is_success());
    
    const auto& derived_key = result.value();
    EXPECT_EQ(derived_key.size(), 32);
    
    // Should be deterministic - same inputs produce same output
    auto result2 = crypto_ops.hkdf_expand_label(secret, "test label", context, 32);
    ASSERT_TRUE(result2.is_success());
    EXPECT_EQ(derived_key, result2.value());
}

TEST_F(CryptoOperationsImplTest, HKDFExpandLabelDifferentHashAlgorithms) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto secret = create_test_key(32);
    auto context = create_test_data(16);
    
    auto result_sha256 = crypto_ops.hkdf_expand_label(
        secret, "test", context, 32, HashAlgorithm::SHA256);
    auto result_sha384 = crypto_ops.hkdf_expand_label(
        secret, "test", context, 32, HashAlgorithm::SHA384);
    
    ASSERT_TRUE(result_sha256.is_success());
    ASSERT_TRUE(result_sha384.is_success());
    
    // Different hash algorithms should produce different results
    EXPECT_NE(result_sha256.value(), result_sha384.value());
}

TEST_F(CryptoOperationsImplTest, HKDFExpandLabelEmptyContext) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto secret = create_test_key(32);
    std::vector<uint8_t> empty_context;
    
    auto result = crypto_ops.hkdf_expand_label(secret, "test label", empty_context, 32);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value().size(), 32);
}

TEST_F(CryptoOperationsImplTest, HKDFExpandLabelVariousLengths) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto secret = create_test_key(32);
    auto context = create_test_data(16);
    
    // Test various output lengths
    for (size_t length : {1, 16, 32, 48, 64, 128}) {
        auto result = crypto_ops.hkdf_expand_label(secret, "test", context, length);
        ASSERT_TRUE(result.is_success()) << "Failed for length " << length;
        EXPECT_EQ(result.value().size(), length);
    }
}

TEST_F(CryptoOperationsImplTest, DeriveTrafficKeys) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto master_secret = create_test_key(32);
    auto context = create_test_data(64);
    
    auto result = crypto_ops.derive_traffic_keys(
        master_secret, CipherSuite::TLS_AES_128_GCM_SHA256, context);
    
    ASSERT_TRUE(result.is_success());
    
    const auto& schedule = result.value();
    EXPECT_EQ(schedule.client_write_key.size(), 16);   // AES-128 key
    EXPECT_EQ(schedule.server_write_key.size(), 16);
    EXPECT_EQ(schedule.client_write_iv.size(), 12);    // GCM IV
    EXPECT_EQ(schedule.server_write_iv.size(), 12);
    EXPECT_EQ(schedule.client_sequence_number_key.size(), 16);
    EXPECT_EQ(schedule.server_sequence_number_key.size(), 16);
}

TEST_F(CryptoOperationsImplTest, DeriveTrafficKeysAES256) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto master_secret = create_test_key(48); // Larger secret for AES-256
    auto context = create_test_data(64);
    
    auto result = crypto_ops.derive_traffic_keys(
        master_secret, CipherSuite::TLS_AES_256_GCM_SHA384, context);
    
    ASSERT_TRUE(result.is_success());
    
    const auto& schedule = result.value();
    EXPECT_EQ(schedule.client_write_key.size(), 32);   // AES-256 key
    EXPECT_EQ(schedule.server_write_key.size(), 32);
    EXPECT_EQ(schedule.client_write_iv.size(), 12);    // GCM IV
    EXPECT_EQ(schedule.server_write_iv.size(), 12);
}

TEST_F(CryptoOperationsImplTest, DeriveTrafficKeysChaCha20) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto master_secret = create_test_key(32);
    auto context = create_test_data(64);
    
    auto result = crypto_ops.derive_traffic_keys(
        master_secret, CipherSuite::TLS_CHACHA20_POLY1305_SHA256, context);
    
    ASSERT_TRUE(result.is_success());
    
    const auto& schedule = result.value();
    EXPECT_EQ(schedule.client_write_key.size(), 32);   // ChaCha20 key
    EXPECT_EQ(schedule.server_write_key.size(), 32);
    EXPECT_EQ(schedule.client_write_iv.size(), 12);    // Poly1305 IV
    EXPECT_EQ(schedule.server_write_iv.size(), 12);
}

TEST_F(CryptoOperationsImplTest, DeriveTrafficKeysUnsupportedCipher) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto master_secret = create_test_key(32);
    auto context = create_test_data(64);
    
    // Use an invalid cipher suite
    auto result = crypto_ops.derive_traffic_keys(
        master_secret, static_cast<CipherSuite>(0xFFFF), context);
    
    EXPECT_FALSE(result.is_success());
}

// ==================== AEAD Encryption/Decryption Tests ====================

TEST_F(CryptoOperationsImplTest, AEADEncryptDecryptAES128GCM) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);  // AES-128 key
    auto nonce = create_test_key(12); // GCM nonce
    auto plaintext = create_test_data(256);
    auto aad = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& output = encrypt_result.value();
    EXPECT_EQ(output.ciphertext.size(), plaintext.size());
    EXPECT_EQ(output.tag.size(), 16); // GCM tag size
    EXPECT_NE(output.ciphertext, plaintext); // Should be different
    
    // Decrypt
    auto decrypt_result = crypto_ops.aead_decrypt(
        output.ciphertext, output.tag, key, nonce, aad, AEADCipher::AES_128_GCM);
    
    ASSERT_TRUE(decrypt_result.is_success());
    EXPECT_EQ(decrypt_result.value(), plaintext);
}

TEST_F(CryptoOperationsImplTest, AEADEncryptDecryptAES256GCM) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(32);  // AES-256 key
    auto nonce = create_test_key(12); // GCM nonce
    auto plaintext = create_test_data(256);
    auto aad = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::AES_256_GCM);
    
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& output = encrypt_result.value();
    EXPECT_EQ(output.ciphertext.size(), plaintext.size());
    EXPECT_EQ(output.tag.size(), 16); // GCM tag size
    
    // Decrypt
    auto decrypt_result = crypto_ops.aead_decrypt(
        output.ciphertext, output.tag, key, nonce, aad, AEADCipher::AES_256_GCM);
    
    ASSERT_TRUE(decrypt_result.is_success());
    EXPECT_EQ(decrypt_result.value(), plaintext);
}

TEST_F(CryptoOperationsImplTest, AEADEncryptDecryptChaCha20Poly1305) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(32);  // ChaCha20 key
    auto nonce = create_test_key(12); // Poly1305 nonce
    auto plaintext = create_test_data(256);
    auto aad = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::CHACHA20_POLY1305);
    
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& output = encrypt_result.value();
    EXPECT_EQ(output.ciphertext.size(), plaintext.size());
    EXPECT_EQ(output.tag.size(), 16); // Poly1305 tag size
    
    // Decrypt
    auto decrypt_result = crypto_ops.aead_decrypt(
        output.ciphertext, output.tag, key, nonce, aad, AEADCipher::CHACHA20_POLY1305);
    
    ASSERT_TRUE(decrypt_result.is_success());
    EXPECT_EQ(decrypt_result.value(), plaintext);
}

TEST_F(CryptoOperationsImplTest, AEADEncryptEmptyPlaintext) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);
    auto nonce = create_test_key(12);
    std::vector<uint8_t> empty_plaintext;
    auto aad = create_test_data(16);
    
    auto encrypt_result = crypto_ops.aead_encrypt(
        empty_plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& output = encrypt_result.value();
    EXPECT_EQ(output.ciphertext.size(), 0);
    EXPECT_EQ(output.tag.size(), 16);
}

TEST_F(CryptoOperationsImplTest, AEADDecryptWrongTag) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);
    auto nonce = create_test_key(12);
    auto plaintext = create_test_data(256);
    auto aad = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success());
    
    // Corrupt the tag
    auto corrupted_tag = encrypt_result.value().tag;
    corrupted_tag[0] ^= 0xFF;
    
    // Decrypt with corrupted tag should fail
    auto decrypt_result = crypto_ops.aead_decrypt(
        encrypt_result.value().ciphertext, corrupted_tag, key, nonce, aad, 
        AEADCipher::AES_128_GCM);
    
    EXPECT_FALSE(decrypt_result.is_success());
}

TEST_F(CryptoOperationsImplTest, AEADDecryptWrongAAD) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);
    auto nonce = create_test_key(12);
    auto plaintext = create_test_data(256);
    auto aad = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success());
    
    // Use different AAD for decryption
    auto wrong_aad = create_test_data(16);
    wrong_aad[0] ^= 0xFF;
    
    auto decrypt_result = crypto_ops.aead_decrypt(
        encrypt_result.value().ciphertext, encrypt_result.value().tag, 
        key, nonce, wrong_aad, AEADCipher::AES_128_GCM);
    
    EXPECT_FALSE(decrypt_result.is_success());
}

// ==================== Hash and HMAC Tests ====================

TEST_F(CryptoOperationsImplTest, ComputeHashSHA256) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto data = create_test_data(256);
    
    auto result = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& hash = result.value();
    EXPECT_EQ(hash.size(), 32); // SHA-256 produces 32 bytes
    
    // Should be deterministic
    auto result2 = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result2.is_success());
    EXPECT_EQ(hash, result2.value());
}

TEST_F(CryptoOperationsImplTest, ComputeHashSHA384) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto data = create_test_data(256);
    
    auto result = crypto_ops.compute_hash(data, HashAlgorithm::SHA384);
    ASSERT_TRUE(result.is_success());
    
    const auto& hash = result.value();
    EXPECT_EQ(hash.size(), 48); // SHA-384 produces 48 bytes
}

TEST_F(CryptoOperationsImplTest, ComputeHashSHA512) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto data = create_test_data(256);
    
    auto result = crypto_ops.compute_hash(data, HashAlgorithm::SHA512);
    ASSERT_TRUE(result.is_success());
    
    const auto& hash = result.value();
    EXPECT_EQ(hash.size(), 64); // SHA-512 produces 64 bytes
}

TEST_F(CryptoOperationsImplTest, ComputeHashEmptyData) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    std::vector<uint8_t> empty_data;
    
    auto result = crypto_ops.compute_hash(empty_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& hash = result.value();
    EXPECT_EQ(hash.size(), 32);
    
    // Known SHA-256 hash of empty string
    std::vector<uint8_t> expected_empty_hash = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    EXPECT_EQ(hash, expected_empty_hash);
}

TEST_F(CryptoOperationsImplTest, ComputeHMACBasic) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(32);
    auto data = create_test_data(256);
    
    auto result = crypto_ops.compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& mac = result.value();
    EXPECT_EQ(mac.size(), 32); // HMAC-SHA256 produces 32 bytes
    
    // Should be deterministic
    auto result2 = crypto_ops.compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result2.is_success());
    EXPECT_EQ(mac, result2.value());
}

TEST_F(CryptoOperationsImplTest, ComputeHMACDifferentKeys) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key1 = create_test_key(32);
    auto key2 = create_test_key(32);
    key2[0] ^= 0xFF; // Make it different
    auto data = create_test_data(256);
    
    auto result1 = crypto_ops.compute_hmac(key1, data, HashAlgorithm::SHA256);
    auto result2 = crypto_ops.compute_hmac(key2, data, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(result1.is_success());
    ASSERT_TRUE(result2.is_success());
    
    // Different keys should produce different MACs
    EXPECT_NE(result1.value(), result2.value());
}

TEST_F(CryptoOperationsImplTest, VerifyHMACValid) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(32);
    auto data = create_test_data(256);
    
    // Compute HMAC
    auto mac_result = crypto_ops.compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(mac_result.is_success());
    
    // Verify HMAC
    auto verify_result = crypto_ops.verify_hmac(
        key, data, mac_result.value(), HashAlgorithm::SHA256);
    
    ASSERT_TRUE(verify_result.is_success());
    EXPECT_TRUE(verify_result.value());
}

TEST_F(CryptoOperationsImplTest, VerifyHMACInvalid) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(32);
    auto data = create_test_data(256);
    
    // Compute HMAC
    auto mac_result = crypto_ops.compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(mac_result.is_success());
    
    // Corrupt the MAC
    auto corrupted_mac = mac_result.value();
    corrupted_mac[0] ^= 0xFF;
    
    // Verify corrupted HMAC
    auto verify_result = crypto_ops.verify_hmac(
        key, data, corrupted_mac, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(verify_result.is_success());
    EXPECT_FALSE(verify_result.value()); // Should fail verification
}

// ==================== Sequence Number Encryption Tests ====================

TEST_F(CryptoOperationsImplTest, EncryptDecryptSequenceNumber) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    uint64_t original_seq = 0x123456789ABCULL; // 48-bit sequence number
    auto key = create_test_key(16);
    auto sample = create_test_data(16);
    
    // Encrypt
    auto encrypt_result = crypto_ops.encrypt_sequence_number(original_seq, key, sample);
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& encrypted = encrypt_result.value();
    EXPECT_EQ(encrypted.size(), 6); // 48-bit = 6 bytes
    
    // Decrypt
    auto decrypt_result = crypto_ops.decrypt_sequence_number(encrypted, key, sample);
    ASSERT_TRUE(decrypt_result.is_success());
    
    uint64_t decrypted_seq = decrypt_result.value();
    EXPECT_EQ(decrypted_seq, original_seq);
}

TEST_F(CryptoOperationsImplTest, EncryptSequenceNumberMaxValue) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    uint64_t max_seq = 0xFFFFFFFFFFFFULL; // Maximum 48-bit value
    auto key = create_test_key(16);
    auto sample = create_test_data(16);
    
    auto encrypt_result = crypto_ops.encrypt_sequence_number(max_seq, key, sample);
    ASSERT_TRUE(encrypt_result.is_success());
    
    auto decrypt_result = crypto_ops.decrypt_sequence_number(
        encrypt_result.value(), key, sample);
    ASSERT_TRUE(decrypt_result.is_success());
    
    EXPECT_EQ(decrypt_result.value(), max_seq);
}

TEST_F(CryptoOperationsImplTest, DecryptSequenceNumberInvalidLength) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);
    auto sample = create_test_data(16);
    
    // Wrong length encrypted data
    std::vector<uint8_t> wrong_length_data = {0x01, 0x02, 0x03}; // Only 3 bytes instead of 6
    
    auto decrypt_result = crypto_ops.decrypt_sequence_number(wrong_length_data, key, sample);
    EXPECT_FALSE(decrypt_result.is_success());
    EXPECT_EQ(decrypt_result.error(), DTLSError::INVALID_PARAMETER);
}

// ==================== Error Handling Tests ====================

TEST_F(CryptoOperationsImplTest, UninitializedProviderErrors) {
    CryptoOperationsImpl crypto_ops(nullptr);
    ASSERT_FALSE(crypto_ops.is_initialized());
    
    // All operations should fail with CRYPTO_PROVIDER_ERROR
    auto random_result = crypto_ops.generate_random(32);
    EXPECT_FALSE(random_result.is_success());
    EXPECT_EQ(random_result.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
    
    auto dtls_random_result = crypto_ops.generate_dtls_random();
    EXPECT_FALSE(dtls_random_result.is_success());
    EXPECT_EQ(dtls_random_result.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
    
    auto hash_result = crypto_ops.compute_hash({0x01, 0x02}, HashAlgorithm::SHA256);
    EXPECT_FALSE(hash_result.is_success());
    EXPECT_EQ(hash_result.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
}

// ==================== Stress and Performance Tests ====================

TEST_F(CryptoOperationsImplTest, StressTestRandomGeneration) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Generate many random values and verify uniqueness
    std::set<std::vector<uint8_t>> unique_randoms;
    
    for (int i = 0; i < 100; ++i) {
        auto result = crypto_ops.generate_random(32);
        ASSERT_TRUE(result.is_success());
        unique_randoms.insert(result.value());
    }
    
    // Should have high uniqueness (allow for some collisions in test)
    EXPECT_GT(unique_randoms.size(), 90);
}

TEST_F(CryptoOperationsImplTest, StressTestEncryptionDecryption) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto key = create_test_key(16);
    auto nonce = create_test_key(12);
    auto aad = create_test_data(16);
    
    // Test many encrypt/decrypt cycles
    for (int i = 0; i < 50; ++i) {
        auto plaintext = create_test_data(256 + i); // Varying sizes
        
        auto encrypt_result = crypto_ops.aead_encrypt(
            plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
        ASSERT_TRUE(encrypt_result.is_success()) << "Failed at iteration " << i;
        
        auto decrypt_result = crypto_ops.aead_decrypt(
            encrypt_result.value().ciphertext, encrypt_result.value().tag,
            key, nonce, aad, AEADCipher::AES_128_GCM);
        ASSERT_TRUE(decrypt_result.is_success()) << "Failed at iteration " << i;
        
        EXPECT_EQ(decrypt_result.value(), plaintext) << "Mismatch at iteration " << i;
        
        // Modify nonce for next iteration to ensure different ciphertexts
        nonce[11] = static_cast<uint8_t>(i);
    }
}

// ==================== Thread Safety Tests ====================

TEST_F(CryptoOperationsImplTest, ConcurrentOperations) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    const int num_threads = 4;
    const int operations_per_thread = 25;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    auto worker = [&crypto_ops, &success_count, operations_per_thread]() {
        for (int i = 0; i < operations_per_thread; ++i) {
            // Mix different operations
            if (i % 3 == 0) {
                auto result = crypto_ops.generate_random(32);
                if (result.is_success()) success_count++;
            } else if (i % 3 == 1) {
                auto data = std::vector<uint8_t>(32, static_cast<uint8_t>(i));
                auto result = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
                if (result.is_success()) success_count++;
            } else {
                auto key = std::vector<uint8_t>(16, static_cast<uint8_t>(i));
                auto data = std::vector<uint8_t>(32, static_cast<uint8_t>(i + 1));
                auto result = crypto_ops.compute_hmac(key, data, HashAlgorithm::SHA256);
                if (result.is_success()) success_count++;
            }
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All operations should succeed
    EXPECT_EQ(success_count.load(), num_threads * operations_per_thread);
}

// ==================== Edge Case Tests ====================

TEST_F(CryptoOperationsImplTest, LargeDataOperations) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Test with large data (1MB)
    auto large_data = create_test_data(1024 * 1024);
    
    auto hash_result = crypto_ops.compute_hash(large_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hash_result.is_success());
    EXPECT_EQ(hash_result.value().size(), 32);
    
    auto key = create_test_key(32);
    auto hmac_result = crypto_ops.compute_hmac(key, large_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hmac_result.is_success());
    EXPECT_EQ(hmac_result.value().size(), 32);
}

TEST_F(CryptoOperationsImplTest, ZeroLengthOperations) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    std::vector<uint8_t> empty_data;
    auto key = create_test_key(16);
    
    // Hash of empty data should work
    auto hash_result = crypto_ops.compute_hash(empty_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hash_result.is_success());
    
    // HMAC of empty data should work
    auto hmac_result = crypto_ops.compute_hmac(key, empty_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hmac_result.is_success());
}

// ==================== Provider State Tests ====================

TEST_F(CryptoOperationsImplTest, GetProviderInfo) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    EXPECT_FALSE(crypto_ops.provider_name().empty());
    EXPECT_TRUE(crypto_ops.is_initialized());
}

TEST_F(CryptoOperationsImplTest, InvalidProviderHandling) {
    // Test with completely invalid provider name
    CryptoOperationsImpl crypto_ops("totally_fake_provider_name_that_does_not_exist");
    EXPECT_FALSE(crypto_ops.is_initialized());
    
    // All operations should fail
    auto result = crypto_ops.generate_random(32);
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
}

// Performance measurement helper
class PerformanceTimer {
public:
    PerformanceTimer() : start_(std::chrono::high_resolution_clock::now()) {}
    
    double elapsed_ms() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - start_);
        return duration.count() / 1000.0;
    }
    
private:
    std::chrono::high_resolution_clock::time_point start_;
};

TEST_F(CryptoOperationsImplTest, PerformanceBenchmark) {
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    const int iterations = 100;
    
    // Benchmark random generation
    {
        PerformanceTimer timer;
        for (int i = 0; i < iterations; ++i) {
            auto result = crypto_ops.generate_random(32);
            ASSERT_TRUE(result.is_success());
        }
        double elapsed = timer.elapsed_ms();
        std::cout << "Random generation: " << (elapsed / iterations) << " ms per operation\n";
    }
    
    // Benchmark hash computation
    {
        auto data = create_test_data(1024);
        PerformanceTimer timer;
        for (int i = 0; i < iterations; ++i) {
            auto result = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
            ASSERT_TRUE(result.is_success());
        }
        double elapsed = timer.elapsed_ms();
        std::cout << "Hash computation (1KB): " << (elapsed / iterations) << " ms per operation\n";
    }
    
    // Benchmark AEAD encryption
    {
        auto key = create_test_key(16);
        auto nonce = create_test_key(12);
        auto plaintext = create_test_data(1024);
        auto aad = create_test_data(16);
        
        PerformanceTimer timer;
        for (int i = 0; i < iterations; ++i) {
            nonce[11] = static_cast<uint8_t>(i); // Unique nonce
            auto result = crypto_ops.aead_encrypt(
                plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
            ASSERT_TRUE(result.is_success());
        }
        double elapsed = timer.elapsed_ms();
        std::cout << "AEAD encryption (1KB): " << (elapsed / iterations) << " ms per operation\n";
    }
}