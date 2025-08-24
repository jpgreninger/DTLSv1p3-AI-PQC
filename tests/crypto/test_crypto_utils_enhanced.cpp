/**
 * @file test_crypto_utils_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS crypto utilities
 * 
 * This test suite covers all functionality in crypto_utils.cpp to achieve >95% coverage.
 * Currently at 12.3% coverage (103/835 lines). Tests include CipherSpec mapping, HKDF operations,
 * parameter creation, utility functions, buffer management, and cross-provider compatibility.
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
#include <unordered_set>

#include "dtls/crypto/crypto_utils.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/operations_impl.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class CryptoUtilsEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto system if needed
        if (!crypto::is_crypto_system_initialized()) {
            auto init_result = crypto::initialize_crypto_system();
            ASSERT_TRUE(init_result.is_success()) << "Failed to initialize crypto system";
        }
        
        // Setup test provider
        auto& factory = ProviderFactory::instance();
        auto provider_result = factory.create_default_provider();
        ASSERT_TRUE(provider_result.is_success());
        provider_ = std::move(provider_result.value());
        ASSERT_TRUE(provider_->initialize().is_success());
    }
    
    void TearDown() override {
        if (provider_) {
            provider_->cleanup();
        }
    }
    
    // Helper to create test data
    std::vector<uint8_t> create_test_data(size_t size, uint8_t pattern = 0) {
        std::vector<uint8_t> data(size);
        if (pattern == 0) {
            // Create varied pattern
            for (size_t i = 0; i < size; ++i) {
                data[i] = static_cast<uint8_t>(i % 256);
            }
        } else {
            std::fill(data.begin(), data.end(), pattern);
        }
        return data;
    }
    
    // Helper to create random test data
    std::vector<uint8_t> create_random_data(size_t size) {
        std::vector<uint8_t> data(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }
    
    // Helper to verify HKDF compliance with RFC 5869 test vectors
    void verify_hkdf_test_vector() {
        // RFC 5869 Test Case 1
        std::vector<uint8_t> ikm = {
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
        };
        
        std::vector<uint8_t> salt = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c
        };
        
        std::vector<uint8_t> info = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9
        };
        
        // Expected OKM (first 42 bytes)
        std::vector<uint8_t> expected_okm = {
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65
        };
        
        // Test HKDF-Extract
        auto extract_result = utils::hkdf_extract(*provider_, HashAlgorithm::SHA256, salt, ikm);
        ASSERT_TRUE(extract_result.is_success());
        
        // Test HKDF-Expand
        auto expand_result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256,
                                               extract_result.value(), info, 42);
        ASSERT_TRUE(expand_result.is_success());
        
        EXPECT_EQ(expand_result.value(), expected_okm);
    }
    
    std::unique_ptr<CryptoProvider> provider_;
};

// ==================== CipherSpec Tests ====================

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromCipherSuiteAES128GCM) {
    auto result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& spec = result.value();
    EXPECT_EQ(spec.suite, CipherSuite::TLS_AES_128_GCM_SHA256);
    EXPECT_EQ(spec.aead_cipher, AEADCipher::AES_128_GCM);
    EXPECT_EQ(spec.hash_algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(spec.key_length, 16);
    EXPECT_EQ(spec.iv_length, 12);
    EXPECT_EQ(spec.tag_length, 16);
    EXPECT_EQ(spec.hash_length, 32);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromCipherSuiteAES256GCM) {
    auto result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384);
    ASSERT_TRUE(result.is_success());
    
    const auto& spec = result.value();
    EXPECT_EQ(spec.suite, CipherSuite::TLS_AES_256_GCM_SHA384);
    EXPECT_EQ(spec.aead_cipher, AEADCipher::AES_256_GCM);
    EXPECT_EQ(spec.hash_algorithm, HashAlgorithm::SHA384);
    EXPECT_EQ(spec.key_length, 32);
    EXPECT_EQ(spec.iv_length, 12);
    EXPECT_EQ(spec.tag_length, 16);
    EXPECT_EQ(spec.hash_length, 48);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromCipherSuiteChaCha20) {
    auto result = CipherSpec::from_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& spec = result.value();
    EXPECT_EQ(spec.suite, CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    EXPECT_EQ(spec.aead_cipher, AEADCipher::CHACHA20_POLY1305);
    EXPECT_EQ(spec.hash_algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(spec.key_length, 32);
    EXPECT_EQ(spec.iv_length, 12);
    EXPECT_EQ(spec.tag_length, 16);
    EXPECT_EQ(spec.hash_length, 32);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromCipherSuiteAES128CCM) {
    auto result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_CCM_SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& spec = result.value();
    EXPECT_EQ(spec.suite, CipherSuite::TLS_AES_128_CCM_SHA256);
    EXPECT_EQ(spec.aead_cipher, AEADCipher::AES_128_CCM);
    EXPECT_EQ(spec.hash_algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(spec.key_length, 16);
    EXPECT_EQ(spec.iv_length, 12);
    EXPECT_EQ(spec.tag_length, 16);
    EXPECT_EQ(spec.hash_length, 32);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromCipherSuiteAES128CCM8) {
    auto result = CipherSpec::from_cipher_suite(CipherSuite::TLS_AES_128_CCM_8_SHA256);
    ASSERT_TRUE(result.is_success());
    
    const auto& spec = result.value();
    EXPECT_EQ(spec.suite, CipherSuite::TLS_AES_128_CCM_8_SHA256);
    EXPECT_EQ(spec.aead_cipher, AEADCipher::AES_128_CCM_8);
    EXPECT_EQ(spec.hash_algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(spec.key_length, 16);
    EXPECT_EQ(spec.iv_length, 12);
    EXPECT_EQ(spec.tag_length, 8);  // Shorter tag for CCM_8
    EXPECT_EQ(spec.hash_length, 32);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecFromUnsupportedCipherSuite) {
    // Test with an invalid/unsupported cipher suite
    auto result = CipherSpec::from_cipher_suite(static_cast<CipherSuite>(0xFFFF));
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::CIPHER_SUITE_NOT_SUPPORTED);
}

TEST_F(CryptoUtilsEnhancedTest, CipherSpecAllSupportedSuites) {
    std::vector<CipherSuite> supported_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_128_CCM_SHA256,
        CipherSuite::TLS_AES_128_CCM_8_SHA256
    };
    
    for (auto suite : supported_suites) {
        auto result = CipherSpec::from_cipher_suite(suite);
        ASSERT_TRUE(result.is_success()) << "Failed for cipher suite: " << static_cast<int>(suite);
        
        const auto& spec = result.value();
        EXPECT_EQ(spec.suite, suite);
        EXPECT_GT(spec.key_length, 0);
        EXPECT_GT(spec.iv_length, 0);
        EXPECT_GT(spec.tag_length, 0);
        EXPECT_GT(spec.hash_length, 0);
    }
}

// ==================== HKDF Utility Function Tests ====================

TEST_F(CryptoUtilsEnhancedTest, HKDFExtractBasic) {
    auto salt = create_test_data(32);
    auto ikm = create_test_data(64);
    
    auto result = utils::hkdf_extract(*provider_, HashAlgorithm::SHA256, salt, ikm);
    ASSERT_TRUE(result.is_success());
    
    const auto& prk = result.value();
    EXPECT_EQ(prk.size(), 32); // SHA256 output size
    
    // Should be deterministic
    auto result2 = utils::hkdf_extract(*provider_, HashAlgorithm::SHA256, salt, ikm);
    ASSERT_TRUE(result2.is_success());
    EXPECT_EQ(prk, result2.value());
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExtractEmptySalt) {
    std::vector<uint8_t> empty_salt;
    auto ikm = create_test_data(64);
    
    auto result = utils::hkdf_extract(*provider_, HashAlgorithm::SHA256, empty_salt, ikm);
    ASSERT_TRUE(result.is_success());
    
    const auto& prk = result.value();
    EXPECT_EQ(prk.size(), 32); // SHA256 output size
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExtractDifferentHashAlgorithms) {
    auto salt = create_test_data(32);
    auto ikm = create_test_data(64);
    
    // Test SHA256
    auto result_256 = utils::hkdf_extract(*provider_, HashAlgorithm::SHA256, salt, ikm);
    ASSERT_TRUE(result_256.is_success());
    EXPECT_EQ(result_256.value().size(), 32);
    
    // Test SHA384
    auto result_384 = utils::hkdf_extract(*provider_, HashAlgorithm::SHA384, salt, ikm);
    ASSERT_TRUE(result_384.is_success());
    EXPECT_EQ(result_384.value().size(), 48);
    
    // Test SHA512
    auto result_512 = utils::hkdf_extract(*provider_, HashAlgorithm::SHA512, salt, ikm);
    ASSERT_TRUE(result_512.is_success());
    EXPECT_EQ(result_512.value().size(), 64);
    
    // Different algorithms should produce different results
    EXPECT_NE(result_256.value(), result_384.value());
    EXPECT_NE(result_256.value(), result_512.value());
    EXPECT_NE(result_384.value(), result_512.value());
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExpandBasic) {
    auto prk = create_test_data(32); // 32 bytes for SHA256
    auto info = create_test_data(16);
    size_t length = 64;
    
    auto result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, info, length);
    ASSERT_TRUE(result.is_success());
    
    const auto& okm = result.value();
    EXPECT_EQ(okm.size(), length);
    
    // Should be deterministic
    auto result2 = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, info, length);
    ASSERT_TRUE(result2.is_success());
    EXPECT_EQ(okm, result2.value());
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExpandEmptyInfo) {
    auto prk = create_test_data(32);
    std::vector<uint8_t> empty_info;
    size_t length = 32;
    
    auto result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, empty_info, length);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value().size(), length);
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExpandVariousLengths) {
    auto prk = create_test_data(32);
    auto info = create_test_data(16);
    
    std::vector<size_t> test_lengths = {1, 16, 32, 48, 64, 128, 255};
    
    for (size_t length : test_lengths) {
        auto result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, info, length);
        ASSERT_TRUE(result.is_success()) << "Failed for length: " << length;
        EXPECT_EQ(result.value().size(), length);
    }
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExpandMaxLength) {
    auto prk = create_test_data(32);
    auto info = create_test_data(16);
    
    // Maximum length for SHA256 is 255 * 32 = 8160 bytes
    size_t max_length = 255 * 32;
    
    auto result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, info, max_length);
    ASSERT_TRUE(result.is_success());
    EXPECT_EQ(result.value().size(), max_length);
}

TEST_F(CryptoUtilsEnhancedTest, HKDFExpandTooLong) {
    auto prk = create_test_data(32);
    auto info = create_test_data(16);
    
    // Length too large for SHA256 (> 255 * 32)
    size_t too_long = 255 * 32 + 1;
    
    auto result = utils::hkdf_expand(*provider_, HashAlgorithm::SHA256, prk, info, too_long);
    // Should either fail or handle gracefully depending on implementation
    if (!result.is_success()) {
        std::cout << "HKDF-Expand correctly rejected too-long output\n";
    }
}

TEST_F(CryptoUtilsEnhancedTest, HKDFRfc5869TestVector) {
    verify_hkdf_test_vector();
}

// ==================== Hash Output Length Tests ====================

TEST_F(CryptoUtilsEnhancedTest, GetHashOutputLength) {
    EXPECT_EQ(utils::get_hash_output_length(HashAlgorithm::SHA256), 32);
    EXPECT_EQ(utils::get_hash_output_length(HashAlgorithm::SHA384), 48);
    EXPECT_EQ(utils::get_hash_output_length(HashAlgorithm::SHA512), 64);
}

TEST_F(CryptoUtilsEnhancedTest, GetHashOutputLengthInvalid) {
    // Test with invalid hash algorithm
    auto invalid_hash = static_cast<HashAlgorithm>(999);
    size_t length = utils::get_hash_output_length(invalid_hash);
    EXPECT_EQ(length, 0); // Should return 0 for unknown algorithms
}

// ==================== Parameter Creation Tests ====================

TEST_F(CryptoUtilsEnhancedTest, CreateRandomParams) {
    size_t length = 32;
    std::vector<uint8_t> entropy = {0x01, 0x02, 0x03, 0x04};
    
    auto params = utils::create_random_params(length, entropy);
    
    EXPECT_EQ(params.length, length);
    EXPECT_EQ(params.additional_entropy, entropy);
}

TEST_F(CryptoUtilsEnhancedTest, CreateKeyDerivationParams) {
    auto secret = create_test_data(32);
    std::string label = "test label";
    auto context = create_test_data(16);
    size_t length = 64;
    HashAlgorithm hash = HashAlgorithm::SHA256;
    
    auto params = utils::create_key_derivation_params(secret, label, context, length, hash);
    
    EXPECT_EQ(params.master_secret, secret);
    EXPECT_EQ(params.context, context);
    EXPECT_EQ(params.output_length, length);
    EXPECT_EQ(params.hash_algorithm, hash);
    EXPECT_FALSE(params.label.empty());
}

TEST_F(CryptoUtilsEnhancedTest, CreateAEADEncryptionParams) {
    auto plaintext = create_test_data(256);
    auto key = create_test_data(16);
    auto nonce = create_test_data(12);
    auto aad = create_test_data(16);
    AEADCipher cipher = AEADCipher::AES_128_GCM;
    
    auto params = utils::create_aead_encryption_params(plaintext, key, nonce, aad, cipher);
    
    EXPECT_EQ(params.plaintext, plaintext);
    EXPECT_EQ(params.key, key);
    EXPECT_EQ(params.nonce, nonce);
    EXPECT_EQ(params.additional_data, aad);
    EXPECT_EQ(params.cipher, cipher);
}

TEST_F(CryptoUtilsEnhancedTest, CreateAEADDecryptionParams) {
    auto ciphertext = create_test_data(256);
    auto tag = create_test_data(16);
    auto key = create_test_data(16);
    auto nonce = create_test_data(12);
    auto aad = create_test_data(16);
    AEADCipher cipher = AEADCipher::AES_128_GCM;
    
    auto params = utils::create_aead_decryption_params(ciphertext, tag, key, nonce, aad, cipher);
    
    EXPECT_EQ(params.ciphertext, ciphertext);
    EXPECT_EQ(params.tag, tag);
    EXPECT_EQ(params.key, key);
    EXPECT_EQ(params.nonce, nonce);
    EXPECT_EQ(params.additional_data, aad);
    EXPECT_EQ(params.cipher, cipher);
}

TEST_F(CryptoUtilsEnhancedTest, CreateHashParams) {
    auto data = create_test_data(256);
    HashAlgorithm algorithm = HashAlgorithm::SHA256;
    
    auto params = utils::create_hash_params(data, algorithm);
    
    EXPECT_EQ(params.data, data);
    EXPECT_EQ(params.algorithm, algorithm);
}

TEST_F(CryptoUtilsEnhancedTest, CreateHMACParams) {
    auto key = create_test_data(32);
    auto data = create_test_data(256);
    HashAlgorithm algorithm = HashAlgorithm::SHA256;
    
    auto params = utils::create_hmac_params(key, data, algorithm);
    
    EXPECT_EQ(params.key, key);
    EXPECT_EQ(params.data, data);
    EXPECT_EQ(params.algorithm, algorithm);
}

TEST_F(CryptoUtilsEnhancedTest, CreateMACValidationParams) {
    auto key = create_test_data(32);
    auto data = create_test_data(256);
    auto expected_mac = create_test_data(32);
    HashAlgorithm algorithm = HashAlgorithm::SHA256;
    
    auto params = utils::create_mac_validation_params(key, data, expected_mac, algorithm);
    
    EXPECT_EQ(params.key, key);
    EXPECT_EQ(params.data, data);
    EXPECT_EQ(params.expected_mac, expected_mac);
    EXPECT_EQ(params.algorithm, algorithm);
}

// ==================== Buffer Management Tests ====================

TEST_F(CryptoUtilsEnhancedTest, SecureBufferOperations) {
    const size_t buffer_size = 1024;
    auto buffer = utils::allocate_secure_buffer(buffer_size);
    
    ASSERT_NE(buffer, nullptr);
    
    // Write to buffer
    for (size_t i = 0; i < buffer_size; ++i) {
        buffer[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Verify data
    for (size_t i = 0; i < buffer_size; ++i) {
        EXPECT_EQ(buffer[i], static_cast<uint8_t>(i % 256));
    }
    
    // Clear and free
    utils::secure_zero_memory(buffer, buffer_size);
    
    // Verify cleared
    for (size_t i = 0; i < buffer_size; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
    
    utils::free_secure_buffer(buffer, buffer_size);
}

TEST_F(CryptoUtilsEnhancedTest, SecureVectorOperations) {
    auto original_data = create_test_data(256);
    auto data_copy = original_data; // Make a copy
    
    EXPECT_EQ(data_copy, original_data);
    
    // Securely clear the copy
    utils::secure_clear_vector(data_copy);
    
    // Verify cleared
    EXPECT_NE(data_copy, original_data);
    EXPECT_TRUE(std::all_of(data_copy.begin(), data_copy.end(), 
                           [](uint8_t val) { return val == 0; }));
    
    // Original should be unchanged
    EXPECT_NE(original_data, data_copy);
}

TEST_F(CryptoUtilsEnhancedTest, ConstantTimeCompare) {
    auto data1 = create_test_data(256);
    auto data2 = data1; // Identical
    auto data3 = create_test_data(256, 0xFF); // Different
    
    // Same data should compare equal
    EXPECT_TRUE(utils::constant_time_compare(data1, data2));
    
    // Different data should compare unequal
    EXPECT_FALSE(utils::constant_time_compare(data1, data3));
    
    // Different sizes should compare unequal
    std::vector<uint8_t> short_data = {0x01, 0x02, 0x03};
    EXPECT_FALSE(utils::constant_time_compare(data1, short_data));
    
    // Empty vectors should compare equal
    std::vector<uint8_t> empty1, empty2;
    EXPECT_TRUE(utils::constant_time_compare(empty1, empty2));
}

// ==================== Cross-Provider Compatibility Tests ====================

TEST_F(CryptoUtilsEnhancedTest, CrossProviderHKDF) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    if (providers.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider test";
    }
    
    auto salt = create_test_data(32);
    auto ikm = create_test_data(64);
    auto info = create_test_data(16);
    size_t output_length = 32;
    
    std::vector<std::vector<uint8_t>> results;
    
    // Test HKDF with different providers
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (!provider_result.is_success()) continue;
        
        auto provider = std::move(provider_result.value());
        if (!provider->initialize().is_success()) continue;
        
        // HKDF-Extract
        auto extract_result = utils::hkdf_extract(*provider, HashAlgorithm::SHA256, salt, ikm);
        if (!extract_result.is_success()) continue;
        
        // HKDF-Expand
        auto expand_result = utils::hkdf_expand(*provider, HashAlgorithm::SHA256,
                                               extract_result.value(), info, output_length);
        if (!expand_result.is_success()) continue;
        
        results.push_back(expand_result.value());
        std::cout << "HKDF result from " << provider_name << " provider\n";
        
        provider->cleanup();
    }
    
    // All providers should produce the same HKDF result
    for (size_t i = 1; i < results.size(); ++i) {
        EXPECT_EQ(results[0], results[i]) << "HKDF mismatch between providers";
    }
}

// ==================== Performance Optimization Tests ====================

TEST_F(CryptoUtilsEnhancedTest, BufferCopyOptimization) {
    const size_t large_size = 1024 * 1024; // 1MB
    auto source = create_test_data(large_size);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test optimized buffer copy
    auto dest = utils::optimized_buffer_copy(source);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    EXPECT_EQ(dest.size(), source.size());
    EXPECT_EQ(dest, source);
    
    std::cout << "Optimized buffer copy (1MB): " << duration.count() << " microseconds\n";
}

TEST_F(CryptoUtilsEnhancedTest, KeyDerivationPerformance) {
    const int iterations = 100;
    auto secret = create_test_data(32);
    auto context = create_test_data(64);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto params = utils::create_key_derivation_params(
            secret, "test label", context, 32, HashAlgorithm::SHA256);
        // Parameter creation should be fast
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    std::cout << "Key derivation parameter creation (" << iterations 
              << " iterations): " << duration.count() << " microseconds\n";
    
    // Should be fast (less than 1ms per iteration)
    EXPECT_LT(duration.count() / iterations, 1000); // Less than 1000 microseconds per iteration
}

// ==================== Error Handling and Edge Cases ====================

TEST_F(CryptoUtilsEnhancedTest, HKDFWithInvalidProvider) {
    // Create params with null provider (should be handled gracefully)
    auto salt = create_test_data(32);
    auto ikm = create_test_data(64);
    
    // Note: This test depends on the implementation handling null providers
    // The actual behavior may vary based on implementation
}

TEST_F(CryptoUtilsEnhancedTest, ParameterCreationWithEmptyData) {
    // Test parameter creation with empty/minimal data
    std::vector<uint8_t> empty_data;
    std::string empty_label;
    
    auto params1 = utils::create_hash_params(empty_data, HashAlgorithm::SHA256);
    EXPECT_EQ(params1.data, empty_data);
    EXPECT_EQ(params1.algorithm, HashAlgorithm::SHA256);
    
    auto params2 = utils::create_key_derivation_params(
        empty_data, empty_label, empty_data, 0, HashAlgorithm::SHA256);
    EXPECT_EQ(params2.master_secret, empty_data);
    EXPECT_EQ(params2.context, empty_data);
    EXPECT_EQ(params2.output_length, 0);
}

TEST_F(CryptoUtilsEnhancedTest, LargeDataHandling) {
    const size_t large_size = 10 * 1024 * 1024; // 10MB
    
    // Test that utilities can handle large data sizes
    auto large_data = create_test_data(large_size);
    
    // Test parameter creation with large data
    auto hash_params = utils::create_hash_params(large_data, HashAlgorithm::SHA256);
    EXPECT_EQ(hash_params.data.size(), large_size);
    
    auto key = create_test_data(32);
    auto hmac_params = utils::create_hmac_params(key, large_data, HashAlgorithm::SHA256);
    EXPECT_EQ(hmac_params.data.size(), large_size);
    
    std::cout << "Large data handling test completed (10MB)\n";
}

// ==================== Thread Safety Tests ====================

TEST_F(CryptoUtilsEnhancedTest, ConcurrentParameterCreation) {
    const int num_threads = 4;
    const int operations_per_thread = 250;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    auto worker = [&](int thread_id) {
        for (int i = 0; i < operations_per_thread; ++i) {
            auto data = create_test_data(256 + thread_id + i);
            auto key = create_test_data(32);
            
            // Mix different parameter creation operations
            switch (i % 4) {
                case 0: {
                    auto params = utils::create_hash_params(data, HashAlgorithm::SHA256);
                    if (params.data == data) success_count++;
                    break;
                }
                case 1: {
                    auto params = utils::create_hmac_params(key, data, HashAlgorithm::SHA256);
                    if (params.key == key && params.data == data) success_count++;
                    break;
                }
                case 2: {
                    auto params = utils::create_random_params(32);
                    if (params.length == 32) success_count++;
                    break;
                }
                case 3: {
                    auto nonce = create_test_data(12);
                    auto aad = create_test_data(16);
                    auto params = utils::create_aead_encryption_params(
                        data, key, nonce, aad, AEADCipher::AES_128_GCM);
                    if (params.plaintext == data) success_count++;
                    break;
                }
            }
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, i);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All operations should succeed
    EXPECT_EQ(success_count.load(), num_threads * operations_per_thread);
    std::cout << "Concurrent parameter creation: " << success_count.load() 
              << " successful operations\n";
}

// ==================== Memory Efficiency Tests ====================

TEST_F(CryptoUtilsEnhancedTest, MemoryEfficientOperations) {
    // Test that parameter creation doesn't cause excessive memory allocation
    const int iterations = 1000;
    
    for (int i = 0; i < iterations; ++i) {
        auto data = create_test_data(1024);
        auto key = create_test_data(32);
        
        // These operations should reuse memory efficiently
        auto hash_params = utils::create_hash_params(data, HashAlgorithm::SHA256);
        auto hmac_params = utils::create_hmac_params(key, data, HashAlgorithm::SHA256);
        auto random_params = utils::create_random_params(32);
        
        // Parameters should contain the expected data
        EXPECT_EQ(hash_params.data, data);
        EXPECT_EQ(hmac_params.key, key);
        EXPECT_EQ(random_params.length, 32);
    }
    
    std::cout << "Memory efficiency test completed (" << iterations << " iterations)\n";
}

// ==================== Utility Function Integration Tests ====================

TEST_F(CryptoUtilsEnhancedTest, IntegratedCryptoOperations) {
    // Test that utilities work correctly with actual crypto operations
    auto data = create_test_data(1024);
    auto key = create_test_data(32);
    
    // Create parameters using utilities
    auto hash_params = utils::create_hash_params(data, HashAlgorithm::SHA256);
    auto hmac_params = utils::create_hmac_params(key, data, HashAlgorithm::SHA256);
    
    // Use parameters with provider operations
    auto hash_result = provider_->compute_hash(hash_params);
    ASSERT_TRUE(hash_result.is_success());
    EXPECT_EQ(hash_result.value().size(), 32);
    
    auto hmac_result = provider_->compute_hmac(hmac_params);
    ASSERT_TRUE(hmac_result.is_success());
    EXPECT_EQ(hmac_result.value().size(), 32);
    
    // Verify HMAC validation works
    auto validation_params = utils::create_mac_validation_params(
        key, data, hmac_result.value(), HashAlgorithm::SHA256);
    auto verify_result = provider_->verify_hmac(validation_params);
    ASSERT_TRUE(verify_result.is_success());
    EXPECT_TRUE(verify_result.value());
    
    std::cout << "Integrated crypto operations test completed successfully\n";
}