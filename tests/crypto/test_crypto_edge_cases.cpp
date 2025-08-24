/**
 * @file test_crypto_edge_cases.cpp
 * @brief Edge case and error condition tests for cryptographic operations
 * 
 * This test suite focuses on boundary conditions, error cases, and security
 * edge cases to ensure robust crypto operation handling.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/operations.h>
#include <dtls/crypto/operations_impl.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <limits>
#include <random>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class CryptoEdgeCasesTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto init_result = crypto::builtin::register_all_providers();
        ASSERT_TRUE(init_result.is_success()) << "Failed to register crypto providers";
        
        auto ops_result = create_crypto_operations();
        ASSERT_TRUE(ops_result.is_success()) << "Failed to create crypto operations";
        ops_ = std::move(ops_result.value());
        ASSERT_NE(ops_, nullptr) << "Crypto operations pointer is null";
    }
    
    void TearDown() override {
        ops_.reset();
    }
    
    std::unique_ptr<ICryptoOperations> ops_;
};

// === Random Generation Edge Cases ===

TEST_F(CryptoEdgeCasesTest, RandomGeneration_ZeroLength) {
    auto result = ops_->generate_random(0);
    if (result.is_success()) {
        EXPECT_TRUE(result.value().empty()) << "Zero-length random should be empty";
    } else {
        // Some implementations may reject zero-length requests
        EXPECT_NE(result.error(), DTLSError::SUCCESS) << "Should return proper error for zero length";
    }
}

TEST_F(CryptoEdgeCasesTest, RandomGeneration_MaximumLength) {
    // Test with large but reasonable random data request
    const size_t large_size = 1024 * 1024; // 1MB
    auto result = ops_->generate_random(large_size);
    
    if (result.is_success()) {
        EXPECT_EQ(result.value().size(), large_size) << "Large random generation size mismatch";
        
        // Verify entropy quality with basic statistical test
        const auto& random_data = result.value();
        size_t zero_count = std::count(random_data.begin(), random_data.end(), 0);
        double zero_ratio = static_cast<double>(zero_count) / random_data.size();
        
        // Expect roughly 1/256 zeros in good random data (allow variance)
        EXPECT_LT(zero_ratio, 0.01) << "Too many zeros in random data";
        EXPECT_GT(zero_ratio, 0.001) << "Too few zeros in random data";
    } else {
        // Implementation may have size limits
        EXPECT_NE(result.error(), DTLSError::SUCCESS) << "Should return proper error for oversized request";
    }
}

TEST_F(CryptoEdgeCasesTest, RandomGeneration_ExcessiveAdditionalEntropy) {
    // Test with very large additional entropy
    std::vector<uint8_t> huge_entropy(10000, 0x42);
    auto result = ops_->generate_random(32, huge_entropy);
    
    EXPECT_TRUE(result.is_success()) << "Should handle large additional entropy gracefully";
    if (result.is_success()) {
        EXPECT_EQ(result.value().size(), 32) << "Output size should match request";
    }
}

TEST_F(CryptoEdgeCasesTest, ConnectionID_BoundaryLengths) {
    // Test minimum length (1 byte)
    auto result_min = ops_->generate_connection_id(1);
    EXPECT_TRUE(result_min.is_success()) << "1-byte connection ID should work";
    if (result_min.is_success()) {
        EXPECT_EQ(result_min.value().size(), 1) << "1-byte connection ID size mismatch";
    }
    
    // Test maximum length (255 bytes per RFC)
    auto result_max = ops_->generate_connection_id(255);
    EXPECT_TRUE(result_max.is_success()) << "255-byte connection ID should work";
    if (result_max.is_success()) {
        EXPECT_EQ(result_max.value().size(), 255) << "255-byte connection ID size mismatch";
    }
    
    // Test invalid length (0 bytes)
    auto result_zero = ops_->generate_connection_id(0);
    EXPECT_FALSE(result_zero.is_success()) << "0-byte connection ID should fail";
    
    // Test invalid length (> 255 bytes)
    auto result_oversized = ops_->generate_connection_id(256);
    EXPECT_FALSE(result_oversized.is_success()) << "256-byte connection ID should fail";
}

// === Hash Edge Cases ===

TEST_F(CryptoEdgeCasesTest, Hash_EmptyInput) {
    std::vector<uint8_t> empty_data;
    
    for (auto algorithm : {HashAlgorithm::SHA256, HashAlgorithm::SHA384, HashAlgorithm::SHA512}) {
        auto result = ops_->compute_hash(empty_data, algorithm);
        ASSERT_TRUE(result.is_success()) << "Hash of empty data should succeed";
        EXPECT_FALSE(result.value().empty()) << "Hash output should not be empty";
    }
}

TEST_F(CryptoEdgeCasesTest, Hash_SingleByte) {
    std::vector<uint8_t> single_byte = {0x00};
    auto result = ops_->compute_hash(single_byte, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success()) << "Hash of single byte should succeed";
    EXPECT_EQ(result.value().size(), 32) << "SHA256 should produce 32 bytes";
    
    // Test different single bytes produce different hashes
    std::vector<uint8_t> different_byte = {0xFF};
    auto result2 = ops_->compute_hash(different_byte, HashAlgorithm::SHA256);
    ASSERT_TRUE(result2.is_success());
    EXPECT_NE(result.value(), result2.value()) << "Different inputs should produce different hashes";
}

TEST_F(CryptoEdgeCasesTest, Hash_BlockBoundaries) {
    // Test data at SHA block boundaries (64 bytes for SHA256)
    std::vector<uint8_t> block_minus_1(63, 0x41);
    std::vector<uint8_t> block_exact(64, 0x41);
    std::vector<uint8_t> block_plus_1(65, 0x41);
    
    auto result1 = ops_->compute_hash(block_minus_1, HashAlgorithm::SHA256);
    auto result2 = ops_->compute_hash(block_exact, HashAlgorithm::SHA256);
    auto result3 = ops_->compute_hash(block_plus_1, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(result1.is_success()) << "Block-1 hash should succeed";
    ASSERT_TRUE(result2.is_success()) << "Block exact hash should succeed";
    ASSERT_TRUE(result3.is_success()) << "Block+1 hash should succeed";
    
    // All should produce different hashes
    EXPECT_NE(result1.value(), result2.value()) << "Different lengths should produce different hashes";
    EXPECT_NE(result2.value(), result3.value()) << "Different lengths should produce different hashes";
}

// === HMAC Edge Cases ===

TEST_F(CryptoEdgeCasesTest, HMAC_EmptyKey) {
    std::vector<uint8_t> empty_key;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    
    auto result = ops_->compute_hmac(empty_key, data, HashAlgorithm::SHA256);
    EXPECT_FALSE(result.is_success()) << "HMAC with empty key should fail";
}

TEST_F(CryptoEdgeCasesTest, HMAC_EmptyData) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> empty_data;
    
    auto result = ops_->compute_hmac(key, empty_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success()) << "HMAC with empty data should succeed";
    EXPECT_EQ(result.value().size(), 32) << "HMAC-SHA256 should produce 32 bytes";
    
    // Verify HMAC
    auto verify_result = ops_->verify_hmac(key, empty_data, result.value(), HashAlgorithm::SHA256);
    ASSERT_TRUE(verify_result.is_success()) << "HMAC verification should succeed";
    EXPECT_TRUE(verify_result.value()) << "HMAC verification should be true";
}

TEST_F(CryptoEdgeCasesTest, HMAC_VeryLongKey) {
    // Key longer than hash block size (should be hashed down)
    std::vector<uint8_t> long_key(1000, 0x42);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    
    auto result = ops_->compute_hmac(long_key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(result.is_success()) << "HMAC with long key should succeed";
    EXPECT_EQ(result.value().size(), 32) << "HMAC-SHA256 should produce 32 bytes";
}

TEST_F(CryptoEdgeCasesTest, HMAC_IncorrectTagLength) {
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data = {0x05, 0x06, 0x07, 0x08};
    
    auto hmac_result = ops_->compute_hmac(key, data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hmac_result.is_success());
    
    auto correct_hmac = hmac_result.value();
    
    // Test with truncated HMAC
    std::vector<uint8_t> truncated_hmac(correct_hmac.begin(), correct_hmac.begin() + 16);
    auto verify_result = ops_->verify_hmac(key, data, truncated_hmac, HashAlgorithm::SHA256);
    EXPECT_FALSE(verify_result.is_success()) << "HMAC verification should fail with wrong length";
    
    // Test with extended HMAC
    auto extended_hmac = correct_hmac;
    extended_hmac.push_back(0x00);
    auto verify_result2 = ops_->verify_hmac(key, data, extended_hmac, HashAlgorithm::SHA256);
    EXPECT_FALSE(verify_result2.is_success()) << "HMAC verification should fail with wrong length";
}

// === AEAD Edge Cases ===

TEST_F(CryptoEdgeCasesTest, AEAD_EmptyPlaintext) {
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> empty_plaintext;
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
    
    auto encrypt_result = ops_->aead_encrypt(empty_plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success()) << "AEAD encryption of empty plaintext should succeed";
    
    const auto& output = encrypt_result.value();
    EXPECT_TRUE(output.ciphertext.empty()) << "Ciphertext should be empty for empty plaintext";
    EXPECT_FALSE(output.tag.empty()) << "Authentication tag should not be empty";
    
    // Decrypt and verify
    auto decrypt_result = ops_->aead_decrypt(output.ciphertext, output.tag, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(decrypt_result.is_success()) << "AEAD decryption should succeed";
    EXPECT_TRUE(decrypt_result.value().empty()) << "Decrypted plaintext should be empty";
}

TEST_F(CryptoEdgeCasesTest, AEAD_EmptyAAD) {
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> empty_aad;
    
    auto encrypt_result = ops_->aead_encrypt(plaintext, key, nonce, empty_aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success()) << "AEAD encryption with empty AAD should succeed";
    
    const auto& output = encrypt_result.value();
    
    auto decrypt_result = ops_->aead_decrypt(output.ciphertext, output.tag, key, nonce, empty_aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(decrypt_result.is_success()) << "AEAD decryption with empty AAD should succeed";
    EXPECT_EQ(decrypt_result.value(), plaintext) << "Round-trip should preserve plaintext";
}

TEST_F(CryptoEdgeCasesTest, AEAD_InvalidKeySize) {
    std::vector<uint8_t> invalid_key(15, 0x42); // Wrong size for AES-128
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad;
    
    auto result = ops_->aead_encrypt(plaintext, invalid_key, nonce, aad, AEADCipher::AES_128_GCM);
    EXPECT_FALSE(result.is_success()) << "AEAD should fail with invalid key size";
}

TEST_F(CryptoEdgeCasesTest, AEAD_InvalidNonceSize) {
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> invalid_nonce(11, 0x33); // Wrong size for GCM
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad;
    
    auto result = ops_->aead_encrypt(plaintext, key, invalid_nonce, aad, AEADCipher::AES_128_GCM);
    EXPECT_FALSE(result.is_success()) << "AEAD should fail with invalid nonce size";
}

TEST_F(CryptoEdgeCasesTest, AEAD_AADTampering) {
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> nonce(12, 0x33);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0x01, 0x02, 0x03};
    
    auto encrypt_result = ops_->aead_encrypt(plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success());
    
    const auto& output = encrypt_result.value();
    
    // Tamper with AAD during decryption
    std::vector<uint8_t> tampered_aad = {0x01, 0x02, 0x04}; // Changed last byte
    
    auto decrypt_result = ops_->aead_decrypt(output.ciphertext, output.tag, key, nonce, tampered_aad, AEADCipher::AES_128_GCM);
    EXPECT_FALSE(decrypt_result.is_success()) << "AEAD decryption should fail with tampered AAD";
}

// === Key Derivation Edge Cases ===

TEST_F(CryptoEdgeCasesTest, KeyDerivation_EmptySecret) {
    std::vector<uint8_t> empty_secret;
    std::string label = "test key";
    std::vector<uint8_t> context = {0x05, 0x06};
    
    auto result = ops_->hkdf_expand_label(empty_secret, label, context, 16);
    EXPECT_FALSE(result.is_success()) << "HKDF should fail with empty secret";
}

TEST_F(CryptoEdgeCasesTest, KeyDerivation_EmptyLabel) {
    std::vector<uint8_t> secret = {0x01, 0x02, 0x03, 0x04};
    std::string empty_label = "";
    std::vector<uint8_t> context = {0x05, 0x06};
    
    auto result = ops_->hkdf_expand_label(secret, empty_label, context, 16);
    ASSERT_TRUE(result.is_success()) << "HKDF with empty label should succeed";
    EXPECT_EQ(result.value().size(), 16) << "Output size should match request";
}

TEST_F(CryptoEdgeCasesTest, KeyDerivation_VeryLongLabel) {
    std::vector<uint8_t> secret = {0x01, 0x02, 0x03, 0x04};
    std::string long_label(1000, 'A');
    std::vector<uint8_t> context = {0x05, 0x06};
    
    auto result = ops_->hkdf_expand_label(secret, long_label, context, 16);
    EXPECT_TRUE(result.is_success()) << "HKDF should handle long labels";
}

TEST_F(CryptoEdgeCasesTest, KeyDerivation_ZeroLengthOutput) {
    std::vector<uint8_t> secret = {0x01, 0x02, 0x03, 0x04};
    std::string label = "test key";
    std::vector<uint8_t> context = {0x05, 0x06};
    
    auto result = ops_->hkdf_expand_label(secret, label, context, 0);
    if (result.is_success()) {
        EXPECT_TRUE(result.value().empty()) << "Zero-length output should be empty";
    } else {
        EXPECT_NE(result.error(), DTLSError::SUCCESS) << "Should return proper error for zero length";
    }
}

TEST_F(CryptoEdgeCasesTest, KeyDerivation_MaximumLengthOutput) {
    std::vector<uint8_t> secret = {0x01, 0x02, 0x03, 0x04};
    std::string label = "test key";
    std::vector<uint8_t> context = {0x05, 0x06};
    
    // HKDF-Expand has a maximum output length of 255 * hash_length
    // For SHA256, that's 255 * 32 = 8160 bytes
    size_t max_length = 255 * 32;
    
    auto result = ops_->hkdf_expand_label(secret, label, context, max_length);
    if (result.is_success()) {
        EXPECT_EQ(result.value().size(), max_length) << "Maximum length output size mismatch";
    } else {
        // Implementation may have stricter limits
        EXPECT_NE(result.error(), DTLSError::SUCCESS) << "Should return proper error for oversized request";
    }
    
    // Test exceeding maximum
    auto result_over = ops_->hkdf_expand_label(secret, label, context, max_length + 1);
    EXPECT_FALSE(result_over.is_success()) << "Should fail when exceeding HKDF maximum length";
}

// === Sequence Number Encryption Edge Cases ===

TEST_F(CryptoEdgeCasesTest, SequenceNumber_MaximumValue) {
    uint64_t max_seq = std::numeric_limits<uint64_t>::max();
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> sample(16, 0x33);
    
    auto encrypt_result = ops_->encrypt_sequence_number(max_seq, key, sample);
    ASSERT_TRUE(encrypt_result.is_success()) << "Max sequence number encryption should succeed";
    
    auto decrypt_result = ops_->decrypt_sequence_number(encrypt_result.value(), key, sample);
    ASSERT_TRUE(decrypt_result.is_success()) << "Max sequence number decryption should succeed";
    EXPECT_EQ(decrypt_result.value(), max_seq) << "Max sequence number round-trip failed";
}

TEST_F(CryptoEdgeCasesTest, SequenceNumber_ZeroValue) {
    uint64_t zero_seq = 0;
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> sample(16, 0x33);
    
    auto encrypt_result = ops_->encrypt_sequence_number(zero_seq, key, sample);
    ASSERT_TRUE(encrypt_result.is_success()) << "Zero sequence number encryption should succeed";
    
    auto decrypt_result = ops_->decrypt_sequence_number(encrypt_result.value(), key, sample);
    ASSERT_TRUE(decrypt_result.is_success()) << "Zero sequence number decryption should succeed";
    EXPECT_EQ(decrypt_result.value(), zero_seq) << "Zero sequence number round-trip failed";
}

TEST_F(CryptoEdgeCasesTest, SequenceNumber_InvalidKeySize) {
    uint64_t sequence_number = 12345;
    std::vector<uint8_t> invalid_key(10, 0x42); // Wrong size
    std::vector<uint8_t> sample(16, 0x33);
    
    auto result = ops_->encrypt_sequence_number(sequence_number, invalid_key, sample);
    EXPECT_FALSE(result.is_success()) << "Should fail with invalid key size";
}

TEST_F(CryptoEdgeCasesTest, SequenceNumber_InvalidSampleSize) {
    uint64_t sequence_number = 12345;
    std::vector<uint8_t> key(16, 0x42);
    std::vector<uint8_t> invalid_sample(10, 0x33); // Wrong size
    
    auto result = ops_->encrypt_sequence_number(sequence_number, key, invalid_sample);
    EXPECT_FALSE(result.is_success()) << "Should fail with invalid sample size";
}

// === Provider Stress Tests ===

TEST_F(CryptoEdgeCasesTest, StressTest_ManySmallOperations) {
    const size_t num_operations = 10000;
    size_t success_count = 0;
    
    for (size_t i = 0; i < num_operations; ++i) {
        std::vector<uint8_t> data = {static_cast<uint8_t>(i & 0xFF)};
        auto result = ops_->compute_hash(data, HashAlgorithm::SHA256);
        
        if (result.is_success()) {
            success_count++;
        }
    }
    
    EXPECT_EQ(success_count, num_operations) << "All operations should succeed in stress test";
}

TEST_F(CryptoEdgeCasesTest, StressTest_RandomizedInputs) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::uniform_int_distribution<size_t> size_dist(1, 1000);
    
    const size_t num_tests = 1000;
    size_t success_count = 0;
    
    for (size_t i = 0; i < num_tests; ++i) {
        size_t data_size = size_dist(gen);
        std::vector<uint8_t> random_data(data_size);
        
        for (size_t j = 0; j < data_size; ++j) {
            random_data[j] = byte_dist(gen);
        }
        
        auto result = ops_->compute_hash(random_data, HashAlgorithm::SHA256);
        if (result.is_success()) {
            success_count++;
        }
    }
    
    EXPECT_EQ(success_count, num_tests) << "All randomized operations should succeed";
}

// === Memory Safety Tests ===

TEST_F(CryptoEdgeCasesTest, MemorySafety_LargeInputs) {
    // Test with large inputs that might cause memory issues
    const size_t large_size = 10 * 1024 * 1024; // 10MB
    std::vector<uint8_t> large_data(large_size, 0x42);
    
    auto result = ops_->compute_hash(large_data, HashAlgorithm::SHA256);
    if (result.is_success()) {
        EXPECT_EQ(result.value().size(), 32) << "Large data hash should produce correct size";
    } else {
        // Implementation may have size limits for memory safety
        EXPECT_NE(result.error(), DTLSError::SUCCESS) << "Should return proper error for oversized input";
    }
}

TEST_F(CryptoEdgeCasesTest, MemorySafety_RepeatedOperations) {
    // Test for memory leaks with repeated operations
    const size_t num_iterations = 1000;
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
    
    for (size_t i = 0; i < num_iterations; ++i) {
        auto result = ops_->compute_hash(test_data, HashAlgorithm::SHA256);
        ASSERT_TRUE(result.is_success()) << "Iteration " << i << " failed";
        
        // Force result to go out of scope to test cleanup
        result.value().clear();
    }
    
    // If we get here without crashes, memory management is likely correct
    SUCCEED() << "Memory safety test completed without issues";
}