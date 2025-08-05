/**
 * @file test_sequence_number_encryption.cpp
 * @brief Comprehensive tests for DTLS v1.3 sequence number encryption (RFC 9147 Section 4.2.3)
 */

#include <gtest/gtest.h>
#include "dtls/crypto/crypto_utils.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/error.h"
#include <vector>
#include <cstdint>
#include <algorithm>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class SequenceNumberEncryptionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto provider factory
        auto factory_result = builtin::register_all_providers();
        ASSERT_TRUE(factory_result.is_success()) << "Failed to register crypto providers";
        
        // Create a crypto provider for testing
        auto provider_result = ProviderFactory::instance().create_default_provider();
        ASSERT_TRUE(provider_result.is_success()) << "Failed to create crypto provider";
        
        provider_ = std::move(provider_result.value());
        ASSERT_NE(provider_, nullptr);
        
        auto init_result = provider_->initialize();
        ASSERT_TRUE(init_result.is_success()) << "Failed to initialize crypto provider";
        
        // Test data
        test_sequence_number_ = 0x123456789ABCULL; // 48-bit test sequence number
        
        // Sample key material (32 bytes for ChaCha20, 16 bytes minimum for AES)
        sequence_number_key_ = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
        };
        
        // Sample ciphertext (at least 16 bytes for encryption mask generation)
        test_ciphertext_ = {
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0xF0, 0x0D, 0xD0, 0x0D, 0xAB, 0xCD, 0xEF, 0x12,
            0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12,
            0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12
        };
    }
    
    void TearDown() override {
        if (provider_) {
            provider_->cleanup();
        }
    }
    
    std::unique_ptr<CryptoProvider> provider_;
    uint64_t test_sequence_number_;
    std::vector<uint8_t> sequence_number_key_;
    std::vector<uint8_t> test_ciphertext_;
};

// Test AES-GCM sequence number encryption/decryption
TEST_F(SequenceNumberEncryptionTest, AES128GCM_EncryptDecrypt) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // Encrypt sequence number
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(encrypted_result.is_success()) 
        << "Failed to encrypt sequence number: " << static_cast<int>(encrypted_result.error());
    
    uint64_t encrypted_seq = encrypted_result.value();
    
    // Encrypted sequence number should be different from original
    EXPECT_NE(encrypted_seq, test_sequence_number_) 
        << "Encrypted sequence number should differ from original";
    
    // Ensure 48-bit constraint
    EXPECT_EQ(encrypted_seq & 0xFFFF000000000000ULL, 0ULL) 
        << "Encrypted sequence number should be 48-bit";
    
    // Decrypt sequence number
    auto decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_seq, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(decrypted_result.is_success()) 
        << "Failed to decrypt sequence number: " << static_cast<int>(decrypted_result.error());
    
    uint64_t decrypted_seq = decrypted_result.value();
    
    // Decrypted should match original
    EXPECT_EQ(decrypted_seq, test_sequence_number_) 
        << "Decrypted sequence number should match original";
}

// Test AES-256-GCM sequence number encryption/decryption  
TEST_F(SequenceNumberEncryptionTest, AES256GCM_EncryptDecrypt) {
    AEADCipher cipher_type = AEADCipher::AES_256_GCM;
    
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(encrypted_result.is_success());
    
    auto decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_result.value(), sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(decrypted_result.is_success());
    EXPECT_EQ(decrypted_result.value(), test_sequence_number_);
}

// Test ChaCha20-Poly1305 sequence number encryption/decryption
TEST_F(SequenceNumberEncryptionTest, ChaCha20Poly1305_EncryptDecrypt) {
    AEADCipher cipher_type = AEADCipher::CHACHA20_POLY1305;
    
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(encrypted_result.is_success());
    
    auto decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_result.value(), sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(decrypted_result.is_success());
    EXPECT_EQ(decrypted_result.value(), test_sequence_number_);
}

// Test AES-CCM sequence number encryption/decryption
TEST_F(SequenceNumberEncryptionTest, AES128CCM_EncryptDecrypt) {
    AEADCipher cipher_type = AEADCipher::AES_128_CCM;
    
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(encrypted_result.is_success());
    
    auto decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_result.value(), sequence_number_key_, 
        test_ciphertext_, cipher_type);
    
    ASSERT_TRUE(decrypted_result.is_success());
    EXPECT_EQ(decrypted_result.value(), test_sequence_number_);
}

// Test that different ciphertext produces different encrypted sequence numbers
TEST_F(SequenceNumberEncryptionTest, DifferentCiphertextProducesDifferentEncryption) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // First encryption with original ciphertext
    auto encrypted1_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted1_result.is_success());
    
    // Modify first byte of ciphertext
    std::vector<uint8_t> modified_ciphertext = test_ciphertext_;
    modified_ciphertext[0] ^= 0xFF;
    
    // Second encryption with modified ciphertext
    auto encrypted2_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        modified_ciphertext, cipher_type);
    ASSERT_TRUE(encrypted2_result.is_success());
    
    // Results should be different
    EXPECT_NE(encrypted1_result.value(), encrypted2_result.value())
        << "Different ciphertext should produce different encrypted sequence numbers";
}

// Test that different keys produce different encrypted sequence numbers
TEST_F(SequenceNumberEncryptionTest, DifferentKeysProduceDifferentEncryption) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // First encryption with original key
    auto encrypted1_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted1_result.is_success());
    
    // Modify key
    std::vector<uint8_t> modified_key = sequence_number_key_;
    modified_key[0] ^= 0xFF;
    
    // Second encryption with modified key
    auto encrypted2_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, modified_key, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted2_result.is_success());
    
    // Results should be different
    EXPECT_NE(encrypted1_result.value(), encrypted2_result.value())
        << "Different keys should produce different encrypted sequence numbers";
}

// Test error handling for invalid parameters
TEST_F(SequenceNumberEncryptionTest, InvalidParameters) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // Empty key
    std::vector<uint8_t> empty_key;
    auto result1 = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, empty_key, 
        test_ciphertext_, cipher_type);
    EXPECT_FALSE(result1.is_success()) << "Should fail with empty key";
    
    // Short ciphertext (less than 16 bytes)
    std::vector<uint8_t> short_ciphertext = {0x01, 0x02, 0x03, 0x04};
    auto result2 = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        short_ciphertext, cipher_type);
    EXPECT_FALSE(result2.is_success()) << "Should fail with short ciphertext";
    
    // Test decrypt with invalid parameters
    auto result3 = utils::decrypt_sequence_number(
        *provider_, test_sequence_number_, empty_key, 
        test_ciphertext_, cipher_type);
    EXPECT_FALSE(result3.is_success()) << "Decrypt should fail with empty key";
    
    auto result4 = utils::decrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        short_ciphertext, cipher_type);
    EXPECT_FALSE(result4.is_success()) << "Decrypt should fail with short ciphertext";
}

// Test 48-bit boundary values
TEST_F(SequenceNumberEncryptionTest, BoundaryValues) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // Test maximum 48-bit value
    uint64_t max_48bit = 0xFFFFFFFFFFFFULL;
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, max_48bit, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted_result.is_success());
    
    auto decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_result.value(), sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(decrypted_result.is_success());
    EXPECT_EQ(decrypted_result.value(), max_48bit);
    
    // Test zero value
    uint64_t zero_value = 0ULL;
    encrypted_result = utils::encrypt_sequence_number(
        *provider_, zero_value, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted_result.is_success());
    
    decrypted_result = utils::decrypt_sequence_number(
        *provider_, encrypted_result.value(), sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(decrypted_result.is_success());
    EXPECT_EQ(decrypted_result.value(), zero_value);
}

// Test RFC 9147 compliance - same inputs should produce same outputs
TEST_F(SequenceNumberEncryptionTest, RFC9147_Deterministic) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // Encrypt the same sequence number twice
    auto encrypted1_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted1_result.is_success());
    
    auto encrypted2_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, cipher_type);
    ASSERT_TRUE(encrypted2_result.is_success());
    
    // Results should be identical (deterministic)
    EXPECT_EQ(encrypted1_result.value(), encrypted2_result.value())
        << "Same inputs should produce same encrypted sequence number";
}

// Performance test for sequence number encryption
TEST_F(SequenceNumberEncryptionTest, Performance) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    const int iterations = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        uint64_t seq_num = static_cast<uint64_t>(i);
        auto encrypted_result = utils::encrypt_sequence_number(
            *provider_, seq_num, sequence_number_key_, 
            test_ciphertext_, cipher_type);
        ASSERT_TRUE(encrypted_result.is_success());
        
        auto decrypted_result = utils::decrypt_sequence_number(
            *provider_, encrypted_result.value(), sequence_number_key_, 
            test_ciphertext_, cipher_type);
        ASSERT_TRUE(decrypted_result.is_success());
        EXPECT_EQ(decrypted_result.value(), seq_num);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete in reasonable time (less than 1 second for 10k operations)
    EXPECT_LT(duration.count(), 1000000) 
        << "Performance test took too long: " << duration.count() << " microseconds";
    
    std::cout << "Sequence number encryption performance: " 
              << iterations << " encrypt/decrypt cycles in " 
              << duration.count() << " microseconds\n";
}

// Test unsupported cipher handling
TEST_F(SequenceNumberEncryptionTest, UnsupportedCipher) {
    // Use an invalid cipher type
    AEADCipher invalid_cipher = static_cast<AEADCipher>(999);
    
    auto encrypted_result = utils::encrypt_sequence_number(
        *provider_, test_sequence_number_, sequence_number_key_, 
        test_ciphertext_, invalid_cipher);
    EXPECT_FALSE(encrypted_result.is_success()) 
        << "Should fail with unsupported cipher";
    EXPECT_EQ(encrypted_result.error(), DTLSError::CIPHER_SUITE_NOT_SUPPORTED)
        << "Should return CIPHER_SUITE_NOT_SUPPORTED error";
}

// Test that encrypted sequence numbers maintain 48-bit constraint
TEST_F(SequenceNumberEncryptionTest, Maintains48BitConstraint) {
    AEADCipher cipher_type = AEADCipher::AES_128_GCM;
    
    // Test multiple sequence numbers
    std::vector<uint64_t> test_sequence_numbers = {
        0x000000000001ULL,
        0x123456789ABCULL,
        0xFFFFFFFFFFFFULL,
        0x800000000000ULL,
        0x555555555555ULL
    };
    
    for (uint64_t seq_num : test_sequence_numbers) {
        auto encrypted_result = utils::encrypt_sequence_number(
            *provider_, seq_num, sequence_number_key_, 
            test_ciphertext_, cipher_type);
        ASSERT_TRUE(encrypted_result.is_success()) 
            << "Failed to encrypt sequence number: " << std::hex << seq_num;
        
        uint64_t encrypted_seq = encrypted_result.value();
        
        // Verify 48-bit constraint
        EXPECT_EQ(encrypted_seq & 0xFFFF000000000000ULL, 0ULL) 
            << "Encrypted sequence number " << std::hex << encrypted_seq 
            << " exceeds 48-bit constraint for input " << seq_num;
    }
}

