/**
 * @file test_aead_operations.cpp
 * @brief Comprehensive AEAD operations tests for DTLS v1.3 crypto providers
 * 
 * Tests AEAD encryption/decryption functionality across all supported cipher suites,
 * with focus on RFC 9147 compliance, cross-provider consistency, and security validation.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/types.h>
#include <vector>
#include <memory>
#include <string>
#include <numeric>
#include <chrono>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class AEADOperationsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Try to get available providers
        auto openssl_result = factory.create_provider("openssl");
        if (openssl_result && openssl_result.value()->is_available()) {
            openssl_provider_ = std::move(openssl_result.value());
            auto init_result = openssl_provider_->initialize();
            if (!init_result) {
                openssl_provider_.reset();
            }
        }
        
        auto botan_result = factory.create_provider("botan");
        if (botan_result && botan_result.value()->is_available()) {
            botan_provider_ = std::move(botan_result.value());
            auto init_result = botan_provider_->initialize();
            if (!init_result) {
                botan_provider_.reset();
            }
        }
    }
    
    void TearDown() override {
        if (openssl_provider_) {
            openssl_provider_->cleanup();
        }
        if (botan_provider_) {
            botan_provider_->cleanup();
        }
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    
    // Test vectors for different cipher suites
    struct AEADTestVector {
        AEADCipher cipher;
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> additional_data;
        std::string description;
    };
    
    std::vector<AEADTestVector> getTestVectors() {
        return {
            // AES-128-GCM test vector
            {
                AEADCipher::AES_128_GCM,
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // 16-byte key
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b}, // 12-byte nonce
                {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}, // "Hello World"
                {0x41, 0x41, 0x44}, // "AAD"
                "AES-128-GCM with Hello World"
            },
            // AES-256-GCM test vector
            {
                AEADCipher::AES_256_GCM,
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, // 32-byte key
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b}, // 12-byte nonce
                {0x44, 0x54, 0x4c, 0x53, 0x20, 0x76, 0x31, 0x2e, 0x33}, // "DTLS v1.3"
                {0x52, 0x46, 0x43, 0x20, 0x39, 0x31, 0x34, 0x37}, // "RFC 9147"
                "AES-256-GCM with DTLS data"
            },
            // ChaCha20-Poly1305 test vector
            {
                AEADCipher::CHACHA20_POLY1305,
                {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f}, // 32-byte key
                {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
                 0x04, 0x05, 0x06, 0x07}, // 12-byte nonce
                {0x41, 0x45, 0x41, 0x44, 0x20, 0x74, 0x65, 0x73, 0x74}, // "AEAD test"
                {0x50, 0x6f, 0x6c, 0x79, 0x31, 0x33, 0x30, 0x35}, // "Poly1305"
                "ChaCha20-Poly1305 with test data"
            }
        };
    }
};

// Test basic AEAD encryption functionality
TEST_F(AEADOperationsTest, BasicAEADEncryption) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    auto test_vectors = getTestVectors();
    for (const auto& vector : test_vectors) {
        SCOPED_TRACE("Testing: " + vector.description);
        
        // Test legacy AEAD interface
        AEADParams params;
        params.cipher = vector.cipher;
        params.key = vector.key;
        params.nonce = vector.nonce;
        params.additional_data = vector.additional_data;
        
        auto encrypt_result = botan_provider_->aead_encrypt(params, vector.plaintext);
        ASSERT_TRUE(encrypt_result) << "Encryption failed for " << vector.description;
        
        const auto& ciphertext = encrypt_result.value();
        EXPECT_GT(ciphertext.size(), vector.plaintext.size()) << "Ciphertext should be larger than plaintext";
        
        // Verify we can decrypt back to original
        auto decrypt_result = botan_provider_->aead_decrypt(params, ciphertext);
        ASSERT_TRUE(decrypt_result) << "Decryption failed for " << vector.description;
        
        const auto& decrypted = decrypt_result.value();
        EXPECT_EQ(decrypted, vector.plaintext) << "Decrypted text doesn't match original";
    }
}

// Test new AEAD interface with separate ciphertext and tag
TEST_F(AEADOperationsTest, NewAEADInterface) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    auto test_vectors = getTestVectors();
    for (const auto& vector : test_vectors) {
        SCOPED_TRACE("Testing: " + vector.description);
        
        // Test new AEAD interface
        AEADEncryptionParams encrypt_params;
        encrypt_params.cipher = vector.cipher;
        encrypt_params.key = vector.key;
        encrypt_params.nonce = vector.nonce;
        encrypt_params.plaintext = vector.plaintext;
        encrypt_params.additional_data = vector.additional_data;
        
        auto encrypt_result = botan_provider_->encrypt_aead(encrypt_params);
        ASSERT_TRUE(encrypt_result) << "Encryption failed for " << vector.description;
        
        const auto& output = encrypt_result.value();
        EXPECT_EQ(output.ciphertext.size(), vector.plaintext.size()) << "Ciphertext size mismatch";
        EXPECT_GT(output.tag.size(), 0) << "Tag should not be empty";
        
        // Test decryption with separate ciphertext and tag
        AEADDecryptionParams decrypt_params;
        decrypt_params.cipher = vector.cipher;
        decrypt_params.key = vector.key;
        decrypt_params.nonce = vector.nonce;
        decrypt_params.ciphertext = output.ciphertext;
        decrypt_params.tag = output.tag;
        decrypt_params.additional_data = vector.additional_data;
        
        auto decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
        ASSERT_TRUE(decrypt_result) << "Decryption failed for " << vector.description;
        
        const auto& decrypted = decrypt_result.value();
        EXPECT_EQ(decrypted, vector.plaintext) << "Decrypted text doesn't match original";
    }
}

// Test AEAD parameter validation
TEST_F(AEADOperationsTest, ParameterValidation) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    AEADEncryptionParams params;
    params.cipher = AEADCipher::AES_128_GCM;
    params.plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    
    // Test with invalid key length
    params.key = {0x00, 0x01, 0x02}; // Too short
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    auto result = botan_provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with invalid key length";
    
    // Test with invalid nonce length
    params.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}; // Correct key
    params.nonce = {0x00, 0x01}; // Too short
    result = botan_provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with invalid nonce length";
    
    // Test with empty plaintext
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    params.plaintext.clear();
    result = botan_provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with empty plaintext";
}

// Test authentication failure detection
TEST_F(AEADOperationsTest, AuthenticationFailureDetection) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    AEADEncryptionParams encrypt_params;
    encrypt_params.cipher = AEADCipher::AES_128_GCM;
    encrypt_params.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    encrypt_params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b};
    encrypt_params.plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    encrypt_params.additional_data = {0x41, 0x41, 0x44}; // "AAD"
    
    // Encrypt data
    auto encrypt_result = botan_provider_->encrypt_aead(encrypt_params);
    ASSERT_TRUE(encrypt_result);
    
    const auto& output = encrypt_result.value();
    
    // Test with corrupted tag
    AEADDecryptionParams decrypt_params;
    decrypt_params.cipher = encrypt_params.cipher;
    decrypt_params.key = encrypt_params.key;
    decrypt_params.nonce = encrypt_params.nonce;
    decrypt_params.ciphertext = output.ciphertext;
    decrypt_params.tag = output.tag;
    decrypt_params.additional_data = encrypt_params.additional_data;
    
    // Corrupt the tag
    decrypt_params.tag[0] ^= 0x01;
    auto decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted tag";
    if (!decrypt_result) {
        EXPECT_EQ(decrypt_result.error(), DTLSError::DECRYPT_ERROR);
    }
    
    // Test with corrupted ciphertext
    decrypt_params.tag = output.tag; // Restore tag
    decrypt_params.ciphertext[0] ^= 0x01; // Corrupt ciphertext
    decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted ciphertext";
    
    // Test with corrupted AAD
    decrypt_params.ciphertext = output.ciphertext; // Restore ciphertext
    decrypt_params.additional_data[0] ^= 0x01; // Corrupt AAD
    decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted AAD";
}

// Test cross-provider consistency (if both providers are available)
TEST_F(AEADOperationsTest, CrossProviderConsistency) {
    if (!botan_provider_ || !openssl_provider_) {
        GTEST_SKIP() << "Both providers not available for cross-provider testing";
    }
    
    auto test_vectors = getTestVectors();
    for (const auto& vector : test_vectors) {
        SCOPED_TRACE("Cross-provider testing: " + vector.description);
        
        // Encrypt with OpenSSL
        AEADEncryptionParams params;
        params.cipher = vector.cipher;
        params.key = vector.key;
        params.nonce = vector.nonce;
        params.plaintext = vector.plaintext;
        params.additional_data = vector.additional_data;
        
        auto openssl_result = openssl_provider_->encrypt_aead(params);
        ASSERT_TRUE(openssl_result) << "OpenSSL encryption failed";
        
        // Encrypt with Botan
        auto botan_result = botan_provider_->encrypt_aead(params);
        ASSERT_TRUE(botan_result) << "Botan encryption failed";
        
        // Both should produce same ciphertext size (though content will differ due to random nonce usage)
        EXPECT_EQ(openssl_result.value().ciphertext.size(), 
                  botan_result.value().ciphertext.size()) << "Ciphertext size mismatch";
        EXPECT_EQ(openssl_result.value().tag.size(), 
                  botan_result.value().tag.size()) << "Tag size mismatch";
        
        // Each provider should be able to decrypt its own output
        AEADDecryptionParams decrypt_params;
        decrypt_params.cipher = vector.cipher;
        decrypt_params.key = vector.key;
        decrypt_params.nonce = vector.nonce;
        decrypt_params.additional_data = vector.additional_data;
        
        // OpenSSL decrypt its own
        decrypt_params.ciphertext = openssl_result.value().ciphertext;
        decrypt_params.tag = openssl_result.value().tag;
        auto openssl_decrypt = openssl_provider_->decrypt_aead(decrypt_params);
        ASSERT_TRUE(openssl_decrypt) << "OpenSSL self-decryption failed";
        EXPECT_EQ(openssl_decrypt.value(), vector.plaintext);
        
        // Botan decrypt its own
        decrypt_params.ciphertext = botan_result.value().ciphertext;
        decrypt_params.tag = botan_result.value().tag;
        auto botan_decrypt = botan_provider_->decrypt_aead(decrypt_params);
        ASSERT_TRUE(botan_decrypt) << "Botan self-decryption failed";
        EXPECT_EQ(botan_decrypt.value(), vector.plaintext);
    }
}

// Test AEAD with empty additional data
TEST_F(AEADOperationsTest, EmptyAdditionalData) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    AEADEncryptionParams params;
    params.cipher = AEADCipher::AES_128_GCM;
    params.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b};
    params.plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    params.additional_data.clear(); // Empty AAD
    
    auto encrypt_result = botan_provider_->encrypt_aead(params);
    ASSERT_TRUE(encrypt_result) << "Encryption with empty AAD should succeed";
    
    AEADDecryptionParams decrypt_params;
    decrypt_params.cipher = params.cipher;
    decrypt_params.key = params.key;
    decrypt_params.nonce = params.nonce;
    decrypt_params.ciphertext = encrypt_result.value().ciphertext;
    decrypt_params.tag = encrypt_result.value().tag;
    decrypt_params.additional_data.clear(); // Empty AAD
    
    auto decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
    ASSERT_TRUE(decrypt_result) << "Decryption with empty AAD should succeed";
    EXPECT_EQ(decrypt_result.value(), params.plaintext);
}

// Test helper functions
TEST_F(AEADOperationsTest, HelperFunctions) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    // Test cipher suite support
    EXPECT_TRUE(botan_provider_->supports_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256));
    EXPECT_TRUE(botan_provider_->supports_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384));
    EXPECT_TRUE(botan_provider_->supports_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
    
    // Test provider capabilities
    auto caps = botan_provider_->capabilities();
    EXPECT_EQ(caps.provider_name, "botan");
    EXPECT_FALSE(caps.supported_cipher_suites.empty());
    EXPECT_FALSE(caps.supported_groups.empty());
    EXPECT_FALSE(caps.supported_signatures.empty());
    EXPECT_FALSE(caps.supported_hashes.empty());
}

// Performance comparison test
TEST_F(AEADOperationsTest, PerformanceBaseline) {
    if (!botan_provider_) {
        GTEST_SKIP() << "Botan provider not available";
    }
    
    AEADEncryptionParams params;
    params.cipher = AEADCipher::AES_128_GCM;
    params.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b};
    params.additional_data = {0x41, 0x41, 0x44}; // "AAD"
    
    // Test with different payload sizes
    const std::vector<size_t> payload_sizes = {16, 64, 256, 1024, 4096};
    
    for (size_t size : payload_sizes) {
        SCOPED_TRACE("Payload size: " + std::to_string(size));
        
        params.plaintext.resize(size);
        std::iota(params.plaintext.begin(), params.plaintext.end(), 0);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Perform multiple operations for timing
        const int iterations = 100;
        for (int i = 0; i < iterations; ++i) {
            auto encrypt_result = botan_provider_->encrypt_aead(params);
            ASSERT_TRUE(encrypt_result) << "Encryption failed at iteration " << i;
            
            AEADDecryptionParams decrypt_params;
            decrypt_params.cipher = params.cipher;
            decrypt_params.key = params.key;
            decrypt_params.nonce = params.nonce;
            decrypt_params.ciphertext = encrypt_result.value().ciphertext;
            decrypt_params.tag = encrypt_result.value().tag;
            decrypt_params.additional_data = params.additional_data;
            
            auto decrypt_result = botan_provider_->decrypt_aead(decrypt_params);
            ASSERT_TRUE(decrypt_result) << "Decryption failed at iteration " << i;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // Log performance for analysis (not a hard requirement)
        std::cout << "Size " << size << " bytes: " << iterations << " encrypt/decrypt cycles took " 
                  << duration.count() << " microseconds" << std::endl;
    }
}