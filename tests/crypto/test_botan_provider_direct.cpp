/**
 * @file test_botan_provider_direct.cpp
 * @brief Direct testing of Botan Provider AEAD implementation
 * 
 * Tests the Botan provider directly without going through the factory,
 * to validate our AEAD implementation structure and error handling.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/types.h>
#include <vector>
#include <memory>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class BotanProviderDirectTest : public ::testing::Test {
protected:
    void SetUp() override {
        provider_ = std::make_unique<BotanProvider>();
        
        // Initialize the provider
        auto init_result = provider_->initialize();
        ASSERT_TRUE(init_result) << "Failed to initialize Botan provider";
    }
    
    void TearDown() override {
        if (provider_) {
            provider_->cleanup();
        }
    }
    
    std::unique_ptr<BotanProvider> provider_;
    
    // Helper to get standard test vector
    struct TestVector {
        AEADCipher cipher;
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> additional_data;
    };
    
    TestVector getAES128GCMVector() {
        return {
            AEADCipher::AES_128_GCM,
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // 16-byte key
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b}, // 12-byte nonce
            {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}, // "Hello World"
            {0x41, 0x41, 0x44} // "AAD"
        };
    }
};

// Test provider initialization and basic functionality
TEST_F(BotanProviderDirectTest, ProviderInitialization) {
    EXPECT_EQ(provider_->name(), "botan");
    EXPECT_EQ(provider_->version(), "3.0.0");
    EXPECT_TRUE(provider_->is_available());
    
    auto caps = provider_->capabilities();
    EXPECT_EQ(caps.provider_name, "botan");
    EXPECT_FALSE(caps.supported_cipher_suites.empty());
    EXPECT_FALSE(caps.supported_groups.empty());
    EXPECT_FALSE(caps.supported_signatures.empty());
    EXPECT_FALSE(caps.supported_hashes.empty());
}

// Test AEAD helper functions
TEST_F(BotanProviderDirectTest, HelperFunctions) {
    // Test key length functions
    EXPECT_EQ(provider_->get_aead_key_length(AEADCipher::AES_128_GCM), 16);
    EXPECT_EQ(provider_->get_aead_key_length(AEADCipher::AES_256_GCM), 32);
    EXPECT_EQ(provider_->get_aead_key_length(AEADCipher::CHACHA20_POLY1305), 32);
    EXPECT_EQ(provider_->get_aead_key_length(AEADCipher::AES_128_CCM), 16);
    EXPECT_EQ(provider_->get_aead_key_length(AEADCipher::AES_128_CCM_8), 16);
    
    // Test nonce length functions
    EXPECT_EQ(provider_->get_aead_nonce_length(AEADCipher::AES_128_GCM), 12);
    EXPECT_EQ(provider_->get_aead_nonce_length(AEADCipher::AES_256_GCM), 12);
    EXPECT_EQ(provider_->get_aead_nonce_length(AEADCipher::CHACHA20_POLY1305), 12);
    EXPECT_EQ(provider_->get_aead_nonce_length(AEADCipher::AES_128_CCM), 12);
    EXPECT_EQ(provider_->get_aead_nonce_length(AEADCipher::AES_128_CCM_8), 12);
    
    // Test tag length functions
    EXPECT_EQ(provider_->get_aead_tag_length(AEADCipher::AES_128_GCM), 16);
    EXPECT_EQ(provider_->get_aead_tag_length(AEADCipher::AES_256_GCM), 16);
    EXPECT_EQ(provider_->get_aead_tag_length(AEADCipher::CHACHA20_POLY1305), 16);
    EXPECT_EQ(provider_->get_aead_tag_length(AEADCipher::AES_128_CCM), 16);
    EXPECT_EQ(provider_->get_aead_tag_length(AEADCipher::AES_128_CCM_8), 8); // Truncated tag
}

// Test legacy AEAD encryption/decryption
TEST_F(BotanProviderDirectTest, LegacyAEADInterface) {
    auto vector = getAES128GCMVector();
    
    AEADParams params;
    params.cipher = vector.cipher;
    params.key = vector.key;
    params.nonce = vector.nonce;
    params.additional_data = vector.additional_data;
    
    // Test encryption
    auto encrypt_result = provider_->aead_encrypt(params, vector.plaintext);
    ASSERT_TRUE(encrypt_result) << "AEAD encryption failed";
    
    const auto& ciphertext = encrypt_result.value();
    EXPECT_GT(ciphertext.size(), vector.plaintext.size()) << "Ciphertext should include tag";
    
    // Test decryption
    auto decrypt_result = provider_->aead_decrypt(params, ciphertext);
    ASSERT_TRUE(decrypt_result) << "AEAD decryption failed";
    
    const auto& plaintext = decrypt_result.value();
    EXPECT_EQ(plaintext, vector.plaintext) << "Decrypted plaintext mismatch";
}

// Test new AEAD interface with separate ciphertext and tag
TEST_F(BotanProviderDirectTest, NewAEADInterface) {
    auto vector = getAES128GCMVector();
    
    AEADEncryptionParams encrypt_params;
    encrypt_params.cipher = vector.cipher;
    encrypt_params.key = vector.key;
    encrypt_params.nonce = vector.nonce;
    encrypt_params.plaintext = vector.plaintext;
    encrypt_params.additional_data = vector.additional_data;
    
    // Test encryption
    auto encrypt_result = provider_->encrypt_aead(encrypt_params);
    ASSERT_TRUE(encrypt_result) << "AEAD encryption failed";
    
    const auto& output = encrypt_result.value();
    EXPECT_EQ(output.ciphertext.size(), vector.plaintext.size());
    EXPECT_EQ(output.tag.size(), provider_->get_aead_tag_length(vector.cipher));
    
    // Test decryption
    AEADDecryptionParams decrypt_params;
    decrypt_params.cipher = vector.cipher;
    decrypt_params.key = vector.key;
    decrypt_params.nonce = vector.nonce;
    decrypt_params.ciphertext = output.ciphertext;
    decrypt_params.tag = output.tag;
    decrypt_params.additional_data = vector.additional_data;
    
    auto decrypt_result = provider_->decrypt_aead(decrypt_params);
    ASSERT_TRUE(decrypt_result) << "AEAD decryption failed";
    
    const auto& plaintext = decrypt_result.value();
    EXPECT_EQ(plaintext, vector.plaintext) << "Decrypted plaintext mismatch";
}

// Test parameter validation
TEST_F(BotanProviderDirectTest, ParameterValidation) {
    AEADEncryptionParams params;
    params.cipher = AEADCipher::AES_128_GCM;
    params.plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    
    // Test with invalid key length
    params.key = {0x00, 0x01, 0x02}; // Too short
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    auto result = provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with invalid key length";
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with invalid nonce length
    params.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}; // Correct key
    params.nonce = {0x00, 0x01}; // Too short
    result = provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with invalid nonce length";
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with empty plaintext
    params.nonce = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    params.plaintext.clear();
    result = provider_->encrypt_aead(params);
    EXPECT_FALSE(result) << "Should fail with empty plaintext";
    EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER);
}

// Test authentication failure detection
TEST_F(BotanProviderDirectTest, AuthenticationFailure) {
    auto vector = getAES128GCMVector();
    
    AEADEncryptionParams encrypt_params;
    encrypt_params.cipher = vector.cipher;
    encrypt_params.key = vector.key;
    encrypt_params.nonce = vector.nonce;
    encrypt_params.plaintext = vector.plaintext;
    encrypt_params.additional_data = vector.additional_data;
    
    // Encrypt data
    auto encrypt_result = provider_->encrypt_aead(encrypt_params);
    ASSERT_TRUE(encrypt_result);
    
    const auto& output = encrypt_result.value();
    
    // Test with corrupted tag
    AEADDecryptionParams decrypt_params;
    decrypt_params.cipher = vector.cipher;
    decrypt_params.key = vector.key;
    decrypt_params.nonce = vector.nonce;
    decrypt_params.ciphertext = output.ciphertext;
    decrypt_params.tag = output.tag;
    decrypt_params.additional_data = vector.additional_data;
    
    // Corrupt the tag
    decrypt_params.tag[0] ^= 0x01;
    auto decrypt_result = provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted tag";
    EXPECT_EQ(decrypt_result.error(), DTLSError::DECRYPT_ERROR);
    
    // Test with corrupted ciphertext
    decrypt_params.tag = output.tag; // Restore tag
    decrypt_params.ciphertext[0] ^= 0x01; // Corrupt ciphertext
    decrypt_result = provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted ciphertext";
    EXPECT_EQ(decrypt_result.error(), DTLSError::DECRYPT_ERROR);
    
    // Test with corrupted AAD
    decrypt_params.ciphertext = output.ciphertext; // Restore ciphertext
    decrypt_params.additional_data[0] ^= 0x01; // Corrupt AAD
    decrypt_result = provider_->decrypt_aead(decrypt_params);
    EXPECT_FALSE(decrypt_result) << "Should fail with corrupted AAD";
    EXPECT_EQ(decrypt_result.error(), DTLSError::DECRYPT_ERROR);
}

// Test multiple cipher suites
TEST_F(BotanProviderDirectTest, MultipleCipherSuites) {
    const std::vector<TestVector> test_vectors = {
        // AES-128-GCM
        {
            AEADCipher::AES_128_GCM,
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // 16-byte key
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b}, // 12-byte nonce
            {0x48, 0x65, 0x6c, 0x6c, 0x6f}, // "Hello"
            {0x41, 0x41, 0x44} // "AAD"
        },
        // AES-256-GCM
        {
            AEADCipher::AES_256_GCM,
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, // 32-byte key
            {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
             0x08, 0x09, 0x0a, 0x0b}, // 12-byte nonce
            {0x44, 0x54, 0x4c, 0x53}, // "DTLS"
            {0x52, 0x46, 0x43} // "RFC"
        },
        // ChaCha20-Poly1305
        {
            AEADCipher::CHACHA20_POLY1305,
            {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
             0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
             0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
             0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f}, // 32-byte key
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
             0x04, 0x05, 0x06, 0x07}, // 12-byte nonce
            {0x41, 0x45, 0x41, 0x44}, // "AEAD"
            {0x50, 0x6f, 0x6c, 0x79} // "Poly"
        }
    };
    
    for (const auto& vector : test_vectors) {
        SCOPED_TRACE("Testing cipher: " + std::to_string(static_cast<int>(vector.cipher)));
        
        AEADEncryptionParams encrypt_params;
        encrypt_params.cipher = vector.cipher;
        encrypt_params.key = vector.key;
        encrypt_params.nonce = vector.nonce;
        encrypt_params.plaintext = vector.plaintext;
        encrypt_params.additional_data = vector.additional_data;
        
        auto encrypt_result = provider_->encrypt_aead(encrypt_params);
        ASSERT_TRUE(encrypt_result) << "Encryption failed";
        
        AEADDecryptionParams decrypt_params;
        decrypt_params.cipher = vector.cipher;
        decrypt_params.key = vector.key;
        decrypt_params.nonce = vector.nonce;
        decrypt_params.ciphertext = encrypt_result.value().ciphertext;
        decrypt_params.tag = encrypt_result.value().tag;
        decrypt_params.additional_data = vector.additional_data;
        
        auto decrypt_result = provider_->decrypt_aead(decrypt_params);
        ASSERT_TRUE(decrypt_result) << "Decryption failed";
        EXPECT_EQ(decrypt_result.value(), vector.plaintext);
    }
}

// Test empty additional data
TEST_F(BotanProviderDirectTest, EmptyAdditionalData) {
    auto vector = getAES128GCMVector();
    
    AEADEncryptionParams params;
    params.cipher = vector.cipher;
    params.key = vector.key;
    params.nonce = vector.nonce;
    params.plaintext = vector.plaintext;
    params.additional_data.clear(); // Empty AAD
    
    auto encrypt_result = provider_->encrypt_aead(params);
    ASSERT_TRUE(encrypt_result) << "Encryption with empty AAD should succeed";
    
    AEADDecryptionParams decrypt_params;
    decrypt_params.cipher = params.cipher;
    decrypt_params.key = params.key;
    decrypt_params.nonce = params.nonce;
    decrypt_params.ciphertext = encrypt_result.value().ciphertext;
    decrypt_params.tag = encrypt_result.value().tag;
    decrypt_params.additional_data.clear(); // Empty AAD
    
    auto decrypt_result = provider_->decrypt_aead(decrypt_params);
    ASSERT_TRUE(decrypt_result) << "Decryption with empty AAD should succeed";
    EXPECT_EQ(decrypt_result.value(), params.plaintext);
}

// Test cipher suite support
TEST_F(BotanProviderDirectTest, CipherSuiteSupport) {
    EXPECT_TRUE(provider_->supports_cipher_suite(CipherSuite::TLS_AES_128_GCM_SHA256));
    EXPECT_TRUE(provider_->supports_cipher_suite(CipherSuite::TLS_AES_256_GCM_SHA384));
    EXPECT_TRUE(provider_->supports_cipher_suite(CipherSuite::TLS_CHACHA20_POLY1305_SHA256));
    EXPECT_TRUE(provider_->supports_cipher_suite(CipherSuite::TLS_AES_128_CCM_SHA256));
    EXPECT_TRUE(provider_->supports_cipher_suite(CipherSuite::TLS_AES_128_CCM_8_SHA256));
}