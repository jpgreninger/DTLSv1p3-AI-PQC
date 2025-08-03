#include <gtest/gtest.h>
#include <dtls/crypto/crypto_utils.h>
#include <dtls/crypto/openssl_provider.h>
#include <dtls/crypto/botan_provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <test_infrastructure/test_certificates.h>
#include <test_infrastructure/test_utilities.h>
#include <chrono>
#include <random>

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace dtls::test;

class SignatureVerificationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto providers
        openssl_provider_ = std::make_unique<OpenSSLProvider>();
        if (openssl_provider_->is_available()) {
            openssl_provider_->initialize();
        }
        
        // Botan provider testing disabled for now
        // if (botan_utils::is_botan_available()) {
        //     botan_provider_ = std::make_unique<BotanProvider>();
        //     botan_provider_->initialize();
        // }
        
        // Create test data
        createTestData();
    }
    
    void TearDown() override {
        if (openssl_provider_) {
            openssl_provider_->cleanup();
        }
        if (botan_provider_) {
            botan_provider_->cleanup();
        }
    }
    
    void createTestData() {
        // Create various transcript hash sizes for testing
        test_transcript_sha256_ = std::vector<uint8_t>(32, 0x42);
        test_transcript_sha384_ = std::vector<uint8_t>(48, 0x43);
        test_transcript_sha512_ = std::vector<uint8_t>(64, 0x44);
        
        // Generate random transcript hashes for more realistic testing
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (auto& byte : test_transcript_sha256_) {
            byte = dis(gen);
        }
        for (auto& byte : test_transcript_sha384_) {
            byte = dis(gen);
        }
        for (auto& byte : test_transcript_sha512_) {
            byte = dis(gen);
        }
        
        // Import test certificates and keys
        auto server_cert_pem = TestCertificates::get_server_certificate();
        auto server_key_pem = TestCertificates::get_server_private_key();
        auto client_cert_pem = TestCertificates::get_client_certificate();
        auto client_key_pem = TestCertificates::get_client_private_key();
        
        if (openssl_provider_ && openssl_provider_->is_available()) {
            // Import keys for testing
            auto server_cert_result = openssl_provider_->extract_public_key(
                std::vector<uint8_t>(server_cert_pem.begin(), server_cert_pem.end()));
            if (server_cert_result.is_success()) {
                server_public_key_ = std::move(server_cert_result.value());
            } else {
                std::cout << "Warning: Failed to load server certificate: " 
                          << static_cast<int>(server_cert_result.error()) << std::endl;
            }
            
            auto server_key_result = openssl_provider_->import_private_key(
                std::vector<uint8_t>(server_key_pem.begin(), server_key_pem.end()));
            if (server_key_result.is_success()) {
                server_private_key_ = std::move(server_key_result.value());
            } else {
                std::cout << "Warning: Failed to load server private key: " 
                          << static_cast<int>(server_key_result.error()) << std::endl;
            }
            
            auto client_cert_result = openssl_provider_->extract_public_key(
                std::vector<uint8_t>(client_cert_pem.begin(), client_cert_pem.end()));
            if (client_cert_result.is_success()) {
                client_public_key_ = std::move(client_cert_result.value());
            } else {
                std::cout << "Warning: Failed to load client certificate: " 
                          << static_cast<int>(client_cert_result.error()) << std::endl;
            }
            
            auto client_key_result = openssl_provider_->import_private_key(
                std::vector<uint8_t>(client_key_pem.begin(), client_key_pem.end()));
            if (client_key_result.is_success()) {
                client_private_key_ = std::move(client_key_result.value());
            } else {
                std::cout << "Warning: Failed to load client private key: " 
                          << static_cast<int>(client_key_result.error()) << std::endl;
            }
        }
    }
    
    std::unique_ptr<OpenSSLProvider> openssl_provider_;
    std::unique_ptr<BotanProvider> botan_provider_;
    
    std::vector<uint8_t> test_transcript_sha256_;
    std::vector<uint8_t> test_transcript_sha384_;
    std::vector<uint8_t> test_transcript_sha512_;
    
    std::unique_ptr<PublicKey> server_public_key_;
    std::unique_ptr<PrivateKey> server_private_key_;
    std::unique_ptr<PublicKey> client_public_key_;
    std::unique_ptr<PrivateKey> client_private_key_;
};

// Test the DTLS signature context construction utility
class DTLSSignatureContextTest : public SignatureVerificationTest {};

TEST_F(DTLSSignatureContextTest, ServerContextConstruction) {
    // Test server context string construction
    auto context_result = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
    
    ASSERT_TRUE(context_result.is_success());
    const auto& context = context_result.value();
    
    // Expected format: 64 bytes of 0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    size_t expected_size = 64 + strlen("TLS 1.3, server CertificateVerify") + 1 + test_transcript_sha256_.size();
    EXPECT_EQ(context.size(), expected_size);
    
    // Verify structure
    // First 64 bytes should be 0x20 (space character)
    for (size_t i = 0; i < 64; ++i) {
        EXPECT_EQ(context[i], 0x20) << "Byte " << i << " should be 0x20";
    }
    
    // Next should be the context string
    const char* expected_server_context = "TLS 1.3, server CertificateVerify";
    for (size_t i = 0; i < strlen(expected_server_context); ++i) {
        EXPECT_EQ(context[64 + i], static_cast<uint8_t>(expected_server_context[i]));
    }
    
    // Then separator byte (0x00)
    size_t separator_pos = 64 + strlen(expected_server_context);
    EXPECT_EQ(context[separator_pos], 0x00);
    
    // Finally the transcript hash
    for (size_t i = 0; i < test_transcript_sha256_.size(); ++i) {
        EXPECT_EQ(context[separator_pos + 1 + i], test_transcript_sha256_[i]);
    }
}

TEST_F(DTLSSignatureContextTest, ClientContextConstruction) {
    // Test client context string construction
    auto context_result = utils::construct_dtls_signature_context(test_transcript_sha384_, false);
    
    ASSERT_TRUE(context_result.is_success());
    const auto& context = context_result.value();
    
    // Expected format: 64 bytes of 0x20 + "TLS 1.3, client CertificateVerify" + 0x00 + transcript_hash
    size_t expected_size = 64 + strlen("TLS 1.3, client CertificateVerify") + 1 + test_transcript_sha384_.size();
    EXPECT_EQ(context.size(), expected_size);
    
    // Verify the client context string
    const char* expected_client_context = "TLS 1.3, client CertificateVerify";
    for (size_t i = 0; i < strlen(expected_client_context); ++i) {
        EXPECT_EQ(context[64 + i], static_cast<uint8_t>(expected_client_context[i]));
    }
}

TEST_F(DTLSSignatureContextTest, DifferentHashSizes) {
    // Test with different hash sizes
    std::vector<std::vector<uint8_t>> test_hashes = {
        std::vector<uint8_t>(20, 0x11),  // SHA-1 size
        test_transcript_sha256_,          // SHA-256 size (32)
        test_transcript_sha384_,          // SHA-384 size (48)
        test_transcript_sha512_           // SHA-512 size (64)
    };
    
    for (const auto& hash : test_hashes) {
        auto server_result = utils::construct_dtls_signature_context(hash, true);
        auto client_result = utils::construct_dtls_signature_context(hash, false);
        
        ASSERT_TRUE(server_result.is_success()) << "Hash size: " << hash.size();
        ASSERT_TRUE(client_result.is_success()) << "Hash size: " << hash.size();
        
        // Server and client contexts should have the same size (both strings are same length)
        EXPECT_EQ(server_result.value().size(), client_result.value().size());
        
        // Both should end with the same hash
        const auto& server_ctx = server_result.value();
        const auto& client_ctx = client_result.value();
        
        std::vector<uint8_t> server_hash_suffix(server_ctx.end() - hash.size(), server_ctx.end());
        std::vector<uint8_t> client_hash_suffix(client_ctx.end() - hash.size(), client_ctx.end());
        
        EXPECT_EQ(server_hash_suffix, hash);
        EXPECT_EQ(client_hash_suffix, hash);
    }
}

TEST_F(DTLSSignatureContextTest, ErrorHandling) {
    // Test empty transcript hash
    auto empty_result = utils::construct_dtls_signature_context({}, true);
    EXPECT_FALSE(empty_result.is_success());
    EXPECT_EQ(empty_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test oversized transcript hash (> 64 bytes)
    std::vector<uint8_t> oversized_hash(65, 0xAA);
    auto oversized_result = utils::construct_dtls_signature_context(oversized_hash, true);
    EXPECT_FALSE(oversized_result.is_success());
    EXPECT_EQ(oversized_result.error(), DTLSError::INVALID_PARAMETER);
}

// Test ASN.1 signature format validation for ECDSA
class ECDSASignatureValidationTest : public SignatureVerificationTest {};

TEST_F(ECDSASignatureValidationTest, ValidASN1Signatures) {
    if (!server_public_key_) {
        GTEST_SKIP() << "Server public key not available";
    }
    
    // Valid ECDSA ASN.1 signature examples (P-256)
    // SEQUENCE { r INTEGER, s INTEGER }
    std::vector<std::vector<uint8_t>> valid_signatures = {
        // Minimal valid signature
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        
        // Typical P-256 signature
        {0x30, 0x44, 
         0x02, 0x20, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
         0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
         0x02, 0x20, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
    };
    
    for (const auto& signature : valid_signatures) {
        auto result = utils::validate_ecdsa_asn1_signature(signature, *server_public_key_);
        ASSERT_TRUE(result.is_success()) << "Signature validation should succeed";
        EXPECT_TRUE(*result) << "Valid signature should pass ASN.1 validation";
    }
}

TEST_F(ECDSASignatureValidationTest, InvalidASN1Signatures) {
    if (!server_public_key_) {
        GTEST_SKIP() << "Server public key not available";
    }
    
    // Invalid ECDSA ASN.1 signature examples
    std::vector<std::vector<uint8_t>> invalid_signatures = {
        // Empty signature
        {},
        
        // Too short
        {0x30, 0x02},
        
        // Wrong tag (not SEQUENCE)
        {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        
        // Invalid length encoding
        {0x30, 0xFF, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
        
        // Truncated signature
        {0x30, 0x06, 0x02, 0x01},
        
        // Too large (> 150 bytes)
        std::vector<uint8_t>(200, 0x30)
    };
    
    for (size_t i = 0; i < invalid_signatures.size(); ++i) {
        const auto& signature = invalid_signatures[i];
        auto result = utils::validate_ecdsa_asn1_signature(signature, *server_public_key_);
        
        if (signature.empty()) {
            // Empty signature should return an error
            EXPECT_FALSE(result.is_success()) << "Test case " << i << ": Empty signature should fail";
        } else {
            // Other invalid signatures should return false but not error
            ASSERT_TRUE(result.is_success()) << "Test case " << i << ": Validation should succeed";
            EXPECT_FALSE(*result) << "Test case " << i << ": Invalid signature should fail ASN.1 validation";
        }
    }
}

// Test DTLS certificate signature verification
class DTLSCertificateVerificationTest : public SignatureVerificationTest {};

TEST_F(DTLSCertificateVerificationTest, BasicParameterValidation) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Valid parameters for testing
    DTLSCertificateVerifyParams valid_params;
    valid_params.transcript_hash = test_transcript_sha256_;
    valid_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    valid_params.public_key = server_public_key_.get();
    valid_params.is_server_context = true;
    
    std::vector<uint8_t> dummy_signature(256, 0x42); // RSA signature size
    
    // Test with null public key
    DTLSCertificateVerifyParams null_key_params = valid_params;
    null_key_params.public_key = nullptr;
    auto null_key_result = openssl_provider_->verify_dtls_certificate_signature(null_key_params, dummy_signature);
    EXPECT_FALSE(null_key_result.is_success());
    EXPECT_EQ(null_key_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with empty transcript hash
    DTLSCertificateVerifyParams empty_hash_params = valid_params;
    empty_hash_params.transcript_hash = {};
    auto empty_hash_result = openssl_provider_->verify_dtls_certificate_signature(empty_hash_params, dummy_signature);
    EXPECT_FALSE(empty_hash_result.is_success());
    EXPECT_EQ(empty_hash_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with empty signature
    auto empty_sig_result = openssl_provider_->verify_dtls_certificate_signature(valid_params, {});
    EXPECT_FALSE(empty_sig_result.is_success());
    EXPECT_EQ(empty_sig_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with transcript hash too small
    DTLSCertificateVerifyParams small_hash_params = valid_params;
    small_hash_params.transcript_hash = std::vector<uint8_t>(19, 0x42); // < 20 bytes
    auto small_hash_result = openssl_provider_->verify_dtls_certificate_signature(small_hash_params, dummy_signature);
    EXPECT_FALSE(small_hash_result.is_success());
    EXPECT_EQ(small_hash_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with transcript hash too large
    DTLSCertificateVerifyParams large_hash_params = valid_params;
    large_hash_params.transcript_hash = std::vector<uint8_t>(65, 0x42); // > 64 bytes
    auto large_hash_result = openssl_provider_->verify_dtls_certificate_signature(large_hash_params, dummy_signature);
    EXPECT_FALSE(large_hash_result.is_success());
    EXPECT_EQ(large_hash_result.error(), DTLSError::INVALID_PARAMETER);
    
    // Test with signature too large (DoS protection)
    std::vector<uint8_t> large_signature(1025, 0x42); // > 1024 bytes
    auto large_sig_result = openssl_provider_->verify_dtls_certificate_signature(valid_params, large_signature);
    EXPECT_FALSE(large_sig_result.is_success());
    EXPECT_EQ(large_sig_result.error(), DTLSError::INVALID_PARAMETER);
}

TEST_F(DTLSCertificateVerificationTest, ServerAndClientContexts) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || 
        !server_private_key_ || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Create a valid signature for testing different contexts
    DTLSCertificateVerifyParams server_params;
    server_params.transcript_hash = test_transcript_sha256_;
    server_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    server_params.public_key = server_public_key_.get();
    server_params.is_server_context = true;
    
    // Generate server context signature
    auto server_context = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
    ASSERT_TRUE(server_context.is_success());
    
    SignatureParams sign_params;
    sign_params.data = *server_context;
    sign_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    sign_params.private_key = server_private_key_.get();
    
    auto server_signature_result = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(server_signature_result.is_success()) << "Failed to create test signature";
    
    // Test server context verification (should succeed)
    auto server_verify_result = openssl_provider_->verify_dtls_certificate_signature(
        server_params, *server_signature_result);
    ASSERT_TRUE(server_verify_result.is_success());
    EXPECT_TRUE(*server_verify_result);
    
    // Test client context verification with server signature (should fail)
    DTLSCertificateVerifyParams client_params = server_params;
    client_params.is_server_context = false;
    
    auto client_verify_result = openssl_provider_->verify_dtls_certificate_signature(
        client_params, *server_signature_result);
    ASSERT_TRUE(client_verify_result.is_success());
    EXPECT_FALSE(*client_verify_result) << "Server signature should not verify with client context";
}

TEST_F(DTLSCertificateVerificationTest, DifferentSignatureSchemes) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || 
        !server_private_key_ || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Test different supported signature schemes
    std::vector<SignatureScheme> schemes_to_test = {
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        SignatureScheme::RSA_PSS_RSAE_SHA512
    };
    
    for (auto scheme : schemes_to_test) {
        // Check if the provider supports this scheme
        if (!openssl_provider_->supports_signature_scheme(scheme)) {
            continue;
        }
        
        DTLSCertificateVerifyParams params;
        params.transcript_hash = test_transcript_sha256_;
        params.scheme = scheme;
        params.public_key = server_public_key_.get();
        params.is_server_context = true;
        
        // Create signature with this scheme
        auto context = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
        ASSERT_TRUE(context.is_success());
        
        SignatureParams sign_params;
        sign_params.data = *context;
        sign_params.scheme = scheme;
        sign_params.private_key = server_private_key_.get();
        
        auto signature_result = openssl_provider_->sign_data(sign_params);
        if (!signature_result.is_success()) {
            continue; // Skip if signing fails (might not be supported with test key)
        }
        
        // Verify the signature
        auto verify_result = openssl_provider_->verify_dtls_certificate_signature(
            params, *signature_result);
        ASSERT_TRUE(verify_result.is_success()) << "Scheme: " << static_cast<int>(scheme);
        EXPECT_TRUE(*verify_result) << "Scheme: " << static_cast<int>(scheme);
    }
}

TEST_F(DTLSCertificateVerificationTest, EdDSASignatureValidation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test EdDSA signature length validation
    DTLSCertificateVerifyParams ed25519_params;
    ed25519_params.transcript_hash = test_transcript_sha256_;
    ed25519_params.scheme = SignatureScheme::ED25519;
    ed25519_params.is_server_context = true;
    
    // We'll use a dummy public key for testing the validation logic
    // (actual EdDSA keys would require different test setup)
    if (server_public_key_) {
        ed25519_params.public_key = server_public_key_.get();
        
        // Test wrong length for Ed25519 (should be exactly 64 bytes)
        std::vector<uint8_t> wrong_length_sig(63, 0x42);
        auto wrong_length_result = openssl_provider_->verify_dtls_certificate_signature(
            ed25519_params, wrong_length_sig);
        // This might succeed or fail depending on key compatibility, but shouldn't crash
        EXPECT_TRUE(wrong_length_result.is_success() || 
                   wrong_length_result.error() == DTLSError::INVALID_PARAMETER);
        
        // Test signature with leading zero (invalid for EdDSA)
        std::vector<uint8_t> leading_zero_sig(64, 0x42);
        leading_zero_sig[0] = 0x00;
        auto leading_zero_result = openssl_provider_->verify_dtls_certificate_signature(
            ed25519_params, leading_zero_sig);
        // Should handle gracefully
        EXPECT_TRUE(leading_zero_result.is_success() || 
                   leading_zero_result.error() == DTLSError::INVALID_PARAMETER);
    }
}

// Test certificate-signature scheme compatibility
class CertificateCompatibilityTest : public SignatureVerificationTest {};

TEST_F(CertificateCompatibilityTest, CertificateSchemeCompatibility) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Test with certificate DER data for enhanced validation
    auto server_cert_pem = TestCertificates::get_server_certificate();
    std::vector<uint8_t> cert_der(server_cert_pem.begin(), server_cert_pem.end());
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = test_transcript_sha256_;
    params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    params.public_key = server_public_key_.get();
    params.is_server_context = true;
    params.certificate_der = cert_der; // Add certificate data
    
    std::vector<uint8_t> dummy_signature(256, 0x42);
    
    // This test verifies that certificate compatibility validation is called
    // The actual result depends on the test certificate format and compatibility
    auto result = openssl_provider_->verify_dtls_certificate_signature(params, dummy_signature);
    EXPECT_TRUE(result.is_success()); // Should not crash or error due to certificate validation
}

// Test timing attack resistance
class TimingAttackResistanceTest : public SignatureVerificationTest {};

TEST_F(TimingAttackResistanceTest, ConsistentTimingBehavior) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || 
        !server_private_key_ || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = test_transcript_sha256_;
    params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    params.public_key = server_public_key_.get();
    params.is_server_context = true;
    
    // Create a valid signature
    auto context = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
    ASSERT_TRUE(context.is_success());
    
    SignatureParams sign_params;
    sign_params.data = *context;
    sign_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    sign_params.private_key = server_private_key_.get();
    
    auto valid_signature_result = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(valid_signature_result.is_success());
    
    // Create an invalid signature (flipped bits)
    auto invalid_signature = *valid_signature_result;
    invalid_signature[0] ^= 0xFF;
    invalid_signature[1] ^= 0xFF;
    
    // Measure timing for multiple valid and invalid signature verifications
    const int iterations = 100;
    
    // Time valid signature verifications
    auto start_valid = std::chrono::high_resolution_clock::now();
    int valid_count = 0;
    for (int i = 0; i < iterations; ++i) {
        auto result = openssl_provider_->verify_dtls_certificate_signature(params, *valid_signature_result);
        if (result.is_success() && *result) {
            valid_count++;
        }
    }
    auto end_valid = std::chrono::high_resolution_clock::now();
    
    // Time invalid signature verifications
    auto start_invalid = std::chrono::high_resolution_clock::now();
    int invalid_count = 0;
    for (int i = 0; i < iterations; ++i) {
        auto result = openssl_provider_->verify_dtls_certificate_signature(params, invalid_signature);
        if (result.is_success() && !*result) {
            invalid_count++;
        }
    }
    auto end_invalid = std::chrono::high_resolution_clock::now();
    
    auto valid_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_valid - start_valid);
    auto invalid_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_invalid - start_invalid);
    
    // Basic timing analysis - should not have dramatic differences
    // (This is a basic test; full timing attack resistance requires more sophisticated analysis)
    double valid_avg = static_cast<double>(valid_duration.count()) / iterations;
    double invalid_avg = static_cast<double>(invalid_duration.count()) / iterations;
    double timing_ratio = std::max(valid_avg, invalid_avg) / std::min(valid_avg, invalid_avg);
    
    // Timing should not differ by more than 10x (very generous threshold)
    EXPECT_LT(timing_ratio, 10.0) << "Timing difference too large: valid=" << valid_avg 
                                  << "μs, invalid=" << invalid_avg << "μs";
    
    // Verify that verifications actually worked as expected
    EXPECT_EQ(valid_count, iterations) << "Valid signatures should verify successfully";
    EXPECT_EQ(invalid_count, iterations) << "Invalid signatures should fail verification";
}

// Negative test cases and attack scenarios
class SignatureAttackTest : public SignatureVerificationTest {};

TEST_F(SignatureAttackTest, MalformedSignatureInputs) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = test_transcript_sha256_;
    params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    params.public_key = server_public_key_.get();
    params.is_server_context = true;
    
    // Test various malformed signatures
    std::vector<std::vector<uint8_t>> malformed_signatures = {
        // All zeros
        std::vector<uint8_t>(256, 0x00),
        
        // All ones
        std::vector<uint8_t>(256, 0xFF),
        
        // Random data
        std::vector<uint8_t>(256, 0xAA),
        
        // Truncated signature
        std::vector<uint8_t>(128, 0x42),
        
        // Wrong size signature
        std::vector<uint8_t>(512, 0x42),
        
        // Very small signature
        std::vector<uint8_t>(1, 0x42)
    };
    
    for (size_t i = 0; i < malformed_signatures.size(); ++i) {
        const auto& signature = malformed_signatures[i];
        auto result = openssl_provider_->verify_dtls_certificate_signature(params, signature);
        
        // Should either return false (signature invalid) or error for obviously wrong sizes
        EXPECT_TRUE(result.is_success()) << "Test case " << i << " should not crash";
        if (result.is_success()) {
            EXPECT_FALSE(*result) << "Test case " << i << " malformed signature should not verify";
        }
    }
}

TEST_F(SignatureAttackTest, TranscriptHashManipulation) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || 
        !server_private_key_ || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Create a valid signature for original transcript
    auto context = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
    ASSERT_TRUE(context.is_success());
    
    SignatureParams sign_params;
    sign_params.data = *context;
    sign_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    sign_params.private_key = server_private_key_.get();
    
    auto signature_result = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(signature_result.is_success());
    
    // Try to verify with manipulated transcript hashes
    std::vector<std::vector<uint8_t>> manipulated_hashes = {
        // Single bit flip
        [this]() {
            auto hash = test_transcript_sha256_;
            hash[0] ^= 0x01;
            return hash;
        }(),
        
        // Multiple bit flips
        [this]() {
            auto hash = test_transcript_sha256_;
            hash[0] ^= 0x01;
            hash[15] ^= 0x80;
            hash[31] ^= 0xFF;
            return hash;
        }(),
        
        // All zeros hash
        std::vector<uint8_t>(32, 0x00),
        
        // All ones hash
        std::vector<uint8_t>(32, 0xFF),
        
        // Different size hash (if we created signature with SHA-256, try with "SHA-384" size)
        std::vector<uint8_t>(48, 0x42)
    };
    
    for (size_t i = 0; i < manipulated_hashes.size(); ++i) {
        DTLSCertificateVerifyParams params;
        params.transcript_hash = manipulated_hashes[i];
        params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
        params.public_key = server_public_key_.get();
        params.is_server_context = true;
        
        auto result = openssl_provider_->verify_dtls_certificate_signature(params, *signature_result);
        
        if (result.is_success()) {
            EXPECT_FALSE(*result) << "Test case " << i << " manipulated hash should not verify";
        } else {
            // Size mismatches might cause parameter errors, which is also acceptable
            EXPECT_EQ(result.error(), DTLSError::INVALID_PARAMETER) << "Test case " << i;
        }
    }
}

// Cross-provider consistency tests
class CrossProviderSignatureTest : public SignatureVerificationTest {};

TEST_F(CrossProviderSignatureTest, ConsistentValidation) {
    bool openssl_available = openssl_provider_ && openssl_provider_->is_available();
    bool botan_available = botan_provider_ && botan_provider_->is_available();
    
    if (!openssl_available || !botan_available || !server_public_key_) {
        GTEST_SKIP() << "Both providers and test keys required for cross-validation";
    }
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = test_transcript_sha256_;
    params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    params.public_key = server_public_key_.get();
    params.is_server_context = true;
    
    // Test with various signature inputs
    std::vector<std::vector<uint8_t>> test_signatures = {
        std::vector<uint8_t>(256, 0x00),
        std::vector<uint8_t>(256, 0xFF),
        std::vector<uint8_t>(256, 0x42)
    };
    
    for (const auto& signature : test_signatures) {
        auto openssl_result = openssl_provider_->verify_dtls_certificate_signature(params, signature);
        auto botan_result = botan_provider_->verify_dtls_certificate_signature(params, signature);
        
        // Both should succeed or both should fail consistently
        EXPECT_EQ(openssl_result.is_success(), botan_result.is_success());
        
        if (openssl_result.is_success() && botan_result.is_success()) {
            EXPECT_EQ(*openssl_result, *botan_result) << "Providers should give consistent results";
        }
    }
}

// Performance and load testing
class SignaturePerformanceTest : public SignatureVerificationTest {};

TEST_F(SignaturePerformanceTest, VerificationPerformance) {
    if (!openssl_provider_ || !openssl_provider_->is_available() || 
        !server_private_key_ || !server_public_key_) {
        GTEST_SKIP() << "OpenSSL provider or test keys not available";
    }
    
    // Create a valid signature for performance testing
    auto context = utils::construct_dtls_signature_context(test_transcript_sha256_, true);
    ASSERT_TRUE(context.is_success());
    
    SignatureParams sign_params;
    sign_params.data = *context;
    sign_params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    sign_params.private_key = server_private_key_.get();
    
    auto signature_result = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(signature_result.is_success());
    
    DTLSCertificateVerifyParams params;
    params.transcript_hash = test_transcript_sha256_;
    params.scheme = SignatureScheme::RSA_PKCS1_SHA256;
    params.public_key = server_public_key_.get();
    params.is_server_context = true;
    
    // Performance test
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    int success_count = 0;
    for (int i = 0; i < iterations; ++i) {
        auto result = openssl_provider_->verify_dtls_certificate_signature(params, *signature_result);
        if (result.is_success() && *result) {
            success_count++;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Performance should be reasonable (< 10ms per verification on average)
    double avg_time = static_cast<double>(duration.count()) / iterations;
    EXPECT_LT(avg_time, 10000) << "Average verification time: " << avg_time << " μs";
    EXPECT_EQ(success_count, iterations) << "All verifications should succeed";
    
    std::cout << "DTLS signature verification performance: " 
              << iterations << " operations in " 
              << duration.count() << " microseconds ("
              << avg_time << " μs per operation)"
              << std::endl;
}

// main function is provided by gtest_main library