#include <gtest/gtest.h>
#include <memory>
#include <chrono>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/types.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class SignatureSecurityVectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
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
    
    // RFC test vectors for signature schemes
    struct SignatureTestVector {
        SignatureScheme scheme;
        NamedGroup group;
        std::vector<uint8_t> message;
        std::string description;
        bool expect_success;
    };
    
    std::vector<SignatureTestVector> getSignatureTestVectors() {
        return {
            {
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                NamedGroup::SECP256R1,
                {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}, // "Hello World"
                "ECDSA P-256 with SHA-256",
                true
            },
            {
                SignatureScheme::ECDSA_SECP384R1_SHA384,
                NamedGroup::SECP384R1,
                {0x44, 0x54, 0x4c, 0x53, 0x20, 0x76, 0x31, 0x2e, 0x33}, // "DTLS v1.3"
                "ECDSA P-384 with SHA-384",
                true
            },
            {
                SignatureScheme::ECDSA_SECP521R1_SHA512,
                NamedGroup::SECP521R1,
                {0x52, 0x46, 0x43, 0x20, 0x39, 0x31, 0x34, 0x37}, // "RFC 9147"
                "ECDSA P-521 with SHA-512",
                true
            },
            {
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                NamedGroup::SECP256R1, // Not used for RSA
                {0x54, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74, 0x61}, // "Test data"
                "RSA-PSS with SHA-256",
                true
            },
            {
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                NamedGroup::SECP256R1, // Not used for RSA
                {0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79}, // "Security"
                "RSA-PSS with SHA-384",
                true
            },
            {
                SignatureScheme::ED25519,
                NamedGroup::X25519, // Ed25519 uses its own curve
                {0x45, 0x64, 0x44, 0x53, 0x41, 0x20, 0x74, 0x65, 0x73, 0x74}, // "EdDSA test"
                "Ed25519 signature",
                true
            }
        };
    }
};

TEST_F(SignatureSecurityVectorTest, SignatureSchemeValidation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    auto test_vectors = getSignatureTestVectors();
    
    for (const auto& vector : test_vectors) {
        SCOPED_TRACE("Testing: " + vector.description);
        
        // Check if provider supports this signature scheme
        if (!openssl_provider_->supports_signature_scheme(vector.scheme)) {
            std::cout << "Skipping " << vector.description << " - not supported by provider" << std::endl;
            continue;
        }
        
        // Generate key pair for the signature scheme
        auto key_pair_result = openssl_provider_->generate_key_pair(vector.group);
        if (!key_pair_result.is_success()) {
            if (vector.expect_success) {
                FAIL() << "Failed to generate key pair for " << vector.description;
            }
            continue;
        }
        
        auto private_key = std::move(key_pair_result.value().first);
        auto public_key = std::move(key_pair_result.value().second);
        
        // Sign the test message
        SignatureParams sign_params{};
        sign_params.data = vector.message;
        sign_params.scheme = vector.scheme;
        sign_params.private_key = private_key.get();
        
        auto signature_result = openssl_provider_->sign_data(sign_params);
        if (!signature_result.is_success()) {
            if (vector.expect_success) {
                FAIL() << "Failed to sign data for " << vector.description 
;
            }
            continue;
        }
        
        // Verify the signature
        SignatureParams verify_params{};
        verify_params.data = vector.message;
        verify_params.scheme = vector.scheme;
        verify_params.public_key = public_key.get();
        
        auto verify_result = openssl_provider_->verify_signature(verify_params, signature_result.value());
        ASSERT_TRUE(verify_result.is_success()) 
            << "Signature verification failed for " << vector.description;
        EXPECT_TRUE(verify_result.value()) 
            << "Signature verification returned false for " << vector.description;
        
        // Test signature tampering detection
        auto tampered_signature = signature_result.value();
        if (!tampered_signature.empty()) {
            tampered_signature[0] ^= 0x01; // Flip first bit
            
            auto tampered_verify_result = openssl_provider_->verify_signature(
                verify_params, tampered_signature);
            
            if (tampered_verify_result.is_success()) {
                EXPECT_FALSE(tampered_verify_result.value()) 
                    << "Tampered signature was incorrectly verified for " << vector.description;
            }
            // If verification fails entirely, that's also acceptable for tampered signatures
        }
        
        // Test message tampering detection
        auto tampered_message = vector.message;
        if (!tampered_message.empty()) {
            tampered_message[0] ^= 0x01; // Flip first bit
            
            SignatureParams tampered_verify_params{};
            tampered_verify_params.data = tampered_message;
            tampered_verify_params.scheme = vector.scheme;
            tampered_verify_params.public_key = public_key.get();
            
            auto tampered_msg_result = openssl_provider_->verify_signature(
                tampered_verify_params, signature_result.value());
            
            if (tampered_msg_result.is_success()) {
                EXPECT_FALSE(tampered_msg_result.value()) 
                    << "Signature verified with tampered message for " << vector.description;
            }
        }
    }
}

TEST_F(SignatureSecurityVectorTest, DTLS_CertificateVerify_RFC9147) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test DTLS 1.3 Certificate Verify signature format (RFC 9147 Section 4.2.3)
    
    // Generate ECDSA P-256 key pair
    auto key_pair_result = openssl_provider_->generate_key_pair(NamedGroup::SECP256R1);
    ASSERT_TRUE(key_pair_result.is_success()) << "Failed to generate ECDSA key pair";
    
    auto private_key = std::move(key_pair_result.value().first);
    auto public_key = std::move(key_pair_result.value().second);
    
    // Create transcript hash (simulated)
    std::vector<uint8_t> transcript_hash = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    // Mock certificate DER (simplified)
    std::vector<uint8_t> certificate_der = {
        0x30, 0x82, 0x01, 0x00, // Simplified DER structure
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    
    // Test client certificate verify
    DTLSCertificateVerifyParams client_params{};
    client_params.transcript_hash = transcript_hash;
    client_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    client_params.public_key = public_key.get();
    client_params.is_server_context = false; // Client context
    client_params.certificate_der = certificate_der;
    
    // For this test, we'll create the signature manually since we need the private key
    // In real DTLS, the signature would come from the peer
    
    // Create the signature input as per RFC 9147
    std::vector<uint8_t> signature_input;
    
    // Add 64 spaces
    signature_input.insert(signature_input.end(), 64, 0x20);
    
    // Add context string for client
    std::string context = "TLS 1.3, client CertificateVerify";
    signature_input.insert(signature_input.end(), context.begin(), context.end());
    
    // Add separator byte
    signature_input.push_back(0x00);
    
    // Add transcript hash
    signature_input.insert(signature_input.end(), transcript_hash.begin(), transcript_hash.end());
    
    // Sign the constructed input
    SignatureParams sign_params{};
    sign_params.data = signature_input;
    sign_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    sign_params.private_key = private_key.get();
    
    auto signature_result = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(signature_result.is_success()) << "Failed to create certificate verify signature";
    
    // Verify the DTLS certificate verify signature
    auto verify_result = openssl_provider_->verify_dtls_certificate_signature(
        client_params, signature_result.value());
    ASSERT_TRUE(verify_result.is_success()) << "DTLS certificate verify failed";
    EXPECT_TRUE(verify_result.value()) << "DTLS certificate verify returned false";
    
    // Test server certificate verify (different context string)
    DTLSCertificateVerifyParams server_params = client_params;
    server_params.is_server_context = true; // Server context
    
    // Create server signature input
    std::vector<uint8_t> server_signature_input;
    server_signature_input.insert(server_signature_input.end(), 64, 0x20);
    std::string server_context = "TLS 1.3, server CertificateVerify";
    server_signature_input.insert(server_signature_input.end(), server_context.begin(), server_context.end());
    server_signature_input.push_back(0x00);
    server_signature_input.insert(server_signature_input.end(), transcript_hash.begin(), transcript_hash.end());
    
    SignatureParams server_sign_params{};
    server_sign_params.data = server_signature_input;
    server_sign_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    server_sign_params.private_key = private_key.get();
    
    auto server_signature_result = openssl_provider_->sign_data(server_sign_params);
    ASSERT_TRUE(server_signature_result.is_success()) << "Failed to create server certificate verify signature";
    
    auto server_verify_result = openssl_provider_->verify_dtls_certificate_signature(
        server_params, server_signature_result.value());
    ASSERT_TRUE(server_verify_result.is_success()) << "Server DTLS certificate verify failed";
    EXPECT_TRUE(server_verify_result.value()) << "Server DTLS certificate verify returned false";
    
    // Verify that client signature doesn't work for server context and vice versa
    auto cross_verify_result = openssl_provider_->verify_dtls_certificate_signature(
        server_params, signature_result.value()); // Client signature with server params
    if (cross_verify_result.is_success()) {
        EXPECT_FALSE(cross_verify_result.value()) 
            << "Client signature incorrectly verified in server context";
    }
}

TEST_F(SignatureSecurityVectorTest, SignatureNonRepudiation) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test that signatures provide non-repudiation
    auto key_pair1_result = openssl_provider_->generate_key_pair(NamedGroup::SECP256R1);
    auto key_pair2_result = openssl_provider_->generate_key_pair(NamedGroup::SECP256R1);
    
    ASSERT_TRUE(key_pair1_result.is_success());
    ASSERT_TRUE(key_pair2_result.is_success());
    
    auto private_key1 = std::move(key_pair1_result.value().first);
    auto public_key1 = std::move(key_pair1_result.value().second);
    auto private_key2 = std::move(key_pair2_result.value().first);
    auto public_key2 = std::move(key_pair2_result.value().second);
    
    std::vector<uint8_t> message = {0x4e, 0x6f, 0x6e, 0x2d, 0x72, 0x65, 0x70, 0x75, 0x64, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e}; // "Non-repudiation"
    
    // Sign with first key
    SignatureParams sign_params1{};
    sign_params1.data = message;
    sign_params1.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    sign_params1.private_key = private_key1.get();
    
    auto signature1_result = openssl_provider_->sign_data(sign_params1);
    ASSERT_TRUE(signature1_result.is_success());
    
    // Sign with second key
    SignatureParams sign_params2{};
    sign_params2.data = message;
    sign_params2.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    sign_params2.private_key = private_key2.get();
    
    auto signature2_result = openssl_provider_->sign_data(sign_params2);
    ASSERT_TRUE(signature2_result.is_success());
    
    // Verify signature1 with public_key1 - should succeed
    SignatureParams verify_params1{};
    verify_params1.data = message;
    verify_params1.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    verify_params1.public_key = public_key1.get();
    
    auto verify1_result = openssl_provider_->verify_signature(verify_params1, signature1_result.value());
    ASSERT_TRUE(verify1_result.is_success());
    EXPECT_TRUE(verify1_result.value());
    
    // Verify signature1 with public_key2 - should fail (non-repudiation)
    SignatureParams verify_params2{};
    verify_params2.data = message;
    verify_params2.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    verify_params2.public_key = public_key2.get();
    
    auto verify2_result = openssl_provider_->verify_signature(verify_params2, signature1_result.value());
    if (verify2_result.is_success()) {
        EXPECT_FALSE(verify2_result.value()) 
            << "Signature verified with wrong public key - non-repudiation violated";
    }
    
    // Verify signature2 with public_key1 - should fail
    auto verify3_result = openssl_provider_->verify_signature(verify_params1, signature2_result.value());
    if (verify3_result.is_success()) {
        EXPECT_FALSE(verify3_result.value()) 
            << "Signature verified with wrong public key - non-repudiation violated";
    }
    
    // Verify signature2 with public_key2 - should succeed
    auto verify4_result = openssl_provider_->verify_signature(verify_params2, signature2_result.value());
    ASSERT_TRUE(verify4_result.is_success());
    EXPECT_TRUE(verify4_result.value());
}

TEST_F(SignatureSecurityVectorTest, SignatureUniqueness) {
    if (!openssl_provider_ || !openssl_provider_->is_available()) {
        GTEST_SKIP() << "OpenSSL provider not available";
    }
    
    // Test that signatures are unique (probabilistic signatures should differ)
    auto key_pair_result = openssl_provider_->generate_key_pair(NamedGroup::SECP256R1);
    ASSERT_TRUE(key_pair_result.is_success());
    
    auto private_key = std::move(key_pair_result.value().first);
    std::vector<uint8_t> message = {0x55, 0x6e, 0x69, 0x71, 0x75, 0x65}; // "Unique"
    
    // Generate multiple signatures of the same message
    std::vector<std::vector<uint8_t>> signatures;
    const int num_signatures = 10;
    
    for (int i = 0; i < num_signatures; ++i) {
        SignatureParams sign_params{};
        sign_params.data = message;
        sign_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
        sign_params.private_key = private_key.get();
        
        auto signature_result = openssl_provider_->sign_data(sign_params);
        ASSERT_TRUE(signature_result.is_success()) << "Failed to create signature " << i;
        signatures.push_back(signature_result.value());
    }
    
    // Verify all signatures are different (for probabilistic signatures like ECDSA)
    for (size_t i = 0; i < signatures.size(); ++i) {
        for (size_t j = i + 1; j < signatures.size(); ++j) {
            EXPECT_NE(signatures[i], signatures[j]) 
                << "Signatures " << i << " and " << j << " are identical - randomness issue?";
        }
    }
}

TEST_F(SignatureSecurityVectorTest, CrossProviderSignatureCompatibility) {
    bool openssl_available = openssl_provider_ && openssl_provider_->is_available();
    bool botan_available = botan_provider_ && botan_provider_->is_available();
    
    if (!openssl_available || !botan_available) {
        GTEST_SKIP() << "Both OpenSSL and Botan providers required for cross-validation";
    }
    
    // Test that signatures created by one provider can be verified by another
    auto openssl_keys = openssl_provider_->generate_key_pair(NamedGroup::SECP256R1);
    ASSERT_TRUE(openssl_keys.is_success());
    
    std::vector<uint8_t> message = {0x43, 0x72, 0x6f, 0x73, 0x73, 0x2d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72}; // "Cross-provider"
    
    // Sign with OpenSSL
    SignatureParams sign_params{};
    sign_params.data = message;
    sign_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    sign_params.private_key = openssl_keys.value().first.get();
    
    auto openssl_signature = openssl_provider_->sign_data(sign_params);
    ASSERT_TRUE(openssl_signature.is_success());
    
    // Export public key from OpenSSL format
    auto public_key_der = openssl_provider_->export_public_key(
        *openssl_keys.value().second, "DER");
    ASSERT_TRUE(public_key_der.is_success());
    
    // Import public key in Botan
    auto botan_public_key = botan_provider_->import_public_key(
        public_key_der.value(), "DER");
    ASSERT_TRUE(botan_public_key.is_success());
    
    // Verify OpenSSL signature with Botan
    SignatureParams verify_params{};
    verify_params.data = message;
    verify_params.scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
    verify_params.public_key = botan_public_key.value().get();
    
    auto botan_verify_result = botan_provider_->verify_signature(
        verify_params, openssl_signature.value());
    ASSERT_TRUE(botan_verify_result.is_success()) 
        << "Cross-provider signature verification failed";
    EXPECT_TRUE(botan_verify_result.value()) 
        << "Botan could not verify OpenSSL signature";
    
    std::cout << "Cross-provider signature compatibility verified: OpenSSL->Botan" << std::endl;
}