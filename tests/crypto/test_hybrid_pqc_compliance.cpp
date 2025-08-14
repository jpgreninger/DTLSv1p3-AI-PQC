/**
 * @file test_hybrid_pqc_compliance.cpp
 * @brief Specification compliance tests for hybrid PQC implementation
 * 
 * Tests exact compliance with draft-kwiatkowski-tls-ecdhe-mlkem-03 specification
 * including wire format validation, named group assignments, key derivation,
 * and protocol message structures for DTLS v1.3 hybrid post-quantum cryptography.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <dtls/protocol/handshake.h>
#include <vector>
#include <memory>
#include <string>
#include <cstring>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HybridPQCComplianceTest : public ::testing::Test {
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
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        return providers;
    }
    
    // Helper to create HKDF-Extract as per draft specification
    std::vector<uint8_t> hkdf_extract_zero_salt(CryptoProvider* provider,
                                               const std::vector<uint8_t>& ikm) {
        KeyDerivationParams params;
        params.secret = ikm;
        params.salt.clear(); // Zero-length salt as specified
        params.info.clear(); // No info for extract step
        params.output_length = 32; // SHA256 output length
        params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(params);
        return result ? result.value() : std::vector<uint8_t>{};
    }
    
    // Encode a 16-bit value in network byte order
    std::vector<uint8_t> encode_uint16(uint16_t value) {
        return {static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value & 0xFF)};
    }
    
    // Encode a variable-length byte array with 16-bit length prefix
    std::vector<uint8_t> encode_opaque16(const std::vector<uint8_t>& data) {
        auto result = encode_uint16(static_cast<uint16_t>(data.size()));
        result.insert(result.end(), data.begin(), data.end());
        return result;
    }
};

// Test named group assignments per draft specification Section 4
TEST_F(HybridPQCComplianceTest, NamedGroupAssignments) {
    // Verify exact codepoint assignments from draft-kwiatkowski-tls-ecdhe-mlkem-03
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::ECDHE_P256_MLKEM512), 0x1140);
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::ECDHE_P384_MLKEM768), 0x1141);
    EXPECT_EQ(static_cast<uint16_t>(NamedGroup::ECDHE_P521_MLKEM1024), 0x1142);
    
    // Verify hybrid group identification
    EXPECT_TRUE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::ECDHE_P256_MLKEM512));
    EXPECT_TRUE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::ECDHE_P384_MLKEM768));
    EXPECT_TRUE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::ECDHE_P521_MLKEM1024));
    
    // Verify correct component extraction
    EXPECT_EQ(hybrid_pqc::get_classical_group(NamedGroup::ECDHE_P256_MLKEM512), NamedGroup::SECP256R1);
    EXPECT_EQ(hybrid_pqc::get_classical_group(NamedGroup::ECDHE_P384_MLKEM768), NamedGroup::SECP384R1);
    EXPECT_EQ(hybrid_pqc::get_classical_group(NamedGroup::ECDHE_P521_MLKEM1024), NamedGroup::SECP521R1);
    
    EXPECT_EQ(hybrid_pqc::get_mlkem_parameter_set(NamedGroup::ECDHE_P256_MLKEM512), MLKEMParameterSet::MLKEM512);
    EXPECT_EQ(hybrid_pqc::get_mlkem_parameter_set(NamedGroup::ECDHE_P384_MLKEM768), MLKEMParameterSet::MLKEM768);
    EXPECT_EQ(hybrid_pqc::get_mlkem_parameter_set(NamedGroup::ECDHE_P521_MLKEM1024), MLKEMParameterSet::MLKEM1024);
}

// Test ML-KEM parameter compliance with FIPS 203
TEST_F(HybridPQCComplianceTest, MLKEMParameterCompliance) {
    // Verify exact sizes as specified in FIPS 203
    
    // ML-KEM-512 (security level 1)
    auto sizes_512 = hybrid_pqc::get_mlkem_sizes(MLKEMParameterSet::MLKEM512);
    EXPECT_EQ(sizes_512.public_key_bytes, 800) << "ML-KEM-512 public key size must be 800 bytes";
    EXPECT_EQ(sizes_512.private_key_bytes, 1632) << "ML-KEM-512 private key size must be 1632 bytes";
    EXPECT_EQ(sizes_512.ciphertext_bytes, 768) << "ML-KEM-512 ciphertext size must be 768 bytes";
    EXPECT_EQ(sizes_512.shared_secret_bytes, 32) << "ML-KEM shared secret size must be 32 bytes";
    
    // ML-KEM-768 (security level 3)
    auto sizes_768 = hybrid_pqc::get_mlkem_sizes(MLKEMParameterSet::MLKEM768);
    EXPECT_EQ(sizes_768.public_key_bytes, 1184) << "ML-KEM-768 public key size must be 1184 bytes";
    EXPECT_EQ(sizes_768.private_key_bytes, 2400) << "ML-KEM-768 private key size must be 2400 bytes";
    EXPECT_EQ(sizes_768.ciphertext_bytes, 1088) << "ML-KEM-768 ciphertext size must be 1088 bytes";
    EXPECT_EQ(sizes_768.shared_secret_bytes, 32) << "ML-KEM shared secret size must be 32 bytes";
    
    // ML-KEM-1024 (security level 5)
    auto sizes_1024 = hybrid_pqc::get_mlkem_sizes(MLKEMParameterSet::MLKEM1024);
    EXPECT_EQ(sizes_1024.public_key_bytes, 1568) << "ML-KEM-1024 public key size must be 1568 bytes";
    EXPECT_EQ(sizes_1024.private_key_bytes, 3168) << "ML-KEM-1024 private key size must be 3168 bytes";
    EXPECT_EQ(sizes_1024.ciphertext_bytes, 1568) << "ML-KEM-1024 ciphertext size must be 1568 bytes";
    EXPECT_EQ(sizes_1024.shared_secret_bytes, 32) << "ML-KEM shared secret size must be 32 bytes";
}

// Test key share format compliance per draft specification Section 5.1
TEST_F(HybridPQCComplianceTest, KeyShareFormatCompliance) {
    // Client KeyShare format: ECDHE public key || ML-KEM public key
    auto client_size_512 = hybrid_pqc::get_hybrid_client_keyshare_size(NamedGroup::ECDHE_P256_MLKEM512);
    EXPECT_EQ(client_size_512, 65 + 800) << "Client KeyShare for ECDHE_P256_MLKEM512 must be 865 bytes";
    
    auto client_size_768 = hybrid_pqc::get_hybrid_client_keyshare_size(NamedGroup::ECDHE_P384_MLKEM768);
    EXPECT_EQ(client_size_768, 97 + 1184) << "Client KeyShare for ECDHE_P384_MLKEM768 must be 1281 bytes";
    
    auto client_size_1024 = hybrid_pqc::get_hybrid_client_keyshare_size(NamedGroup::ECDHE_P521_MLKEM1024);
    EXPECT_EQ(client_size_1024, 133 + 1568) << "Client KeyShare for ECDHE_P521_MLKEM1024 must be 1701 bytes";
    
    // Server KeyShare format: ECDHE public key || ML-KEM ciphertext
    auto server_size_512 = hybrid_pqc::get_hybrid_server_keyshare_size(NamedGroup::ECDHE_P256_MLKEM512);
    EXPECT_EQ(server_size_512, 65 + 768) << "Server KeyShare for ECDHE_P256_MLKEM512 must be 833 bytes";
    
    auto server_size_768 = hybrid_pqc::get_hybrid_server_keyshare_size(NamedGroup::ECDHE_P384_MLKEM768);
    EXPECT_EQ(server_size_768, 97 + 1088) << "Server KeyShare for ECDHE_P384_MLKEM768 must be 1185 bytes";
    
    auto server_size_1024 = hybrid_pqc::get_hybrid_server_keyshare_size(NamedGroup::ECDHE_P521_MLKEM1024);
    EXPECT_EQ(server_size_1024, 133 + 1568) << "Server KeyShare for ECDHE_P521_MLKEM1024 must be 1701 bytes";
}

// Test shared secret combination per draft specification Section 5.2
TEST_F(HybridPQCComplianceTest, SharedSecretCombination) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test vectors for shared secret combination
        std::vector<uint8_t> ecdhe_shared_secret = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
        };
        
        std::vector<uint8_t> mlkem_shared_secret = {
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
        };
        
        // According to draft specification Section 5.2:
        // combined_shared_secret = HKDF-Extract(salt=zero, IKM = ecdh_ss || mlkem_ss)
        std::vector<uint8_t> combined_ikm;
        combined_ikm.insert(combined_ikm.end(), ecdhe_shared_secret.begin(), ecdhe_shared_secret.end());
        combined_ikm.insert(combined_ikm.end(), mlkem_shared_secret.begin(), mlkem_shared_secret.end());
        
        auto combined_secret = hkdf_extract_zero_salt(provider, combined_ikm);
        ASSERT_FALSE(combined_secret.empty()) << "HKDF-Extract failed";
        EXPECT_EQ(combined_secret.size(), 32) << "Combined shared secret must be exactly 32 bytes";
        
        // Verify the combination is deterministic
        auto combined_secret_2 = hkdf_extract_zero_salt(provider, combined_ikm);
        EXPECT_EQ(combined_secret, combined_secret_2) << "HKDF-Extract must be deterministic";
        
        // Verify different inputs produce different outputs
        std::vector<uint8_t> different_ikm = combined_ikm;
        different_ikm[0] ^= 0x01; // Flip one bit
        
        auto different_combined = hkdf_extract_zero_salt(provider, different_ikm);
        ASSERT_FALSE(different_combined.empty());
        EXPECT_NE(combined_secret, different_combined) << "Different inputs must produce different outputs";
    }
}

// Test HKDF usage compliance per draft specification
TEST_F(HybridPQCComplianceTest, HKDFUsageCompliance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test HKDF-Extract with zero-length salt (as required by draft)
        std::vector<uint8_t> test_ikm(64, 0x42);
        
        KeyDerivationParams extract_params;
        extract_params.secret = test_ikm;
        extract_params.salt.clear(); // Zero-length salt is required
        extract_params.info.clear(); // No info for extract
        extract_params.output_length = 32;
        extract_params.hash_algorithm = HashAlgorithm::SHA256; // Must use SHA-256 or stronger
        
        auto extract_result = provider->derive_key_hkdf(extract_params);
        ASSERT_TRUE(extract_result) << "HKDF-Extract with zero salt must be supported";
        EXPECT_EQ(extract_result.value().size(), 32);
        
        // Test with SHA-384 (should also be supported)
        extract_params.hash_algorithm = HashAlgorithm::SHA384;
        extract_result = provider->derive_key_hkdf(extract_params);
        ASSERT_TRUE(extract_result) << "HKDF-Extract with SHA-384 should be supported";
        
        // Test HKDF-Expand (for completeness, though not directly specified in draft)
        KeyDerivationParams expand_params;
        expand_params.secret = extract_result.value(); // Use PRK from extract
        expand_params.salt.clear(); // No salt for expand
        expand_params.info = std::vector<uint8_t>{'t', 'e', 's', 't'};
        expand_params.output_length = 48; // Different length
        expand_params.hash_algorithm = HashAlgorithm::SHA384;
        
        auto expand_result = provider->derive_key_hkdf(expand_params);
        EXPECT_TRUE(expand_result) << "HKDF-Expand should work with PRK from extract";
        if (expand_result) {
            EXPECT_EQ(expand_result.value().size(), 48);
        }
    }
}

// Test wire format encoding compliance
TEST_F(HybridPQCComplianceTest, WireFormatCompliance) {
    // Test that named group values are correctly encoded in network byte order
    auto group_512 = encode_uint16(static_cast<uint16_t>(NamedGroup::ECDHE_P256_MLKEM512));
    EXPECT_EQ(group_512, std::vector<uint8_t>({0x11, 0x40}));
    
    auto group_768 = encode_uint16(static_cast<uint16_t>(NamedGroup::ECDHE_P384_MLKEM768));
    EXPECT_EQ(group_768, std::vector<uint8_t>({0x11, 0x41}));
    
    auto group_1024 = encode_uint16(static_cast<uint16_t>(NamedGroup::ECDHE_P521_MLKEM1024));
    EXPECT_EQ(group_1024, std::vector<uint8_t>({0x11, 0x42}));
    
    // Test KeyShare structure encoding (conceptual)
    // KeyShare {
    //     NamedGroup group;
    //     opaque key_exchange<1..2^16-1>;
    // } KeyShare;
    
    std::vector<uint8_t> mock_keyshare_data(100, 0xAA);
    auto encoded_keyshare = encode_opaque16(mock_keyshare_data);
    
    EXPECT_EQ(encoded_keyshare.size(), 2 + mock_keyshare_data.size());
    EXPECT_EQ(encoded_keyshare[0], 0x00); // Length high byte
    EXPECT_EQ(encoded_keyshare[1], 0x64); // Length low byte (100)
    EXPECT_EQ(std::vector<uint8_t>(encoded_keyshare.begin() + 2, encoded_keyshare.end()), 
             mock_keyshare_data);
}

// Test security level mappings per draft specification
TEST_F(HybridPQCComplianceTest, SecurityLevelMappings) {
    // According to draft specification:
    // - ECDHE_P256_MLKEM512 provides ~128-bit security
    // - ECDHE_P384_MLKEM768 provides ~192-bit security  
    // - ECDHE_P521_MLKEM1024 provides ~256-bit security
    
    // Verify classical component security levels match PQ component
    struct SecurityMapping {
        NamedGroup hybrid_group;
        NamedGroup classical_group;
        MLKEMParameterSet pq_param_set;
        int expected_security_bits;
    };
    
    std::vector<SecurityMapping> mappings = {
        {NamedGroup::ECDHE_P256_MLKEM512, NamedGroup::SECP256R1, MLKEMParameterSet::MLKEM512, 128},
        {NamedGroup::ECDHE_P384_MLKEM768, NamedGroup::SECP384R1, MLKEMParameterSet::MLKEM768, 192},
        {NamedGroup::ECDHE_P521_MLKEM1024, NamedGroup::SECP521R1, MLKEMParameterSet::MLKEM1024, 256}
    };
    
    for (const auto& mapping : mappings) {
        SCOPED_TRACE("Testing security mapping for hybrid group " + 
                    std::to_string(static_cast<int>(mapping.hybrid_group)));
        
        EXPECT_EQ(hybrid_pqc::get_classical_group(mapping.hybrid_group), mapping.classical_group)
            << "Classical component mismatch";
        EXPECT_EQ(hybrid_pqc::get_mlkem_parameter_set(mapping.hybrid_group), mapping.pq_param_set)
            << "PQ component mismatch";
        
        // Verify key sizes are consistent with security level
        auto sizes = hybrid_pqc::get_mlkem_sizes(mapping.pq_param_set);
        
        if (mapping.expected_security_bits == 128) {
            EXPECT_EQ(sizes.public_key_bytes, 800);
            EXPECT_EQ(sizes.ciphertext_bytes, 768);
        } else if (mapping.expected_security_bits == 192) {
            EXPECT_EQ(sizes.public_key_bytes, 1184);
            EXPECT_EQ(sizes.ciphertext_bytes, 1088);
        } else if (mapping.expected_security_bits == 256) {
            EXPECT_EQ(sizes.public_key_bytes, 1568);
            EXPECT_EQ(sizes.ciphertext_bytes, 1568);
        }
        
        // All ML-KEM variants produce 32-byte shared secrets
        EXPECT_EQ(sizes.shared_secret_bytes, 32);
    }
}

// Test algorithm identifier compliance
TEST_F(HybridPQCComplianceTest, AlgorithmIdentifierCompliance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Verify provider correctly identifies hybrid groups
        EXPECT_TRUE(provider->supports_hybrid_group(NamedGroup::ECDHE_P256_MLKEM512));
        EXPECT_TRUE(provider->supports_hybrid_group(NamedGroup::ECDHE_P384_MLKEM768));
        EXPECT_TRUE(provider->supports_hybrid_group(NamedGroup::ECDHE_P521_MLKEM1024));
        
        EXPECT_TRUE(provider->is_hybrid_group(NamedGroup::ECDHE_P256_MLKEM512));
        EXPECT_TRUE(provider->is_hybrid_group(NamedGroup::ECDHE_P384_MLKEM768));
        EXPECT_TRUE(provider->is_hybrid_group(NamedGroup::ECDHE_P521_MLKEM1024));
        
        // Verify provider does not identify classical groups as hybrid
        EXPECT_FALSE(provider->is_hybrid_group(NamedGroup::SECP256R1));
        EXPECT_FALSE(provider->is_hybrid_group(NamedGroup::SECP384R1));
        EXPECT_FALSE(provider->is_hybrid_group(NamedGroup::SECP521R1));
        EXPECT_FALSE(provider->is_hybrid_group(NamedGroup::X25519));
        EXPECT_FALSE(provider->is_hybrid_group(NamedGroup::FFDHE2048));
        
        // Verify provider capabilities include hybrid groups
        auto capabilities = provider->capabilities();
        bool has_hybrid_support = false;
        for (auto group : capabilities.supported_groups) {
            if (hybrid_pqc::is_hybrid_pqc_group(group)) {
                has_hybrid_support = true;
                break;
            }
        }
        EXPECT_TRUE(has_hybrid_support) << "Provider capabilities should include hybrid groups";
    }
}

// Test error handling compliance
TEST_F(HybridPQCComplianceTest, ErrorHandlingCompliance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test invalid parameter set handling
        MLKEMKeyGenParams invalid_keygen;
        invalid_keygen.parameter_set = static_cast<MLKEMParameterSet>(99); // Invalid
        auto result = provider->mlkem_generate_keypair(invalid_keygen);
        EXPECT_FALSE(result) << "Should reject invalid parameter set";
        
        // Test invalid key sizes
        MLKEMEncapParams invalid_encap;
        invalid_encap.parameter_set = MLKEMParameterSet::MLKEM512;
        invalid_encap.public_key = std::vector<uint8_t>(100, 0x42); // Wrong size
        result = provider->mlkem_encapsulate(invalid_encap);
        EXPECT_FALSE(result) << "Should reject invalid public key size";
        
        MLKEMDecapParams invalid_decap;
        invalid_decap.parameter_set = MLKEMParameterSet::MLKEM512;
        invalid_decap.private_key = std::vector<uint8_t>(100, 0x42); // Wrong size
        invalid_decap.ciphertext = std::vector<uint8_t>(768, 0x42);
        result = provider->mlkem_decapsulate(invalid_decap);
        EXPECT_FALSE(result) << "Should reject invalid private key size";
        
        // Test parameter set mismatch
        invalid_encap.parameter_set = MLKEMParameterSet::MLKEM512;
        invalid_encap.public_key = std::vector<uint8_t>(1184, 0x42); // ML-KEM-768 size
        result = provider->mlkem_encapsulate(invalid_encap);
        EXPECT_FALSE(result) << "Should reject mismatched parameter set and key size";
    }
}

// Test backwards compatibility requirements  
TEST_F(HybridPQCComplianceTest, BackwardsCompatibility) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Verify classical groups still work
        auto classical_groups = {
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1
        };
        
        for (auto group : classical_groups) {
            EXPECT_TRUE(provider->supports_named_group(group)) 
                << "Must maintain support for classical group " << static_cast<int>(group);
            
            auto keypair = provider->generate_key_pair(group);
            EXPECT_TRUE(keypair) << "Key generation must work for classical group " << static_cast<int>(group);
            
            if (keypair) {
                KeyExchangeParams params;
                params.group = group;
                params.peer_public_key = std::vector<uint8_t>(65, 0x42); // Placeholder
                params.private_key = keypair.value().first.get();
                auto kex_result = provider->perform_key_exchange(params);
                EXPECT_TRUE(kex_result) << "Key exchange must work for classical group " << static_cast<int>(group);
            }
        }
        
        // Verify classical cipher suites still work
        auto classical_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        };
        
        for (auto suite : classical_suites) {
            EXPECT_TRUE(provider->supports_cipher_suite(suite))
                << "Must maintain support for classical cipher suite " << static_cast<int>(suite);
        }
    }
}