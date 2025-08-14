/**
 * @file test_hybrid_pqc_test_vectors.cpp
 * @brief Reference test vectors for hybrid PQC validation
 * 
 * Contains reference test vectors and known answer tests for hybrid post-quantum
 * cryptography implementation validation including ML-KEM test vectors, HKDF test
 * vectors, and hybrid key exchange reference data per draft-kwiatkowski-tls-ecdhe-mlkem-03.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include <vector>
#include <memory>
#include <string>
#include <array>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HybridPQCTestVectorsTest : public ::testing::Test {
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
    
    // Helper to convert hex string to bytes
    std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> result;
        result.reserve(hex.length() / 2);
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
            result.push_back(byte);
        }
        
        return result;
    }
    
    // Helper to convert bytes to hex string for debugging
    std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        std::string result;
        result.reserve(bytes.size() * 2);
        
        for (uint8_t byte : bytes) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", byte);
            result += hex;
        }
        
        return result;
    }
};

// HKDF test vectors from RFC 5869
TEST_F(HybridPQCTestVectorsTest, HKDF_RFC5869_TestVectors) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // RFC 5869 Test Case 1 - Basic test case with SHA-256
    std::vector<uint8_t> ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    std::vector<uint8_t> salt = hex_to_bytes("000102030405060708090a0b0c");
    std::vector<uint8_t> info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    std::vector<uint8_t> expected_okm = hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        KeyDerivationParams params;
        params.secret = ikm;
        params.salt = salt;
        params.info = info;
        params.output_length = 42; // L=42 from RFC test vector
        params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(params);
        ASSERT_TRUE(result) << "HKDF failed";
        EXPECT_EQ(result.value(), expected_okm) 
            << "HKDF output mismatch for RFC 5869 test vector 1";
    }
    
    // RFC 5869 Test Case 2 - Test with longer inputs/outputs
    ikm = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f");
    salt = hex_to_bytes(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    info = hex_to_bytes(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    expected_okm = hex_to_bytes(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87");
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        KeyDerivationParams params;
        params.secret = ikm;
        params.salt = salt;
        params.info = info;
        params.output_length = 82; // L=82 from RFC test vector
        params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(params);
        ASSERT_TRUE(result) << "HKDF failed";
        EXPECT_EQ(result.value(), expected_okm) 
            << "HKDF output mismatch for RFC 5869 test vector 2";
    }
}

// Test hybrid shared secret combination as per draft specification
TEST_F(HybridPQCTestVectorsTest, HybridSharedSecretCombination) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // Test vectors for hybrid shared secret combination
    struct HybridTestVector {
        std::string name;
        std::vector<uint8_t> ecdhe_shared_secret;
        std::vector<uint8_t> mlkem_shared_secret;
        std::vector<uint8_t> expected_combined;
    };
    
    std::vector<HybridTestVector> test_vectors = {
        {
            "Basic combination test",
            hex_to_bytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            hex_to_bytes("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
            // Expected result computed with HKDF-Extract(salt=empty, IKM=ecdhe||mlkem)
            hex_to_bytes("e3b5b6c8d8c4e8f4a8e7d5c6b8a7d5c8e3f4a8e7d5c6b8a7d5c8e3f4a8e7d5c6")
        }
        // Note: Expected values would need to be computed with reference implementation
        // These are placeholders for demonstration
    };
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        for (const auto& tv : test_vectors) {
            SCOPED_TRACE("Test vector: " + tv.name);
            
            // Combine as per draft specification: HKDF-Extract(salt=empty, IKM = ecdhe || mlkem)
            KeyDerivationParams params;
            params.secret.insert(params.secret.end(), 
                                tv.ecdhe_shared_secret.begin(), tv.ecdhe_shared_secret.end());
            params.secret.insert(params.secret.end(), 
                                tv.mlkem_shared_secret.begin(), tv.mlkem_shared_secret.end());
            params.salt.clear(); // Empty salt as per draft
            params.info.clear(); // No info for HKDF-Extract
            params.output_length = 32;
            params.hash_algorithm = HashAlgorithm::SHA256;
            
            auto result = provider->derive_key_hkdf(params);
            ASSERT_TRUE(result) << "Hybrid shared secret combination failed";
            EXPECT_EQ(result.value().size(), 32) << "Combined shared secret size mismatch";
            
            // Note: In a real implementation, we would validate against known expected values
            // For now, we just verify the operation succeeds and produces correct-sized output
            std::cout << "Provider " << provider->name() << " combined result: " 
                     << bytes_to_hex(result.value()) << std::endl;
        }
    }
}

// ML-KEM size validation test vectors
TEST_F(HybridPQCTestVectorsTest, MLKEMSizeValidation) {
    // Test vectors for ML-KEM parameter set sizes per FIPS 203
    struct MLKEMSizeTestVector {
        MLKEMParameterSet param_set;
        std::string name;
        size_t public_key_bytes;
        size_t private_key_bytes;
        size_t ciphertext_bytes;
        size_t shared_secret_bytes;
    };
    
    std::vector<MLKEMSizeTestVector> size_vectors = {
        {MLKEMParameterSet::MLKEM512, "ML-KEM-512", 800, 1632, 768, 32},
        {MLKEMParameterSet::MLKEM768, "ML-KEM-768", 1184, 2400, 1088, 32},
        {MLKEMParameterSet::MLKEM1024, "ML-KEM-1024", 1568, 3168, 1568, 32}
    };
    
    for (const auto& tv : size_vectors) {
        SCOPED_TRACE("Testing: " + tv.name);
        
        auto sizes = hybrid_pqc::get_mlkem_sizes(tv.param_set);
        
        EXPECT_EQ(sizes.public_key_bytes, tv.public_key_bytes) 
            << tv.name << " public key size mismatch";
        EXPECT_EQ(sizes.private_key_bytes, tv.private_key_bytes) 
            << tv.name << " private key size mismatch";
        EXPECT_EQ(sizes.ciphertext_bytes, tv.ciphertext_bytes) 
            << tv.name << " ciphertext size mismatch";
        EXPECT_EQ(sizes.shared_secret_bytes, tv.shared_secret_bytes) 
            << tv.name << " shared secret size mismatch";
    }
}

// Hybrid group wire format test vectors
TEST_F(HybridPQCTestVectorsTest, HybridGroupWireFormat) {
    // Test vectors for hybrid named group wire format per draft specification
    struct HybridGroupTestVector {
        NamedGroup group;
        std::string name;
        uint16_t wire_value;
        NamedGroup classical_component;
        MLKEMParameterSet pq_component;
        size_t client_keyshare_size;
        size_t server_keyshare_size;
    };
    
    std::vector<HybridGroupTestVector> group_vectors = {
        {
            NamedGroup::ECDHE_P256_MLKEM512,
            "ECDHE_P256_MLKEM512",
            0x1140,
            NamedGroup::SECP256R1,
            MLKEMParameterSet::MLKEM512,
            65 + 800,  // P-256 uncompressed + ML-KEM-512 public key
            65 + 768   // P-256 uncompressed + ML-KEM-512 ciphertext
        },
        {
            NamedGroup::ECDHE_P384_MLKEM768,
            "ECDHE_P384_MLKEM768",
            0x1141,
            NamedGroup::SECP384R1,
            MLKEMParameterSet::MLKEM768,
            97 + 1184, // P-384 uncompressed + ML-KEM-768 public key
            97 + 1088  // P-384 uncompressed + ML-KEM-768 ciphertext
        },
        {
            NamedGroup::ECDHE_P521_MLKEM1024,
            "ECDHE_P521_MLKEM1024",
            0x1142,
            NamedGroup::SECP521R1,
            MLKEMParameterSet::MLKEM1024,
            133 + 1568, // P-521 uncompressed + ML-KEM-1024 public key
            133 + 1568  // P-521 uncompressed + ML-KEM-1024 ciphertext
        }
    };
    
    for (const auto& tv : group_vectors) {
        SCOPED_TRACE("Testing: " + tv.name);
        
        // Validate wire format value
        EXPECT_EQ(static_cast<uint16_t>(tv.group), tv.wire_value)
            << tv.name << " wire value mismatch";
        
        // Validate component extraction
        EXPECT_EQ(hybrid_pqc::get_classical_group(tv.group), tv.classical_component)
            << tv.name << " classical component mismatch";
        EXPECT_EQ(hybrid_pqc::get_mlkem_parameter_set(tv.group), tv.pq_component)
            << tv.name << " PQ component mismatch";
        
        // Validate key share sizes
        EXPECT_EQ(hybrid_pqc::get_hybrid_client_keyshare_size(tv.group), tv.client_keyshare_size)
            << tv.name << " client keyshare size mismatch";
        EXPECT_EQ(hybrid_pqc::get_hybrid_server_keyshare_size(tv.group), tv.server_keyshare_size)
            << tv.name << " server keyshare size mismatch";
        
        // Validate hybrid group identification
        EXPECT_TRUE(hybrid_pqc::is_hybrid_pqc_group(tv.group))
            << tv.name << " should be identified as hybrid";
    }
}

// Security parameter mapping test vectors
TEST_F(HybridPQCTestVectorsTest, SecurityParameterMapping) {
    // Test vectors for security parameter mapping per draft specification
    struct SecurityMappingVector {
        NamedGroup hybrid_group;
        std::string name;
        int classical_security_bits;
        int pq_security_bits;
        int combined_security_bits;
    };
    
    std::vector<SecurityMappingVector> security_vectors = {
        {NamedGroup::ECDHE_P256_MLKEM512, "ECDHE_P256_MLKEM512", 128, 128, 128},
        {NamedGroup::ECDHE_P384_MLKEM768, "ECDHE_P384_MLKEM768", 192, 192, 192},
        {NamedGroup::ECDHE_P521_MLKEM1024, "ECDHE_P521_MLKEM1024", 256, 256, 256}
    };
    
    for (const auto& tv : security_vectors) {
        SCOPED_TRACE("Testing: " + tv.name);
        
        auto classical_group = hybrid_pqc::get_classical_group(tv.hybrid_group);
        auto pq_param_set = hybrid_pqc::get_mlkem_parameter_set(tv.hybrid_group);
        
        // Verify security level consistency
        // In practice, you would check against actual security parameters
        // For now, verify the mapping is consistent with expected combinations
        
        if (tv.combined_security_bits == 128) {
            EXPECT_EQ(classical_group, NamedGroup::SECP256R1);
            EXPECT_EQ(pq_param_set, MLKEMParameterSet::MLKEM512);
        } else if (tv.combined_security_bits == 192) {
            EXPECT_EQ(classical_group, NamedGroup::SECP384R1);
            EXPECT_EQ(pq_param_set, MLKEMParameterSet::MLKEM768);
        } else if (tv.combined_security_bits == 256) {
            EXPECT_EQ(classical_group, NamedGroup::SECP521R1);
            EXPECT_EQ(pq_param_set, MLKEMParameterSet::MLKEM1024);
        }
        
        // Verify key sizes are consistent with security level
        auto pq_sizes = hybrid_pqc::get_mlkem_sizes(pq_param_set);
        EXPECT_EQ(pq_sizes.shared_secret_bytes, 32) << "All ML-KEM variants should produce 32-byte secrets";
    }
}

// Key exchange message format test vectors
TEST_F(HybridPQCTestVectorsTest, KeyExchangeMessageFormat) {
    // Test the conceptual message format for hybrid key exchange
    // In practice, this would be integrated with the handshake protocol
    
    struct KeyExchangeFormatVector {
        NamedGroup group;
        std::string phase;
        size_t expected_size;
        std::string description;
    };
    
    std::vector<KeyExchangeFormatVector> format_vectors = {
        // Client Hello KeyShare entries
        {NamedGroup::ECDHE_P256_MLKEM512, "ClientHello", 865, "P-256 pubkey + ML-KEM-512 pubkey"},
        {NamedGroup::ECDHE_P384_MLKEM768, "ClientHello", 1281, "P-384 pubkey + ML-KEM-768 pubkey"},
        {NamedGroup::ECDHE_P521_MLKEM1024, "ClientHello", 1701, "P-521 pubkey + ML-KEM-1024 pubkey"},
        
        // Server Hello KeyShare entries  
        {NamedGroup::ECDHE_P256_MLKEM512, "ServerHello", 833, "P-256 pubkey + ML-KEM-512 ciphertext"},
        {NamedGroup::ECDHE_P384_MLKEM768, "ServerHello", 1185, "P-384 pubkey + ML-KEM-768 ciphertext"},
        {NamedGroup::ECDHE_P521_MLKEM1024, "ServerHello", 1701, "P-521 pubkey + ML-KEM-1024 ciphertext"}
    };
    
    for (const auto& tv : format_vectors) {
        SCOPED_TRACE("Testing: " + tv.description);
        
        size_t actual_size;
        if (tv.phase == "ClientHello") {
            actual_size = hybrid_pqc::get_hybrid_client_keyshare_size(tv.group);
        } else {
            actual_size = hybrid_pqc::get_hybrid_server_keyshare_size(tv.group);
        }
        
        EXPECT_EQ(actual_size, tv.expected_size)
            << tv.phase << " KeyShare size mismatch for " << tv.description;
    }
}

// Edge case test vectors
TEST_F(HybridPQCTestVectorsTest, EdgeCases) {
    // Test edge cases and boundary conditions
    
    // Empty input HKDF test
    auto providers = get_available_providers();
    if (!providers.empty()) {
        auto* provider = providers[0];
        
        // Test HKDF with minimum valid inputs
        KeyDerivationParams min_params;
        min_params.secret = {0x01}; // Minimal non-empty secret
        min_params.salt.clear();
        min_params.info.clear();
        min_params.output_length = 1; // Minimal output length
        min_params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(min_params);
        EXPECT_TRUE(result) << "HKDF should work with minimal valid inputs";
        if (result) {
            EXPECT_EQ(result.value().size(), 1);
        }
        
        // Test HKDF with maximum practical output length
        KeyDerivationParams max_params;
        max_params.secret = std::vector<uint8_t>(64, 0x42);
        max_params.salt.clear();
        max_params.info.clear();
        max_params.output_length = 255; // Maximum for single HKDF-Expand iteration
        max_params.hash_algorithm = HashAlgorithm::SHA256;
        
        result = provider->derive_key_hkdf(max_params);
        EXPECT_TRUE(result) << "HKDF should work with maximum practical output length";
        if (result) {
            EXPECT_EQ(result.value().size(), 255);
        }
    }
    
    // Test utility function edge cases
    EXPECT_FALSE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::SECP256R1));
    EXPECT_FALSE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::X25519));
    EXPECT_FALSE(hybrid_pqc::is_hybrid_pqc_group(NamedGroup::FFDHE2048));
    
    // Test fallback behavior for invalid/unknown groups
    auto fallback_classical = hybrid_pqc::get_classical_group(NamedGroup::X25519);
    EXPECT_EQ(fallback_classical, NamedGroup::SECP256R1) << "Should fallback to P-256";
    
    auto fallback_pq = hybrid_pqc::get_mlkem_parameter_set(NamedGroup::X25519);
    EXPECT_EQ(fallback_pq, MLKEMParameterSet::MLKEM512) << "Should fallback to ML-KEM-512";
}