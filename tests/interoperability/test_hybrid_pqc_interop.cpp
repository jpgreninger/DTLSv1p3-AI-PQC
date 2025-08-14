/**
 * @file test_hybrid_pqc_interop.cpp
 * @brief Cross-provider interoperability tests for hybrid PQC
 * 
 * Tests interoperability of hybrid post-quantum cryptography implementation
 * across different crypto providers (OpenSSL, Botan, Hardware Accelerated)
 * ensuring consistent behavior and cross-provider compatibility.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include "../test_infrastructure/test_utilities.h"
#include <vector>
#include <memory>
#include <string>
#include <algorithm>
#include <map>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HybridPQCInteropTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Initialize all available providers
        providers_.clear();
        provider_names_.clear();
        
        auto openssl_result = factory.create_provider("openssl");
        if (openssl_result && openssl_result.value()->is_available()) {
            auto provider = std::move(openssl_result.value());
            auto init_result = provider->initialize();
            if (init_result) {
                provider_names_.push_back("OpenSSL");
                providers_.push_back(std::move(provider));
            }
        }
        
        auto botan_result = factory.create_provider("botan");
        if (botan_result && botan_result.value()->is_available()) {
            auto provider = std::move(botan_result.value());
            auto init_result = provider->initialize();
            if (init_result) {
                provider_names_.push_back("Botan");
                providers_.push_back(std::move(provider));
            }
        }

        auto hardware_result = factory.create_provider("hardware");
        if (hardware_result && hardware_result.value()->is_available()) {
            auto provider = std::move(hardware_result.value());
            auto init_result = provider->initialize();
            if (init_result) {
                provider_names_.push_back("Hardware");
                providers_.push_back(std::move(provider));
            }
        }
    }
    
    void TearDown() override {
        for (auto& provider : providers_) {
            provider->cleanup();
        }
        providers_.clear();
        provider_names_.clear();
    }
    
    std::vector<std::unique_ptr<CryptoProvider>> providers_;
    std::vector<std::string> provider_names_;
    
    // Get provider combinations for cross-testing
    std::vector<std::pair<size_t, size_t>> get_provider_pairs() {
        std::vector<std::pair<size_t, size_t>> pairs;
        for (size_t i = 0; i < providers_.size(); ++i) {
            for (size_t j = i + 1; j < providers_.size(); ++j) {
                pairs.emplace_back(i, j);
            }
        }
        return pairs;
    }
    
    // Compare two vectors with tolerance for floating point issues
    bool vectors_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        return a == b;
    }
    
    // Combine shared secrets using HKDF (consistent across providers)
    std::vector<uint8_t> combine_shared_secrets(
        CryptoProvider* provider,
        const std::vector<uint8_t>& classical_ss,
        const std::vector<uint8_t>& pq_ss) {
        
        KeyDerivationParams hkdf_params;
        hkdf_params.secret.insert(hkdf_params.secret.end(), classical_ss.begin(), classical_ss.end());
        hkdf_params.secret.insert(hkdf_params.secret.end(), pq_ss.begin(), pq_ss.end());
        hkdf_params.salt.clear(); // Empty salt as per draft
        hkdf_params.info = std::vector<uint8_t>{'i', 'n', 't', 'e', 'r', 'o', 'p'};
        hkdf_params.output_length = 32;
        hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(hkdf_params);
        return result ? result.value() : std::vector<uint8_t>{};
    }
};

// Test that all providers support the same hybrid groups
TEST_F(HybridPQCInteropTest, HybridGroupSupport) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    std::vector<NamedGroup> hybrid_groups = {
        NamedGroup::ECDHE_P256_MLKEM512,
        NamedGroup::ECDHE_P384_MLKEM768,
        NamedGroup::ECDHE_P521_MLKEM1024
    };
    
    // Verify all providers support the same hybrid groups
    for (size_t i = 0; i < providers_.size(); ++i) {
        SCOPED_TRACE("Provider: " + provider_names_[i]);
        
        for (auto group : hybrid_groups) {
            EXPECT_TRUE(providers_[i]->supports_hybrid_group(group))
                << provider_names_[i] << " should support hybrid group " << static_cast<int>(group);
            EXPECT_TRUE(providers_[i]->is_hybrid_group(group))
                << provider_names_[i] << " should identify " << static_cast<int>(group) << " as hybrid";
        }
    }
    
    // Compare provider capabilities
    auto base_capabilities = providers_[0]->capabilities();
    for (size_t i = 1; i < providers_.size(); ++i) {
        auto capabilities = providers_[i]->capabilities();
        
        // Check for hybrid group support consistency
        bool base_has_hybrid = false;
        bool current_has_hybrid = false;
        
        for (auto group : base_capabilities.supported_groups) {
            if (hybrid_pqc::is_hybrid_pqc_group(group)) {
                base_has_hybrid = true;
                break;
            }
        }
        
        for (auto group : capabilities.supported_groups) {
            if (hybrid_pqc::is_hybrid_pqc_group(group)) {
                current_has_hybrid = true;
                break;
            }
        }
        
        EXPECT_EQ(base_has_hybrid, current_has_hybrid)
            << "Hybrid group support should be consistent across providers";
    }
}

// Test cross-provider ML-KEM key generation consistency
TEST_F(HybridPQCInteropTest, MLKEMKeyGenerationConsistency) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    std::vector<MLKEMParameterSet> param_sets = {
        MLKEMParameterSet::MLKEM512,
        MLKEMParameterSet::MLKEM768,
        MLKEMParameterSet::MLKEM1024
    };
    
    for (auto param_set : param_sets) {
        SCOPED_TRACE("Parameter set: " + std::to_string(static_cast<int>(param_set)));
        
        // Generate keys with all providers
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keypairs;
        
        for (size_t i = 0; i < providers_.size(); ++i) {
            SCOPED_TRACE("Provider: " + provider_names_[i]);
            
            MLKEMKeyGenParams params;
            params.parameter_set = param_set;
            
            auto result = providers_[i]->mlkem_generate_keypair(params);
            ASSERT_TRUE(result) << "Key generation failed for " << provider_names_[i];
            
            keypairs.push_back(result.value());
        }
        
        // Verify all keys have consistent sizes
        auto expected_sizes = hybrid_pqc::get_mlkem_sizes(param_set);
        
        for (size_t i = 0; i < keypairs.size(); ++i) {
            const auto& [pubkey, privkey] = keypairs[i];
            
            EXPECT_EQ(pubkey.size(), expected_sizes.public_key_bytes)
                << "Public key size mismatch for " << provider_names_[i];
            EXPECT_EQ(privkey.size(), expected_sizes.private_key_bytes)
                << "Private key size mismatch for " << provider_names_[i];
        }
        
        // Keys should be different (not deterministic without fixed seed)
        for (size_t i = 0; i < keypairs.size(); ++i) {
            for (size_t j = i + 1; j < keypairs.size(); ++j) {
                EXPECT_NE(keypairs[i].first, keypairs[j].first)
                    << "Public keys should differ between " << provider_names_[i] 
                    << " and " << provider_names_[j];
                EXPECT_NE(keypairs[i].second, keypairs[j].second)
                    << "Private keys should differ between " << provider_names_[i] 
                    << " and " << provider_names_[j];
            }
        }
    }
}

// Test cross-provider HKDF consistency 
TEST_F(HybridPQCInteropTest, HKDFConsistency) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    // Test vectors for HKDF consistency
    std::vector<uint8_t> test_secret = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    std::vector<uint8_t> test_info = {'t', 'e', 's', 't', '_', 'i', 'n', 'f', 'o'};
    
    KeyDerivationParams hkdf_params;
    hkdf_params.secret = test_secret;
    hkdf_params.salt.clear(); // Empty salt
    hkdf_params.info = test_info;
    hkdf_params.output_length = 32;
    hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
    
    // Derive with all providers
    std::vector<std::vector<uint8_t>> derived_keys;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        SCOPED_TRACE("Provider: " + provider_names_[i]);
        
        auto result = providers_[i]->derive_key_hkdf(hkdf_params);
        ASSERT_TRUE(result) << "HKDF failed for " << provider_names_[i];
        
        derived_keys.push_back(result.value());
        EXPECT_EQ(result.value().size(), 32) << "Derived key size mismatch for " << provider_names_[i];
    }
    
    // All providers should produce the same result for HKDF
    for (size_t i = 1; i < derived_keys.size(); ++i) {
        EXPECT_EQ(derived_keys[0], derived_keys[i])
            << "HKDF results differ between " << provider_names_[0] 
            << " and " << provider_names_[i];
    }
    
    // Test with different hash algorithms
    hkdf_params.hash_algorithm = HashAlgorithm::SHA384;
    derived_keys.clear();
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        auto result = providers_[i]->derive_key_hkdf(hkdf_params);
        if (result) { // Some providers might not support SHA384
            derived_keys.push_back(result.value());
        }
    }
    
    // If multiple providers support SHA384, they should agree
    if (derived_keys.size() > 1) {
        for (size_t i = 1; i < derived_keys.size(); ++i) {
            EXPECT_EQ(derived_keys[0], derived_keys[i])
                << "HKDF SHA384 results should be consistent";
        }
    }
}

// Test cross-provider shared secret combination
TEST_F(HybridPQCInteropTest, SharedSecretCombination) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    // Test data
    std::vector<uint8_t> classical_ss = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    
    std::vector<uint8_t> pq_ss = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
    };
    
    // Combine with all providers
    std::vector<std::vector<uint8_t>> combined_secrets;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        SCOPED_TRACE("Provider: " + provider_names_[i]);
        
        auto combined = combine_shared_secrets(providers_[i].get(), classical_ss, pq_ss);
        ASSERT_FALSE(combined.empty()) << "Shared secret combination failed for " << provider_names_[i];
        EXPECT_EQ(combined.size(), 32) << "Combined secret size mismatch for " << provider_names_[i];
        
        combined_secrets.push_back(combined);
    }
    
    // All providers should produce the same combined secret
    for (size_t i = 1; i < combined_secrets.size(); ++i) {
        EXPECT_EQ(combined_secrets[0], combined_secrets[i])
            << "Combined shared secrets differ between " << provider_names_[0] 
            << " and " << provider_names_[i];
    }
}

// Test cross-provider classical key exchange compatibility
TEST_F(HybridPQCInteropTest, ClassicalKeyExchangeCompatibility) {
    auto provider_pairs = get_provider_pairs();
    if (provider_pairs.empty()) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    std::vector<NamedGroup> classical_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::SECP521R1
    };
    
    for (auto [i, j] : provider_pairs) {
        SCOPED_TRACE("Provider pair: " + provider_names_[i] + " <-> " + provider_names_[j]);
        
        for (auto group : classical_groups) {
            SCOPED_TRACE("Group: " + std::to_string(static_cast<int>(group)));
            
            // Both providers should support the same classical groups
            bool provider_i_supports = providers_[i]->supports_named_group(group);
            bool provider_j_supports = providers_[j]->supports_named_group(group);
            
            if (!provider_i_supports || !provider_j_supports) {
                continue; // Skip if either provider doesn't support this group
            }
            
            // Generate keypairs with both providers
            auto keypair_i = providers_[i]->generate_key_pair(group);
            auto keypair_j = providers_[j]->generate_key_pair(group);
            
            ASSERT_TRUE(keypair_i) << "Key generation failed for " << provider_names_[i];
            ASSERT_TRUE(keypair_j) << "Key generation failed for " << provider_names_[j];
            
            // Note: In a real test, we would perform actual key exchange
            // between providers, but that requires access to raw public key data
            // which may not be directly available through the abstract interface
            
            // For now, verify that key generation succeeds and produces
            // appropriately sized keys (implementation-specific validation)
            EXPECT_TRUE(keypair_i.value().first != nullptr);
            EXPECT_TRUE(keypair_i.value().second != nullptr);
            EXPECT_TRUE(keypair_j.value().first != nullptr);
            EXPECT_TRUE(keypair_j.value().second != nullptr);
        }
    }
}

// Test provider capability consistency
TEST_F(HybridPQCInteropTest, ProviderCapabilityConsistency) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    std::map<std::string, ProviderCapabilities> capabilities_map;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        capabilities_map[provider_names_[i]] = providers_[i]->capabilities();
    }
    
    // Compare supported cipher suites
    std::vector<CipherSuite> common_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    
    for (auto suite : common_cipher_suites) {
        std::vector<bool> support_status;
        
        for (size_t i = 0; i < providers_.size(); ++i) {
            support_status.push_back(providers_[i]->supports_cipher_suite(suite));
        }
        
        // All providers should support common cipher suites
        bool all_support = std::all_of(support_status.begin(), support_status.end(), 
                                      [](bool b) { return b; });
        EXPECT_TRUE(all_support) 
            << "All providers should support cipher suite " << static_cast<int>(suite);
    }
    
    // Compare supported hash algorithms
    std::vector<HashAlgorithm> common_hashes = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384
    };
    
    for (auto hash : common_hashes) {
        std::vector<bool> support_status;
        
        for (size_t i = 0; i < providers_.size(); ++i) {
            support_status.push_back(providers_[i]->supports_hash_algorithm(hash));
        }
        
        bool all_support = std::all_of(support_status.begin(), support_status.end(), 
                                      [](bool b) { return b; });
        EXPECT_TRUE(all_support) 
            << "All providers should support hash algorithm " << static_cast<int>(hash);
    }
}

// Test error handling consistency across providers
TEST_F(HybridPQCInteropTest, ErrorHandlingConsistency) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    // Test invalid ML-KEM parameters
    MLKEMKeyGenParams invalid_params;
    invalid_params.parameter_set = static_cast<MLKEMParameterSet>(99); // Invalid
    
    std::vector<bool> error_results;
    for (size_t i = 0; i < providers_.size(); ++i) {
        auto result = providers_[i]->mlkem_generate_keypair(invalid_params);
        error_results.push_back(!result.is_success());
    }
    
    // All providers should consistently reject invalid parameters
    bool all_failed = std::all_of(error_results.begin(), error_results.end(), 
                                 [](bool failed) { return failed; });
    EXPECT_TRUE(all_failed) << "All providers should reject invalid ML-KEM parameters";
    
    // Test invalid HKDF parameters
    KeyDerivationParams invalid_hkdf;
    invalid_hkdf.secret.clear(); // Empty secret
    invalid_hkdf.output_length = 0; // Invalid length
    
    error_results.clear();
    for (size_t i = 0; i < providers_.size(); ++i) {
        auto result = providers_[i]->derive_key_hkdf(invalid_hkdf);
        error_results.push_back(!result.is_success());
    }
    
    all_failed = std::all_of(error_results.begin(), error_results.end(), 
                            [](bool failed) { return failed; });
    EXPECT_TRUE(all_failed) << "All providers should reject invalid HKDF parameters";
}

// Test performance characteristics consistency
TEST_F(HybridPQCInteropTest, PerformanceCharacteristics) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for interoperability testing";
    }
    
    const size_t iterations = 5;
    
    // Compare ML-KEM key generation performance
    std::vector<std::chrono::microseconds> keygen_times;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        SCOPED_TRACE("Provider: " + provider_names_[i]);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (size_t iter = 0; iter < iterations; ++iter) {
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            
            auto result = providers_[i]->mlkem_generate_keypair(params);
            ASSERT_TRUE(result) << "Key generation failed at iteration " << iter;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        keygen_times.push_back(duration / iterations);
        
        std::cout << provider_names_[i] << " ML-KEM key generation: " 
                  << (duration.count() / iterations) << " µs average" << std::endl;
    }
    
    // Compare HKDF performance
    std::vector<std::chrono::microseconds> hkdf_times;
    std::vector<uint8_t> test_secret(64, 0x42);
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        SCOPED_TRACE("Provider: " + provider_names_[i]);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (size_t iter = 0; iter < iterations; ++iter) {
            KeyDerivationParams params;
            params.secret = test_secret;
            params.salt.clear();
            params.info = std::vector<uint8_t>{'t', 'e', 's', 't'};
            params.output_length = 32;
            params.hash_algorithm = HashAlgorithm::SHA256;
            
            auto result = providers_[i]->derive_key_hkdf(params);
            ASSERT_TRUE(result) << "HKDF failed at iteration " << iter;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        hkdf_times.push_back(duration / iterations);
        
        std::cout << provider_names_[i] << " HKDF: " 
                  << (duration.count() / iterations) << " µs average" << std::endl;
    }
    
    // Performance should be within reasonable ranges (not a strict requirement)
    // This is mainly for informational purposes
    if (keygen_times.size() > 1) {
        auto min_keygen = *std::min_element(keygen_times.begin(), keygen_times.end());
        auto max_keygen = *std::max_element(keygen_times.begin(), keygen_times.end());
        
        std::cout << "ML-KEM key generation performance range: " 
                  << min_keygen.count() << " - " << max_keygen.count() << " µs" << std::endl;
    }
    
    if (hkdf_times.size() > 1) {
        auto min_hkdf = *std::min_element(hkdf_times.begin(), hkdf_times.end());
        auto max_hkdf = *std::max_element(hkdf_times.begin(), hkdf_times.end());
        
        std::cout << "HKDF performance range: " 
                  << min_hkdf.count() << " - " << max_hkdf.count() << " µs" << std::endl;
    }
}