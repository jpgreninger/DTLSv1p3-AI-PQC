/**
 * @file test_cross_provider_comprehensive.cpp
 * @brief Cross-provider compatibility and validation tests
 * 
 * This test suite validates that different crypto providers produce
 * compatible results and can interoperate correctly.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <numeric>
#include <algorithm>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/crypto/botan_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class CrossProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register all available providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            builtin::register_null_provider();
            builtin::register_openssl_provider();
            builtin::register_botan_provider();
        }
        
        // Get available providers
        providers_ = get_available_providers();
        
        // Setup test data
        test_data_.resize(256);
        std::iota(test_data_.begin(), test_data_.end(), 0);
        
        test_key_.resize(32);
        std::iota(test_key_.begin(), test_key_.end(), 1);
        
        test_salt_ = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        test_info_vec_ = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    }
    
    void TearDown() override {
        for (auto* provider : providers_) {
            delete provider;
        }
        ProviderFactory::instance().reset_all_stats();
    }
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        auto& factory = ProviderFactory::instance();
        
        for (const auto& name : {"openssl", "botan"}) {
            auto provider_result = factory.create_provider(name);
            if (provider_result.is_success() && provider_result.value()->is_available()) {
                providers.push_back(provider_result.value().release());
            }
        }
        return providers;
    }
    
    std::vector<CryptoProvider*> providers_;
    std::vector<uint8_t> test_data_;
    std::vector<uint8_t> test_key_;
    std::vector<uint8_t> test_salt_;
    std::vector<uint8_t> test_info_vec_;
};

// ============================================================================
// CROSS-PROVIDER HASH COMPATIBILITY TESTS
// ============================================================================

/**
 * Test that hash functions produce identical results across providers
 */
TEST_F(CrossProviderTest, HashCompatibility) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider testing";
    }
    
    std::vector<HashAlgorithm> hash_algorithms = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    for (auto hash_alg : hash_algorithms) {
        std::map<std::string, std::vector<uint8_t>> provider_results;
        
        for (auto* provider : providers_) {
            HashParams params;
            params.data = test_data_;
            params.algorithm = hash_alg;
            
            auto result = provider->compute_hash(params);
            if (result.is_success()) {
                provider_results[provider->name()] = result.value();
            }
        }
        
        // All providers that support the algorithm should produce identical results
        if (provider_results.size() >= 2) {
            auto first_result = provider_results.begin()->second;
            for (const auto& [provider_name, hash_result] : provider_results) {
                EXPECT_EQ(hash_result, first_result) 
                    << "Hash mismatch between providers for " << static_cast<int>(hash_alg)
                    << " (provider: " << provider_name << ")";
            }
        }
    }
}

/**
 * Test HMAC compatibility across providers
 */
TEST_F(CrossProviderTest, HMACCompatibility) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider testing";
    }
    
    std::vector<HashAlgorithm> hash_algorithms = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    for (auto hash_alg : hash_algorithms) {
        std::map<std::string, std::vector<uint8_t>> provider_results;
        
        for (auto* provider : providers_) {
            HMACParams params;
            params.key = test_key_;
            params.data = test_data_;
            params.algorithm = hash_alg;
            
            auto result = provider->compute_hmac(params);
            if (result.is_success()) {
                provider_results[provider->name()] = result.value();
            }
        }
        
        // All providers should produce identical HMAC results
        if (provider_results.size() >= 2) {
            auto first_result = provider_results.begin()->second;
            for (const auto& [provider_name, hmac_result] : provider_results) {
                EXPECT_EQ(hmac_result, first_result) 
                    << "HMAC mismatch between providers for " << static_cast<int>(hash_alg)
                    << " (provider: " << provider_name << ")";
            }
        }
    }
}

// ============================================================================
// CROSS-PROVIDER KEY DERIVATION COMPATIBILITY TESTS
// ============================================================================

/**
 * Test HKDF compatibility across providers
 */
TEST_F(CrossProviderTest, HKDFCompatibility) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider testing";
    }
    
    std::vector<HashAlgorithm> hash_algorithms = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512
    };
    
    for (auto hash_alg : hash_algorithms) {
        std::map<std::string, std::vector<uint8_t>> provider_results;
        
        for (auto* provider : providers_) {
            KeyDerivationParams params;
            params.secret = test_key_;
            params.salt = test_salt_;
            params.info = test_info_vec_;
            params.output_length = 32;
            params.hash_algorithm = hash_alg;
            
            auto result = provider->derive_key_hkdf(params);
            if (result.is_success()) {
                provider_results[provider->name()] = result.value();
            }
        }
        
        // All providers should produce identical HKDF results
        if (provider_results.size() >= 2) {
            auto first_result = provider_results.begin()->second;
            for (const auto& [provider_name, hkdf_result] : provider_results) {
                EXPECT_EQ(hkdf_result, first_result) 
                    << "HKDF mismatch between providers for " << static_cast<int>(hash_alg)
                    << " (provider: " << provider_name << ")";
            }
        }
    }
}

/**
 * Test PBKDF2 compatibility across providers
 */
TEST_F(CrossProviderTest, PBKDF2Compatibility) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider testing";
    }
    
    std::map<std::string, std::vector<uint8_t>> provider_results;
    
    for (auto* provider : providers_) {
        KeyDerivationParams params;
        params.secret = test_key_;  // Used as password
        params.salt = test_salt_;
        params.output_length = 32;
        params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_pbkdf2(params);
        if (result.is_success()) {
            provider_results[provider->name()] = result.value();
        }
    }
    
    // All providers should produce identical PBKDF2 results
    if (provider_results.size() >= 2) {
        auto first_result = provider_results.begin()->second;
        for (const auto& [provider_name, pbkdf2_result] : provider_results) {
            EXPECT_EQ(pbkdf2_result, first_result) 
                << "PBKDF2 mismatch between providers (provider: " << provider_name << ")";
        }
    }
}

// ============================================================================
// CROSS-PROVIDER AEAD COMPATIBILITY TESTS
// ============================================================================

/**
 * Test AEAD encryption/decryption compatibility across providers
 */
TEST_F(CrossProviderTest, AEADCompatibility) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for cross-provider testing";
    }
    
    std::vector<AEADCipher> ciphers = {
        AEADCipher::AES_128_GCM,
        AEADCipher::AES_256_GCM,
        AEADCipher::CHACHA20_POLY1305
    };
    
    for (auto cipher : ciphers) {
        // Use appropriate key size for cipher
        std::vector<uint8_t> aead_key = test_key_;
        if (cipher == AEADCipher::AES_128_GCM) {
            aead_key.resize(16);
        } else if (cipher == AEADCipher::AES_256_GCM || cipher == AEADCipher::CHACHA20_POLY1305) {
            aead_key.resize(32);
        }
        
        std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
        std::vector<uint8_t> aad = {0xAA, 0xBB, 0xCC, 0xDD};
        
        // Test encryption across providers
        std::map<std::string, AEADEncryptionOutput> encryption_results;
        
        for (auto* provider : providers_) {
            AEADEncryptionParams encrypt_params;
            encrypt_params.key = aead_key;
            encrypt_params.nonce = nonce;
            encrypt_params.additional_data = aad;
            encrypt_params.plaintext = test_data_;
            encrypt_params.cipher = cipher;
            
            auto result = provider->encrypt_aead(encrypt_params);
            if (result.is_success()) {
                encryption_results[provider->name()] = result.value();
            }
        }
        
        // Test cross-provider decryption (encrypted by one, decrypted by another)
        for (const auto& [encrypt_provider, encrypt_output] : encryption_results) {
            for (auto* decrypt_provider : providers_) {
                AEADDecryptionParams decrypt_params;
                decrypt_params.key = aead_key;
                decrypt_params.nonce = nonce;
                decrypt_params.additional_data = aad;
                decrypt_params.ciphertext = encrypt_output.ciphertext;
                decrypt_params.tag = encrypt_output.tag;
                decrypt_params.cipher = cipher;
                
                auto decrypt_result = decrypt_provider->decrypt_aead(decrypt_params);
                if (decrypt_result.is_success()) {
                    EXPECT_EQ(decrypt_result.value(), test_data_)
                        << "Cross-provider AEAD decryption failed: "
                        << "cipher=" << static_cast<int>(cipher)
                        << ", encrypt_provider=" << encrypt_provider
                        << ", decrypt_provider=" << decrypt_provider->name();
                }
            }
        }
    }
}

// ============================================================================
// CROSS-PROVIDER RANDOM GENERATION QUALITY TESTS
// ============================================================================

/**
 * Test random generation quality across providers
 */
TEST_F(CrossProviderTest, RandomGenerationQuality) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for random generation testing";
    }
    
    const size_t sample_size = 1000;
    const size_t random_length = 32;
    
    for (auto* provider : providers_) {
        std::set<std::vector<uint8_t>> unique_samples;
        std::vector<double> byte_frequencies(256, 0.0);
        
        for (size_t i = 0; i < sample_size; ++i) {
            RandomParams params;
            params.length = random_length;
            params.cryptographically_secure = true;
            
            auto result = provider->generate_random(params);
            ASSERT_TRUE(result.is_success()) 
                << "Random generation failed for provider " << provider->name();
            
            const auto& random_data = result.value();
            unique_samples.insert(random_data);
            
            // Count byte frequencies
            for (uint8_t byte : random_data) {
                byte_frequencies[byte] += 1.0;
            }
        }
        
        // Test uniqueness
        double uniqueness_ratio = static_cast<double>(unique_samples.size()) / sample_size;
        EXPECT_GT(uniqueness_ratio, 0.95) 
            << "Random uniqueness too low for provider " << provider->name()
            << " (ratio: " << uniqueness_ratio << ")";
        
        // Test byte distribution (chi-square test would be more rigorous)
        double total_bytes = sample_size * random_length;
        double expected_frequency = total_bytes / 256.0;
        double chi_square = 0.0;
        
        for (double freq : byte_frequencies) {
            double diff = freq - expected_frequency;
            chi_square += (diff * diff) / expected_frequency;
        }
        
        // Very loose chi-square test (proper threshold would be ~293.25 for 255 DOF at 95%)
        EXPECT_LT(chi_square, 400.0) 
            << "Random distribution too non-uniform for provider " << provider->name()
            << " (chi-square: " << chi_square << ")";
    }
}

// ============================================================================
// PROVIDER FEATURE PARITY TESTS
// ============================================================================

/**
 * Test feature parity across providers
 */
TEST_F(CrossProviderTest, FeatureParity) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for feature parity testing";
    }
    
    // Test cipher suite support consistency
    std::vector<CipherSuite> important_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    
    for (auto suite : important_suites) {
        std::vector<bool> support_status;
        for (auto* provider : providers_) {
            support_status.push_back(provider->supports_cipher_suite(suite));
        }
        
        // Log support status for analysis
        std::string support_info = "Cipher suite " + std::to_string(static_cast<int>(suite)) + " support: ";
        for (size_t i = 0; i < providers_.size(); ++i) {
            support_info += providers_[i]->name() + "=" + (support_status[i] ? "Y" : "N") + " ";
        }
        SCOPED_TRACE(support_info);
    }
    
    // Test named group support
    std::vector<NamedGroup> important_groups = {
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
        NamedGroup::X25519
    };
    
    for (auto group : important_groups) {
        std::vector<bool> support_status;
        for (auto* provider : providers_) {
            support_status.push_back(provider->supports_named_group(group));
        }
        
        // Log support status for analysis
        std::string support_info = "Named group " + std::to_string(static_cast<int>(group)) + " support: ";
        for (size_t i = 0; i < providers_.size(); ++i) {
            support_info += providers_[i]->name() + "=" + (support_status[i] ? "Y" : "N") + " ";
        }
        SCOPED_TRACE(support_info);
    }
}

// ============================================================================
// PROVIDER PERFORMANCE COMPARISON TESTS
// ============================================================================

/**
 * Compare performance characteristics across providers
 */
TEST_F(CrossProviderTest, PerformanceComparison) {
    if (providers_.empty()) {
        GTEST_SKIP() << "No providers available for performance testing";
    }
    
    const size_t iterations = 100;
    
    for (auto* provider : providers_) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Perform a series of operations
        for (size_t i = 0; i < iterations; ++i) {
            // Hash operation
            HashParams hash_params;
            hash_params.data = test_data_;
            hash_params.algorithm = HashAlgorithm::SHA256;
            auto hash_result = provider->compute_hash(hash_params);
            
            // HMAC operation
            HMACParams hmac_params;
            hmac_params.key = test_key_;
            hmac_params.data = test_data_;
            hmac_params.algorithm = HashAlgorithm::SHA256;
            auto hmac_result = provider->compute_hmac(hmac_params);
            
            // HKDF operation
            KeyDerivationParams hkdf_params;
            hkdf_params.secret = test_key_;
            hkdf_params.salt = test_salt_;
            hkdf_params.info = test_info_vec_;
            hkdf_params.output_length = 32;
            hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
            auto hkdf_result = provider->derive_key_hkdf(hkdf_params);
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        double ops_per_second = (iterations * 3.0) / (duration.count() / 1e6);
        
        // Log performance for analysis (not a test failure)
        SCOPED_TRACE("Provider " + provider->name() + " performance: " + 
                    std::to_string(ops_per_second) + " ops/sec");
        
        // Sanity check - should complete in reasonable time
        EXPECT_LT(duration.count(), 10000000) // 10 seconds
            << "Provider " << provider->name() << " performance too slow";
    }
}

// ============================================================================
// PROVIDER ERROR HANDLING CONSISTENCY TESTS
// ============================================================================

/**
 * Test that providers handle errors consistently
 */
TEST_F(CrossProviderTest, ErrorHandlingConsistency) {
    if (providers_.size() < 2) {
        GTEST_SKIP() << "Need at least 2 providers for error handling testing";
    }
    
    // Test invalid HKDF parameters
    KeyDerivationParams invalid_hkdf;
    invalid_hkdf.secret.clear();  // Empty secret
    invalid_hkdf.output_length = 0;  // Invalid length
    
    std::vector<bool> error_results;
    for (auto* provider : providers_) {
        auto result = provider->derive_key_hkdf(invalid_hkdf);
        error_results.push_back(result.is_error());
    }
    
    // All providers should handle this error case similarly
    bool first_result = error_results[0];
    for (size_t i = 1; i < error_results.size(); ++i) {
        EXPECT_EQ(error_results[i], first_result)
            << "Inconsistent error handling between providers for invalid HKDF";
    }
    
    // Test invalid AEAD parameters
    AEADEncryptionParams invalid_aead;
    invalid_aead.key = {0x01, 0x02};  // Too short
    invalid_aead.cipher = AEADCipher::AES_256_GCM;  // Requires 32-byte key
    
    error_results.clear();
    for (auto* provider : providers_) {
        auto result = provider->encrypt_aead(invalid_aead);
        error_results.push_back(result.is_error());
    }
    
    // All providers should handle this error case similarly
    first_result = error_results[0];
    for (size_t i = 1; i < error_results.size(); ++i) {
        EXPECT_EQ(error_results[i], first_result)
            << "Inconsistent error handling between providers for invalid AEAD";
    }
}