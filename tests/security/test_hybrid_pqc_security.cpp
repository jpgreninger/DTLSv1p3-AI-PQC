/**
 * @file test_hybrid_pqc_security.cpp
 * @brief Security validation tests for hybrid PQC implementation
 * 
 * Tests security properties of hybrid post-quantum cryptography including
 * shared secret entropy, key derivation security, attack resistance,
 * and compliance with security requirements from draft-kwiatkowski-tls-ecdhe-mlkem-03.
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include "../test_infrastructure/test_utilities.h"
#include <vector>
#include <memory>
#include <string>
#include <random>
#include <algorithm>
#include <cmath>
#include <set>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class HybridPQCSecurityTest : public ::testing::Test {
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

        auto hardware_result = factory.create_provider("hardware");
        if (hardware_result && hardware_result.value()->is_available()) {
            hardware_provider_ = std::move(hardware_result.value());
            auto init_result = hardware_provider_->initialize();
            if (!init_result) {
                hardware_provider_.reset();
            }
        }
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    // Statistical entropy test for randomness
    double calculate_shannon_entropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;
        
        std::array<size_t, 256> freq = {0};
        for (uint8_t byte : data) {
            freq[byte]++;
        }
        
        double entropy = 0.0;
        double data_size = static_cast<double>(data.size());
        
        for (size_t count : freq) {
            if (count > 0) {
                double p = static_cast<double>(count) / data_size;
                entropy -= p * std::log2(p);
            }
        }
        
        return entropy;
    }
    
    // Test for repeated patterns in data
    bool has_suspicious_patterns(const std::vector<uint8_t>& data) {
        if (data.size() < 32) return false;
        
        // Check for repeated 4-byte patterns
        std::set<std::vector<uint8_t>> patterns;
        size_t pattern_repeats = 0;
        
        for (size_t i = 0; i <= data.size() - 4; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + 4);
            if (patterns.count(pattern)) {
                pattern_repeats++;
            }
            patterns.insert(pattern);
        }
        
        // Suspicious if more than 10% of 4-byte windows are repeats
        double repeat_ratio = static_cast<double>(pattern_repeats) / (data.size() - 3);
        return repeat_ratio > 0.1;
    }
    
    // Combine classical and PQ shared secrets using HKDF as per draft spec
    std::vector<uint8_t> combine_shared_secrets(
        CryptoProvider* provider,
        const std::vector<uint8_t>& classical_ss,
        const std::vector<uint8_t>& pq_ss) {
        
        KeyDerivationParams hkdf_params;
        hkdf_params.secret.insert(hkdf_params.secret.end(), classical_ss.begin(), classical_ss.end());
        hkdf_params.secret.insert(hkdf_params.secret.end(), pq_ss.begin(), pq_ss.end());
        hkdf_params.salt.clear(); // Empty salt as per draft
        hkdf_params.info = std::vector<uint8_t>{'d', 't', 'l', 's', '_', 'h', 'y', 'b', 'r', 'i', 'd'};
        hkdf_params.output_length = 32;
        hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto result = provider->derive_key_hkdf(hkdf_params);
        return result ? result.value() : std::vector<uint8_t>{};
    }
};

// Test shared secret entropy and randomness
TEST_F(HybridPQCSecurityTest, SharedSecretEntropy) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int test_iterations = 20;
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        std::vector<MLKEMParameterSet> param_sets = {
            MLKEMParameterSet::MLKEM512,
            MLKEMParameterSet::MLKEM768,
            MLKEMParameterSet::MLKEM1024
        };
        
        for (auto param_set : param_sets) {
            SCOPED_TRACE("Parameter set: " + std::to_string(static_cast<int>(param_set)));
            
            std::vector<std::vector<uint8_t>> shared_secrets;
            
            for (int i = 0; i < test_iterations; ++i) {
                // Generate keypair
                MLKEMKeyGenParams keygen_params;
                keygen_params.parameter_set = param_set;
                auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
                ASSERT_TRUE(keygen_result) << "Key generation failed at iteration " << i;
                auto [public_key, private_key] = keygen_result.value();
                
                // Encapsulate
                MLKEMEncapParams encap_params;
                encap_params.parameter_set = param_set;
                encap_params.public_key = public_key;
                auto encap_result = provider->mlkem_encapsulate(encap_params);
                ASSERT_TRUE(encap_result) << "Encapsulation failed at iteration " << i;
                
                shared_secrets.push_back(encap_result.value().shared_secret);
            }
            
            // Test entropy of each shared secret
            for (size_t i = 0; i < shared_secrets.size(); ++i) {
                const auto& ss = shared_secrets[i];
                
                // Shannon entropy should be high (close to 8 for good randomness)
                double entropy = calculate_shannon_entropy(ss);
                EXPECT_GE(entropy, 6.0) << "Low entropy in shared secret " << i;
                
                // Should not have suspicious patterns
                EXPECT_FALSE(has_suspicious_patterns(ss)) 
                    << "Suspicious patterns in shared secret " << i;
                
                // Should not be all zeros or all ones
                EXPECT_NE(std::count(ss.begin(), ss.end(), 0), ss.size()) 
                    << "Shared secret " << i << " is all zeros";
                EXPECT_NE(std::count(ss.begin(), ss.end(), 0xFF), ss.size()) 
                    << "Shared secret " << i << " is all ones";
            }
            
            // Test uniqueness - no two shared secrets should be identical
            for (size_t i = 0; i < shared_secrets.size(); ++i) {
                for (size_t j = i + 1; j < shared_secrets.size(); ++j) {
                    EXPECT_NE(shared_secrets[i], shared_secrets[j]) 
                        << "Duplicate shared secrets at indices " << i << " and " << j;
                }
            }
        }
    }
}

// Test HKDF key combination security
TEST_F(HybridPQCSecurityTest, HybridKeyDerivationSecurity) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        const int test_iterations = 10;
        std::vector<std::vector<uint8_t>> combined_secrets;
        
        for (int i = 0; i < test_iterations; ++i) {
            // Generate classical shared secret (simulate ECDHE)
            RandomParams random_params;
            random_params.length = 32;
            auto classical_ss = provider->generate_random(random_params);
            ASSERT_TRUE(classical_ss) << "Failed to generate classical shared secret";
            
            // Generate ML-KEM shared secret
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result) << "Key generation failed";
            auto [public_key, private_key] = keygen_result.value();
            
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
            encap_params.public_key = public_key;
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result) << "Encapsulation failed";
            
            // Combine using HKDF
            auto combined = combine_shared_secrets(provider, 
                                                  classical_ss.value(),
                                                  encap_result.value().shared_secret);
            ASSERT_FALSE(combined.empty()) << "HKDF combination failed";
            
            combined_secrets.push_back(combined);
        }
        
        // Test properties of combined secrets
        for (size_t i = 0; i < combined_secrets.size(); ++i) {
            const auto& combined = combined_secrets[i];
            
            EXPECT_EQ(combined.size(), 32) << "Combined secret has wrong size";
            
            // High entropy requirement
            double entropy = calculate_shannon_entropy(combined);
            EXPECT_GE(entropy, 6.5) << "Combined secret " << i << " has low entropy";
            
            // No obvious patterns
            EXPECT_FALSE(has_suspicious_patterns(combined)) 
                << "Combined secret " << i << " has suspicious patterns";
        }
        
        // Test uniqueness of combined secrets
        for (size_t i = 0; i < combined_secrets.size(); ++i) {
            for (size_t j = i + 1; j < combined_secrets.size(); ++j) {
                EXPECT_NE(combined_secrets[i], combined_secrets[j]) 
                    << "Duplicate combined secrets at indices " << i << " and " << j;
            }
        }
    }
}

// Test that individual components don't leak into combined secret
TEST_F(HybridPQCSecurityTest, ComponentIsolation) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Create known test vectors
        std::vector<uint8_t> classical_ss(32, 0xAA);
        std::vector<uint8_t> pq_ss(32, 0x55);
        
        auto combined = combine_shared_secrets(provider, classical_ss, pq_ss);
        ASSERT_FALSE(combined.empty()) << "HKDF combination failed";
        
        // Combined secret should not equal either component
        EXPECT_NE(combined, classical_ss) 
            << "Combined secret equals classical component";
        EXPECT_NE(combined, pq_ss) 
            << "Combined secret equals PQ component";
        
        // Combined secret should not contain long runs of component bytes
        size_t classical_byte_count = std::count(combined.begin(), combined.end(), 0xAA);
        size_t pq_byte_count = std::count(combined.begin(), combined.end(), 0x55);
        
        EXPECT_LT(classical_byte_count, combined.size() / 2) 
            << "Too many classical component bytes in combined secret";
        EXPECT_LT(pq_byte_count, combined.size() / 2) 
            << "Too many PQ component bytes in combined secret";
    }
}

// Test resistance to common attacks on hybrid systems
TEST_F(HybridPQCSecurityTest, AttackResistance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test 1: Resistance to classical component compromise
        // Even if classical ECDHE is broken, PQ component should provide security
        std::vector<uint8_t> compromised_classical(32, 0x00); // Known/zero classical
        
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result);
        auto [public_key, private_key] = keygen_result.value();
        
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = public_key;
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        ASSERT_TRUE(encap_result);
        
        auto combined = combine_shared_secrets(provider,
                                              compromised_classical,
                                              encap_result.value().shared_secret);
        ASSERT_FALSE(combined.empty());
        
        // Combined secret should still have high entropy despite classical compromise
        double entropy = calculate_shannon_entropy(combined);
        EXPECT_GE(entropy, 6.0) << "Combined secret vulnerable to classical compromise";
        
        // Combined secret should not be predictable from compromised classical part
        EXPECT_NE(combined, compromised_classical);
        EXPECT_LT(std::count(combined.begin(), combined.end(), 0x00), combined.size() / 4);
        
        // Test 2: Resistance to PQ component compromise (theoretical)
        // Even if PQ is broken, classical should provide some security
        std::vector<uint8_t> compromised_pq(32, 0x00); // Known/zero PQ
        
        RandomParams random_params;
        random_params.length = 32;
        auto good_classical = provider->generate_random(random_params);
        ASSERT_TRUE(good_classical);
        
        combined = combine_shared_secrets(provider,
                                        good_classical.value(),
                                        compromised_pq);
        ASSERT_FALSE(combined.empty());
        
        // Combined should still have entropy from classical part
        entropy = calculate_shannon_entropy(combined);
        EXPECT_GE(entropy, 5.0) << "Combined secret vulnerable to PQ compromise";
    }
}

// Test key material cleanup and side-channel resistance
TEST_F(HybridPQCSecurityTest, KeyMaterialSecurity) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test that key generation produces different keys each time
        std::vector<std::vector<uint8_t>> private_keys;
        std::vector<std::vector<uint8_t>> public_keys;
        
        const int key_count = 5;
        for (int i = 0; i < key_count; ++i) {
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result) << "Key generation failed at iteration " << i;
            
            auto [pubkey, privkey] = result.value();
            public_keys.push_back(pubkey);
            private_keys.push_back(privkey);
        }
        
        // Verify all keys are unique
        for (int i = 0; i < key_count; ++i) {
            for (int j = i + 1; j < key_count; ++j) {
                EXPECT_NE(public_keys[i], public_keys[j]) 
                    << "Duplicate public keys at " << i << " and " << j;
                EXPECT_NE(private_keys[i], private_keys[j]) 
                    << "Duplicate private keys at " << i << " and " << j;
            }
        }
        
        // Test timing consistency (basic side-channel resistance)
        const int timing_tests = 20;
        std::vector<std::chrono::microseconds> keygen_times;
        std::vector<std::chrono::microseconds> encap_times;
        
        for (int i = 0; i < timing_tests; ++i) {
            // Measure key generation time
            auto start = std::chrono::high_resolution_clock::now();
            MLKEMKeyGenParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            auto keygen_result = provider->mlkem_generate_keypair(params);
            auto end = std::chrono::high_resolution_clock::now();
            
            ASSERT_TRUE(keygen_result);
            auto keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            keygen_times.push_back(keygen_duration);
            
            // Measure encapsulation time
            auto [pubkey, privkey] = keygen_result.value();
            start = std::chrono::high_resolution_clock::now();
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
            encap_params.public_key = pubkey;
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            end = std::chrono::high_resolution_clock::now();
            
            ASSERT_TRUE(encap_result);
            auto encap_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            encap_times.push_back(encap_duration);
        }
        
        // Calculate timing statistics
        auto avg_keygen = std::accumulate(keygen_times.begin(), keygen_times.end(), 
                                        std::chrono::microseconds(0)) / timing_tests;
        auto avg_encap = std::accumulate(encap_times.begin(), encap_times.end(), 
                                       std::chrono::microseconds(0)) / timing_tests;
        
        // Check for reasonable timing consistency (not too much variance)
        auto max_keygen = *std::max_element(keygen_times.begin(), keygen_times.end());
        auto min_keygen = *std::min_element(keygen_times.begin(), keygen_times.end());
        auto max_encap = *std::max_element(encap_times.begin(), encap_times.end());
        auto min_encap = *std::min_element(encap_times.begin(), encap_times.end());
        
        // Timing variance should not be excessive (basic side-channel check)
        auto keygen_variance = (max_keygen - min_keygen).count();
        auto encap_variance = (max_encap - min_encap).count();
        
        std::cout << provider->name() << " timing analysis:" << std::endl;
        std::cout << "  Key generation avg: " << avg_keygen.count() << " µs, variance: " 
                  << keygen_variance << " µs" << std::endl;
        std::cout << "  Encapsulation avg: " << avg_encap.count() << " µs, variance: " 
                  << encap_variance << " µs" << std::endl;
        
        // Basic timing attack resistance - variance should not exceed 10x average
        EXPECT_LT(keygen_variance, avg_keygen.count() * 10) 
            << "Excessive timing variance in key generation";
        EXPECT_LT(encap_variance, avg_encap.count() * 10) 
            << "Excessive timing variance in encapsulation";
    }
}

// Test compliance with security requirements from draft specification
TEST_F(HybridPQCSecurityTest, SpecificationCompliance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test 1: HKDF must use SHA-256 or stronger
        std::vector<uint8_t> test_classical(32, 0x42);
        std::vector<uint8_t> test_pq(32, 0x24);
        
        KeyDerivationParams hkdf_params;
        hkdf_params.secret.insert(hkdf_params.secret.end(), test_classical.begin(), test_classical.end());
        hkdf_params.secret.insert(hkdf_params.secret.end(), test_pq.begin(), test_pq.end());
        hkdf_params.salt.clear();
        hkdf_params.info = std::vector<uint8_t>{'t', 'e', 's', 't'};
        hkdf_params.output_length = 32;
        hkdf_params.hash_algorithm = HashAlgorithm::SHA256;
        
        auto hkdf_result = provider->derive_key_hkdf(hkdf_params);
        ASSERT_TRUE(hkdf_result) << "HKDF with SHA-256 must be supported";
        EXPECT_EQ(hkdf_result.value().size(), 32);
        
        // Test SHA-384 support
        hkdf_params.hash_algorithm = HashAlgorithm::SHA384;
        hkdf_result = provider->derive_key_hkdf(hkdf_params);
        ASSERT_TRUE(hkdf_result) << "HKDF with SHA-384 should be supported";
        
        // Test 2: Combined shared secret must be exactly 32 bytes
        auto combined = combine_shared_secrets(provider, test_classical, test_pq);
        ASSERT_FALSE(combined.empty());
        EXPECT_EQ(combined.size(), 32) << "Combined shared secret must be 32 bytes";
        
        // Test 3: ML-KEM shared secrets must be exactly 32 bytes
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result);
        auto [pubkey, privkey] = keygen_result.value();
        
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = pubkey;
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        ASSERT_TRUE(encap_result);
        
        EXPECT_EQ(encap_result.value().shared_secret.size(), 32) 
            << "ML-KEM shared secret must be 32 bytes";
        
        // Test 4: Key sizes must match FIPS 203 specification
        auto sizes = hybrid_pqc::get_mlkem_sizes(MLKEMParameterSet::MLKEM512);
        EXPECT_EQ(sizes.public_key_bytes, 800);
        EXPECT_EQ(sizes.private_key_bytes, 1632);
        EXPECT_EQ(sizes.ciphertext_bytes, 768);
        EXPECT_EQ(sizes.shared_secret_bytes, 32);
        
        EXPECT_EQ(pubkey.size(), 800) << "ML-KEM-512 public key size must be 800 bytes";
        EXPECT_EQ(privkey.size(), 1632) << "ML-KEM-512 private key size must be 1632 bytes";
        EXPECT_EQ(encap_result.value().ciphertext.size(), 768) 
            << "ML-KEM-512 ciphertext size must be 768 bytes";
    }
}

// Test resistance to malformed input attacks
TEST_F(HybridPQCSecurityTest, MalformedInputResistance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        SCOPED_TRACE("Provider: " + provider->name());
        
        // Test malformed ML-KEM public key
        MLKEMEncapParams malformed_encap;
        malformed_encap.parameter_set = MLKEMParameterSet::MLKEM512;
        malformed_encap.public_key = std::vector<uint8_t>(800, 0xFF); // All 1s
        
        auto result = provider->mlkem_encapsulate(malformed_encap);
        // Should either succeed (if implementation handles it) or fail gracefully
        if (!result) {
            EXPECT_EQ(result.error(), DTLSError::CRYPTO_ERROR);
        }
        
        // Test malformed ML-KEM ciphertext
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result);
        auto [pubkey, privkey] = keygen_result.value();
        
        MLKEMDecapParams malformed_decap;
        malformed_decap.parameter_set = MLKEMParameterSet::MLKEM512;
        malformed_decap.private_key = privkey;
        malformed_decap.ciphertext = std::vector<uint8_t>(768, 0x00); // All zeros
        
        result = provider->mlkem_decapsulate(malformed_decap);
        // Should fail gracefully or handle the malformed input
        if (!result) {
            EXPECT_EQ(result.error(), DTLSError::CRYPTO_ERROR);
        }
        
        // Test oversized inputs
        malformed_encap.public_key = std::vector<uint8_t>(1000, 0x42); // Too large
        result = provider->mlkem_encapsulate(malformed_encap);
        EXPECT_FALSE(result) << "Should reject oversized public key";
        
        malformed_decap.ciphertext = std::vector<uint8_t>(1000, 0x42); // Too large
        result = provider->mlkem_decapsulate(malformed_decap);
        EXPECT_FALSE(result) << "Should reject oversized ciphertext";
        
        // Test undersized inputs
        malformed_encap.public_key = std::vector<uint8_t>(10, 0x42); // Too small
        result = provider->mlkem_encapsulate(malformed_encap);
        EXPECT_FALSE(result) << "Should reject undersized public key";
        
        malformed_decap.ciphertext = std::vector<uint8_t>(10, 0x42); // Too small
        result = provider->mlkem_decapsulate(malformed_decap);
        EXPECT_FALSE(result) << "Should reject undersized ciphertext";
    }
}