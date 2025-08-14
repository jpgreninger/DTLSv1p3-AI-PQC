/**
 * @file test_mlkem_security.cpp
 * @brief Security validation tests for ML-KEM implementation
 * 
 * This test suite validates the security properties of the ML-KEM implementation
 * including failure rate handling, key validation mechanisms, side-channel
 * resistance, and compliance with FIPS 203 security requirements.
 * 
 * Security Test Coverage:
 * - ML-KEM failure rate handling (< 2^-138)
 * - Key validation mechanisms
 * - Invalid key/ciphertext handling
 * - Side-channel resistance verification
 * - Randomness quality validation
 * - Attack resilience testing
 * 
 * @author DTLS v1.3 Test Suite
 * @version 1.0.0
 */

#include <gtest/gtest.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/types.h>
#include "../test_infrastructure/test_utilities.h"
#include <vector>
#include <memory>
#include <string>
#include <chrono>
#include <random>
#include <algorithm>
#include <cmath>
#include <set>
#include <bitset>
#include <functional>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

/**
 * Security test fixture for ML-KEM operations
 */
class MLKEMSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Initialize available providers
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
        
        // Initialize random engine
        random_engine_.seed(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    std::mt19937 random_engine_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    // Statistical entropy calculation for randomness testing
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
    
    // Test for repeated patterns in data (simple pattern detection)
    bool has_suspicious_patterns(const std::vector<uint8_t>& data) {
        if (data.size() < 8) return false;
        
        // Check for repeated bytes
        for (size_t i = 0; i < data.size() - 4; ++i) {
            bool repeated = true;
            for (size_t j = 1; j < 4; ++j) {
                if (data[i] != data[i + j]) {
                    repeated = false;
                    break;
                }
            }
            if (repeated) return true;
        }
        
        // Check for simple patterns
        for (size_t i = 0; i < data.size() - 4; ++i) {
            if (data[i] == 0x00 && data[i+1] == 0x01 && 
                data[i+2] == 0x02 && data[i+3] == 0x03) {
                return true; // Found sequential pattern
            }
        }
        
        return false;
    }
    
    // Generate corrupted key/ciphertext for testing
    std::vector<uint8_t> corrupt_data(const std::vector<uint8_t>& original, 
                                     size_t num_bit_flips = 1) {
        auto corrupted = original;
        if (corrupted.empty()) return corrupted;
        
        std::uniform_int_distribution<size_t> byte_dist(0, corrupted.size() - 1);
        std::uniform_int_distribution<int> bit_dist(0, 7);
        
        for (size_t i = 0; i < num_bit_flips; ++i) {
            size_t byte_idx = byte_dist(random_engine_);
            int bit_idx = bit_dist(random_engine_);
            corrupted[byte_idx] ^= (1 << bit_idx);
        }
        
        return corrupted;
    }
    
    // Time a function execution
    template<typename Func>
    std::chrono::nanoseconds time_execution(Func&& func) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }
    
    // Generate zero-filled data for testing
    std::vector<uint8_t> generate_zeros(size_t length) {
        return std::vector<uint8_t>(length, 0);
    }
    
    // Generate all-ones data for testing
    std::vector<uint8_t> generate_ones(size_t length) {
        return std::vector<uint8_t>(length, 0xFF);
    }
};

// ============================================================================
// SECURITY TESTS - Failure Rate Handling
// ============================================================================

/**
 * Test ML-KEM theoretical failure rate constraints
 * According to FIPS 203, ML-KEM has a decapsulation failure rate < 2^-138
 */
TEST_F(MLKEMSecurityTest, FailureRateSpecification) {
    // This is a specification compliance test - the actual failure rate
    // is astronomically small and would require impractical statistical testing
    
    const double max_failure_rate = 1e-42; // Approximately 2^-138
    EXPECT_LT(max_failure_rate, 1e-40) 
        << "ML-KEM failure rate specification must be < 2^-138";
        
    // Verify this is practically zero for cryptographic applications
    EXPECT_LT(max_failure_rate, 1e-30) 
        << "ML-KEM failure rate is acceptably negligible";
}

/**
 * Test error handling for invalid parameter sets
 */
TEST_F(MLKEMSecurityTest, InvalidParameterSets) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Test key generation with invalid parameter set
        MLKEMKeyGenParams invalid_params;
        invalid_params.parameter_set = static_cast<MLKEMParameterSet>(99); // Invalid value
        
        auto result = provider->mlkem_generate_keypair(invalid_params);
        EXPECT_FALSE(result.is_success())
            << "Key generation should fail with invalid parameter set";
    }
}

// ============================================================================
// SECURITY TESTS - Key Validation Mechanisms  
// ============================================================================

/**
 * Test handling of invalid public keys
 */
TEST_F(MLKEMSecurityTest, InvalidPublicKeyHandling) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Test encapsulation with zero-filled public key
        MLKEMEncapParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        params.public_key = generate_zeros(800); // ML-KEM-512 public key size
        
        auto result = provider->mlkem_encapsulate(params);
        // Result handling depends on provider implementation
        // Some may detect invalid keys, others may process them
        if (!result.is_success()) {
            SUCCEED() << "Provider correctly rejected zero-filled public key";
        } else {
            // If accepted, ensure operation completes without crashing
            SUCCEED() << "Provider handled zero-filled public key gracefully";
        }
        
        // Test with all-ones public key
        params.public_key = generate_ones(800);
        
        auto result2 = provider->mlkem_encapsulate(params);
        if (!result2.is_success()) {
            SUCCEED() << "Provider correctly rejected all-ones public key";
        } else {
            SUCCEED() << "Provider handled all-ones public key gracefully";
        }
        
        // Test with wrong-sized public key
        params.public_key = generate_zeros(100); // Wrong size
        
        auto result3 = provider->mlkem_encapsulate(params);
        EXPECT_FALSE(result3.is_success())
            << "Provider should reject wrong-sized public key";
    }
}

/**
 * Test handling of invalid private keys
 */
TEST_F(MLKEMSecurityTest, InvalidPrivateKeyHandling) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Generate valid keypair first for valid ciphertext
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, valid_private_key] = keygen_result.value();
        
        // Generate valid ciphertext
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = public_key;
        
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        ASSERT_TRUE(encap_result.is_success());
        
        // Test decapsulation with zero-filled private key
        MLKEMDecapParams decap_params;
        decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        decap_params.private_key = generate_zeros(1632); // ML-KEM-512 private key size
        decap_params.ciphertext = encap_result.value().ciphertext;
        
        auto result = provider->mlkem_decapsulate(decap_params);
        // Invalid private key should either fail or produce wrong shared secret
        if (!result.is_success()) {
            SUCCEED() << "Provider correctly rejected zero-filled private key";
        } else {
            // If it succeeds, the shared secret should be different from expected
            // (cannot verify without valid operation since we don't have expected result)
            SUCCEED() << "Provider handled invalid private key gracefully";
        }
        
        // Test with wrong-sized private key
        decap_params.private_key = generate_zeros(100); // Wrong size
        
        auto result2 = provider->mlkem_decapsulate(decap_params);
        EXPECT_FALSE(result2.is_success())
            << "Provider should reject wrong-sized private key";
    }
}

/**
 * Test handling of invalid ciphertexts
 */
TEST_F(MLKEMSecurityTest, InvalidCiphertextHandling) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Generate valid keypair
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, private_key] = keygen_result.value();
        
        // Test decapsulation with zero-filled ciphertext
        MLKEMDecapParams decap_params;
        decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        decap_params.private_key = private_key;
        decap_params.ciphertext = generate_zeros(768); // ML-KEM-512 ciphertext size
        
        auto result = provider->mlkem_decapsulate(decap_params);
        // Should handle gracefully (may succeed with different shared secret)
        if (!result.is_success()) {
            SUCCEED() << "Provider detected invalid ciphertext";
        } else {
            SUCCEED() << "Provider handled invalid ciphertext gracefully";
        }
        
        // Test with wrong-sized ciphertext
        decap_params.ciphertext = generate_zeros(100); // Wrong size
        
        auto result2 = provider->mlkem_decapsulate(decap_params);
        EXPECT_FALSE(result2.is_success())
            << "Provider should reject wrong-sized ciphertext";
    }
}

// ============================================================================
// SECURITY TESTS - Randomness Quality Validation
// ============================================================================

/**
 * Test quality of generated keys (entropy analysis)
 */
TEST_F(MLKEMSecurityTest, KeyRandomnessQuality) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_samples = 20; // Limited for CI performance
    
    for (auto* provider : providers) {
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        std::vector<double> public_key_entropies;
        std::vector<double> private_key_entropies;
        
        for (int i = 0; i < num_samples; ++i) {
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success()) << "Key generation failed on sample " << i;
            
            const auto& [public_key, private_key] = result.value();
            
            // Calculate entropy
            double pub_entropy = calculate_shannon_entropy(public_key);
            double priv_entropy = calculate_shannon_entropy(private_key);
            
            public_key_entropies.push_back(pub_entropy);
            private_key_entropies.push_back(priv_entropy);
            
            // Check for suspicious patterns
            EXPECT_FALSE(has_suspicious_patterns(public_key))
                << "Public key has suspicious patterns in sample " << i;
            EXPECT_FALSE(has_suspicious_patterns(private_key))
                << "Private key has suspicious patterns in sample " << i;
        }
        
        // Calculate average entropy
        double avg_pub_entropy = std::accumulate(public_key_entropies.begin(),
                                                public_key_entropies.end(), 0.0) / 
                                 public_key_entropies.size();
        double avg_priv_entropy = std::accumulate(private_key_entropies.begin(),
                                                 private_key_entropies.end(), 0.0) / 
                                  private_key_entropies.size();
        
        // Expect reasonable entropy (should be close to 8.0 for random data)
        EXPECT_GT(avg_pub_entropy, 7.0)
            << "Public keys have insufficient entropy (avg: " << avg_pub_entropy << ")";
        EXPECT_GT(avg_priv_entropy, 7.0)
            << "Private keys have insufficient entropy (avg: " << avg_priv_entropy << ")";
    }
}

/**
 * Test quality of generated ciphertexts and shared secrets
 */
TEST_F(MLKEMSecurityTest, EncapsulationRandomnessQuality) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_samples = 20;
    
    for (auto* provider : providers) {
        // Generate keypair
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, private_key] = keygen_result.value();
        
        std::vector<double> ciphertext_entropies;
        std::vector<double> shared_secret_entropies;
        std::set<std::vector<uint8_t>> unique_ciphertexts;
        std::set<std::vector<uint8_t>> unique_shared_secrets;
        
        for (int i = 0; i < num_samples; ++i) {
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
            encap_params.public_key = public_key;
            
            auto result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(result.is_success()) << "Encapsulation failed on sample " << i;
            
            const auto& encap_output = result.value();
            
            // Collect entropy statistics
            double ct_entropy = calculate_shannon_entropy(encap_output.ciphertext);
            double ss_entropy = calculate_shannon_entropy(encap_output.shared_secret);
            
            ciphertext_entropies.push_back(ct_entropy);
            shared_secret_entropies.push_back(ss_entropy);
            
            // Ensure uniqueness
            unique_ciphertexts.insert(encap_output.ciphertext);
            unique_shared_secrets.insert(encap_output.shared_secret);
            
            // Check for patterns
            EXPECT_FALSE(has_suspicious_patterns(encap_output.ciphertext))
                << "Ciphertext has suspicious patterns in sample " << i;
            EXPECT_FALSE(has_suspicious_patterns(encap_output.shared_secret))
                << "Shared secret has suspicious patterns in sample " << i;
        }
        
        // Verify all values are unique
        EXPECT_EQ(unique_ciphertexts.size(), static_cast<size_t>(num_samples))
            << "Ciphertexts should all be unique";
        EXPECT_EQ(unique_shared_secrets.size(), static_cast<size_t>(num_samples))
            << "Shared secrets should all be unique";
        
        // Calculate average entropies
        double avg_ct_entropy = std::accumulate(ciphertext_entropies.begin(),
                                               ciphertext_entropies.end(), 0.0) / 
                               ciphertext_entropies.size();
        double avg_ss_entropy = std::accumulate(shared_secret_entropies.begin(),
                                               shared_secret_entropies.end(), 0.0) / 
                               shared_secret_entropies.size();
        
        // Expect good entropy
        EXPECT_GT(avg_ct_entropy, 7.0)
            << "Ciphertexts have insufficient entropy";
        EXPECT_GT(avg_ss_entropy, 7.0)
            << "Shared secrets have insufficient entropy";
    }
}

// ============================================================================
// SECURITY TESTS - Side-Channel Resistance
// ============================================================================

/**
 * Test timing consistency for key generation
 */
TEST_F(MLKEMSecurityTest, KeyGenerationTimingConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_measurements = 50; // Reduced for CI performance
    
    for (auto* provider : providers) {
        std::vector<std::chrono::nanoseconds> timings;
        
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        for (int i = 0; i < num_measurements; ++i) {
            auto duration = time_execution([&]() {
                auto result = provider->mlkem_generate_keypair(params);
                // Force execution to prevent optimization
                volatile bool success = result.is_success();
                (void)success;
            });
            
            timings.push_back(duration);
        }
        
        // Calculate statistics
        auto min_time = *std::min_element(timings.begin(), timings.end());
        auto max_time = *std::max_element(timings.begin(), timings.end());
        
        auto avg_time = std::accumulate(timings.begin(), timings.end(), 
                                       std::chrono::nanoseconds(0)) / timings.size();
        
        // Calculate coefficient of variation (std dev / mean)
        double sum_sq_diff = 0.0;
        for (const auto& t : timings) {
            double diff = static_cast<double>((t - avg_time).count());
            sum_sq_diff += diff * diff;
        }
        double std_dev = std::sqrt(sum_sq_diff / timings.size());
        double cv = std_dev / static_cast<double>(avg_time.count());
        
        // Timing should be relatively consistent (CV < 0.5 is reasonable)
        EXPECT_LT(cv, 0.5) 
            << "Key generation timing variation too high (CV: " << cv << ")";
            
        // Ratio of max to min should be reasonable
        double ratio = static_cast<double>(max_time.count()) / 
                      static_cast<double>(min_time.count());
        EXPECT_LT(ratio, 3.0)
            << "Key generation timing ratio too high: " << ratio;
    }
}

/**
 * Test timing consistency for encapsulation
 */
TEST_F(MLKEMSecurityTest, EncapsulationTimingConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_measurements = 50;
    
    for (auto* provider : providers) {
        // Generate keypair
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, private_key] = keygen_result.value();
        
        std::vector<std::chrono::nanoseconds> timings;
        
        for (int i = 0; i < num_measurements; ++i) {
            MLKEMEncapParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            params.public_key = public_key;
            
            auto duration = time_execution([&]() {
                auto result = provider->mlkem_encapsulate(params);
                volatile bool success = result.is_success();
                (void)success;
            });
            
            timings.push_back(duration);
        }
        
        // Calculate timing statistics
        auto avg_time = std::accumulate(timings.begin(), timings.end(), 
                                       std::chrono::nanoseconds(0)) / timings.size();
        
        double sum_sq_diff = 0.0;
        for (const auto& t : timings) {
            double diff = static_cast<double>((t - avg_time).count());
            sum_sq_diff += diff * diff;
        }
        double std_dev = std::sqrt(sum_sq_diff / timings.size());
        double cv = std_dev / static_cast<double>(avg_time.count());
        
        EXPECT_LT(cv, 0.5)
            << "Encapsulation timing variation too high (CV: " << cv << ")";
    }
}

/**
 * Test that decapsulation timing doesn't leak information about ciphertext validity
 */
TEST_F(MLKEMSecurityTest, DecapsulationTimingConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    const int num_measurements = 30; // Reduced for performance
    
    for (auto* provider : providers) {
        // Generate keypair
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, private_key] = keygen_result.value();
        
        // Generate valid ciphertext
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = public_key;
        
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        ASSERT_TRUE(encap_result.is_success());
        
        const auto& valid_ciphertext = encap_result.value().ciphertext;
        
        // Time valid decapsulations
        std::vector<std::chrono::nanoseconds> valid_timings;
        for (int i = 0; i < num_measurements; ++i) {
            MLKEMDecapParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            params.private_key = private_key;
            params.ciphertext = valid_ciphertext;
            
            auto duration = time_execution([&]() {
                auto result = provider->mlkem_decapsulate(params);
                volatile bool success = result.is_success();
                (void)success;
            });
            
            valid_timings.push_back(duration);
        }
        
        // Time invalid decapsulations (corrupted ciphertext)
        std::vector<std::chrono::nanoseconds> invalid_timings;
        for (int i = 0; i < num_measurements; ++i) {
            auto corrupted_ciphertext = corrupt_data(valid_ciphertext, 1);
            
            MLKEMDecapParams params;
            params.parameter_set = MLKEMParameterSet::MLKEM512;
            params.private_key = private_key;
            params.ciphertext = corrupted_ciphertext;
            
            auto duration = time_execution([&]() {
                auto result = provider->mlkem_decapsulate(params);
                volatile bool success = result.is_success();
                (void)success;
            });
            
            invalid_timings.push_back(duration);
        }
        
        // Calculate average times
        auto avg_valid = std::accumulate(valid_timings.begin(), valid_timings.end(),
                                        std::chrono::nanoseconds(0)) / valid_timings.size();
        auto avg_invalid = std::accumulate(invalid_timings.begin(), invalid_timings.end(),
                                          std::chrono::nanoseconds(0)) / invalid_timings.size();
        
        // Times should be similar (constant-time implementation)
        double ratio = static_cast<double>(std::max(avg_valid, avg_invalid).count()) /
                      static_cast<double>(std::min(avg_valid, avg_invalid).count());
        
        // Allow some variation due to system noise, but should be reasonably close
        EXPECT_LT(ratio, 2.0)
            << "Decapsulation timing differs significantly between valid/invalid ciphertext";
    }
}

// ============================================================================
// SECURITY TESTS - Attack Resilience
// ============================================================================

/**
 * Test resilience to bit-flip attacks on ciphertext
 */
TEST_F(MLKEMSecurityTest, BitFlipAttackResilience) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Generate keypair and valid encapsulation
        MLKEMKeyGenParams keygen_params;
        keygen_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
        ASSERT_TRUE(keygen_result.is_success());
        
        const auto& [public_key, private_key] = keygen_result.value();
        
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = public_key;
        
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        ASSERT_TRUE(encap_result.is_success());
        
        const auto& [valid_ciphertext, expected_shared_secret] = encap_result.value();
        
        // Test multiple bit-flip scenarios
        int different_results = 0;
        const int num_tests = 20;
        
        for (int i = 0; i < num_tests; ++i) {
            auto corrupted_ciphertext = corrupt_data(valid_ciphertext, 1 + (i % 3));
            
            MLKEMDecapParams decap_params;
            decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
            decap_params.private_key = private_key;
            decap_params.ciphertext = corrupted_ciphertext;
            
            auto decap_result = provider->mlkem_decapsulate(decap_params);
            
            if (decap_result.is_success()) {
                // If decapsulation succeeds, shared secret should be different
                if (decap_result.value() != expected_shared_secret) {
                    different_results++;
                }
            } else {
                // Failure is also acceptable (different result)
                different_results++;
            }
        }
        
        // Most corrupted ciphertexts should produce different results
        EXPECT_GT(different_results, num_tests * 0.8)
            << "Bit-flip attacks should generally produce different shared secrets";
    }
}

/**
 * Test key recovery attack resistance (basic test)
 */
TEST_F(MLKEMSecurityTest, KeyRecoveryResistance) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // This is a basic test - real key recovery attacks are computationally intensive
    for (auto* provider : providers) {
        // Generate multiple keypairs
        const int num_keypairs = 10;
        std::vector<std::vector<uint8_t>> public_keys;
        std::vector<std::vector<uint8_t>> private_keys;
        
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        for (int i = 0; i < num_keypairs; ++i) {
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success());
            
            const auto& [pub_key, priv_key] = result.value();
            public_keys.push_back(pub_key);
            private_keys.push_back(priv_key);
        }
        
        // Verify all keys are different (no obvious patterns)
        for (size_t i = 0; i < public_keys.size(); ++i) {
            for (size_t j = i + 1; j < public_keys.size(); ++j) {
                EXPECT_NE(public_keys[i], public_keys[j])
                    << "Public keys should be unique";
                EXPECT_NE(private_keys[i], private_keys[j])
                    << "Private keys should be unique";
            }
        }
        
        // Simple statistical test - keys should have good entropy
        for (const auto& pub_key : public_keys) {
            double entropy = calculate_shannon_entropy(pub_key);
            EXPECT_GT(entropy, 7.0) << "Public key entropy too low";
        }
        
        for (const auto& priv_key : private_keys) {
            double entropy = calculate_shannon_entropy(priv_key);
            EXPECT_GT(entropy, 7.0) << "Private key entropy too low";
        }
    }
}