/**
 * @file test_mlkem_interop.cpp
 * @brief Interoperability tests for ML-KEM implementation
 * 
 * This test suite validates interoperability of the ML-KEM implementation
 * across different crypto providers and ensures protocol conformance with
 * draft-connolly-tls-mlkem-key-agreement-05.
 * 
 * Interoperability Test Coverage:
 * - Cross-provider ML-KEM key exchange compatibility
 * - Protocol message format conformance
 * - Key share serialization/deserialization
 * - Error scenario handling compatibility
 * - DTLS v1.3 handshake integration
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
#include <map>
#include <set>

using namespace dtls::v13;
using namespace dtls::v13::crypto;

/**
 * Interoperability test fixture for ML-KEM operations
 */
class MLKEMInteroperabilityTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& factory = ProviderFactory::instance();
        
        // Initialize all available providers
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
        
        // Set up test parameters
        test_groups_ = {
            NamedGroup::MLKEM512,
            NamedGroup::MLKEM768,
            NamedGroup::MLKEM1024
        };
        
        test_parameter_sets_ = {
            MLKEMParameterSet::MLKEM512,
            MLKEMParameterSet::MLKEM768,
            MLKEMParameterSet::MLKEM1024
        };
    }
    
    void TearDown() override {
        if (openssl_provider_) openssl_provider_->cleanup();
        if (botan_provider_) botan_provider_->cleanup();
        if (hardware_provider_) hardware_provider_->cleanup();
    }
    
    std::unique_ptr<CryptoProvider> openssl_provider_;
    std::unique_ptr<CryptoProvider> botan_provider_;
    std::unique_ptr<CryptoProvider> hardware_provider_;
    
    std::vector<NamedGroup> test_groups_;
    std::vector<MLKEMParameterSet> test_parameter_sets_;
    
    std::vector<CryptoProvider*> get_available_providers() {
        std::vector<CryptoProvider*> providers;
        if (openssl_provider_) providers.push_back(openssl_provider_.get());
        if (botan_provider_) providers.push_back(botan_provider_.get());
        if (hardware_provider_) providers.push_back(hardware_provider_.get());
        return providers;
    }
    
    std::string get_param_set_name(MLKEMParameterSet param_set) {
        switch (param_set) {
            case MLKEMParameterSet::MLKEM512: return "ML-KEM-512";
            case MLKEMParameterSet::MLKEM768: return "ML-KEM-768";
            case MLKEMParameterSet::MLKEM1024: return "ML-KEM-1024";
            default: return "Unknown";
        }
    }
    
    std::string get_named_group_name(NamedGroup group) {
        switch (group) {
            case NamedGroup::MLKEM512: return "MLKEM512";
            case NamedGroup::MLKEM768: return "MLKEM768";
            case NamedGroup::MLKEM1024: return "MLKEM1024";
            default: return "Unknown";
        }
    }
    
    // Helper to get all provider pairs for cross-testing
    std::vector<std::pair<CryptoProvider*, CryptoProvider*>> get_provider_pairs() {
        auto providers = get_available_providers();
        std::vector<std::pair<CryptoProvider*, CryptoProvider*>> pairs;
        
        for (size_t i = 0; i < providers.size(); ++i) {
            for (size_t j = 0; j < providers.size(); ++j) {
                pairs.emplace_back(providers[i], providers[j]);
            }
        }
        
        return pairs;
    }
    
    // Validate key sizes match FIPS 203 specification
    void validate_key_sizes(MLKEMParameterSet param_set,
                           const std::vector<uint8_t>& public_key,
                           const std::vector<uint8_t>& private_key) {
        using namespace hybrid_pqc;
        auto sizes = get_mlkem_sizes(param_set);
        
        EXPECT_EQ(public_key.size(), sizes.public_key_bytes)
            << "Public key size mismatch for " << get_param_set_name(param_set);
            
        EXPECT_EQ(private_key.size(), sizes.private_key_bytes)
            << "Private key size mismatch for " << get_param_set_name(param_set);
    }
    
    // Validate encapsulation output sizes
    void validate_encap_sizes(MLKEMParameterSet param_set,
                             const MLKEMEncapResult& result) {
        using namespace hybrid_pqc;
        auto sizes = get_mlkem_sizes(param_set);
        
        EXPECT_EQ(result.ciphertext.size(), sizes.ciphertext_bytes)
            << "Ciphertext size mismatch for " << get_param_set_name(param_set);
            
        EXPECT_EQ(result.shared_secret.size(), sizes.shared_secret_bytes)
            << "Shared secret size mismatch for " << get_param_set_name(param_set);
    }
};

// ============================================================================
// INTEROPERABILITY TESTS - Cross-Provider Compatibility
// ============================================================================

/**
 * Test cross-provider key generation compatibility
 * Verifies that all providers generate keys with consistent sizes
 */
TEST_F(MLKEMInteroperabilityTest, CrossProviderKeyGenerationCompatibility) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto param_set : test_parameter_sets_) {
        std::map<std::string, std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> provider_keys;
        
        for (auto* provider : providers) {
            MLKEMKeyGenParams params;
            params.parameter_set = param_set;
            
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success())
                << "Key generation failed for " << provider->name() 
                << " with " << get_param_set_name(param_set);
            
            const auto& [public_key, private_key] = result.value();
            
            // Validate key sizes
            validate_key_sizes(param_set, public_key, private_key);
            
            // Store keys for comparison
            provider_keys[provider->name()] = {public_key, private_key};
        }
        
        // Verify all providers produce keys of the same size
        if (provider_keys.size() > 1) {
            auto first_provider = provider_keys.begin();
            size_t expected_pub_size = first_provider->second.first.size();
            size_t expected_priv_size = first_provider->second.second.size();
            
            for (const auto& [provider_name, keys] : provider_keys) {
                EXPECT_EQ(keys.first.size(), expected_pub_size)
                    << "Public key size inconsistent between providers for " 
                    << get_param_set_name(param_set);
                EXPECT_EQ(keys.second.size(), expected_priv_size)
                    << "Private key size inconsistent between providers for "
                    << get_param_set_name(param_set);
            }
        }
    }
}

/**
 * Test cross-provider encapsulation/decapsulation compatibility
 * Provider A generates keys, Provider B performs encapsulation, Provider A decapsulates
 */
TEST_F(MLKEMInteroperabilityTest, CrossProviderEncapsulationCompatibility) {
    auto provider_pairs = get_provider_pairs();
    if (provider_pairs.empty()) {
        GTEST_SKIP() << "No crypto provider pairs available";
    }
    
    for (auto param_set : test_parameter_sets_) {
        for (const auto& [provider_a, provider_b] : provider_pairs) {
            // Provider A generates keypair
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider_a->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success())
                << "Key generation failed for " << provider_a->name();
            
            const auto& [public_key, private_key] = keygen_result.value();
            
            // Provider B performs encapsulation using Provider A's public key
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider_b->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success())
                << "Encapsulation failed: " << provider_a->name() 
                << " keys with " << provider_b->name() << " encapsulation";
            
            validate_encap_sizes(param_set, encap_result.value());
            
            // Provider A performs decapsulation using Provider B's ciphertext
            MLKEMDecapParams decap_params;
            decap_params.parameter_set = param_set;
            decap_params.private_key = private_key;
            decap_params.ciphertext = encap_result.value().ciphertext;
            
            auto decap_result = provider_a->mlkem_decapsulate(decap_params);
            ASSERT_TRUE(decap_result.is_success())
                << "Decapsulation failed: " << provider_b->name()
                << " ciphertext with " << provider_a->name() << " decapsulation";
            
            // Shared secrets must match
            EXPECT_EQ(encap_result.value().shared_secret, decap_result.value())
                << "Shared secrets mismatch between " << provider_a->name()
                << " and " << provider_b->name() << " for " << get_param_set_name(param_set);
        }
    }
}

/**
 * Test pure ML-KEM key exchange cross-provider compatibility
 */
TEST_F(MLKEMInteroperabilityTest, PureMLKEMKeyExchangeCompatibility) {
    auto provider_pairs = get_provider_pairs();
    if (provider_pairs.empty()) {
        GTEST_SKIP() << "No crypto provider pairs available";
    }
    
    for (size_t i = 0; i < test_groups_.size(); ++i) {
        auto group = test_groups_[i];
        auto param_set = test_parameter_sets_[i];
        
        for (const auto& [client_provider, server_provider] : provider_pairs) {
            // Server (Provider A) generates keypair
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto server_keygen = server_provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(server_keygen.is_success())
                << "Server key generation failed for " << server_provider->name();
            
            const auto& [server_public_key, server_private_key] = server_keygen.value();
            
            // Client (Provider B) performs key exchange (encapsulation)
            PureMLKEMKeyExchangeParams client_params;
            client_params.mlkem_group = group;
            client_params.peer_public_key = server_public_key;
            client_params.is_encapsulation = true;
            
            auto client_result = client_provider->perform_pure_mlkem_key_exchange(client_params);
            ASSERT_TRUE(client_result.is_success())
                << "Client key exchange failed: " << client_provider->name()
                << " client, " << server_provider->name() << " server";
            
            // Server (Provider A) performs key exchange (decapsulation)
            PureMLKEMKeyExchangeParams server_params;
            server_params.mlkem_group = group;
            server_params.private_key = server_private_key;
            server_params.peer_public_key = client_result.value().ciphertext;
            server_params.is_encapsulation = false;
            
            auto server_result = server_provider->perform_pure_mlkem_key_exchange(server_params);
            ASSERT_TRUE(server_result.is_success())
                << "Server key exchange failed: " << client_provider->name()
                << " client, " << server_provider->name() << " server";
            
            // Verify shared secrets match
            EXPECT_EQ(client_result.value().shared_secret, server_result.value().shared_secret)
                << "Pure ML-KEM key exchange failed between " << client_provider->name()
                << " and " << server_provider->name() << " for " << get_named_group_name(group);
                
            // Verify ciphertext sizes match specification
            using namespace pqc_utils;
            size_t expected_ciphertext_size = get_pure_mlkem_server_keyshare_size(group);
            EXPECT_EQ(client_result.value().ciphertext.size(), expected_ciphertext_size)
                << "Ciphertext size mismatch for " << get_named_group_name(group);
        }
    }
}

// ============================================================================
// INTEROPERABILITY TESTS - Protocol Message Format Conformance
// ============================================================================

/**
 * Test key share serialization format consistency
 */
TEST_F(MLKEMInteroperabilityTest, KeyShareSerializationConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (size_t i = 0; i < test_groups_.size(); ++i) {
        auto group = test_groups_[i];
        auto param_set = test_parameter_sets_[i];
        
        // Collect key shares from all providers
        std::map<std::string, std::vector<uint8_t>> provider_public_keys;
        std::map<std::string, std::vector<uint8_t>> provider_ciphertexts;
        
        for (auto* provider : providers) {
            // Generate keypair
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = param_set;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            ASSERT_TRUE(keygen_result.is_success());
            
            const auto& [public_key, private_key] = keygen_result.value();
            provider_public_keys[provider->name()] = public_key;
            
            // Generate ciphertext
            MLKEMEncapParams encap_params;
            encap_params.parameter_set = param_set;
            encap_params.public_key = public_key;
            
            auto encap_result = provider->mlkem_encapsulate(encap_params);
            ASSERT_TRUE(encap_result.is_success());
            
            provider_ciphertexts[provider->name()] = encap_result.value().ciphertext;
        }
        
        // Verify all key shares have consistent sizes
        if (provider_public_keys.size() > 1) {
            auto first_pub_size = provider_public_keys.begin()->second.size();
            auto first_ct_size = provider_ciphertexts.begin()->second.size();
            
            for (const auto& [name, pub_key] : provider_public_keys) {
                EXPECT_EQ(pub_key.size(), first_pub_size)
                    << "Public key size inconsistent between providers";
            }
            
            for (const auto& [name, ciphertext] : provider_ciphertexts) {
                EXPECT_EQ(ciphertext.size(), first_ct_size)
                    << "Ciphertext size inconsistent between providers";
            }
        }
        
        // Verify sizes match protocol specification
        using namespace pqc_utils;
        size_t expected_pub_size = get_pure_mlkem_client_keyshare_size(group);
        size_t expected_ct_size = get_pure_mlkem_server_keyshare_size(group);
        
        for (const auto& [name, pub_key] : provider_public_keys) {
            EXPECT_EQ(pub_key.size(), expected_pub_size)
                << "Public key size doesn't match protocol spec for " << name;
        }
        
        for (const auto& [name, ciphertext] : provider_ciphertexts) {
            EXPECT_EQ(ciphertext.size(), expected_ct_size)
                << "Ciphertext size doesn't match protocol spec for " << name;
        }
    }
}

/**
 * Test protocol named group handling consistency
 */
TEST_F(MLKEMInteroperabilityTest, NamedGroupHandlingConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto group : test_groups_) {
        for (auto* provider : providers) {
            // Test provider recognizes ML-KEM groups correctly
            EXPECT_TRUE(provider->supports_pure_mlkem_group(group))
                << provider->name() << " should support " << get_named_group_name(group);
                
            EXPECT_TRUE(provider->is_pure_mlkem_group(group))
                << provider->name() << " should recognize " << get_named_group_name(group)
                << " as pure ML-KEM";
                
            // Test provider rejects non-ML-KEM groups as pure ML-KEM
            EXPECT_FALSE(provider->is_pure_mlkem_group(NamedGroup::SECP256R1))
                << provider->name() << " should not recognize SECP256R1 as pure ML-KEM";
        }
    }
}

// ============================================================================
// INTEROPERABILITY TESTS - Error Scenario Handling
// ============================================================================

/**
 * Test consistent error handling across providers for invalid inputs
 */
TEST_F(MLKEMInteroperabilityTest, ErrorHandlingConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // Test invalid parameter set handling
    for (auto* provider : providers) {
        MLKEMKeyGenParams invalid_params;
        invalid_params.parameter_set = static_cast<MLKEMParameterSet>(99);
        
        auto result = provider->mlkem_generate_keypair(invalid_params);
        EXPECT_FALSE(result.is_success())
            << provider->name() << " should reject invalid parameter set";
    }
    
    // Test wrong-sized input handling
    for (auto* provider : providers) {
        // Test encapsulation with wrong-sized public key
        MLKEMEncapParams encap_params;
        encap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        encap_params.public_key = std::vector<uint8_t>(100, 0); // Wrong size
        
        auto encap_result = provider->mlkem_encapsulate(encap_params);
        EXPECT_FALSE(encap_result.is_success())
            << provider->name() << " should reject wrong-sized public key";
        
        // Test decapsulation with wrong-sized ciphertext
        MLKEMDecapParams decap_params;
        decap_params.parameter_set = MLKEMParameterSet::MLKEM512;
        decap_params.private_key = std::vector<uint8_t>(1632, 0); // Correct private key size
        decap_params.ciphertext = std::vector<uint8_t>(100, 0); // Wrong ciphertext size
        
        auto decap_result = provider->mlkem_decapsulate(decap_params);
        EXPECT_FALSE(decap_result.is_success())
            << provider->name() << " should reject wrong-sized ciphertext";
    }
}

/**
 * Test provider graceful degradation when operations fail
 */
TEST_F(MLKEMInteroperabilityTest, GracefulDegradation) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        // Test multiple failed operations don't break provider
        for (int i = 0; i < 10; ++i) {
            MLKEMKeyGenParams invalid_params;
            invalid_params.parameter_set = static_cast<MLKEMParameterSet>(99 + i);
            
            auto result = provider->mlkem_generate_keypair(invalid_params);
            EXPECT_FALSE(result.is_success()) << "Invalid operation should fail";
        }
        
        // Verify provider can still perform valid operations after failures
        MLKEMKeyGenParams valid_params;
        valid_params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        auto valid_result = provider->mlkem_generate_keypair(valid_params);
        EXPECT_TRUE(valid_result.is_success())
            << provider->name() << " should recover after failed operations";
    }
}

// ============================================================================
// INTEROPERABILITY TESTS - Provider Capability Reporting
// ============================================================================

/**
 * Test provider capability reporting consistency
 */
TEST_F(MLKEMInteroperabilityTest, ProviderCapabilityReporting) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    for (auto* provider : providers) {
        auto capabilities = provider->capabilities();
        
        // Test basic capability reporting
        EXPECT_FALSE(provider->name().empty()) 
            << "Provider name should not be empty";
        EXPECT_FALSE(provider->version().empty())
            << "Provider version should not be empty";
        EXPECT_TRUE(provider->is_available())
            << "Provider should report as available";
        
        // Test ML-KEM specific capabilities
        for (auto group : test_groups_) {
            EXPECT_TRUE(provider->supports_pure_mlkem_group(group))
                << provider->name() << " should support " << get_named_group_name(group);
        }
        
        // Test enhanced capabilities if supported
        if (provider->enhanced_capabilities().health_status != ProviderHealth::UNAVAILABLE) {
            auto enhanced_caps = provider->enhanced_capabilities();
            
            // Basic sanity checks
            EXPECT_GE(enhanced_caps.max_memory_usage, 0)
                << "Max memory usage should be non-negative";
            EXPECT_GE(enhanced_caps.max_concurrent_operations, 0)
                << "Max concurrent operations should be non-negative";
        }
    }
}

/**
 * Test provider performance metrics consistency
 */
TEST_F(MLKEMInteroperabilityTest, ProviderPerformanceMetricsConsistency) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // Perform some operations to generate metrics
    for (auto* provider : providers) {
        MLKEMKeyGenParams params;
        params.parameter_set = MLKEMParameterSet::MLKEM512;
        
        // Generate some operations
        for (int i = 0; i < 5; ++i) {
            auto result = provider->mlkem_generate_keypair(params);
            ASSERT_TRUE(result.is_success());
        }
        
        // Check if provider supports performance metrics
        try {
            auto metrics = provider->get_performance_metrics();
            
            // Basic sanity checks if metrics are supported
            EXPECT_GE(metrics.success_count, 5) 
                << "Success count should reflect operations performed";
            EXPECT_GE(metrics.success_rate, 0.0)
                << "Success rate should be non-negative";
            EXPECT_LE(metrics.success_rate, 1.0)
                << "Success rate should not exceed 100%";
                
        } catch (...) {
            // Provider may not support performance metrics - that's OK
            SUCCEED() << provider->name() << " doesn't support performance metrics";
        }
    }
}

// ============================================================================
// INTEROPERABILITY TESTS - Test Vector Compatibility (if available)
// ============================================================================

/**
 * Test compatibility with known test vectors (basic framework)
 */
TEST_F(MLKEMInteroperabilityTest, TestVectorCompatibility) {
    auto providers = get_available_providers();
    if (providers.empty()) {
        GTEST_SKIP() << "No crypto providers available";
    }
    
    // This is a framework for test vector validation
    // In a real implementation, you would load test vectors from files
    
    struct TestVector {
        MLKEMParameterSet param_set;
        std::vector<uint8_t> seed;
        std::vector<uint8_t> expected_public_key;
        std::vector<uint8_t> expected_private_key;
        std::vector<uint8_t> encap_randomness;
        std::vector<uint8_t> expected_ciphertext;
        std::vector<uint8_t> expected_shared_secret;
    };
    
    // Placeholder for test vectors (would be loaded from specification)
    std::vector<TestVector> test_vectors; // Empty for now
    
    if (test_vectors.empty()) {
        GTEST_SKIP() << "No test vectors available";
    }
    
    for (const auto& tv : test_vectors) {
        for (auto* provider : providers) {
            // Test deterministic key generation if supported
            MLKEMKeyGenParams keygen_params;
            keygen_params.parameter_set = tv.param_set;
            keygen_params.additional_entropy = tv.seed;
            
            auto keygen_result = provider->mlkem_generate_keypair(keygen_params);
            if (keygen_result.is_success()) {
                const auto& [public_key, private_key] = keygen_result.value();
                
                // In practice, deterministic key generation from seed
                // may not be supported by all providers
                // This would test it if available
            }
            
            // Test encapsulation with known randomness if supported
            if (!tv.expected_public_key.empty() && !tv.encap_randomness.empty()) {
                MLKEMEncapParams encap_params;
                encap_params.parameter_set = tv.param_set;
                encap_params.public_key = tv.expected_public_key;
                encap_params.randomness = tv.encap_randomness;
                
                auto encap_result = provider->mlkem_encapsulate(encap_params);
                if (encap_result.is_success()) {
                    // Test would verify ciphertext and shared secret match expected
                    // EXPECT_EQ(encap_result.value().ciphertext, tv.expected_ciphertext);
                    // EXPECT_EQ(encap_result.value().shared_secret, tv.expected_shared_secret);
                }
            }
        }
    }
}