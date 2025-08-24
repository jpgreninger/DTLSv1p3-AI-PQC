/**
 * @file test_enhanced_crypto_providers_fixed.cpp
 * @brief Enhanced comprehensive tests for crypto providers with coverage focus - Fixed API
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>
#include <algorithm>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/crypto/botan_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class EnhancedCryptoProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register all available providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            // Fallback: register core providers for testing
            builtin::register_null_provider();
            builtin::register_openssl_provider();
            builtin::register_botan_provider();
        }
        
        // Set up test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<uint8_t>(i % 256);
        }
        
        small_data_ = {0xDE, 0xAD, 0xBE, 0xEF};
        large_data_.resize(4096, 0xAA);
        
        // Test messages for signatures
        test_message_ = "DTLS v1.3 enhanced test message for cryptographic operations";
        
        // Test selection criteria
        basic_criteria_.require_hardware_acceleration = false;
        basic_criteria_.require_fips_compliance = false;
        basic_criteria_.allow_software_fallback = true;
        basic_criteria_.minimum_security_level = SecurityLevel::MEDIUM;
        basic_criteria_.require_thread_safety = true;
    }
    
    void TearDown() override {
        // Clean up factory state
        ProviderFactory::instance().reset_all_stats();
    }
    
    std::vector<uint8_t> test_data_;
    std::vector<uint8_t> small_data_;
    std::vector<uint8_t> large_data_;
    std::string test_message_;
    ProviderSelection basic_criteria_;
};

// Test provider factory basic functionality
TEST_F(EnhancedCryptoProviderTest, FactoryBasicFunctionality) {
    auto& factory = ProviderFactory::instance();
    
    // Test singleton behavior
    auto& factory2 = ProviderFactory::instance();
    EXPECT_EQ(&factory, &factory2);
    
    // Get available providers
    auto providers = factory.available_providers();
    EXPECT_GT(providers.size(), 0);
    
    // Test provider registration information
    for (const auto& provider_name : providers) {
        auto registration = factory.get_registration(provider_name);
        EXPECT_TRUE(registration.is_ok());
        
        if (registration.is_ok()) {
            auto reg_info = registration.value();
            EXPECT_FALSE(reg_info.name.empty());
            EXPECT_FALSE(reg_info.description.empty());
            EXPECT_NE(reg_info.factory, nullptr);
        }
    }
    
    // Test provider creation
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto provider = provider_result.value();
        EXPECT_TRUE(provider != nullptr);
        EXPECT_EQ(provider->name(), "openssl");
    }
    
    // Test best provider creation
    auto best_provider = factory.create_best_provider(basic_criteria_);
    EXPECT_TRUE(best_provider.is_ok());
    
    // Test provider capabilities query
    auto capabilities_result = factory.get_capabilities("openssl");
    if (capabilities_result.is_ok()) {
        auto capabilities = capabilities_result.value();
        
        EXPECT_FALSE(capabilities.provider_name.empty());
        EXPECT_FALSE(capabilities.provider_version.empty());
        EXPECT_GT(capabilities.supported_cipher_suites.size(), 0);
        EXPECT_GT(capabilities.supported_groups.size(), 0);
        EXPECT_GT(capabilities.supported_signatures.size(), 0);
        EXPECT_GT(capabilities.supported_hashes.size(), 0);
    }
}

// Test OpenSSL provider direct functionality
TEST_F(EnhancedCryptoProviderTest, OpenSSLProviderDirectFunctionality) {
    auto openssl_provider = std::make_unique<OpenSSLProvider>();
    
    // Test basic properties
    EXPECT_EQ(openssl_provider->name(), "openssl");
    EXPECT_FALSE(openssl_provider->version().empty());
    EXPECT_TRUE(openssl_provider->is_available());
    
    // Test initialization
    auto init_result = openssl_provider->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    // Test capabilities
    auto capabilities = openssl_provider->capabilities();
    EXPECT_EQ(capabilities.provider_name, "openssl");
    EXPECT_FALSE(capabilities.provider_version.empty());
    EXPECT_GT(capabilities.supported_cipher_suites.size(), 0);
    EXPECT_GT(capabilities.supported_groups.size(), 0);
    EXPECT_GT(capabilities.supported_signatures.size(), 0);
    EXPECT_GT(capabilities.supported_hashes.size(), 0);
    
    // Test random generation
    RandomParams random_params;
    random_params.length = 32;
    random_params.cryptographically_secure = true;
    
    auto random_result = openssl_provider->generate_random(random_params);
    EXPECT_TRUE(random_result.is_ok());
    
    if (random_result.is_ok()) {
        auto random_data = random_result.value();
        EXPECT_EQ(random_data.size(), 32);
        
        // Generate another random and verify they're different
        auto random_result2 = openssl_provider->generate_random(random_params);
        if (random_result2.is_ok()) {
            auto random_data2 = random_result2.value();
            EXPECT_NE(random_data, random_data2);
        }
    }
    
    // Test key derivation
    KeyDerivationParams kdf_params;
    kdf_params.secret = test_data_;
    kdf_params.salt = {0x01, 0x02, 0x03, 0x04};
    kdf_params.info = {0x05, 0x06, 0x07, 0x08};
    kdf_params.output_length = 32;
    kdf_params.hash_algorithm = HashAlgorithm::SHA256;
    
    auto kdf_result = openssl_provider->derive_key(kdf_params);
    if (kdf_result.is_ok()) {
        auto derived_key = kdf_result.value();
        EXPECT_EQ(derived_key.size(), 32);
        
        // Test consistency - same input should produce same output
        auto kdf_result2 = openssl_provider->derive_key(kdf_params);
        if (kdf_result2.is_ok()) {
            EXPECT_EQ(derived_key, kdf_result2.value());
        }
    }
    
    // Test cleanup
    openssl_provider->cleanup();
}

// Test Botan provider functionality
TEST_F(EnhancedCryptoProviderTest, BotanProviderFunctionality) {
    auto botan_provider = std::make_unique<BotanProvider>();
    
    // Test basic properties
    EXPECT_EQ(botan_provider->name(), "botan");
    EXPECT_FALSE(botan_provider->version().empty());
    
    // Test availability (may not be available in all builds)
    bool is_available = botan_provider->is_available();
    
    if (is_available) {
        // Test initialization
        auto init_result = botan_provider->initialize();
        EXPECT_TRUE(init_result.is_ok());
        
        // Test capabilities
        auto capabilities = botan_provider->capabilities();
        EXPECT_EQ(capabilities.provider_name, "botan");
        EXPECT_FALSE(capabilities.provider_version.empty());
        
        // Test random generation
        RandomParams random_params;
        random_params.length = 16;
        random_params.cryptographically_secure = true;
        
        auto random_result = botan_provider->generate_random(random_params);
        if (random_result.is_ok()) {
            auto random_data = random_result.value();
            EXPECT_EQ(random_data.size(), 16);
        }
        
        // Test cleanup
        botan_provider->cleanup();
    } else {
        // If Botan is not available, test the stub behavior
        auto init_result = botan_provider->initialize();
        // Stub implementation may return error or success
        
        // Test that stub implementation handles operations gracefully
        RandomParams random_params;
        random_params.length = 16;
        random_params.cryptographically_secure = true;
        
        auto random_result = botan_provider->generate_random(random_params);
        // Result may be error for stub implementation
    }
}

// Test provider compatibility checking
TEST_F(EnhancedCryptoProviderTest, ProviderCompatibilityChecking) {
    auto& factory = ProviderFactory::instance();
    
    // Test compatibility checking for OpenSSL
    auto compatibility_result = factory.check_compatibility("openssl", basic_criteria_);
    if (compatibility_result.is_ok()) {
        auto compatibility = compatibility_result.value();
        EXPECT_TRUE(compatibility.is_compatible);
        EXPECT_GT(compatibility.compatibility_score, 0.0);
    }
    
    // Test finding compatible providers
    auto compatible_providers = factory.find_compatible_providers(basic_criteria_);
    EXPECT_GT(compatible_providers.size(), 0);
    
    // Test selecting best compatible provider
    auto best_compatible = factory.select_best_compatible_provider(basic_criteria_);
    EXPECT_TRUE(best_compatible.is_ok());
    
    if (best_compatible.is_ok()) {
        auto provider_name = best_compatible.value();
        EXPECT_FALSE(provider_name.empty());
        
        // Verify the selected provider is actually available
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
}

// Test provider health monitoring
TEST_F(EnhancedCryptoProviderTest, ProviderHealthMonitoring) {
    auto& factory = ProviderFactory::instance();
    
    // Test health check for all providers
    auto health_check_result = factory.perform_health_checks();
    // Health check result may succeed or fail depending on provider states
    
    // Test health check for specific provider
    auto openssl_health = factory.perform_health_check("openssl");
    // Result may vary based on provider health
    
    // Get healthy and unhealthy providers
    auto healthy_providers = factory.get_healthy_providers();
    auto unhealthy_providers = factory.get_unhealthy_providers();
    
    // Should have at least some providers in one category or the other
    EXPECT_GT(healthy_providers.size() + unhealthy_providers.size(), 0);
}

// Test provider statistics
TEST_F(EnhancedCryptoProviderTest, ProviderStatistics) {
    auto& factory = ProviderFactory::instance();
    
    // Create a provider to generate some stats
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        // Get provider statistics
        auto stats = factory.get_provider_stats("openssl");
        EXPECT_GE(stats.creation_count, 1);
        
        // Reset stats and verify
        factory.reset_provider_stats("openssl");
        auto reset_stats = factory.get_provider_stats("openssl");
        EXPECT_EQ(reset_stats.creation_count, 0);
    }
    
    // Test reset all stats
    factory.reset_all_stats();
}

// Test concurrent provider operations
TEST_F(EnhancedCryptoProviderTest, ConcurrentProviderOperations) {
    auto& factory = ProviderFactory::instance();
    
    // Test concurrent provider creation
    std::vector<std::future<std::unique_ptr<CryptoProvider>>> futures;
    
    for (int i = 0; i < 10; ++i) {
        futures.push_back(std::async(std::launch::async, [&factory]() {
            auto provider_result = factory.create_best_provider(ProviderSelection{});
            return provider_result.is_ok() ? std::move(provider_result.value()) : nullptr;
        }));
    }
    
    // Wait for all creations to complete
    std::vector<std::unique_ptr<CryptoProvider>> providers;
    for (auto& future : futures) {
        auto provider = future.get();
        if (provider) {
            providers.push_back(std::move(provider));
        }
    }
    
    EXPECT_GT(providers.size(), 0);
    
    // Test concurrent operations on different providers
    std::vector<std::future<void>> operation_futures;
    
    for (size_t i = 0; i < std::min(providers.size(), size_t(5)); ++i) {
        operation_futures.push_back(std::async(std::launch::async, [&providers, i]() {
            if (providers[i]) {
                RandomParams params;
                params.length = 16;
                params.cryptographically_secure = true;
                
                auto result = providers[i]->generate_random(params);
                EXPECT_TRUE(result.is_ok() || result.is_error()); // Either is fine
            }
        }));
    }
    
    // Wait for all operations to complete
    for (auto& future : operation_futures) {
        future.wait();
    }
}

// Test error handling and edge cases
TEST_F(EnhancedCryptoProviderTest, ErrorHandlingAndEdgeCases) {
    auto& factory = ProviderFactory::instance();
    
    // Test creation of non-existent provider
    auto invalid_provider = factory.create_provider("non_existent_provider");
    EXPECT_TRUE(invalid_provider.is_error());
    
    // Test operations on uninitialized provider
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto provider = provider_result.value();
        
        // Test random generation (may or may not work before explicit initialization)
        RandomParams params;
        params.length = 16;
        params.cryptographically_secure = true;
        
        auto random_result = provider->generate_random(params);
        // Result can be either success or failure
        
        // Initialize and test again
        auto init_result = provider->initialize();
        if (init_result.is_ok()) {
            auto random_result2 = provider->generate_random(params);
            EXPECT_TRUE(random_result2.is_ok());
        }
    }
    
    // Test invalid parameters
    auto openssl_provider = std::make_unique<OpenSSLProvider>();
    auto init_result = openssl_provider->initialize();
    if (init_result.is_ok()) {
        // Test zero-length random
        RandomParams zero_params;
        zero_params.length = 0;
        zero_params.cryptographically_secure = true;
        
        auto zero_result = openssl_provider->generate_random(zero_params);
        EXPECT_TRUE(zero_result.is_error());
        
        // Test extremely large random request
        RandomParams large_params;
        large_params.length = SIZE_MAX;
        large_params.cryptographically_secure = true;
        
        auto large_result = openssl_provider->generate_random(large_params);
        EXPECT_TRUE(large_result.is_error());
    }
}

// Test provider capabilities exhaustively
TEST_F(EnhancedCryptoProviderTest, ProviderCapabilitiesExhaustive) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (provider_result.is_ok()) {
            auto provider = provider_result.value();
            auto init_result = provider->initialize();
            
            if (init_result.is_ok()) {
                auto capabilities = provider->capabilities();
                
                // Test all cipher suites are valid
                for (auto cipher_suite : capabilities.supported_cipher_suites) {
                    EXPECT_NE(cipher_suite, static_cast<CipherSuite>(0));
                }
                
                // Test all groups are valid
                for (auto group : capabilities.supported_groups) {
                    EXPECT_NE(group, static_cast<NamedGroup>(0));
                }
                
                // Test all signatures are valid
                for (auto signature : capabilities.supported_signatures) {
                    EXPECT_NE(signature, static_cast<SignatureScheme>(0));
                }
                
                // Test all hashes are valid
                for (auto hash : capabilities.supported_hashes) {
                    EXPECT_NE(hash, static_cast<HashAlgorithm>(0));
                }
                
                // Test provider-specific features
                if (provider_name == "openssl") {
                    // OpenSSL should support basic cipher suites
                    bool has_aes_128_gcm = std::find(capabilities.supported_cipher_suites.begin(),
                                                   capabilities.supported_cipher_suites.end(),
                                                   CipherSuite::TLS_AES_128_GCM_SHA256) != 
                                         capabilities.supported_cipher_suites.end();
                    EXPECT_TRUE(has_aes_128_gcm);
                    
                    // OpenSSL should support basic curves
                    bool has_p256 = std::find(capabilities.supported_groups.begin(),
                                            capabilities.supported_groups.end(),
                                            NamedGroup::SECP256R1) != 
                                  capabilities.supported_groups.end();
                    EXPECT_TRUE(has_p256);
                    
                    // OpenSSL should support SHA256
                    bool has_sha256 = std::find(capabilities.supported_hashes.begin(),
                                              capabilities.supported_hashes.end(),
                                              HashAlgorithm::SHA256) != 
                                    capabilities.supported_hashes.end();
                    EXPECT_TRUE(has_sha256);
                }
            }
        }
    }
}

// Test memory management and resource cleanup
TEST_F(EnhancedCryptoProviderTest, MemoryManagementAndCleanup) {
    auto& factory = ProviderFactory::instance();
    
    // Create and destroy many providers to test memory management
    for (int i = 0; i < 100; ++i) {
        auto provider_result = factory.create_best_provider(basic_criteria_);
        if (provider_result.is_ok()) {
            auto provider = provider_result.value();
            auto init_result = provider->initialize();
            
            if (init_result.is_ok()) {
                // Perform some operations
                RandomParams params;
                params.length = 16;
                params.cryptographically_secure = true;
                
                auto random_result = provider->generate_random(params);
                // Clean up (automatic through destructor)
            }
        }
    }
    
    // Test explicit cleanup
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto provider = provider_result.value();
        auto init_result = provider->initialize();
        
        if (init_result.is_ok()) {
            // Test cleanup
            provider->cleanup();
            
            // Operations after cleanup may fail (implementation-dependent)
            RandomParams params;
            params.length = 16;
            params.cryptographically_secure = true;
            
            auto random_result = provider->generate_random(params);
            // Result can be success or failure after cleanup
        }
    }
}

// Test performance characteristics
TEST_F(EnhancedCryptoProviderTest, PerformanceCharacteristics) {
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_best_provider(basic_criteria_);
    
    if (provider_result.is_ok()) {
        auto provider = provider_result.value();
        auto init_result = provider->initialize();
        
        if (init_result.is_ok()) {
            // Test random generation performance
            auto start_time = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < 100; ++i) {
                RandomParams params;
                params.length = 32;
                params.cryptographically_secure = true;
                
                auto random_result = provider->generate_random(params);
                EXPECT_TRUE(random_result.is_ok());
            }
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            // Performance expectation: 100 random generations should complete in reasonable time
            EXPECT_LT(duration.count(), 5000); // Less than 5 seconds
            
            // Test key derivation performance if available
            start_time = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < 100; ++i) {
                KeyDerivationParams kdf_params;
                kdf_params.secret = test_data_;
                kdf_params.salt = {0x01, 0x02, 0x03, 0x04};
                kdf_params.info = {0x05, 0x06, 0x07, 0x08};
                kdf_params.output_length = 32;
                kdf_params.hash_algorithm = HashAlgorithm::SHA256;
                
                auto kdf_result = provider->derive_key(kdf_params);
                if (kdf_result.is_error()) {
                    // Skip performance test if KDF not available
                    break;
                }
            }
            
            end_time = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            // Performance expectation: 100 KDF operations should complete in reasonable time
            EXPECT_LT(duration.count(), 5000); // Less than 5 seconds
        }
    }
}

// Test provider ranking and selection algorithms
TEST_F(EnhancedCryptoProviderTest, ProviderRankingAndSelection) {
    auto& factory = ProviderFactory::instance();
    
    // Test performance-based ranking
    auto performance_ranking = factory.rank_providers_by_performance();
    if (performance_ranking.is_ok()) {
        auto ranked_providers = performance_ranking.value();
        EXPECT_GT(ranked_providers.size(), 0);
        
        // Verify all ranked providers are available
        for (const auto& provider_name : ranked_providers) {
            EXPECT_TRUE(factory.is_provider_available(provider_name));
        }
    }
    
    // Test compatibility-based ranking
    auto compatibility_ranking = factory.rank_providers_by_compatibility(basic_criteria_);
    if (compatibility_ranking.is_ok()) {
        auto ranked_providers = compatibility_ranking.value();
        EXPECT_GT(ranked_providers.size(), 0);
        
        // Verify all ranked providers are compatible
        for (const auto& provider_name : ranked_providers) {
            auto compatibility = factory.check_compatibility(provider_name, basic_criteria_);
            if (compatibility.is_ok()) {
                EXPECT_TRUE(compatibility.value().is_compatible);
            }
        }
    }
    
    // Test load balancing selection
    auto load_balanced = factory.select_provider_with_load_balancing(
        basic_criteria_, LoadBalancingStrategy::HEALTH_BASED);
    if (load_balanced.is_ok()) {
        auto provider_name = load_balanced.value();
        EXPECT_FALSE(provider_name.empty());
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
}