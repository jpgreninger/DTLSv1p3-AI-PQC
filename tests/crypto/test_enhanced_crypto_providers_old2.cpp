/**
 * @file test_enhanced_crypto_providers_minimal.cpp
 * @brief Minimal enhanced crypto provider tests for coverage
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/crypto/openssl_provider.h"
#include "dtls/crypto/botan_provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;

class EnhancedCryptoProviderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register providers
        auto register_result = builtin::register_all_providers();
        if (register_result.is_error()) {
            builtin::register_null_provider();
            builtin::register_openssl_provider();
            builtin::register_botan_provider();
        }
        
        // Set up test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<uint8_t>(i % 256);
        }
        
        basic_criteria_.require_hardware_acceleration = false;
        basic_criteria_.require_fips_compliance = false;
        basic_criteria_.allow_software_fallback = true;
        basic_criteria_.minimum_security_level = SecurityLevel::MEDIUM;
        basic_criteria_.require_thread_safety = true;
    }
    
    void TearDown() override {
        ProviderFactory::instance().reset_all_stats();
    }
    
    std::vector<uint8_t> test_data_;
    ProviderSelection basic_criteria_;
};

// Test factory functionality
TEST_F(EnhancedCryptoProviderTest, FactoryFunctionality) {
    auto& factory = ProviderFactory::instance();
    
    // Test singleton
    auto& factory2 = ProviderFactory::instance();
    EXPECT_EQ(&factory, &factory2);
    
    // Test available providers
    auto providers = factory.available_providers();
    EXPECT_GT(providers.size(), 0);
    
    // Test provider creation
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto provider = std::move(provider_result.value());
        EXPECT_TRUE(provider != nullptr);
        EXPECT_EQ(provider->name(), "openssl");
    }
    
    // Test best provider
    auto best_provider = factory.create_best_provider(basic_criteria_);
    EXPECT_TRUE(best_provider.is_ok());
}

// Test OpenSSL provider
TEST_F(EnhancedCryptoProviderTest, OpenSSLProvider) {
    auto openssl_provider = std::make_unique<OpenSSLProvider>();
    
    EXPECT_EQ(openssl_provider->name(), "openssl");
    EXPECT_FALSE(openssl_provider->version().empty());
    EXPECT_TRUE(openssl_provider->is_available());
    
    auto init_result = openssl_provider->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    auto capabilities = openssl_provider->capabilities();
    EXPECT_EQ(capabilities.provider_name, "openssl");
    EXPECT_GT(capabilities.supported_cipher_suites.size(), 0);
    
    // Test random generation
    RandomParams random_params;
    random_params.length = 32;
    random_params.cryptographically_secure = true;
    
    auto random_result = openssl_provider->generate_random(random_params);
    EXPECT_TRUE(random_result.is_ok());
    
    if (random_result.is_ok()) {
        auto random_data = random_result.value();
        EXPECT_EQ(random_data.size(), 32);
    }
    
    openssl_provider->cleanup();
}

// Test Botan provider
TEST_F(EnhancedCryptoProviderTest, BotanProvider) {
    auto botan_provider = std::make_unique<BotanProvider>();
    
    EXPECT_EQ(botan_provider->name(), "botan");
    EXPECT_FALSE(botan_provider->version().empty());
    
    bool is_available = botan_provider->is_available();
    
    if (is_available) {
        auto init_result = botan_provider->initialize();
        if (init_result.is_ok()) {
            auto capabilities = botan_provider->capabilities();
            EXPECT_EQ(capabilities.provider_name, "botan");
            
            RandomParams random_params;
            random_params.length = 16;
            random_params.cryptographically_secure = true;
            
            auto random_result = botan_provider->generate_random(random_params);
            if (random_result.is_ok()) {
                auto random_data = random_result.value();
                EXPECT_EQ(random_data.size(), 16);
            }
        }
        botan_provider->cleanup();
    }
}

// Test provider compatibility
TEST_F(EnhancedCryptoProviderTest, ProviderCompatibility) {
    auto& factory = ProviderFactory::instance();
    
    auto compatibility_result = factory.check_compatibility("openssl", basic_criteria_);
    if (compatibility_result.is_ok()) {
        auto compatibility = compatibility_result.value();
        EXPECT_TRUE(compatibility.is_compatible);
        EXPECT_GT(compatibility.compatibility_score, 0.0);
    }
    
    auto compatible_providers = factory.find_compatible_providers(basic_criteria_);
    EXPECT_GT(compatible_providers.size(), 0);
    
    auto best_compatible = factory.select_best_compatible_provider(basic_criteria_);
    if (best_compatible.is_ok()) {
        auto provider_name = best_compatible.value();
        EXPECT_FALSE(provider_name.empty());
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
}

// Test provider health
TEST_F(EnhancedCryptoProviderTest, ProviderHealth) {
    auto& factory = ProviderFactory::instance();
    
    auto health_check_result = factory.perform_health_checks();
    auto openssl_health = factory.perform_health_check("openssl");
    
    auto healthy_providers = factory.get_healthy_providers();
    auto unhealthy_providers = factory.get_unhealthy_providers();
    
    EXPECT_GT(healthy_providers.size() + unhealthy_providers.size(), 0);
}

// Test provider statistics
TEST_F(EnhancedCryptoProviderTest, ProviderStatistics) {
    auto& factory = ProviderFactory::instance();
    
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto stats = factory.get_provider_stats("openssl");
        EXPECT_GE(stats.creation_count, 1);
        
        factory.reset_provider_stats("openssl");
        auto reset_stats = factory.get_provider_stats("openssl");
        EXPECT_EQ(reset_stats.creation_count, 0);
    }
    
    factory.reset_all_stats();
}

// Test error handling
TEST_F(EnhancedCryptoProviderTest, ErrorHandling) {
    auto& factory = ProviderFactory::instance();
    
    auto invalid_provider = factory.create_provider("non_existent_provider");
    EXPECT_TRUE(invalid_provider.is_error());
    
    auto openssl_provider = std::make_unique<OpenSSLProvider>();
    auto init_result = openssl_provider->initialize();
    if (init_result.is_ok()) {
        RandomParams zero_params;
        zero_params.length = 0;
        zero_params.cryptographically_secure = true;
        
        auto zero_result = openssl_provider->generate_random(zero_params);
        EXPECT_TRUE(zero_result.is_error());
        
        RandomParams large_params;
        large_params.length = SIZE_MAX;
        large_params.cryptographically_secure = true;
        
        auto large_result = openssl_provider->generate_random(large_params);
        EXPECT_TRUE(large_result.is_error());
    }
}

// Test provider capabilities
TEST_F(EnhancedCryptoProviderTest, ProviderCapabilities) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (provider_result.is_ok()) {
            auto provider = std::move(provider_result.value());
            auto init_result = provider->initialize();
            
            if (init_result.is_ok()) {
                auto capabilities = provider->capabilities();
                
                for (auto cipher_suite : capabilities.supported_cipher_suites) {
                    EXPECT_NE(cipher_suite, static_cast<CipherSuite>(0));
                }
                
                for (auto group : capabilities.supported_groups) {
                    EXPECT_NE(group, static_cast<NamedGroup>(0));
                }
                
                for (auto signature : capabilities.supported_signatures) {
                    EXPECT_NE(signature, static_cast<SignatureScheme>(0));
                }
                
                for (auto hash : capabilities.supported_hashes) {
                    EXPECT_NE(hash, static_cast<HashAlgorithm>(0));
                }
                
                if (provider_name == "openssl") {
                    bool has_aes_128_gcm = std::find(capabilities.supported_cipher_suites.begin(),
                                                   capabilities.supported_cipher_suites.end(),
                                                   CipherSuite::TLS_AES_128_GCM_SHA256) != 
                                         capabilities.supported_cipher_suites.end();
                    EXPECT_TRUE(has_aes_128_gcm);
                    
                    bool has_p256 = std::find(capabilities.supported_groups.begin(),
                                            capabilities.supported_groups.end(),
                                            NamedGroup::SECP256R1) != 
                                  capabilities.supported_groups.end();
                    EXPECT_TRUE(has_p256);
                    
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

// Test provider ranking
TEST_F(EnhancedCryptoProviderTest, ProviderRanking) {
    auto& factory = ProviderFactory::instance();
    
    auto performance_ranking = factory.rank_providers_by_performance();
    if (performance_ranking.is_ok()) {
        auto ranked_providers = performance_ranking.value();
        EXPECT_GT(ranked_providers.size(), 0);
        
        for (const auto& provider_name : ranked_providers) {
            EXPECT_TRUE(factory.is_provider_available(provider_name));
        }
    }
    
    auto compatibility_ranking = factory.rank_providers_by_compatibility(basic_criteria_);
    if (compatibility_ranking.is_ok()) {
        auto ranked_providers = compatibility_ranking.value();
        EXPECT_GT(ranked_providers.size(), 0);
    }
    
    auto load_balanced = factory.select_provider_with_load_balancing(
        basic_criteria_, LoadBalancingStrategy::HEALTH_BASED);
    if (load_balanced.is_ok()) {
        auto provider_name = load_balanced.value();
        EXPECT_FALSE(provider_name.empty());
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
}