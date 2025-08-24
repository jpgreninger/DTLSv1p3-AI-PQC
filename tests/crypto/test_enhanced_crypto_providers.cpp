/**
 * @file test_enhanced_crypto_providers_basic.cpp
 * @brief Basic enhanced crypto provider tests for coverage
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

// Test factory basic functionality
TEST_F(EnhancedCryptoProviderTest, FactoryBasicFunctionality) {
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
    
    // Test provider availability
    EXPECT_TRUE(factory.is_provider_available("openssl"));
    EXPECT_FALSE(factory.is_provider_available("non_existent"));
    
    // Test provider registrations
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
}

// Test OpenSSL provider
TEST_F(EnhancedCryptoProviderTest, OpenSSLProviderFunctionality) {
    auto openssl_provider = std::make_unique<OpenSSLProvider>();
    
    EXPECT_EQ(openssl_provider->name(), "openssl");
    EXPECT_FALSE(openssl_provider->version().empty());
    EXPECT_TRUE(openssl_provider->is_available());
    
    auto init_result = openssl_provider->initialize();
    EXPECT_TRUE(init_result.is_ok());
    
    auto capabilities = openssl_provider->capabilities();
    EXPECT_EQ(capabilities.provider_name, "openssl");
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
        
        // Test that multiple generations are different
        auto random_result2 = openssl_provider->generate_random(random_params);
        if (random_result2.is_ok()) {
            auto random_data2 = random_result2.value();
            EXPECT_NE(random_data, random_data2);
        }
    }
    
    openssl_provider->cleanup();
}

// Test Botan provider
TEST_F(EnhancedCryptoProviderTest, BotanProviderFunctionality) {
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
    } else {
        // Test stub behavior
        auto init_result = botan_provider->initialize();
        RandomParams random_params;
        random_params.length = 16;
        random_params.cryptographically_secure = true;
        auto random_result = botan_provider->generate_random(random_params);
        // Results may vary for stub implementation
    }
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

// Test provider capabilities
TEST_F(EnhancedCryptoProviderTest, ProviderCapabilitiesValidation) {
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (provider_result.is_ok()) {
            auto provider = std::move(provider_result.value());
            auto init_result = provider->initialize();
            
            if (init_result.is_ok()) {
                auto capabilities = provider->capabilities();
                
                // Verify all cipher suites are valid
                for (auto cipher_suite : capabilities.supported_cipher_suites) {
                    EXPECT_NE(cipher_suite, static_cast<CipherSuite>(0));
                }
                
                // Verify all groups are valid
                for (auto group : capabilities.supported_groups) {
                    EXPECT_NE(group, static_cast<NamedGroup>(0));
                }
                
                // Verify all signatures are valid
                for (auto signature : capabilities.supported_signatures) {
                    EXPECT_NE(signature, static_cast<SignatureScheme>(0));
                }
                
                // Verify all hashes are valid
                for (auto hash : capabilities.supported_hashes) {
                    EXPECT_NE(hash, static_cast<HashAlgorithm>(0));
                }
                
                // Test provider-specific expectations
                if (provider_name == "openssl") {
                    // OpenSSL should support basic cipher suites
                    bool has_aes_128_gcm = std::find(capabilities.supported_cipher_suites.begin(),
                                                   capabilities.supported_cipher_suites.end(),
                                                   CipherSuite::TLS_AES_128_GCM_SHA256) != 
                                         capabilities.supported_cipher_suites.end();
                    EXPECT_TRUE(has_aes_128_gcm);
                    
                    // OpenSSL should support SECP256R1
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

// Test provider configuration and defaults
TEST_F(EnhancedCryptoProviderTest, ProviderConfiguration) {
    auto& factory = ProviderFactory::instance();
    
    // Test default provider
    auto default_provider = factory.create_default_provider();
    EXPECT_TRUE(default_provider.is_ok());
    
    if (default_provider.is_ok()) {
        auto provider = std::move(default_provider.value());
        EXPECT_TRUE(provider != nullptr);
        EXPECT_FALSE(provider->name().empty());
    }
    
    // Test provider availability refresh
    auto refresh_result = factory.refresh_availability();
    // Result may succeed or fail depending on implementation
    
    // Test getting all registrations
    auto all_registrations = factory.get_all_registrations();
    EXPECT_GT(all_registrations.size(), 0);
    
    for (const auto& registration : all_registrations) {
        EXPECT_FALSE(registration.name.empty());
        EXPECT_FALSE(registration.description.empty());
        EXPECT_NE(registration.factory, nullptr);
    }
}

// Test provider feature support queries
TEST_F(EnhancedCryptoProviderTest, ProviderFeatureSupport) {
    auto& factory = ProviderFactory::instance();
    
    // Test cipher suite support
    bool openssl_supports_aes128 = factory.supports_cipher_suite("openssl", CipherSuite::TLS_AES_128_GCM_SHA256);
    if (factory.is_provider_available("openssl")) {
        EXPECT_TRUE(openssl_supports_aes128);
    }
    
    // Test group support
    bool openssl_supports_p256 = factory.supports_named_group("openssl", NamedGroup::SECP256R1);
    if (factory.is_provider_available("openssl")) {
        EXPECT_TRUE(openssl_supports_p256);
    }
    
    // Test signature support
    bool openssl_supports_rsa = factory.supports_signature_scheme("openssl", SignatureScheme::RSA_PKCS1_SHA256);
    if (factory.is_provider_available("openssl")) {
        EXPECT_TRUE(openssl_supports_rsa);
    }
    
    // Test non-existent provider
    EXPECT_FALSE(factory.supports_cipher_suite("non_existent", CipherSuite::TLS_AES_128_GCM_SHA256));
}

// Test provider memory management
TEST_F(EnhancedCryptoProviderTest, ProviderMemoryManagement) {
    auto& factory = ProviderFactory::instance();
    
    // Create and destroy many providers to test memory management
    for (int i = 0; i < 50; ++i) {
        auto provider_result = factory.create_best_provider(basic_criteria_);
        if (provider_result.is_ok()) {
            auto provider = std::move(provider_result.value());
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
        auto provider = std::move(provider_result.value());
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

// Test provider advanced features
TEST_F(EnhancedCryptoProviderTest, ProviderAdvancedFeatures) {
    auto& factory = ProviderFactory::instance();
    
    // Test FIPS compliant providers
    auto fips_providers = factory.get_fips_compliant_providers();
    // May be empty if no FIPS-compliant providers are available
    
    // Test hardware accelerated providers
    auto hw_providers = factory.get_hardware_accelerated_providers();
    // May be empty if no hardware acceleration is available
    
    // Verify all returned providers are available
    for (const auto& provider_name : fips_providers) {
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
    
    for (const auto& provider_name : hw_providers) {
        EXPECT_TRUE(factory.is_provider_available(provider_name));
    }
    
    // Test capabilities for specific features
    auto capabilities_result = factory.get_capabilities("openssl");
    if (capabilities_result.is_ok()) {
        auto capabilities = capabilities_result.value();
        EXPECT_FALSE(capabilities.provider_name.empty());
        EXPECT_FALSE(capabilities.provider_version.empty());
        
        // Verify provider supports required features
        EXPECT_GT(capabilities.supported_cipher_suites.size(), 0);
        EXPECT_GT(capabilities.supported_groups.size(), 0);
        EXPECT_GT(capabilities.supported_signatures.size(), 0);
        EXPECT_GT(capabilities.supported_hashes.size(), 0);
    }
}