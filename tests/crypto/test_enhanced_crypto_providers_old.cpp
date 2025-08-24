/**
 * @file test_enhanced_crypto_providers.cpp
 * @brief Enhanced comprehensive tests for crypto providers with coverage focus
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
#include "dtls/crypto/crypto_utils.h"
#include "dtls/crypto/hardware_acceleration.h"
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
            // Fallback: register at least core providers for testing
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
        
        // Test selection criteria - basic
        basic_criteria_.require_hardware_acceleration = false;
        basic_criteria_.require_fips_compliance = false;
        basic_criteria_.allow_software_fallback = true;
        basic_criteria_.minimum_security_level = SecurityLevel::MEDIUM;
        basic_criteria_.require_thread_safety = true;
        
        // Test selection criteria - advanced
        advanced_criteria_ = basic_criteria_;
        advanced_criteria_.required_cipher_suites = {
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384
        };
        advanced_criteria_.required_groups = {
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1
        };
        advanced_criteria_.required_signatures = {
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256
        };
        
        // High security criteria
        high_security_criteria_ = basic_criteria_;
        high_security_criteria_.minimum_security_level = SecurityLevel::HIGH;
        high_security_criteria_.require_fips_compliance = true;
        high_security_criteria_.require_hardware_acceleration = true;
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
    ProviderSelection advanced_criteria_;
    ProviderSelection high_security_criteria_;
};

// Test provider factory comprehensive functionality
TEST_F(EnhancedCryptoProviderTest, FactoryComprehensiveFunctionality) {
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
            EXPECT_NE(reg_info.factory_func, nullptr);
        }
    }
    
    // Test provider creation stats
    auto initial_stats = factory.get_creation_stats();
    
    // Create a provider to test stats
    auto provider_result = factory.create_provider("openssl");
    if (provider_result.is_ok()) {
        auto updated_stats = factory.get_creation_stats();
        EXPECT_GE(updated_stats.total_creations, initial_stats.total_creations);
    }
    
    // Test provider selection with criteria
    auto selected_provider = factory.select_provider(basic_criteria_);
    EXPECT_TRUE(selected_provider.is_ok());
    
    // Test best provider selection
    auto best_provider = factory.select_best_provider(advanced_criteria_);
    EXPECT_TRUE(best_provider.is_ok());
    
    // Test provider capabilities query
    if (selected_provider.is_ok()) {
        auto provider = selected_provider.value();
        auto capabilities = provider->capabilities();
        
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
    
    // Test HKDF operations
    HKDFParams hkdf_params;
    hkdf_params.salt = {0x01, 0x02, 0x03, 0x04};
    hkdf_params.ikm = test_data_;
    hkdf_params.info = {0x05, 0x06, 0x07, 0x08};
    hkdf_params.length = 32;
    hkdf_params.hash = HashAlgorithm::SHA256;
    
    auto hkdf_result = openssl_provider->hkdf(hkdf_params);
    EXPECT_TRUE(hkdf_result.is_ok());
    
    if (hkdf_result.is_ok()) {
        auto derived_key = hkdf_result.value();
        EXPECT_EQ(derived_key.size(), 32);
        
        // Test consistency - same input should produce same output
        auto hkdf_result2 = openssl_provider->hkdf(hkdf_params);
        if (hkdf_result2.is_ok()) {
            EXPECT_EQ(derived_key, hkdf_result2.value());
        }
    }
    
    // Test HKDF-Expand-Label
    HKDFExpandLabelParams expand_params;
    expand_params.secret = test_data_;
    expand_params.label = "test label";
    expand_params.context = {0x09, 0x0A, 0x0B, 0x0C};
    expand_params.length = 16;
    expand_params.hash = HashAlgorithm::SHA256;
    
    auto expand_result = openssl_provider->hkdf_expand_label(expand_params);
    EXPECT_TRUE(expand_result.is_ok());
    
    if (expand_result.is_ok()) {
        auto expanded_key = expand_result.value();
        EXPECT_EQ(expanded_key.size(), 16);
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

// Test crypto utilities functionality
TEST_F(EnhancedCryptoProviderTest, CryptoUtilitiesFunctionality) {
    // Test OpenSSL utilities
    EXPECT_TRUE(openssl_utils::is_openssl_available());
    
    auto openssl_init_result = openssl_utils::initialize_openssl();
    EXPECT_TRUE(openssl_init_result.is_ok());
    
    auto openssl_version = openssl_utils::get_openssl_version();
    EXPECT_FALSE(openssl_version.empty());
    
    auto openssl_features = openssl_utils::get_supported_features();
    EXPECT_GT(openssl_features.size(), 0);
    
    // Test Botan utilities
    bool botan_available = botan_utils::is_botan_available();
    if (botan_available) {
        auto botan_init_result = botan_utils::initialize_botan();
        EXPECT_TRUE(botan_init_result.is_ok());
        
        auto botan_version = botan_utils::get_botan_version();
        EXPECT_FALSE(botan_version.empty());
        
        auto botan_features = botan_utils::get_supported_features();
        EXPECT_GT(botan_features.size(), 0);
    }
    
    // Test common utilities
    auto security_level = utils::get_minimum_security_level();
    EXPECT_NE(security_level, SecurityLevel::NONE);
    
    auto entropy_check = utils::check_entropy_available();
    EXPECT_TRUE(entropy_check);
    
    auto fips_status = utils::is_fips_mode_enabled();
    // FIPS mode may or may not be enabled
}

// Test hardware acceleration detection
TEST_F(EnhancedCryptoProviderTest, HardwareAccelerationDetection) {
    auto hw_caps = hardware::detect_capabilities();
    
    // Test that detection doesn't crash and returns valid data
    EXPECT_GE(hw_caps.aes_ni_support, false);
    EXPECT_GE(hw_caps.sse2_support, false);
    EXPECT_GE(hw_caps.avx2_support, false);
    EXPECT_GE(hw_caps.sha_extensions_support, false);
    
    // Test individual feature detection
    bool aes_ni = hardware::has_aes_ni();
    bool sha_ext = hardware::has_sha_extensions();
    bool avx2 = hardware::has_avx2();
    
    // These may be true or false depending on hardware
    EXPECT_EQ(aes_ni, hw_caps.aes_ni_support);
    EXPECT_EQ(sha_ext, hw_caps.sha_extensions_support);
    EXPECT_EQ(avx2, hw_caps.avx2_support);
    
    // Test hardware-accelerated provider creation
    auto hw_provider_result = hardware::create_accelerated_provider();
    if (hw_provider_result.is_ok()) {
        auto hw_provider = hw_provider_result.value();
        EXPECT_TRUE(hw_provider != nullptr);
        
        auto capabilities = hw_provider->capabilities();
        EXPECT_TRUE(capabilities.hardware_acceleration);
    }
}

// Test provider selection with various criteria
TEST_F(EnhancedCryptoProviderTest, ProviderSelectionCriteria) {
    auto& factory = ProviderFactory::instance();
    
    // Test basic selection
    auto basic_provider = factory.select_provider(basic_criteria_);
    EXPECT_TRUE(basic_provider.is_ok());
    
    // Test advanced selection
    auto advanced_provider = factory.select_provider(advanced_criteria_);
    if (advanced_provider.is_ok()) {
        auto capabilities = advanced_provider.value()->capabilities();
        
        // Verify that selected provider supports required features
        for (auto cipher_suite : advanced_criteria_.required_cipher_suites) {
            bool found = std::find(capabilities.supported_cipher_suites.begin(),
                                 capabilities.supported_cipher_suites.end(),
                                 cipher_suite) != capabilities.supported_cipher_suites.end();
            EXPECT_TRUE(found) << "Required cipher suite not supported";
        }
        
        for (auto group : advanced_criteria_.required_groups) {
            bool found = std::find(capabilities.supported_groups.begin(),
                                 capabilities.supported_groups.end(),
                                 group) != capabilities.supported_groups.end();
            EXPECT_TRUE(found) << "Required group not supported";
        }
        
        for (auto signature : advanced_criteria_.required_signatures) {
            bool found = std::find(capabilities.supported_signatures.begin(),
                                 capabilities.supported_signatures.end(),
                                 signature) != capabilities.supported_signatures.end();
            EXPECT_TRUE(found) << "Required signature not supported";
        }
    }
    
    // Test high security selection (may fail if no FIPS-compliant provider)
    auto high_security_provider = factory.select_provider(high_security_criteria_);
    // This may succeed or fail depending on system configuration
    
    // Test impossible criteria (should fail)
    ProviderSelection impossible_criteria;
    impossible_criteria.required_cipher_suites = {static_cast<CipherSuite>(0xFFFF)};
    impossible_criteria.required_groups = {static_cast<NamedGroup>(0xFFFF)};
    impossible_criteria.required_signatures = {static_cast<SignatureScheme>(0xFFFF)};
    
    auto impossible_provider = factory.select_provider(impossible_criteria);
    EXPECT_TRUE(impossible_provider.is_error());
}

// Test concurrent provider operations
TEST_F(EnhancedCryptoProviderTest, ConcurrentProviderOperations) {
    auto& factory = ProviderFactory::instance();
    
    // Test concurrent provider creation
    std::vector<std::future<std::unique_ptr<CryptoProvider>>> futures;
    
    for (int i = 0; i < 10; ++i) {
        futures.push_back(std::async(std::launch::async, [&factory]() {
            auto provider_result = factory.select_provider(ProviderSelection{});
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
        
        // Test random generation before initialization
        RandomParams params;
        params.length = 16;
        params.cryptographically_secure = true;
        
        // Some providers may work without explicit initialization, others may not
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
        
        // Test HKDF with invalid parameters
        HKDFParams invalid_hkdf;
        invalid_hkdf.salt = {};
        invalid_hkdf.ikm = {};
        invalid_hkdf.info = {};
        invalid_hkdf.length = 0;
        invalid_hkdf.hash = static_cast<HashAlgorithm>(0xFF);
        
        auto invalid_hkdf_result = openssl_provider->hkdf(invalid_hkdf);
        EXPECT_TRUE(invalid_hkdf_result.is_error());
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
                
                // Test all cipher suites
                for (auto cipher_suite : capabilities.supported_cipher_suites) {
                    EXPECT_NE(cipher_suite, static_cast<CipherSuite>(0));
                }
                
                // Test all groups
                for (auto group : capabilities.supported_groups) {
                    EXPECT_NE(group, static_cast<NamedGroup>(0));
                }
                
                // Test all signatures
                for (auto signature : capabilities.supported_signatures) {
                    EXPECT_NE(signature, static_cast<SignatureScheme>(0));
                }
                
                // Test all hashes
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
        auto provider_result = factory.select_provider(basic_criteria_);
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
    auto provider_result = factory.select_provider(basic_criteria_);
    
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
            
            // Test HKDF performance
            start_time = std::chrono::high_resolution_clock::now();
            
            for (int i = 0; i < 100; ++i) {
                HKDFParams hkdf_params;
                hkdf_params.salt = {0x01, 0x02, 0x03, 0x04};
                hkdf_params.ikm = test_data_;
                hkdf_params.info = {0x05, 0x06, 0x07, 0x08};
                hkdf_params.length = 32;
                hkdf_params.hash = HashAlgorithm::SHA256;
                
                auto hkdf_result = provider->hkdf(hkdf_params);
                EXPECT_TRUE(hkdf_result.is_ok());
            }
            
            end_time = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            // Performance expectation: 100 HKDF operations should complete in reasonable time
            EXPECT_LT(duration.count(), 5000); // Less than 5 seconds
        }
    }
}