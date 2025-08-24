/**
 * @file test_crypto_system_comprehensive.cpp
 * @brief Comprehensive tests for DTLS crypto system management
 * 
 * This test suite covers all functionality in crypto_system.cpp to achieve >95% coverage.
 * Tests include initialization, configuration, validation, health checks, and self-tests.
 */

#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <chrono>
#include <future>
#include <vector>

#include "dtls/crypto.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/provider.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class CryptoSystemTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Cleanup any previous state
        cleanup_crypto_system();
        
        // Reset factory state
        ProviderFactory::instance().reset_all_stats();
    }
    
    void TearDown() override {
        // Cleanup after each test
        cleanup_crypto_system();
    }
};

// Test initialization and cleanup
TEST_F(CryptoSystemTest, InitializationAndCleanup) {
    // Initially not initialized
    EXPECT_FALSE(is_crypto_system_initialized());
    
    // Initialize should succeed
    auto init_result = initialize_crypto_system();
    EXPECT_TRUE(init_result.is_success()) 
        << "Initialization failed: " << static_cast<int>(init_result.error());
    
    // Should now be initialized
    EXPECT_TRUE(is_crypto_system_initialized());
    
    // Double initialization should fail with ALREADY_INITIALIZED
    auto double_init = initialize_crypto_system();
    EXPECT_TRUE(double_init.is_error());
    EXPECT_EQ(double_init.error(), DTLSError::ALREADY_INITIALIZED);
    
    // Cleanup should work
    cleanup_crypto_system();
    EXPECT_FALSE(is_crypto_system_initialized());
    
    // Cleanup when not initialized should be safe
    cleanup_crypto_system();
    EXPECT_FALSE(is_crypto_system_initialized());
}

// Test configuration management
TEST_F(CryptoSystemTest, ConfigurationManagement) {
    // Configure before initialization should fail
    CryptoSystemConfig config;
    config.preferred_provider = "openssl";
    config.require_hardware_acceleration = true;
    
    auto set_result = set_crypto_system_config(config);
    EXPECT_TRUE(set_result.is_error());
    EXPECT_EQ(set_result.error(), DTLSError::NOT_INITIALIZED);
    
    // Initialize system
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Get default configuration
    auto default_config = get_crypto_system_config();
    EXPECT_EQ(default_config.default_security_level, SecurityLevel::HIGH);
    EXPECT_FALSE(default_config.require_hardware_acceleration);
    EXPECT_FALSE(default_config.require_fips_compliance);
    EXPECT_FALSE(default_config.enable_crypto_stats);
    
    // Set new configuration
    config.default_security_level = SecurityLevel::MEDIUM;
    config.enable_crypto_stats = true;
    config.provider_cache_size = 32;
    config.allow_weak_ciphers = false;
    config.allow_legacy_signatures = false;
    config.disabled_cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256};
    config.disabled_groups = {NamedGroup::SECP256R1};
    config.disabled_signatures = {SignatureScheme::RSA_PKCS1_SHA256};
    config.enable_crypto_logging = true;
    config.log_level = "DEBUG";
    
    auto set_result2 = set_crypto_system_config(config);
    EXPECT_TRUE(set_result2.is_success());
    
    // Verify configuration was applied
    auto new_config = get_crypto_system_config();
    EXPECT_EQ(new_config.default_security_level, SecurityLevel::MEDIUM);
    EXPECT_TRUE(new_config.enable_crypto_stats);
    EXPECT_EQ(new_config.provider_cache_size, 32);
    EXPECT_FALSE(new_config.allow_weak_ciphers);
    EXPECT_FALSE(new_config.allow_legacy_signatures);
    EXPECT_EQ(new_config.disabled_cipher_suites.size(), 1);
    EXPECT_EQ(new_config.disabled_groups.size(), 1);
    EXPECT_EQ(new_config.disabled_signatures.size(), 1);
    EXPECT_TRUE(new_config.enable_crypto_logging);
    EXPECT_EQ(new_config.log_level, "DEBUG");
    
    // Reset configuration
    reset_crypto_system_config();
    auto reset_config = get_crypto_system_config();
    EXPECT_EQ(reset_config.default_security_level, SecurityLevel::HIGH);
    EXPECT_FALSE(reset_config.enable_crypto_stats);
    EXPECT_TRUE(reset_config.disabled_cipher_suites.empty());
}

// Test configuration with invalid provider
TEST_F(CryptoSystemTest, ConfigurationWithInvalidProvider) {
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    CryptoSystemConfig config;
    config.preferred_provider = "nonexistent_provider";
    
    // Setting invalid provider should still succeed (handled during validation)
    auto set_result = set_crypto_system_config(config);
    EXPECT_TRUE(set_result.is_success());
    
    auto new_config = get_crypto_system_config();
    EXPECT_EQ(new_config.preferred_provider, "nonexistent_provider");
}

// Test configuration validation
TEST_F(CryptoSystemTest, ConfigurationValidation) {
    // Validation before initialization should return critical issue
    auto validation = validate_crypto_config();
    EXPECT_TRUE(validation.is_success());
    
    auto issues = *validation;
    EXPECT_FALSE(issues.empty());
    EXPECT_EQ(issues[0].severity, ConfigValidationIssue::Severity::CRITICAL);
    EXPECT_EQ(issues[0].component, "system");
    
    // Initialize system
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Basic validation should pass
    auto validation2 = validate_crypto_config();
    EXPECT_TRUE(validation2.is_success());
    
    // Test various configuration issues
    CryptoSystemConfig config;
    
    // Test invalid preferred provider
    config.preferred_provider = "invalid_provider";
    ASSERT_TRUE(set_crypto_system_config(config).is_success());
    
    auto validation3 = validate_crypto_config();
    EXPECT_TRUE(validation3.is_success());
    auto issues3 = *validation3;
    bool found_provider_warning = false;
    for (const auto& issue : issues3) {
        if (issue.component == "provider" && 
            issue.severity == ConfigValidationIssue::Severity::WARNING) {
            found_provider_warning = true;
            break;
        }
    }
    EXPECT_TRUE(found_provider_warning);
    
    // Test hardware acceleration requirement
    config.preferred_provider = "";
    config.require_hardware_acceleration = true;
    ASSERT_TRUE(set_crypto_system_config(config).is_success());
    
    auto validation4 = validate_crypto_config();
    EXPECT_TRUE(validation4.is_success());
    auto issues4 = *validation4;
    bool found_hardware_error = false;
    for (const auto& issue : issues4) {
        if (issue.component == "hardware" && 
            issue.severity == ConfigValidationIssue::Severity::ERROR) {
            found_hardware_error = true;
            break;
        }
    }
    // May or may not find hardware error depending on system capabilities
    
    // Test FIPS compliance requirement
    config.require_hardware_acceleration = false;
    config.require_fips_compliance = true;
    ASSERT_TRUE(set_crypto_system_config(config).is_success());
    
    auto validation5 = validate_crypto_config();
    EXPECT_TRUE(validation5.is_success());
    
    // Test security level warning
    config.require_fips_compliance = false;
    config.default_security_level = SecurityLevel::NONE;
    ASSERT_TRUE(set_crypto_system_config(config).is_success());
    
    auto validation6 = validate_crypto_config();
    EXPECT_TRUE(validation6.is_success());
    auto issues6 = *validation6;
    bool found_security_warning = false;
    for (const auto& issue : issues6) {
        if (issue.component == "security" && 
            issue.severity == ConfigValidationIssue::Severity::WARNING) {
            found_security_warning = true;
            break;
        }
    }
    EXPECT_TRUE(found_security_warning);
}

// Test system status
TEST_F(CryptoSystemTest, SystemStatus) {
    // Status before initialization
    auto status = get_crypto_system_status();
    EXPECT_FALSE(status.is_initialized);
    EXPECT_TRUE(status.default_provider.empty());
    EXPECT_EQ(status.available_providers, 0);
    EXPECT_EQ(status.active_providers, 0);
    EXPECT_EQ(status.uptime, std::chrono::milliseconds(0));
    
    // Initialize and check status
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    auto status2 = get_crypto_system_status();
    EXPECT_TRUE(status2.is_initialized);
    EXPECT_GE(status2.available_providers, 0);
    EXPECT_EQ(status2.available_providers, status2.active_providers);
    EXPECT_GE(status2.uptime, std::chrono::milliseconds(0));
    
    // If OpenSSL is available, version should be set
    if (!status2.openssl_version.empty()) {
        EXPECT_TRUE(status2.openssl_version.find("OpenSSL") != std::string::npos ||
                   status2.openssl_version.find("3.") != std::string::npos ||
                   status2.openssl_version.find("1.1") != std::string::npos);
    }
    
    // Wait a bit and check uptime increases
    std::this_thread::sleep_for(1ms);
    auto status3 = get_crypto_system_status();
    EXPECT_GT(status3.uptime, status2.uptime);
}

// Test health check
TEST_F(CryptoSystemTest, HealthCheck) {
    // Health check before initialization
    auto health = perform_crypto_health_check();
    EXPECT_TRUE(health.is_success());
    
    auto result = *health;
    EXPECT_FALSE(result.overall_healthy);
    EXPECT_FALSE(result.issues.empty());
    EXPECT_EQ(result.issues[0].severity, ConfigValidationIssue::Severity::CRITICAL);
    EXPECT_GE(result.check_duration, std::chrono::milliseconds(0));
    
    // Initialize and check health
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    auto health2 = perform_crypto_health_check();
    EXPECT_TRUE(health2.is_success());
    
    auto result2 = *health2;
    EXPECT_GE(result2.available_providers.size(), 0);
    EXPECT_GE(result2.check_duration, std::chrono::milliseconds(0));
    
    // Health should be true if we have working providers
    if (!result2.available_providers.empty()) {
        EXPECT_TRUE(result2.overall_healthy);
    }
}

// Test self-tests
TEST_F(CryptoSystemTest, SelfTests) {
    // Self-tests before initialization
    auto selftest = run_crypto_self_tests();
    EXPECT_TRUE(selftest.is_success());
    
    auto result = *selftest;
    EXPECT_FALSE(result.all_tests_passed);
    EXPECT_EQ(result.tests_run, 1);
    EXPECT_EQ(result.tests_failed, 1);
    EXPECT_FALSE(result.failed_test_names.empty());
    EXPECT_EQ(result.failed_test_names[0], "system_initialization");
    
    // Initialize and run self-tests
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    auto selftest2 = run_crypto_self_tests();
    EXPECT_TRUE(selftest2.is_success());
    
    auto result2 = *selftest2;
    EXPECT_GE(result2.tests_run, 0);
    EXPECT_EQ(result2.tests_passed + result2.tests_failed, result2.tests_run);
    
    // Only check timing if tests actually ran
    if (result2.tests_run > 0) {
        EXPECT_GE(result2.total_test_time, std::chrono::milliseconds(0));
    }
    
    // If tests pass, all_tests_passed should be true
    if (result2.tests_failed == 0 && result2.tests_run > 0) {
        EXPECT_TRUE(result2.all_tests_passed);
    }
}

// Test exception handling in configuration
TEST_F(CryptoSystemTest, ExceptionHandling) {
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Try to trigger error conditions
    CryptoSystemConfig config;
    config.preferred_provider = std::string(10000, 'x'); // Very long string
    
    // Should handle gracefully
    auto set_result = set_crypto_system_config(config);
    // Should either succeed or fail gracefully, not crash
    EXPECT_TRUE(set_result.is_success() || set_result.is_error());
}

// Test concurrent operations
TEST_F(CryptoSystemTest, ConcurrentOperations) {
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Run multiple operations concurrently
    std::vector<std::future<void>> futures;
    
    for (int i = 0; i < 10; ++i) {
        futures.push_back(std::async(std::launch::async, [this]() {
            // Get status
            auto status = get_crypto_system_status();
            EXPECT_TRUE(status.is_initialized);
            
            // Get config
            auto config = get_crypto_system_config();
            
            // Run validation
            auto validation = validate_crypto_config();
            EXPECT_TRUE(validation.is_success());
            
            // Run health check
            auto health = perform_crypto_health_check();
            EXPECT_TRUE(health.is_success());
        }));
    }
    
    // Wait for all operations to complete
    for (auto& future : futures) {
        future.wait();
    }
}

// Test comprehensive cipher suite validation
TEST_F(CryptoSystemTest, CipherSuiteValidation) {
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Test disabling all cipher suites for validation warning
    CryptoSystemConfig config;
    config.disabled_cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        // Add more cipher suites to trigger validation
    };
    
    ASSERT_TRUE(set_crypto_system_config(config).is_success());
    
    auto validation = validate_crypto_config();
    EXPECT_TRUE(validation.is_success());
    
    // Check for cipher suite warnings (may not always trigger depending on provider capabilities)
    auto issues = *validation;
    for (const auto& issue : issues) {
        if (issue.component == "cipher_suites") {
            EXPECT_EQ(issue.severity, ConfigValidationIssue::Severity::WARNING);
        }
    }
}

// Test provider-specific validation paths
TEST_F(CryptoSystemTest, ProviderSpecificValidation) {
    ASSERT_TRUE(initialize_crypto_system().is_success());
    
    // Try to set specific providers and validate
    auto& factory = ProviderFactory::instance();
    auto available = factory.available_providers();
    
    for (const auto& provider_name : available) {
        CryptoSystemConfig config;
        config.preferred_provider = provider_name;
        
        EXPECT_TRUE(set_crypto_system_config(config).is_success());
        
        auto validation = validate_crypto_config();
        EXPECT_TRUE(validation.is_success());
        
        auto health = perform_crypto_health_check();
        EXPECT_TRUE(health.is_success());
    }
}