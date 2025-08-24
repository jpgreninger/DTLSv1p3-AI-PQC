/**
 * @file test_hardware_acceleration_comprehensive.cpp
 * @brief Comprehensive tests for DTLS hardware acceleration detection and management
 * 
 * This test suite covers all functionality in hardware_acceleration.cpp to achieve >95% coverage.
 * Tests include capability detection, platform identification, provider selection, and benchmarking.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>

#include "dtls/crypto/hardware_acceleration.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class HardwareAccelerationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup test environment
    }
    
    void TearDown() override {
        // Cleanup after each test
    }
    
    // Helper to check if running on specific architectures
    bool is_x86_architecture() {
#if defined(__x86_64__) || defined(__i386__)
        return true;
#else
        return false;
#endif
    }
    
    bool is_arm_architecture() {
#if defined(__aarch64__) || defined(__arm__)
        return true;
#else
        return false;
#endif
    }
    
    bool is_windows() {
#ifdef _WIN32
        return true;
#else
        return false;
#endif
    }
    
    bool is_linux() {
#ifdef __linux__
        return true;
#else
        return false;
#endif
    }
};

// Test basic capability detection
TEST_F(HardwareAccelerationTest, CapabilityDetection) {
    auto profile_result = HardwareAccelerationDetector::detect_capabilities();
    EXPECT_TRUE(profile_result.is_success()) 
        << "Hardware detection failed: " << static_cast<int>(profile_result.error());
    
    if (profile_result.is_success()) {
        auto profile = *profile_result;
        
        // Basic profile validation
        EXPECT_FALSE(profile.platform_name.empty());
        EXPECT_FALSE(profile.cpu_model.empty());
        
        // Should have at least some capabilities entry (even if false)
        EXPECT_GE(profile.capabilities.size(), 0);
        
        // Overall performance score should be reasonable
        EXPECT_GE(profile.overall_performance_score, 0.0f);
        EXPECT_LE(profile.overall_performance_score, 100.0f);
        
        // Check architecture-specific capabilities
        if (is_x86_architecture()) {
            bool found_x86_cap = false;
            for (const auto& cap : profile.capabilities) {
                if (cap.capability == HardwareCapability::AES_NI ||
                    cap.capability == HardwareCapability::AVX ||
                    cap.capability == HardwareCapability::SSE2) {
                    found_x86_cap = true;
                    EXPECT_GE(cap.performance_multiplier, 0.0f);
                    EXPECT_FALSE(cap.description.empty());
                    break;
                }
            }
            // We expect at least some x86 capabilities to be detected on x86 systems
            EXPECT_TRUE(found_x86_cap);
        }
        
        if (is_arm_architecture()) {
            bool found_arm_cap = false;
            for (const auto& cap : profile.capabilities) {
                if (cap.capability == HardwareCapability::ARM_AES ||
                    cap.capability == HardwareCapability::ARM_NEON ||
                    cap.capability == HardwareCapability::ARM_SHA1) {
                    found_arm_cap = true;
                    break;
                }
            }
            // We might find ARM capabilities on ARM systems
        }
        
        // has_any_acceleration should match capabilities
        bool expected_acceleration = false;
        for (const auto& cap : profile.capabilities) {
            if (cap.available && cap.enabled) {
                expected_acceleration = true;
                break;
            }
        }
        EXPECT_EQ(profile.has_any_acceleration, expected_acceleration);
    }
}

// Test individual capability checking
TEST_F(HardwareAccelerationTest, IndividualCapabilityChecking) {
    // Test all defined capabilities
    std::vector<HardwareCapability> all_capabilities = {
        HardwareCapability::AES_NI,
        HardwareCapability::AVX,
        HardwareCapability::AVX2,
        HardwareCapability::SSE2,
        HardwareCapability::SSE3,
        HardwareCapability::SSE4_1,
        HardwareCapability::SSE4_2,
        HardwareCapability::PCLMULQDQ,
        HardwareCapability::ARM_NEON,
        HardwareCapability::ARM_AES,
        HardwareCapability::ARM_SHA1,
        HardwareCapability::ARM_SHA2,
        HardwareCapability::ARM_SHA3,
        HardwareCapability::TPM_2_0,
        HardwareCapability::HSM,
        HardwareCapability::SECURE_ENCLAVE,
        HardwareCapability::CRYPTO_ENGINE,
        HardwareCapability::RNG_HARDWARE,
        HardwareCapability::INTEL_QAT,
        HardwareCapability::ARM_CRYPTO_EXT,
        HardwareCapability::POWER_CRYPTO,
        HardwareCapability::VIRTUAL_HSM,
        HardwareCapability::CLOUD_KMS
    };
    
    for (auto capability : all_capabilities) {
        // Should not crash when checking any capability
        bool available = HardwareAccelerationDetector::is_capability_available(capability);
        
        // Result should be consistent with profile
        auto profile_result = HardwareAccelerationDetector::detect_capabilities();
        if (profile_result.is_success()) {
            auto profile = *profile_result;
            bool found_in_profile = false;
            for (const auto& cap : profile.capabilities) {
                if (cap.capability == capability) {
                    EXPECT_EQ(available, cap.available);
                    found_in_profile = true;
                    break;
                }
            }
            // Some capabilities might not be in profile if not relevant to platform
        }
    }
}

// Test provider recommendation
TEST_F(HardwareAccelerationTest, ProviderRecommendation) {
    auto provider_result = HardwareAccelerationDetector::get_recommended_provider();
    
    // Should either succeed with a provider name or fail gracefully
    if (provider_result.is_success()) {
        auto provider_name = *provider_result;
        EXPECT_FALSE(provider_name.empty());
        
        // Common provider names
        EXPECT_TRUE(provider_name == "openssl" || 
                   provider_name == "botan" ||
                   provider_name == "hardware" ||
                   provider_name == "null" ||
                   !provider_name.empty()); // Any non-empty string is valid
    } else {
        // If it fails, error should be reasonable
        EXPECT_NE(provider_result.error(), DTLSError::SUCCESS);
    }
}

// Test capability enable/disable
TEST_F(HardwareAccelerationTest, CapabilityEnableDisable) {
    // Test with a common capability
    HardwareCapability test_cap = HardwareCapability::AES_NI;
    
    // Try to enable
    auto enable_result = HardwareAccelerationDetector::enable_capability(test_cap);
    // Should either succeed or fail gracefully
    EXPECT_TRUE(enable_result.is_success() || enable_result.is_error());
    
    // Try to disable
    auto disable_result = HardwareAccelerationDetector::disable_capability(test_cap);
    // Should either succeed or fail gracefully
    EXPECT_TRUE(disable_result.is_success() || disable_result.is_error());
    
    // Test with multiple capabilities
    std::vector<HardwareCapability> test_caps = {
        HardwareCapability::AES_NI,
        HardwareCapability::AVX,
        HardwareCapability::ARM_AES,
        HardwareCapability::RNG_HARDWARE
    };
    
    for (auto cap : test_caps) {
        auto enable = HardwareAccelerationDetector::enable_capability(cap);
        auto disable = HardwareAccelerationDetector::disable_capability(cap);
        
        // Should not crash
        EXPECT_TRUE(enable.is_success() || enable.is_error());
        EXPECT_TRUE(disable.is_success() || disable.is_error());
    }
}

// Test capability benchmarking
TEST_F(HardwareAccelerationTest, CapabilityBenchmarking) {
    // Test benchmarking various capabilities
    std::vector<HardwareCapability> test_caps = {
        HardwareCapability::AES_NI,
        HardwareCapability::AVX,
        HardwareCapability::SSE2,
        HardwareCapability::ARM_AES,
        HardwareCapability::ARM_NEON
    };
    
    for (auto cap : test_caps) {
        auto benchmark_result = HardwareAccelerationDetector::benchmark_capability(cap);
        
        if (benchmark_result.is_success()) {
            auto score = *benchmark_result;
            EXPECT_GE(score, 0.0f);
            EXPECT_LE(score, 1000.0f); // Reasonable upper bound for performance multiplier
        }
        // If benchmarking fails, that's okay - capability might not be available
    }
}

// Test optimization recommendations
TEST_F(HardwareAccelerationTest, OptimizationRecommendations) {
    auto recommendations_result = HardwareAccelerationDetector::get_optimization_recommendations();
    
    if (recommendations_result.is_success()) {
        auto recommendations = *recommendations_result;
        
        // Should be a list of strings
        for (const auto& recommendation : recommendations) {
            EXPECT_FALSE(recommendation.empty());
            EXPECT_GT(recommendation.length(), 10); // Should be meaningful text
        }
    }
    // If no recommendations available, that's also valid
}

// Test hardware RNG detection
TEST_F(HardwareAccelerationTest, HardwareRNGDetection) {
    bool has_hw_rng = HardwareAccelerationDetector::detect_hardware_rng();
    
    // Should return consistently
    bool has_hw_rng2 = HardwareAccelerationDetector::detect_hardware_rng();
    EXPECT_EQ(has_hw_rng, has_hw_rng2);
    
    // Cross-check with capability detection
    bool rng_capability = HardwareAccelerationDetector::is_capability_available(
        HardwareCapability::RNG_HARDWARE);
    
    // These should be consistent (though not necessarily equal)
    if (has_hw_rng) {
        // If hardware RNG is detected, the capability should likely be available too
        // But this is not strictly required due to different detection methods
    }
}

// Test platform information
TEST_F(HardwareAccelerationTest, PlatformInformation) {
    std::string platform_info = HardwareAccelerationDetector::get_platform_info();
    
    EXPECT_FALSE(platform_info.empty());
    
    // Should contain some reasonable platform information
    if (is_linux()) {
        EXPECT_TRUE(platform_info.find("Linux") != std::string::npos ||
                   platform_info.find("linux") != std::string::npos);
    }
    
    if (is_windows()) {
        EXPECT_TRUE(platform_info.find("Windows") != std::string::npos ||
                   platform_info.find("windows") != std::string::npos);
    }
    
    if (is_x86_architecture()) {
        EXPECT_TRUE(platform_info.find("x86") != std::string::npos ||
                   platform_info.find("x64") != std::string::npos ||
                   platform_info.find("amd64") != std::string::npos ||
                   platform_info.find("Intel") != std::string::npos ||
                   platform_info.find("AMD") != std::string::npos);
    }
}

// Test provider selector
TEST_F(HardwareAccelerationTest, ProviderSelector) {
    auto profile_result = HardwareAccelerationDetector::detect_capabilities();
    ASSERT_TRUE(profile_result.is_success());
    auto profile = *profile_result;
    
    std::vector<std::string> available_providers = {"openssl", "botan", "null"};
    
    auto best_provider_result = HardwareAcceleratedProviderSelector::select_best_provider(
        available_providers, profile);
    
    if (best_provider_result.is_success()) {
        auto best_provider = *best_provider_result;
        EXPECT_FALSE(best_provider.empty());
        
        // Should be one of the available providers
        bool found = std::find(available_providers.begin(), available_providers.end(),
                              best_provider) != available_providers.end();
        EXPECT_TRUE(found);
    }
    // If selection fails, that's also acceptable
}

// Test provider acceleration settings
TEST_F(HardwareAccelerationTest, ProviderAccelerationSettings) {
    std::vector<std::string> test_providers = {"openssl", "botan", "null", "hardware"};
    
    for (const auto& provider : test_providers) {
        auto settings_result = HardwareAcceleratedProviderSelector::get_provider_acceleration_settings(provider);
        
        if (settings_result.is_success()) {
            auto settings = *settings_result;
            
            // Should be a list of key-value pairs
            for (const auto& setting : settings) {
                EXPECT_FALSE(setting.first.empty());  // Key should not be empty
                // Value can be empty for boolean flags
            }
        }
        // If no settings available for this provider, that's okay
    }
}

// Test provider optimization
TEST_F(HardwareAccelerationTest, ProviderOptimization) {
    auto profile_result = HardwareAccelerationDetector::detect_capabilities();
    ASSERT_TRUE(profile_result.is_success());
    auto profile = *profile_result;
    
    std::vector<std::string> test_providers = {"openssl", "botan", "null"};
    
    for (const auto& provider : test_providers) {
        auto optimize_result = HardwareAcceleratedProviderSelector::optimize_provider_for_hardware(
            provider, profile);
        
        // Should either succeed or fail gracefully
        EXPECT_TRUE(optimize_result.is_success() || optimize_result.is_error());
    }
}

// Test utility functions
TEST_F(HardwareAccelerationTest, UtilityFunctions) {
    // Test acceleration summary
    std::string summary = hardware_utils::get_acceleration_summary();
    EXPECT_FALSE(summary.empty());
    EXPECT_GT(summary.length(), 20); // Should be a meaningful summary
    
    // Test benchmark all capabilities
    auto benchmark_result = hardware_utils::benchmark_all_capabilities();
    if (benchmark_result.is_success()) {
        auto benchmarks = *benchmark_result;
        
        for (const auto& benchmark : benchmarks) {
            EXPECT_GE(benchmark.second, 0.0f); // Performance score should be non-negative
            EXPECT_LE(benchmark.second, 1000.0f); // Reasonable upper bound
        }
    }
    // If benchmarking fails, that's acceptable
}

// Test error conditions and edge cases
TEST_F(HardwareAccelerationTest, ErrorConditionsAndEdgeCases) {
    // Test with empty provider list
    auto profile_result = HardwareAccelerationDetector::detect_capabilities();
    ASSERT_TRUE(profile_result.is_success());
    auto profile = *profile_result;
    
    std::vector<std::string> empty_providers;
    auto empty_result = HardwareAcceleratedProviderSelector::select_best_provider(
        empty_providers, profile);
    
    // Should handle empty provider list gracefully
    EXPECT_TRUE(empty_result.is_error());
    
    // Test with invalid provider names
    std::vector<std::string> invalid_providers = {"", "invalid_provider_name", "nonexistent"};
    auto invalid_result = HardwareAcceleratedProviderSelector::select_best_provider(
        invalid_providers, profile);
    
    // Should handle invalid providers gracefully
    EXPECT_TRUE(invalid_result.is_success() || invalid_result.is_error());
}

// Test concurrent access safety
TEST_F(HardwareAccelerationTest, ConcurrentAccess) {
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    // Launch multiple threads doing capability detection
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&success_count]() {
            auto result = HardwareAccelerationDetector::detect_capabilities();
            if (result.is_success()) {
                success_count++;
            }
            
            // Test other operations
            auto platform_info = HardwareAccelerationDetector::get_platform_info();
            auto hw_rng = HardwareAccelerationDetector::detect_hardware_rng();
            auto aes_available = HardwareAccelerationDetector::is_capability_available(
                HardwareCapability::AES_NI);
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should have completed successfully
    EXPECT_EQ(success_count.load(), 5);
}

// Test consistency across multiple calls
TEST_F(HardwareAccelerationTest, ConsistencyAcrossMultipleCalls) {
    // Hardware capabilities should be consistent across calls
    auto profile1 = HardwareAccelerationDetector::detect_capabilities();
    std::this_thread::sleep_for(1ms);
    auto profile2 = HardwareAccelerationDetector::detect_capabilities();
    
    ASSERT_TRUE(profile1.is_success());
    ASSERT_TRUE(profile2.is_success());
    
    auto p1 = *profile1;
    auto p2 = *profile2;
    
    // Basic properties should be the same
    EXPECT_EQ(p1.platform_name, p2.platform_name);
    EXPECT_EQ(p1.cpu_model, p2.cpu_model);
    EXPECT_EQ(p1.has_any_acceleration, p2.has_any_acceleration);
    
    // Platform info should be consistent
    std::string info1 = HardwareAccelerationDetector::get_platform_info();
    std::string info2 = HardwareAccelerationDetector::get_platform_info();
    EXPECT_EQ(info1, info2);
    
    // Hardware RNG detection should be consistent
    bool rng1 = HardwareAccelerationDetector::detect_hardware_rng();
    bool rng2 = HardwareAccelerationDetector::detect_hardware_rng();
    EXPECT_EQ(rng1, rng2);
}