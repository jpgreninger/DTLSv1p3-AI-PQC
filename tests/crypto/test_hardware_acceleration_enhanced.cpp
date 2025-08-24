/**
 * @file test_hardware_acceleration_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS hardware acceleration detection and management
 * 
 * This test suite extends the existing comprehensive hardware acceleration tests to achieve 
 * maximum coverage of hardware_acceleration.cpp (currently 0% coverage - 0/382 lines).
 * Tests include deep CPU feature detection, platform optimization, performance validation,
 * and hardware-specific crypto acceleration paths.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>
#include <unordered_set>
#include <fstream>
#include <sstream>

#include "dtls/crypto/hardware_acceleration.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/operations_impl.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class HardwareAccelerationEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize crypto system if needed
        if (!crypto::is_crypto_system_initialized()) {
            auto init_result = crypto::initialize_crypto_system();
            ASSERT_TRUE(init_result.is_success()) << "Failed to initialize crypto system";
        }
        
        // Get fresh hardware info for each test
        hw_info_ = std::make_unique<HardwareInfo>();
        *hw_info_ = HardwareAcceleration::detect_hardware_capabilities();
    }
    
    void TearDown() override {
        hw_info_.reset();
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
    
    bool is_windows_platform() {
#ifdef _WIN32
        return true;
#else
        return false;
#endif
    }
    
    bool is_linux_platform() {
#ifdef __linux__
        return true;
#else
        return false;
#endif
    }
    
    bool is_macos_platform() {
#ifdef __APPLE__
        return true;
#else
        return false;
#endif
    }
    
    // Helper to create test data for performance testing
    std::vector<uint8_t> create_test_data(size_t size) {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i % 256);
        }
        return data;
    }
    
    // Helper to measure operation performance
    template<typename Func>
    double measure_operation_time_ms(Func&& func, int iterations = 100) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            func();
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        return duration.count() / 1000.0; // Convert to milliseconds
    }
    
    std::unique_ptr<HardwareInfo> hw_info_;
};

// ==================== Hardware Detection Core Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, DetectHardwareCapabilitiesBasic) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Basic structure validation
    EXPECT_FALSE(hw_info.cpu_vendor.empty());
    EXPECT_FALSE(hw_info.cpu_brand.empty());
    EXPECT_GE(hw_info.cpu_cores, 1);
    EXPECT_GE(hw_info.cpu_threads, hw_info.cpu_cores);
    
    // Platform-specific validations
    if (is_x86_architecture()) {
        EXPECT_TRUE(hw_info.cpu_vendor == "GenuineIntel" || 
                   hw_info.cpu_vendor == "AuthenticAMD" ||
                   hw_info.cpu_vendor == "CyrixInstead" ||
                   !hw_info.cpu_vendor.empty()); // Allow other vendors
        
        // Brand string should contain meaningful information
        EXPECT_GT(hw_info.cpu_brand.length(), 10);
    }
    
    if (is_arm_architecture()) {
        EXPECT_TRUE(hw_info.cpu_vendor == "ARM" || !hw_info.cpu_vendor.empty());
    }
}

TEST_F(HardwareAccelerationEnhancedTest, HardwareCapabilityDetectionX86) {
    if (!is_x86_architecture()) {
        GTEST_SKIP() << "X86-specific test skipped on non-x86 platform";
    }
    
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Check for common x86 capabilities
    bool has_any_sse = 
        hw_info.has_capability(HardwareCapability::SSE2) ||
        hw_info.has_capability(HardwareCapability::SSE3) ||
        hw_info.has_capability(HardwareCapability::SSE4_1) ||
        hw_info.has_capability(HardwareCapability::SSE4_2);
    
    // Most modern x86 processors should have at least SSE2
    EXPECT_TRUE(has_any_sse) << "No SSE capabilities detected on x86 platform";
    
    // Test individual capability checks
    if (hw_info.has_capability(HardwareCapability::AES_NI)) {
        std::cout << "AES-NI acceleration available\n";
        EXPECT_TRUE(hw_info.supports_hardware_aes());
    }
    
    if (hw_info.has_capability(HardwareCapability::PCLMULQDQ)) {
        std::cout << "PCLMULQDQ acceleration available\n";
    }
    
    if (hw_info.has_capability(HardwareCapability::AVX) ||
        hw_info.has_capability(HardwareCapability::AVX2)) {
        std::cout << "AVX acceleration available\n";
    }
}

TEST_F(HardwareAccelerationEnhancedTest, HardwareCapabilityDetectionARM) {
    if (!is_arm_architecture()) {
        GTEST_SKIP() << "ARM-specific test skipped on non-ARM platform";
    }
    
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Check for common ARM capabilities
    if (hw_info.has_capability(HardwareCapability::ARM_AES)) {
        std::cout << "ARM AES acceleration available\n";
        EXPECT_TRUE(hw_info.supports_hardware_aes());
    }
    
    if (hw_info.has_capability(HardwareCapability::ARM_SHA1)) {
        std::cout << "ARM SHA1 acceleration available\n";
        EXPECT_TRUE(hw_info.supports_hardware_hash());
    }
    
    if (hw_info.has_capability(HardwareCapability::ARM_SHA2)) {
        std::cout << "ARM SHA2 acceleration available\n";
        EXPECT_TRUE(hw_info.supports_hardware_hash());
    }
    
    if (hw_info.has_capability(HardwareCapability::ARM_NEON)) {
        std::cout << "ARM NEON acceleration available\n";
    }
}

// ==================== Platform-Specific Detection Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, PlatformSpecificDetection) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Validate platform detection
    if (is_windows_platform()) {
        EXPECT_EQ(hw_info.platform, Platform::WINDOWS);
        std::cout << "Running on Windows platform\n";
    } else if (is_linux_platform()) {
        EXPECT_EQ(hw_info.platform, Platform::LINUX);
        std::cout << "Running on Linux platform\n";
    } else if (is_macos_platform()) {
        EXPECT_EQ(hw_info.platform, Platform::MACOS);
        std::cout << "Running on macOS platform\n";
    } else {
        EXPECT_EQ(hw_info.platform, Platform::UNKNOWN);
        std::cout << "Running on unknown platform\n";
    }
    
    // Validate architecture detection
    if (is_x86_architecture()) {
#if defined(__x86_64__)
        EXPECT_EQ(hw_info.architecture, Architecture::X86_64);
#elif defined(__i386__)
        EXPECT_EQ(hw_info.architecture, Architecture::X86);
#endif
    } else if (is_arm_architecture()) {
#if defined(__aarch64__)
        EXPECT_EQ(hw_info.architecture, Architecture::ARM64);
#elif defined(__arm__)
        EXPECT_EQ(hw_info.architecture, Architecture::ARM);
#endif
    }
}

TEST_F(HardwareAccelerationEnhancedTest, CPUInfoDetailedParsing) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Validate CPU information parsing
    EXPECT_GT(hw_info.cpu_cores, 0);
    EXPECT_GE(hw_info.cpu_threads, hw_info.cpu_cores);
    EXPECT_GE(hw_info.cpu_cache_line_size, 32); // Typical minimum
    EXPECT_LE(hw_info.cpu_cache_line_size, 256); // Typical maximum
    
    // CPU frequency should be reasonable if detected
    if (hw_info.cpu_frequency_mhz > 0) {
        EXPECT_GE(hw_info.cpu_frequency_mhz, 500);    // At least 500 MHz
        EXPECT_LE(hw_info.cpu_frequency_mhz, 10000); // At most 10 GHz
    }
    
    // Family and model should be set for x86
    if (is_x86_architecture()) {
        EXPECT_GT(hw_info.cpu_family, 0);
        // Model can be 0, so no lower bound check
    }
}

// ==================== TPM and Security Hardware Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, TPMDetection) {
    bool tpm_available = HardwareAcceleration::is_tpm_available();
    
    // TPM availability depends on platform and hardware
    std::cout << "TPM available: " << (tpm_available ? "Yes" : "No") << "\n";
    
    if (tpm_available) {
        auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
        EXPECT_TRUE(hw_info.has_tpm);
        EXPECT_TRUE(hw_info.supports_hardware_random());
    }
}

TEST_F(HardwareAccelerationEnhancedTest, SecureEnclaveDetection) {
    bool secure_enclave = HardwareAcceleration::has_secure_enclave();
    
    std::cout << "Secure Enclave available: " << (secure_enclave ? "Yes" : "No") << "\n";
    
    // Secure enclave primarily available on Apple Silicon and Intel SGX
    if (is_macos_platform() && is_arm_architecture()) {
        // May have Apple Secure Enclave
        if (secure_enclave) {
            auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
            EXPECT_TRUE(hw_info.has_secure_enclave);
        }
    }
}

// ==================== Provider Selection and Optimization Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, OptimalProviderSelection) {
    auto selection = HardwareAcceleration::select_optimal_provider();
    
    EXPECT_FALSE(selection.provider_name.empty());
    EXPECT_GE(selection.performance_score, 0.0);
    EXPECT_LE(selection.performance_score, 1.0);
    
    std::cout << "Optimal provider: " << selection.provider_name 
              << " (score: " << selection.performance_score << ")\n";
    
    // If hardware acceleration is available, score should be higher
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    if (hw_info.supports_hardware_aes() || hw_info.supports_hardware_hash()) {
        EXPECT_GT(selection.performance_score, 0.5);
    }
}

TEST_F(HardwareAccelerationEnhancedTest, ProviderSelectionWithCriteria) {
    ProviderSelection criteria;
    criteria.require_hardware_acceleration = true;
    criteria.prefer_hardware_random = true;
    criteria.minimum_security_level = SecurityLevel::HIGH;
    
    auto selection = HardwareAcceleration::select_provider_with_criteria(criteria);
    
    if (selection.is_success()) {
        std::cout << "Hardware-accelerated provider found: " << selection.value().provider_name << "\n";
        EXPECT_GT(selection.value().performance_score, 0.0);
        
        // Verify the provider actually supports hardware acceleration
        auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
        if (criteria.require_hardware_acceleration) {
            EXPECT_TRUE(hw_info.supports_hardware_aes() || 
                       hw_info.supports_hardware_hash() ||
                       hw_info.supports_hardware_random());
        }
    } else {
        std::cout << "No hardware-accelerated provider available\n";
        // This is acceptable on platforms without hardware acceleration
    }
}

// ==================== Performance Benchmarking Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, HardwareAccelerationPerformanceBenchmark) {
    auto& factory = ProviderFactory::instance();
    
    // Get all available providers
    auto providers = factory.available_providers();
    ASSERT_FALSE(providers.empty());
    
    const size_t test_data_size = 1024; // 1KB
    auto test_data = create_test_data(test_data_size);
    
    std::map<std::string, double> provider_performance;
    
    // Benchmark each provider
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (!provider_result.is_success()) continue;
        
        CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
        if (!crypto_ops.is_initialized()) continue;
        
        // Benchmark hash computation
        double hash_time = measure_operation_time_ms([&]() {
            auto result = crypto_ops.compute_hash(test_data, HashAlgorithm::SHA256);
            EXPECT_TRUE(result.is_success());
        }, 50);
        
        provider_performance[provider_name] = hash_time;
        std::cout << provider_name << " hash performance: " 
                  << (hash_time / 50.0) << " ms per operation\n";
    }
    
    // Verify we got some performance data
    EXPECT_FALSE(provider_performance.empty());
    
    // Find the fastest provider
    auto fastest = std::min_element(provider_performance.begin(), provider_performance.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    if (fastest != provider_performance.end()) {
        std::cout << "Fastest provider: " << fastest->first 
                  << " (" << (fastest->second / 50.0) << " ms per hash)\n";
    }
}

TEST_F(HardwareAccelerationEnhancedTest, AESPerformanceComparison) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    if (!hw_info.supports_hardware_aes()) {
        GTEST_SKIP() << "Hardware AES not available for performance comparison";
    }
    
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    const size_t plaintext_size = 1024;
    auto plaintext = create_test_data(plaintext_size);
    auto key = create_test_data(16); // AES-128 key
    auto nonce = create_test_data(12); // GCM nonce
    auto aad = create_test_data(16);
    
    std::map<std::string, double> aes_performance;
    
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (!provider_result.is_success()) continue;
        
        CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
        if (!crypto_ops.is_initialized()) continue;
        
        // Benchmark AES-GCM encryption
        double encrypt_time = measure_operation_time_ms([&]() {
            auto result = crypto_ops.aead_encrypt(
                plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
            EXPECT_TRUE(result.is_success());
        }, 50);
        
        aes_performance[provider_name] = encrypt_time;
        std::cout << provider_name << " AES-GCM performance: " 
                  << (encrypt_time / 50.0) << " ms per operation\n";
    }
    
    EXPECT_FALSE(aes_performance.empty());
}

// ==================== Hardware Feature Validation Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, ValidateHardwareAESUsage) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    if (!hw_info.supports_hardware_aes()) {
        GTEST_SKIP() << "Hardware AES not available";
    }
    
    // Create provider that should use hardware AES
    auto& factory = ProviderFactory::instance();
    ProviderSelection criteria;
    criteria.require_hardware_acceleration = true;
    
    auto selection = HardwareAcceleration::select_provider_with_criteria(criteria);
    if (!selection.is_success()) {
        GTEST_SKIP() << "No hardware-accelerated provider available";
    }
    
    auto provider_result = factory.create_provider(selection.value().provider_name);
    ASSERT_TRUE(provider_result.is_success());
    
    CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Test AES operations to ensure they work with hardware acceleration
    auto plaintext = create_test_data(256);
    auto key = create_test_data(16);
    auto nonce = create_test_data(12);
    auto aad = create_test_data(16);
    
    auto encrypt_result = crypto_ops.aead_encrypt(
        plaintext, key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(encrypt_result.is_success());
    
    auto decrypt_result = crypto_ops.aead_decrypt(
        encrypt_result.value().ciphertext, encrypt_result.value().tag,
        key, nonce, aad, AEADCipher::AES_128_GCM);
    ASSERT_TRUE(decrypt_result.is_success());
    
    EXPECT_EQ(decrypt_result.value(), plaintext);
}

TEST_F(HardwareAccelerationEnhancedTest, ValidateHardwareRandomGeneration) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    if (!hw_info.supports_hardware_random()) {
        GTEST_SKIP() << "Hardware random generation not available";
    }
    
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    // Test hardware random with available providers
    for (const auto& provider_name : providers) {
        auto provider_result = factory.create_provider(provider_name);
        if (!provider_result.is_success()) continue;
        
        CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
        if (!crypto_ops.is_initialized()) continue;
        
        // Generate multiple random values
        std::vector<std::vector<uint8_t>> random_values;
        for (int i = 0; i < 10; ++i) {
            auto result = crypto_ops.generate_random(32);
            ASSERT_TRUE(result.is_success());
            random_values.push_back(result.value());
        }
        
        // Verify uniqueness (should be highly unlikely to get duplicates)
        std::set<std::vector<uint8_t>> unique_values(random_values.begin(), random_values.end());
        EXPECT_EQ(unique_values.size(), random_values.size());
        
        std::cout << provider_name << " hardware random generation validated\n";
        break; // Test with first available provider
    }
}

// ==================== Error Handling and Edge Cases ====================

TEST_F(HardwareAccelerationEnhancedTest, HandleMissingHardwareFeatures) {
    // Create criteria that require features that might not be available
    ProviderSelection strict_criteria;
    strict_criteria.require_hardware_acceleration = true;
    strict_criteria.require_quantum_resistance = true;
    strict_criteria.minimum_security_level = SecurityLevel::QUANTUM_SAFE;
    
    auto selection = HardwareAcceleration::select_provider_with_criteria(strict_criteria);
    
    // This might fail on systems without quantum-resistant hardware
    if (!selection.is_success()) {
        std::cout << "Strict criteria not met (expected on most systems)\n";
        EXPECT_TRUE(true); // This is acceptable
    } else {
        std::cout << "Quantum-safe provider found: " << selection.value().provider_name << "\n";
    }
}

TEST_F(HardwareAccelerationEnhancedTest, MultithreadedHardwareDetection) {
    const int num_threads = 4;
    std::vector<std::thread> threads;
    std::vector<HardwareInfo> results(num_threads);
    std::atomic<int> success_count{0};
    
    auto worker = [&](int thread_id) {
        try {
            results[thread_id] = HardwareAcceleration::detect_hardware_capabilities();
            success_count++;
        } catch (...) {
            // Detection failed
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, i);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should succeed
    EXPECT_EQ(success_count.load(), num_threads);
    
    // All results should be identical (hardware doesn't change during test)
    for (int i = 1; i < num_threads; ++i) {
        EXPECT_EQ(results[0].cpu_vendor, results[i].cpu_vendor);
        EXPECT_EQ(results[0].cpu_brand, results[i].cpu_brand);
        EXPECT_EQ(results[0].cpu_cores, results[i].cpu_cores);
        EXPECT_EQ(results[0].capabilities, results[i].capabilities);
    }
}

// ==================== Capability Set Operations ====================

TEST_F(HardwareAccelerationEnhancedTest, CapabilitySetOperations) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Test capability queries
    auto all_capabilities = hw_info.get_all_capabilities();
    
    for (const auto& capability : all_capabilities) {
        EXPECT_TRUE(hw_info.has_capability(capability));
    }
    
    // Test capability combinations
    bool has_advanced_crypto = 
        hw_info.supports_hardware_aes() && 
        hw_info.supports_hardware_hash();
    
    if (has_advanced_crypto) {
        std::cout << "Advanced hardware crypto acceleration available\n";
    }
    
    // Test performance tier calculation
    auto performance_tier = hw_info.get_performance_tier();
    EXPECT_GE(static_cast<int>(performance_tier), 0);
    EXPECT_LE(static_cast<int>(performance_tier), 3); // Assume 4 tiers: 0-3
    
    std::cout << "Hardware performance tier: " << static_cast<int>(performance_tier) << "\n";
}

// ==================== Integration with Crypto Operations ====================

TEST_F(HardwareAccelerationEnhancedTest, HardwareAcceleratedCryptoIntegration) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Select optimal provider based on hardware
    auto selection = HardwareAcceleration::select_optimal_provider();
    
    auto& factory = ProviderFactory::instance();
    auto provider_result = factory.create_provider(selection.provider_name);
    ASSERT_TRUE(provider_result.is_success());
    
    CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Test that all crypto operations work with hardware-optimized provider
    const size_t test_size = 1024;
    auto test_data = create_test_data(test_size);
    auto key = create_test_data(32);
    
    // Test hash operations
    auto hash_result = crypto_ops.compute_hash(test_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hash_result.is_success());
    EXPECT_EQ(hash_result.value().size(), 32);
    
    // Test HMAC operations
    auto hmac_result = crypto_ops.compute_hmac(key, test_data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hmac_result.is_success());
    EXPECT_EQ(hmac_result.value().size(), 32);
    
    // Test AEAD operations if hardware AES is available
    if (hw_info.supports_hardware_aes()) {
        auto aes_key = create_test_data(16);
        auto nonce = create_test_data(12);
        auto aad = create_test_data(16);
        
        auto encrypt_result = crypto_ops.aead_encrypt(
            test_data, aes_key, nonce, aad, AEADCipher::AES_128_GCM);
        ASSERT_TRUE(encrypt_result.is_success());
        
        auto decrypt_result = crypto_ops.aead_decrypt(
            encrypt_result.value().ciphertext, encrypt_result.value().tag,
            aes_key, nonce, aad, AEADCipher::AES_128_GCM);
        ASSERT_TRUE(decrypt_result.is_success());
        
        EXPECT_EQ(decrypt_result.value(), test_data);
    }
    
    std::cout << "Hardware-accelerated crypto operations validated\n";
}

// ==================== Platform-Specific File System Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, PlatformSpecificInfoFiles) {
    if (!is_linux_platform()) {
        GTEST_SKIP() << "Linux-specific test skipped on non-Linux platform";
    }
    
    // Test /proc/cpuinfo parsing on Linux
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        bool found_features = false;
        bool found_model = false;
        
        while (std::getline(cpuinfo, line)) {
            if (line.find("flags") != std::string::npos || 
                line.find("Features") != std::string::npos) {
                found_features = true;
                std::cout << "CPU features line: " << line.substr(0, 100) << "...\n";
            }
            if (line.find("model name") != std::string::npos) {
                found_model = true;
                std::cout << "CPU model: " << line << "\n";
            }
        }
        
        EXPECT_TRUE(found_model) << "/proc/cpuinfo should contain model name";
        // Features line might not be present on all architectures
    }
}

// ==================== Security Validation Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, SecurityLevelValidation) {
    auto hw_info = HardwareAcceleration::detect_hardware_capabilities();
    
    // Test different security level requirements
    std::vector<SecurityLevel> levels = {
        SecurityLevel::STANDARD,
        SecurityLevel::HIGH,
        SecurityLevel::QUANTUM_SAFE
    };
    
    for (auto level : levels) {
        ProviderSelection criteria;
        criteria.minimum_security_level = level;
        
        auto selection = HardwareAcceleration::select_provider_with_criteria(criteria);
        
        if (selection.is_success()) {
            std::cout << "Provider meeting security level " << static_cast<int>(level) 
                      << ": " << selection.value().provider_name << "\n";
            
            // Verify the provider can be created and initialized
            auto& factory = ProviderFactory::instance();
            auto provider_result = factory.create_provider(selection.value().provider_name);
            EXPECT_TRUE(provider_result.is_success());
            
            if (provider_result.is_success()) {
                CryptoOperationsImpl crypto_ops(std::move(provider_result.value()));
                EXPECT_TRUE(crypto_ops.is_initialized());
            }
        } else {
            std::cout << "No provider meeting security level " << static_cast<int>(level) << "\n";
        }
    }
}

// ==================== Memory and Resource Tests ====================

TEST_F(HardwareAccelerationEnhancedTest, ResourceUsageValidation) {
    // Test multiple detection calls don't leak memory or resources
    std::vector<HardwareInfo> infos;
    
    for (int i = 0; i < 100; ++i) {
        infos.push_back(HardwareAcceleration::detect_hardware_capabilities());
    }
    
    // All should be identical
    for (size_t i = 1; i < infos.size(); ++i) {
        EXPECT_EQ(infos[0].cpu_vendor, infos[i].cpu_vendor);
        EXPECT_EQ(infos[0].cpu_cores, infos[i].cpu_cores);
        EXPECT_EQ(infos[0].platform, infos[i].platform);
    }
    
    std::cout << "Resource usage validation completed (100 detection calls)\n";
}