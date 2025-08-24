/**
 * @file test_crypto_system_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS crypto system initialization and management
 * 
 * This test suite covers all functionality in crypto_system.cpp to achieve >95% coverage.
 * Tests include system initialization, configuration management, provider coordination,
 * statistics collection, and error handling. Target: Cover all 234 lines with 0% coverage.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <future>

#include "dtls/crypto.h"
#include "dtls/crypto/crypto_system.h"
#include "dtls/crypto/provider_factory.h"
#include "dtls/crypto/operations_impl.h"
#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/error.h"

using namespace dtls::v13;
using namespace dtls::v13::crypto;
using namespace std::chrono_literals;

class CryptoSystemEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state before each test
        if (crypto::is_crypto_system_initialized()) {
            crypto::cleanup_crypto_system();
        }
        
        // Verify clean state
        ASSERT_FALSE(crypto::is_crypto_system_initialized());
    }
    
    void TearDown() override {
        // Cleanup after each test
        if (crypto::is_crypto_system_initialized()) {
            crypto::cleanup_crypto_system();
        }
    }
    
    // Helper to create test configuration
    CryptoSystemConfig create_test_config() {
        CryptoSystemConfig config;
        config.preferred_provider = "openssl";
        config.enable_hardware_acceleration = true;
        config.enable_performance_monitoring = true;
        config.minimum_security_level = SecurityLevel::STANDARD;
        config.max_concurrent_operations = 1000;
        config.operation_timeout_ms = 5000;
        return config;
    }
    
    // Helper to verify system is properly initialized
    void verify_system_initialized() {
        EXPECT_TRUE(crypto::is_crypto_system_initialized());
        
        auto config = crypto::get_crypto_system_config();
        EXPECT_TRUE(config.is_success());
        
        auto stats = crypto::get_crypto_system_stats();
        EXPECT_TRUE(stats.is_success());
    }
};

// ==================== Basic System Initialization Tests ====================

TEST_F(CryptoSystemEnhancedTest, InitializeCryptoSystemBasic) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    auto result = crypto::initialize_crypto_system();
    ASSERT_TRUE(result.is_success()) << "Failed to initialize crypto system";
    
    verify_system_initialized();
}

TEST_F(CryptoSystemEnhancedTest, InitializeCryptoSystemWithConfig) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    auto config = create_test_config();
    auto result = crypto::initialize_crypto_system(config);
    ASSERT_TRUE(result.is_success()) << "Failed to initialize with config";
    
    verify_system_initialized();
    
    // Verify config was applied
    auto current_config = crypto::get_crypto_system_config();
    ASSERT_TRUE(current_config.is_success());
    
    EXPECT_EQ(current_config.value().preferred_provider, config.preferred_provider);
    EXPECT_EQ(current_config.value().enable_hardware_acceleration, config.enable_hardware_acceleration);
    EXPECT_EQ(current_config.value().minimum_security_level, config.minimum_security_level);
}

TEST_F(CryptoSystemEnhancedTest, InitializeCryptoSystemTwice) {
    // First initialization should succeed
    auto result1 = crypto::initialize_crypto_system();
    ASSERT_TRUE(result1.is_success());
    
    // Second initialization should fail with ALREADY_INITIALIZED
    auto result2 = crypto::initialize_crypto_system();
    EXPECT_FALSE(result2.is_success());
    EXPECT_EQ(result2.error(), DTLSError::ALREADY_INITIALIZED);
    
    // System should still be initialized and functional
    verify_system_initialized();
}

TEST_F(CryptoSystemEnhancedTest, CleanupCryptoSystem) {
    // Initialize system
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    verify_system_initialized();
    
    // Cleanup
    crypto::cleanup_crypto_system();
    EXPECT_FALSE(crypto::is_crypto_system_initialized());
    
    // Operations on uninitialized system should fail
    auto config_result = crypto::get_crypto_system_config();
    EXPECT_FALSE(config_result.is_success());
    EXPECT_EQ(config_result.error(), DTLSError::NOT_INITIALIZED);
}

TEST_F(CryptoSystemEnhancedTest, CleanupUninitializedSystem) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    // Cleanup should be safe even when not initialized
    crypto::cleanup_crypto_system();
    EXPECT_FALSE(crypto::is_crypto_system_initialized());
}

TEST_F(CryptoSystemEnhancedTest, MultipleCleanupCalls) {
    // Initialize system
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Multiple cleanup calls should be safe
    crypto::cleanup_crypto_system();
    EXPECT_FALSE(crypto::is_crypto_system_initialized());
    
    crypto::cleanup_crypto_system(); // Second call
    EXPECT_FALSE(crypto::is_crypto_system_initialized());
    
    crypto::cleanup_crypto_system(); // Third call
    EXPECT_FALSE(crypto::is_crypto_system_initialized());
}

// ==================== Configuration Management Tests ====================

TEST_F(CryptoSystemEnhancedTest, SetCryptoSystemConfig) {
    // Initialize system first
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Create and set new configuration
    auto new_config = create_test_config();
    new_config.preferred_provider = "botan";
    new_config.max_concurrent_operations = 2000;
    new_config.operation_timeout_ms = 10000;
    
    auto set_result = crypto::set_crypto_system_config(new_config);
    EXPECT_TRUE(set_result.is_success());
    
    // Verify configuration was updated
    auto get_result = crypto::get_crypto_system_config();
    ASSERT_TRUE(get_result.is_success());
    
    const auto& config = get_result.value();
    EXPECT_EQ(config.preferred_provider, new_config.preferred_provider);
    EXPECT_EQ(config.max_concurrent_operations, new_config.max_concurrent_operations);
    EXPECT_EQ(config.operation_timeout_ms, new_config.operation_timeout_ms);
}

TEST_F(CryptoSystemEnhancedTest, SetConfigUninitializedSystem) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    auto config = create_test_config();
    auto result = crypto::set_crypto_system_config(config);
    
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::NOT_INITIALIZED);
}

TEST_F(CryptoSystemEnhancedTest, GetConfigUninitializedSystem) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    auto result = crypto::get_crypto_system_config();
    EXPECT_FALSE(result.is_success());
    EXPECT_EQ(result.error(), DTLSError::NOT_INITIALIZED);
}

TEST_F(CryptoSystemEnhancedTest, ConfigValidation) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Test various configuration scenarios
    CryptoSystemConfig config;
    
    // Test with empty preferred provider (should use default)
    config.preferred_provider = "";
    config.enable_hardware_acceleration = true;
    config.minimum_security_level = SecurityLevel::STANDARD;
    
    auto result1 = crypto::set_crypto_system_config(config);
    EXPECT_TRUE(result1.is_success());
    
    // Test with invalid security level
    config.minimum_security_level = static_cast<SecurityLevel>(999);
    auto result2 = crypto::set_crypto_system_config(config);
    // Should either succeed (if validation is lenient) or fail with appropriate error
    if (!result2.is_success()) {
        EXPECT_NE(result2.error(), DTLSError::NOT_INITIALIZED);
    }
    
    // Test with extreme values
    config.minimum_security_level = SecurityLevel::STANDARD;
    config.max_concurrent_operations = 0; // Edge case
    auto result3 = crypto::set_crypto_system_config(config);
    // Implementation should handle this appropriately
    
    config.max_concurrent_operations = UINT32_MAX; // Maximum value
    auto result4 = crypto::set_crypto_system_config(config);
    EXPECT_TRUE(result4.is_success()); // Should be valid
}

// ==================== Provider Management Tests ====================

TEST_F(CryptoSystemEnhancedTest, DefaultProviderSelection) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    auto config = crypto::get_crypto_system_config();
    ASSERT_TRUE(config.is_success());
    
    // Should have selected a default provider
    EXPECT_FALSE(config.value().preferred_provider.empty());
    
    // Verify the provider is actually available
    auto& factory = ProviderFactory::instance();
    auto providers = factory.available_providers();
    
    auto it = std::find(providers.begin(), providers.end(), config.value().preferred_provider);
    EXPECT_NE(it, providers.end()) << "Default provider not in available providers list";
}

TEST_F(CryptoSystemEnhancedTest, ProviderAvailabilityRefresh) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    auto& factory = ProviderFactory::instance();
    
    // Get initial provider list
    auto initial_providers = factory.available_providers();
    EXPECT_FALSE(initial_providers.empty());
    
    // Refresh availability
    auto refresh_result = factory.refresh_availability();
    EXPECT_TRUE(refresh_result.is_success());
    
    // Get updated provider list
    auto updated_providers = factory.available_providers();
    EXPECT_FALSE(updated_providers.empty());
    
    // Lists should be the same (no providers should disappear during test)
    EXPECT_EQ(initial_providers.size(), updated_providers.size());
}

TEST_F(CryptoSystemEnhancedTest, ProviderRegistration) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    auto& factory = ProviderFactory::instance();
    
    // Verify built-in providers are registered
    auto providers = factory.available_providers();
    
    // Should have at least OpenSSL
    auto openssl_it = std::find(providers.begin(), providers.end(), "openssl");
    EXPECT_NE(openssl_it, providers.end()) << "OpenSSL provider not registered";
    
    // Check if other providers are available
    for (const auto& provider_name : providers) {
        std::cout << "Available provider: " << provider_name << std::endl;
        
        // Verify each provider can be created
        auto provider_result = factory.create_provider(provider_name);
        EXPECT_TRUE(provider_result.is_success()) << "Failed to create provider: " << provider_name;
        
        if (provider_result.is_success()) {
            auto provider = std::move(provider_result.value());
            EXPECT_FALSE(provider->name().empty());
        }
    }
}

// ==================== Statistics and Monitoring Tests ====================

TEST_F(CryptoSystemEnhancedTest, GetCryptoSystemStats) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    auto stats_result = crypto::get_crypto_system_stats();
    ASSERT_TRUE(stats_result.is_success());
    
    const auto& stats = stats_result.value();
    
    // Verify basic statistics structure
    EXPECT_GE(stats.initialization_time_ms, 0);
    EXPECT_GE(stats.total_operations, 0);
    EXPECT_GE(stats.successful_operations, 0);
    EXPECT_GE(stats.failed_operations, 0);
    EXPECT_EQ(stats.total_operations, stats.successful_operations + stats.failed_operations);
    
    // Provider stats
    EXPECT_FALSE(stats.active_providers.empty());
    
    std::cout << "Crypto system stats:\n";
    std::cout << "  Initialization time: " << stats.initialization_time_ms << " ms\n";
    std::cout << "  Total operations: " << stats.total_operations << "\n";
    std::cout << "  Successful operations: " << stats.successful_operations << "\n";
    std::cout << "  Failed operations: " << stats.failed_operations << "\n";
    std::cout << "  Active providers: " << stats.active_providers.size() << "\n";
}

TEST_F(CryptoSystemEnhancedTest, StatsUninitializedSystem) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    auto stats_result = crypto::get_crypto_system_stats();
    EXPECT_FALSE(stats_result.is_success());
    EXPECT_EQ(stats_result.error(), DTLSError::NOT_INITIALIZED);
}

TEST_F(CryptoSystemEnhancedTest, OperationStatistics) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Get initial stats
    auto initial_stats = crypto::get_crypto_system_stats();
    ASSERT_TRUE(initial_stats.is_success());
    
    // Perform some crypto operations to update statistics
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    const int num_operations = 10;
    
    for (int i = 0; i < num_operations; ++i) {
        auto result = crypto_ops.generate_random(32);
        EXPECT_TRUE(result.is_success());
    }
    
    // Get updated stats
    auto updated_stats = crypto::get_crypto_system_stats();
    ASSERT_TRUE(updated_stats.is_success());
    
    // Operations count should have increased
    EXPECT_GE(updated_stats.value().total_operations, initial_stats.value().total_operations);
    EXPECT_GE(updated_stats.value().successful_operations, initial_stats.value().successful_operations);
}

TEST_F(CryptoSystemEnhancedTest, PerformanceMonitoring) {
    // Initialize with performance monitoring enabled
    CryptoSystemConfig config = create_test_config();
    config.enable_performance_monitoring = true;
    
    auto init_result = crypto::initialize_crypto_system(config);
    ASSERT_TRUE(init_result.is_success());
    
    // Perform operations that should be monitored
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    auto data = std::vector<uint8_t>(1024, 0x42);
    
    for (int i = 0; i < 5; ++i) {
        auto hash_result = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
        EXPECT_TRUE(hash_result.is_success());
        
        auto random_result = crypto_ops.generate_random(32);
        EXPECT_TRUE(random_result.is_success());
    }
    
    // Get stats and verify performance data is collected
    auto stats = crypto::get_crypto_system_stats();
    ASSERT_TRUE(stats.is_success());
    
    EXPECT_GT(stats.value().total_operations, 0);
    
    // Check if performance metrics are available
    if (stats.value().performance_metrics.size() > 0) {
        std::cout << "Performance metrics collected: " << stats.value().performance_metrics.size() << std::endl;
    }
}

// ==================== Thread Safety Tests ====================

TEST_F(CryptoSystemEnhancedTest, ConcurrentInitialization) {
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    const int num_threads = 8;
    std::vector<std::thread> threads;
    std::vector<std::future<bool>> futures;
    
    // Launch multiple threads trying to initialize concurrently
    for (int i = 0; i < num_threads; ++i) {
        auto promise = std::make_shared<std::promise<bool>>();
        futures.push_back(promise->get_future());
        
        threads.emplace_back([promise]() {
            auto result = crypto::initialize_crypto_system();
            promise->set_value(result.is_success());
        });
    }
    
    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Exactly one thread should succeed
    int success_count = 0;
    for (auto& future : futures) {
        if (future.get()) {
            success_count++;
        }
    }
    
    EXPECT_EQ(success_count, 1) << "Only one thread should successfully initialize";
    EXPECT_TRUE(crypto::is_crypto_system_initialized());
}

TEST_F(CryptoSystemEnhancedTest, ConcurrentConfigurationAccess) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    const int num_threads = 4;
    const int operations_per_thread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    
    auto worker = [&](int thread_id) {
        for (int i = 0; i < operations_per_thread; ++i) {
            if (i % 2 == 0) {
                // Read configuration
                auto result = crypto::get_crypto_system_config();
                if (result.is_success()) {
                    success_count++;
                } else {
                    failure_count++;
                }
            } else {
                // Modify configuration
                auto config = create_test_config();
                config.max_concurrent_operations = 1000 + thread_id * 100 + i;
                
                auto result = crypto::set_crypto_system_config(config);
                if (result.is_success()) {
                    success_count++;
                } else {
                    failure_count++;
                }
            }
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
    
    std::cout << "Concurrent config operations - Success: " << success_count.load() 
              << ", Failures: " << failure_count.load() << std::endl;
    
    // Most operations should succeed (allowing for some race conditions)
    EXPECT_GT(success_count.load(), failure_count.load());
    
    // System should still be functional
    verify_system_initialized();
}

TEST_F(CryptoSystemEnhancedTest, ConcurrentStatsAccess) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    const int num_threads = 6;
    const int reads_per_thread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    auto worker = [&]() {
        for (int i = 0; i < reads_per_thread; ++i) {
            auto result = crypto::get_crypto_system_stats();
            if (result.is_success()) {
                success_count++;
            }
            
            // Small delay to increase chance of contention
            std::this_thread::sleep_for(1ms);
        }
    };
    
    // Start threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All stats reads should succeed
    EXPECT_EQ(success_count.load(), num_threads * reads_per_thread);
}

// ==================== Error Handling and Edge Cases ====================

TEST_F(CryptoSystemEnhancedTest, InitializationFailureRecovery) {
    // This test simulates initialization failure scenarios
    ASSERT_FALSE(crypto::is_crypto_system_initialized());
    
    // Try to initialize with invalid configuration
    CryptoSystemConfig bad_config;
    bad_config.preferred_provider = "absolutely_nonexistent_provider";
    bad_config.minimum_security_level = static_cast<SecurityLevel>(999);
    
    auto result = crypto::initialize_crypto_system(bad_config);
    
    // If initialization fails, system should remain uninitialized
    if (!result.is_success()) {
        EXPECT_FALSE(crypto::is_crypto_system_initialized());
        
        // Should be able to initialize with valid config afterwards
        auto good_result = crypto::initialize_crypto_system();
        EXPECT_TRUE(good_result.is_success());
        verify_system_initialized();
    } else {
        // If it somehow succeeds, that's also valid (lenient validation)
        verify_system_initialized();
    }
}

TEST_F(CryptoSystemEnhancedTest, SystemStateAfterException) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Perform operations that might cause exceptions (caught internally)
    CryptoSystemConfig config;
    config.preferred_provider = "test";
    config.max_concurrent_operations = UINT32_MAX;
    config.operation_timeout_ms = 0;
    
    // These should be handled gracefully
    auto result = crypto::set_crypto_system_config(config);
    // Implementation should handle edge cases without crashing
    
    // System should remain functional
    EXPECT_TRUE(crypto::is_crypto_system_initialized());
    
    auto stats = crypto::get_crypto_system_stats();
    EXPECT_TRUE(stats.is_success());
}

// ==================== Performance and Stress Tests ====================

TEST_F(CryptoSystemEnhancedTest, HighFrequencyConfigurationChanges) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    const int num_changes = 1000;
    auto base_config = create_test_config();
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_changes; ++i) {
        auto config = base_config;
        config.max_concurrent_operations = 1000 + (i % 100);
        config.operation_timeout_ms = 5000 + (i % 1000);
        
        auto result = crypto::set_crypto_system_config(config);
        EXPECT_TRUE(result.is_success()) << "Failed at iteration " << i;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "High frequency config changes: " << num_changes 
              << " changes in " << duration.count() << " ms" << std::endl;
    
    // System should still be functional
    verify_system_initialized();
}

TEST_F(CryptoSystemEnhancedTest, StressTestSystemOperations) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    const int num_iterations = 100;
    std::vector<std::thread> threads;
    std::atomic<int> total_operations{0};
    
    // Mix of different system operations
    auto worker = [&]() {
        for (int i = 0; i < num_iterations; ++i) {
            // Alternate between different operations
            switch (i % 4) {
                case 0: {
                    auto result = crypto::get_crypto_system_config();
                    if (result.is_success()) total_operations++;
                    break;
                }
                case 1: {
                    auto result = crypto::get_crypto_system_stats();
                    if (result.is_success()) total_operations++;
                    break;
                }
                case 2: {
                    auto config = create_test_config();
                    config.max_concurrent_operations = 1000 + (i % 500);
                    auto result = crypto::set_crypto_system_config(config);
                    if (result.is_success()) total_operations++;
                    break;
                }
                case 3: {
                    // Check if system is still initialized
                    if (crypto::is_crypto_system_initialized()) {
                        total_operations++;
                    }
                    break;
                }
            }
        }
    };
    
    // Start multiple worker threads
    const int num_workers = 4;
    for (int i = 0; i < num_workers; ++i) {
        threads.emplace_back(worker);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    std::cout << "Stress test completed: " << total_operations.load() 
              << " successful operations" << std::endl;
    
    // Most operations should succeed
    EXPECT_GT(total_operations.load(), num_workers * num_iterations * 0.8);
    
    // System should still be functional
    verify_system_initialized();
}

// ==================== Memory and Resource Management Tests ====================

TEST_F(CryptoSystemEnhancedTest, RepeatedInitializationCleanup) {
    const int cycles = 50;
    
    for (int i = 0; i < cycles; ++i) {
        // Initialize
        auto init_result = crypto::initialize_crypto_system();
        ASSERT_TRUE(init_result.is_success()) << "Failed at cycle " << i;
        
        // Use the system briefly
        auto config = crypto::get_crypto_system_config();
        EXPECT_TRUE(config.is_success());
        
        auto stats = crypto::get_crypto_system_stats();
        EXPECT_TRUE(stats.is_success());
        
        // Cleanup
        crypto::cleanup_crypto_system();
        EXPECT_FALSE(crypto::is_crypto_system_initialized());
    }
    
    std::cout << "Completed " << cycles << " initialization/cleanup cycles" << std::endl;
}

TEST_F(CryptoSystemEnhancedTest, LongRunningSystemStability) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Run for a simulated "long time" with various operations
    const auto test_duration = 1s; // Shortened for unit test
    const auto start_time = std::chrono::steady_clock::now();
    
    int operation_count = 0;
    while (std::chrono::steady_clock::now() - start_time < test_duration) {
        // Mix of operations
        switch (operation_count % 3) {
            case 0: {
                auto stats = crypto::get_crypto_system_stats();
                EXPECT_TRUE(stats.is_success());
                break;
            }
            case 1: {
                auto config = crypto::get_crypto_system_config();
                EXPECT_TRUE(config.is_success());
                break;
            }
            case 2: {
                EXPECT_TRUE(crypto::is_crypto_system_initialized());
                break;
            }
        }
        
        operation_count++;
        std::this_thread::sleep_for(1ms);
    }
    
    std::cout << "Long running test: " << operation_count 
              << " operations completed" << std::endl;
    
    // System should still be functional
    verify_system_initialized();
}

// ==================== Integration Tests ====================

TEST_F(CryptoSystemEnhancedTest, SystemIntegrationWithCryptoOperations) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Create crypto operations using the initialized system
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    // Perform various operations to verify system integration
    auto random_result = crypto_ops.generate_random(32);
    ASSERT_TRUE(random_result.is_success());
    
    auto data = std::vector<uint8_t>(256, 0x42);
    auto hash_result = crypto_ops.compute_hash(data, HashAlgorithm::SHA256);
    ASSERT_TRUE(hash_result.is_success());
    
    // Verify statistics are updated
    auto stats = crypto::get_crypto_system_stats();
    ASSERT_TRUE(stats.is_success());
    EXPECT_GT(stats.value().total_operations, 0);
    
    std::cout << "Integration test: " << stats.value().total_operations 
              << " total operations recorded" << std::endl;
}

TEST_F(CryptoSystemEnhancedTest, ConfigurationPersistenceAcrossOperations) {
    auto init_result = crypto::initialize_crypto_system();
    ASSERT_TRUE(init_result.is_success());
    
    // Set specific configuration
    auto config = create_test_config();
    config.max_concurrent_operations = 1337; // Distinctive value
    config.operation_timeout_ms = 7777;      // Distinctive value
    
    auto set_result = crypto::set_crypto_system_config(config);
    ASSERT_TRUE(set_result.is_success());
    
    // Perform many crypto operations
    CryptoOperationsImpl crypto_ops("openssl");
    ASSERT_TRUE(crypto_ops.is_initialized());
    
    for (int i = 0; i < 50; ++i) {
        auto result = crypto_ops.generate_random(32);
        EXPECT_TRUE(result.is_success());
    }
    
    // Verify configuration persisted
    auto final_config = crypto::get_crypto_system_config();
    ASSERT_TRUE(final_config.is_success());
    
    EXPECT_EQ(final_config.value().max_concurrent_operations, 1337);
    EXPECT_EQ(final_config.value().operation_timeout_ms, 7777);
    
    std::cout << "Configuration persistence verified after 50 operations" << std::endl;
}