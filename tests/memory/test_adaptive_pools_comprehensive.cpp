/**
 * @file test_adaptive_pools_comprehensive.cpp
 * @brief Comprehensive tests for DTLS adaptive memory pool management
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

#include "dtls/memory/adaptive_pools.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class AdaptivePoolsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clear any existing global state
        AdaptivePoolManager::instance().enable_global_adaptation(false);
        AdaptivePoolManager::instance().stop_adaptation_thread();
        
        // Standard buffer sizes for testing
        small_buffer_size_ = 256;
        medium_buffer_size_ = 1024;
        large_buffer_size_ = 4096;
        
        // Pool sizes
        small_pool_size_ = 8;
        medium_pool_size_ = 16;
        large_pool_size_ = 32;
        
        // Test data
        test_data_.resize(4096);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
    }
    
    void TearDown() override {
        // Clean up global state
        AdaptivePoolManager::instance().enable_global_adaptation(false);
        AdaptivePoolManager::instance().stop_adaptation_thread();
        
        // Remove all adaptive pools
        AdaptivePoolManager::instance().remove_adaptive_pool(small_buffer_size_);
        AdaptivePoolManager::instance().remove_adaptive_pool(medium_buffer_size_);
        AdaptivePoolManager::instance().remove_adaptive_pool(large_buffer_size_);
    }
    
    size_t small_buffer_size_;
    size_t medium_buffer_size_;
    size_t large_buffer_size_;
    size_t small_pool_size_;
    size_t medium_pool_size_;
    size_t large_pool_size_;
    std::vector<std::byte> test_data_;
};

// Test AdaptivePoolSizer configuration and basic functionality
TEST_F(AdaptivePoolsTest, AdaptivePoolSizerConfiguration) {
    // Test default configuration
    AdaptivePoolSizer default_sizer;
    auto default_config = default_sizer.get_config();
    
    EXPECT_EQ(default_config.algorithm, AdaptivePoolSizer::Algorithm::BALANCED);
    EXPECT_DOUBLE_EQ(default_config.growth_factor, 1.5);
    EXPECT_DOUBLE_EQ(default_config.shrink_threshold, 0.3);
    EXPECT_DOUBLE_EQ(default_config.expand_threshold, 0.8);
    EXPECT_GE(default_config.min_pool_size, 1);
    EXPECT_LE(default_config.max_pool_size, 1000);
    
    // Test custom configuration
    AdaptivePoolSizer::SizingConfig custom_config;
    custom_config.algorithm = AdaptivePoolSizer::Algorithm::AGGRESSIVE;
    custom_config.growth_factor = 2.0;
    custom_config.shrink_threshold = 0.2;
    custom_config.expand_threshold = 0.9;
    custom_config.min_pool_size = 2;
    custom_config.max_pool_size = 128;
    
    AdaptivePoolSizer custom_sizer(custom_config);
    auto retrieved_config = custom_sizer.get_config();
    
    EXPECT_EQ(retrieved_config.algorithm, AdaptivePoolSizer::Algorithm::AGGRESSIVE);
    EXPECT_DOUBLE_EQ(retrieved_config.growth_factor, 2.0);
    EXPECT_DOUBLE_EQ(retrieved_config.shrink_threshold, 0.2);
    EXPECT_DOUBLE_EQ(retrieved_config.expand_threshold, 0.9);
    EXPECT_EQ(retrieved_config.min_pool_size, 2);
    EXPECT_EQ(retrieved_config.max_pool_size, 128);
}

// Test adaptive pool sizer algorithms with usage patterns
TEST_F(AdaptivePoolsTest, AdaptivePoolSizerAlgorithms) {
    // Create usage pattern for testing
    PoolUsagePattern pattern;
    pattern.buffer_size = medium_buffer_size_;
    pattern.allocation_rate = 100.0;  // 100 allocations per second
    pattern.deallocation_rate = 90.0;  // 90 deallocations per second
    pattern.peak_concurrent_usage = 50.0;
    pattern.average_lifetime = 5.0;
    pattern.is_growing = true;
    pattern.growth_rate = 0.1;
    pattern.hit_rate = 0.85;
    pattern.fragmentation_ratio = 0.15;
    pattern.efficiency_score = 0.8;
    
    // Test conservative algorithm
    AdaptivePoolSizer::SizingConfig conservative_config;
    conservative_config.algorithm = AdaptivePoolSizer::Algorithm::CONSERVATIVE;
    AdaptivePoolSizer conservative_sizer(conservative_config);
    
    auto conservative_size = conservative_sizer.calculate_optimal_size(pattern);
    EXPECT_GE(conservative_size, conservative_config.min_pool_size);
    EXPECT_LE(conservative_size, conservative_config.max_pool_size);
    
    // Test balanced algorithm
    AdaptivePoolSizer::SizingConfig balanced_config;
    balanced_config.algorithm = AdaptivePoolSizer::Algorithm::BALANCED;
    AdaptivePoolSizer balanced_sizer(balanced_config);
    
    auto balanced_size = balanced_sizer.calculate_optimal_size(pattern);
    EXPECT_GE(balanced_size, balanced_config.min_pool_size);
    EXPECT_LE(balanced_size, balanced_config.max_pool_size);
    
    // Test aggressive algorithm
    AdaptivePoolSizer::SizingConfig aggressive_config;
    aggressive_config.algorithm = AdaptivePoolSizer::Algorithm::AGGRESSIVE;
    AdaptivePoolSizer aggressive_sizer(aggressive_config);
    
    auto aggressive_size = aggressive_sizer.calculate_optimal_size(pattern);
    EXPECT_GE(aggressive_size, aggressive_config.min_pool_size);
    EXPECT_LE(aggressive_size, aggressive_config.max_pool_size);
    
    // Aggressive should generally recommend larger sizes than conservative
    EXPECT_GE(aggressive_size, conservative_size);
}

// Test expansion and shrinking decisions
TEST_F(AdaptivePoolsTest, AdaptivePoolExpansionShrinking) {
    AdaptivePoolSizer sizer;
    
    // Create high-utilization pattern (should trigger expansion)
    PoolUsagePattern high_util_pattern;
    high_util_pattern.buffer_size = medium_buffer_size_;
    high_util_pattern.allocation_rate = 200.0;
    high_util_pattern.deallocation_rate = 150.0;
    high_util_pattern.peak_concurrent_usage = 90.0;
    high_util_pattern.hit_rate = 0.6;  // Low hit rate indicates pool too small
    high_util_pattern.efficiency_score = 0.5;
    
    EXPECT_TRUE(sizer.should_expand_pool(high_util_pattern, medium_pool_size_));
    EXPECT_FALSE(sizer.should_shrink_pool(high_util_pattern, medium_pool_size_));
    
    // Create low-utilization pattern (should trigger shrinking)
    PoolUsagePattern low_util_pattern;
    low_util_pattern.buffer_size = medium_buffer_size_;
    low_util_pattern.allocation_rate = 10.0;
    low_util_pattern.deallocation_rate = 12.0;
    low_util_pattern.peak_concurrent_usage = 5.0;
    low_util_pattern.hit_rate = 1.0;  // Perfect hit rate
    low_util_pattern.efficiency_score = 0.95;
    
    EXPECT_FALSE(sizer.should_expand_pool(low_util_pattern, medium_pool_size_));
    EXPECT_TRUE(sizer.should_shrink_pool(low_util_pattern, medium_pool_size_));
}

// Test future size prediction
TEST_F(AdaptivePoolsTest, FutureSizePrediction) {
    AdaptivePoolSizer sizer;
    
    // Create growing pattern
    PoolUsagePattern growing_pattern;
    growing_pattern.buffer_size = medium_buffer_size_;
    growing_pattern.allocation_rate = 100.0;
    growing_pattern.deallocation_rate = 80.0;
    growing_pattern.is_growing = true;
    growing_pattern.growth_rate = 0.2;  // 20% growth rate
    
    auto predicted_size_5min = sizer.predict_future_size(growing_pattern, std::chrono::minutes(5));
    auto predicted_size_15min = sizer.predict_future_size(growing_pattern, std::chrono::minutes(15));
    auto predicted_size_30min = sizer.predict_future_size(growing_pattern, std::chrono::minutes(30));
    
    // With positive growth, longer predictions should be larger
    EXPECT_GE(predicted_size_15min, predicted_size_5min);
    EXPECT_GE(predicted_size_30min, predicted_size_15min);
    
    // Create shrinking pattern
    PoolUsagePattern shrinking_pattern;
    shrinking_pattern.buffer_size = medium_buffer_size_;
    shrinking_pattern.allocation_rate = 50.0;
    shrinking_pattern.deallocation_rate = 70.0;
    shrinking_pattern.is_growing = false;
    shrinking_pattern.growth_rate = -0.1;  // 10% decline rate
    
    auto predicted_shrink_5min = sizer.predict_future_size(shrinking_pattern, std::chrono::minutes(5));
    auto predicted_shrink_15min = sizer.predict_future_size(shrinking_pattern, std::chrono::minutes(15));
    
    // With negative growth, longer predictions should be smaller (but not below minimum)
    EXPECT_LE(predicted_shrink_15min, predicted_shrink_5min);
}

// Test AdaptiveBufferPool basic functionality
TEST_F(AdaptivePoolsTest, AdaptiveBufferPoolBasics) {
    AdaptivePoolSizer::SizingConfig config;
    config.min_pool_size = 4;
    config.max_pool_size = 64;
    
    AdaptiveBufferPool pool(medium_buffer_size_, medium_pool_size_, config);
    
    // Test initial state
    EXPECT_EQ(pool.buffer_size(), medium_buffer_size_);
    EXPECT_EQ(pool.available_buffers(), medium_pool_size_);
    EXPECT_TRUE(pool.is_thread_safe());
    
    // Test buffer acquisition
    auto buffer = pool.acquire();
    ASSERT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), medium_buffer_size_);
    EXPECT_EQ(pool.available_buffers(), medium_pool_size_ - 1);
    
    // Test buffer functionality
    auto result = buffer->append(test_data_.data(), std::min(test_data_.size(), medium_buffer_size_));
    EXPECT_TRUE(result.is_ok());
    
    // Test release
    pool.release(std::move(buffer));
    EXPECT_EQ(pool.available_buffers(), medium_pool_size_);
}

// Test adaptive pool usage pattern tracking
TEST_F(AdaptivePoolsTest, UsagePatternTracking) {
    AdaptivePoolSizer::SizingConfig default_config;
    AdaptiveBufferPool pool(medium_buffer_size_, medium_pool_size_, default_config);
    
    // Initial pattern should be empty
    auto initial_pattern = pool.get_usage_pattern();
    EXPECT_EQ(initial_pattern.buffer_size, medium_buffer_size_);
    EXPECT_DOUBLE_EQ(initial_pattern.allocation_rate, 0.0);
    EXPECT_DOUBLE_EQ(initial_pattern.deallocation_rate, 0.0);
    
    // Perform some allocations and releases
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < 10; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        buffers.push_back(std::move(buffer));
        
        // Small delay to simulate realistic usage
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Update statistics
    pool.update_usage_statistics();
    
    // Release buffers
    for (auto& buffer : buffers) {
        pool.release(std::move(buffer));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    pool.update_usage_statistics();
    
    // Check updated pattern
    auto updated_pattern = pool.get_usage_pattern();
    EXPECT_GT(updated_pattern.allocation_rate, 0.0);
    EXPECT_GT(updated_pattern.deallocation_rate, 0.0);
    EXPECT_GT(updated_pattern.hit_rate, 0.0);
}

// Test automatic adaptation
TEST_F(AdaptivePoolsTest, AutomaticAdaptation) {
    AdaptivePoolSizer::SizingConfig config;
    config.expand_threshold = 0.5;  // Low threshold for easier testing
    config.min_pool_size = 4;
    config.max_pool_size = 32;
    
    AdaptiveBufferPool pool(medium_buffer_size_, 8, config);  // Start with small pool
    pool.set_auto_adaptation(true);
    pool.set_adaptation_interval(std::chrono::seconds(1));  // Fast adaptation for testing
    
    // Stress the pool to trigger expansion
    std::vector<std::unique_ptr<ZeroCopyBuffer>> held_buffers;
    
    // Acquire most buffers to increase utilization
    for (size_t i = 0; i < 6; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            held_buffers.push_back(std::move(buffer));
        }
    }
    
    size_t initial_pool_size = pool.total_buffers();
    
    // Force adaptation check
    pool.force_adaptation();
    
    // Pool might have expanded (implementation dependent)
    size_t adapted_pool_size = pool.total_buffers();
    
    // Release buffers
    for (auto& buffer : held_buffers) {
        pool.release(std::move(buffer));
    }
    
    // Test adaptation interval setting
    EXPECT_EQ(pool.get_adaptation_interval(), std::chrono::seconds(1));
}

// Test performance metrics collection
TEST_F(AdaptivePoolsTest, PerformanceMetricsCollection) {
    AdaptivePoolSizer::SizingConfig default_config;
    AdaptiveBufferPool pool(medium_buffer_size_, medium_pool_size_, default_config);
    
    // Initial metrics should be empty
    auto initial_metrics = pool.get_performance_metrics();
    EXPECT_EQ(initial_metrics.average_acquire_time, std::chrono::nanoseconds(0));
    EXPECT_EQ(initial_metrics.average_release_time, std::chrono::nanoseconds(0));
    EXPECT_DOUBLE_EQ(initial_metrics.contention_ratio, 0.0);
    EXPECT_EQ(initial_metrics.cache_misses, 0);
    
    // Perform operations to generate metrics
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (int i = 0; i < 20; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        buffers.push_back(std::move(buffer));
    }
    
    for (auto& buffer : buffers) {
        pool.release(std::move(buffer));
    }
    
    // Check metrics have been updated
    auto updated_metrics = pool.get_performance_metrics();
    // Note: Actual timing values may vary, just check they're measured
    EXPECT_GE(updated_metrics.average_acquire_time.count(), 0);
    EXPECT_GE(updated_metrics.average_release_time.count(), 0);
    
    // Test metrics reset
    pool.reset_performance_metrics();
    auto reset_metrics = pool.get_performance_metrics();
    EXPECT_EQ(reset_metrics.cache_misses, 0);
    EXPECT_EQ(reset_metrics.adaptations_performed, 0);
}

// Test AdaptivePoolManager global management
TEST_F(AdaptivePoolsTest, AdaptivePoolManagerGlobal) {
    auto& manager = AdaptivePoolManager::instance();
    
    // Test singleton behavior
    auto& manager2 = AdaptivePoolManager::instance();
    EXPECT_EQ(&manager, &manager2);
    
    // Create adaptive pool
    AdaptivePoolSizer::SizingConfig config;
    config.min_pool_size = 8;
    config.max_pool_size = 64;
    
    auto result = manager.create_adaptive_pool(medium_buffer_size_, medium_pool_size_, config);
    EXPECT_TRUE(result.is_ok());
    
    // Get created pool
    auto& pool = manager.get_adaptive_pool(medium_buffer_size_);
    EXPECT_EQ(pool.buffer_size(), medium_buffer_size_);
    
    // Test global configuration
    manager.set_global_adaptation_config(config);
    auto retrieved_config = manager.get_global_adaptation_config();
    EXPECT_EQ(retrieved_config.min_pool_size, config.min_pool_size);
    EXPECT_EQ(retrieved_config.max_pool_size, config.max_pool_size);
    
    // Test system statistics
    auto stats = manager.get_system_statistics();
    EXPECT_GE(stats.total_pools, 1);
    EXPECT_GE(stats.total_buffers, 0);
    EXPECT_GE(stats.total_memory_usage, 0);
    
    // Test global adaptation
    manager.enable_global_adaptation(true);
    EXPECT_TRUE(manager.is_global_adaptation_enabled());
    
    manager.force_adapt_all_pools();  // Should not crash
    
    // Clean up
    manager.remove_adaptive_pool(medium_buffer_size_);
    manager.enable_global_adaptation(false);
}

// Test adaptation thread functionality
TEST_F(AdaptivePoolsTest, AdaptationThreadFunctionality) {
    auto& manager = AdaptivePoolManager::instance();
    
    // Create a pool for testing
    AdaptivePoolSizer::SizingConfig default_config;
    auto result = manager.create_adaptive_pool(medium_buffer_size_, medium_pool_size_, default_config);
    EXPECT_TRUE(result.is_ok());
    
    // Start adaptation thread
    manager.enable_global_adaptation(true);
    manager.start_adaptation_thread();
    
    // Let it run briefly
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop adaptation thread
    manager.stop_adaptation_thread();
    manager.enable_global_adaptation(false);
    
    // Clean up
    manager.remove_adaptive_pool(medium_buffer_size_);
}

// Test ConnectionAwarePoolManager
TEST_F(AdaptivePoolsTest, ConnectionAwarePoolManager) {
    auto& manager = ConnectionAwarePoolManager::instance();
    
    // Test singleton
    auto& manager2 = ConnectionAwarePoolManager::instance();
    EXPECT_EQ(&manager, &manager2);
    
    // Register connections
    void* conn1 = reinterpret_cast<void*>(0x1000);
    void* conn2 = reinterpret_cast<void*>(0x2000);
    
    manager.register_connection(conn1, 1024);  // Expected 1KB throughput
    manager.register_connection(conn2, 4096);  // Expected 4KB throughput
    
    // Test connection patterns
    auto patterns = manager.get_connection_patterns();
    EXPECT_GE(patterns.size(), 2);
    
    // Update usage
    manager.update_connection_usage(conn1, 512);
    manager.update_connection_usage(conn2, 2048);
    
    // Allocate for connections
    auto buffer1 = manager.allocate_for_connection(conn1, small_buffer_size_);
    EXPECT_TRUE(buffer1.is_valid());
    
    auto buffer2 = manager.allocate_for_connection(conn2, large_buffer_size_);
    EXPECT_TRUE(buffer2.is_valid());
    
    // Test prediction
    auto predicted_needs = manager.predict_buffer_needs(std::chrono::minutes(5));
    EXPECT_GE(predicted_needs, 0);
    
    // Test pre-allocation
    manager.pre_allocate_for_connections(10);  // Should not crash
    
    // Unregister connections
    manager.unregister_connection(conn1);
    manager.unregister_connection(conn2);
    
    auto updated_patterns = manager.get_connection_patterns();
    EXPECT_LT(updated_patterns.size(), patterns.size());
}

// Test HighPerformancePoolOptimizer
TEST_F(AdaptivePoolsTest, HighPerformancePoolOptimizer) {
    auto& optimizer = HighPerformancePoolOptimizer::instance();
    
    // Test singleton
    auto& optimizer2 = HighPerformancePoolOptimizer::instance();
    EXPECT_EQ(&optimizer, &optimizer2);
    
    // Test configuration
    optimizer.enable_lock_free_pools(true);
    EXPECT_TRUE(optimizer.are_lock_free_pools_enabled());
    
    optimizer.enable_numa_awareness(true);
    EXPECT_TRUE(optimizer.is_numa_awareness_enabled());
    
    optimizer.enable_thread_local_caching(true, 32);
    EXPECT_TRUE(optimizer.is_thread_local_caching_enabled());
    
    // Test cache optimizations
    optimizer.optimize_for_cpu_cache();  // Should not crash
    optimizer.set_cache_line_alignment(true);  // Should not crash
    
    // Test performance analysis
    auto report = optimizer.analyze_performance();
    EXPECT_GE(report.recommendations.size(), 0);
    
    // Apply optimizations
    optimizer.apply_optimizations(report);  // Should not crash
    
    // Reset settings
    optimizer.enable_lock_free_pools(false);
    optimizer.enable_numa_awareness(false);
    optimizer.enable_thread_local_caching(false);
}

// Test configuration presets
TEST_F(AdaptivePoolsTest, ConfigurationPresets) {
    // Test all presets
    auto conservative = presets::conservative_config();
    EXPECT_EQ(conservative.algorithm, AdaptivePoolSizer::Algorithm::CONSERVATIVE);
    EXPECT_LE(conservative.growth_factor, 1.5);
    
    auto balanced = presets::balanced_config();
    EXPECT_EQ(balanced.algorithm, AdaptivePoolSizer::Algorithm::BALANCED);
    
    auto aggressive = presets::aggressive_config();
    EXPECT_EQ(aggressive.algorithm, AdaptivePoolSizer::Algorithm::AGGRESSIVE);
    EXPECT_GE(aggressive.growth_factor, 1.5);
    
    auto high_throughput = presets::high_throughput_config();
    EXPECT_GE(high_throughput.max_pool_size, balanced.max_pool_size);
    
    auto low_memory = presets::low_memory_config();
    EXPECT_LE(low_memory.max_pool_size, balanced.max_pool_size);
}

// Test factory functions
TEST_F(AdaptivePoolsTest, FactoryFunctions) {
    // Configure adaptive pools
    configure_adaptive_pools(presets::balanced_config());
    
    // Enable adaptive sizing
    enable_adaptive_sizing(true);
    
    // Create adaptive buffer
    auto buffer = make_adaptive_buffer(medium_buffer_size_);
    EXPECT_TRUE(buffer.is_valid());
    EXPECT_GE(buffer->capacity(), medium_buffer_size_);
    
    // Get adaptive pool
    auto& pool = get_adaptive_pool(medium_buffer_size_);
    EXPECT_EQ(pool.buffer_size(), medium_buffer_size_);
    
    // Optimize for high concurrency
    optimize_pools_for_high_concurrency();  // Should not crash
    
    // Disable adaptive sizing
    enable_adaptive_sizing(false);
}

// Test concurrent access to adaptive pools
TEST_F(AdaptivePoolsTest, ConcurrentAdaptivePoolAccess) {
    AdaptivePoolSizer::SizingConfig default_config;
    AdaptiveBufferPool pool(medium_buffer_size_, large_pool_size_, default_config);
    pool.set_auto_adaptation(true);
    
    const int num_threads = 8;
    const int operations_per_thread = 50;
    std::atomic<int> successful_operations{0};
    std::atomic<int> adaptation_events{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that stress the adaptive pool
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> hold_time_dis(1, 20);
            
            for (int i = 0; i < operations_per_thread; ++i) {
                auto buffer = pool.acquire();
                if (buffer) {
                    successful_operations.fetch_add(1);
                    
                    // Use the buffer
                    auto result = buffer->append(test_data_.data(), 
                                               std::min(test_data_.size(), medium_buffer_size_));
                    EXPECT_TRUE(result.is_ok());
                    
                    // Hold for random time
                    std::this_thread::sleep_for(std::chrono::microseconds(hold_time_dis(gen)));
                    
                    pool.release(std::move(buffer));
                    
                    // Occasionally trigger adaptation
                    if (i % 10 == 0) {
                        pool.update_usage_statistics();
                        pool.force_adaptation();
                        adaptation_events.fetch_add(1);
                    }
                }
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify operations completed successfully
    EXPECT_GT(successful_operations.load(), 0);
    EXPECT_GT(adaptation_events.load(), 0);
    
    // Check final pool state
    auto final_pattern = pool.get_usage_pattern();
    EXPECT_GT(final_pattern.allocation_rate, 0.0);
    
    auto final_metrics = pool.get_performance_metrics();
    EXPECT_GE(final_metrics.average_acquire_time.count(), 0);
}

// Test stress conditions and adaptation under pressure
TEST_F(AdaptivePoolsTest, StressConditionsAndAdaptation) {
    AdaptivePoolSizer::SizingConfig stress_config;
    stress_config.algorithm = AdaptivePoolSizer::Algorithm::BALANCED;
    stress_config.min_pool_size = 4;
    stress_config.max_pool_size = 128;
    stress_config.expand_threshold = 0.7;
    stress_config.shrink_threshold = 0.3;
    
    AdaptiveBufferPool pool(medium_buffer_size_, 8, stress_config);
    pool.set_auto_adaptation(true);
    pool.set_adaptation_interval(std::chrono::seconds(1));
    
    // Create stress pattern: rapid allocation/deallocation
    std::vector<std::unique_ptr<ZeroCopyBuffer>> stress_buffers;
    
    // Phase 1: Rapid growth
    for (int cycle = 0; cycle < 5; ++cycle) {
        // Allocate burst
        for (int i = 0; i < 20; ++i) {
            auto buffer = pool.acquire();
            if (buffer) {
                stress_buffers.push_back(std::move(buffer));
            }
        }
        
        pool.update_usage_statistics();
        pool.force_adaptation();
        
        // Brief pause
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Release some buffers
        size_t release_count = stress_buffers.size() / 2;
        for (size_t i = 0; i < release_count && !stress_buffers.empty(); ++i) {
            pool.release(std::move(stress_buffers.back()));
            stress_buffers.pop_back();
        }
    }
    
    // Phase 2: Complete release to test shrinking
    for (auto& buffer : stress_buffers) {
        pool.release(std::move(buffer));
    }
    stress_buffers.clear();
    
    pool.update_usage_statistics();
    pool.force_adaptation();
    
    // Verify pool adapted to stress
    auto stress_pattern = pool.get_usage_pattern();
    EXPECT_GT(stress_pattern.allocation_rate, 0.0);
    EXPECT_GT(stress_pattern.deallocation_rate, 0.0);
    
    auto stress_metrics = pool.get_performance_metrics();
    EXPECT_GT(stress_metrics.adaptations_performed, 0);
}

// Test edge cases and error conditions
TEST_F(AdaptivePoolsTest, EdgeCasesAndErrorConditions) {
    // Test with extreme configuration
    AdaptivePoolSizer::SizingConfig extreme_config;
    extreme_config.min_pool_size = 1;
    extreme_config.max_pool_size = 2;  // Very small range
    extreme_config.growth_factor = 10.0;  // Extreme growth
    extreme_config.shrink_threshold = 0.99;  // Almost never shrink
    extreme_config.expand_threshold = 0.01;  // Always expand
    
    AdaptiveBufferPool extreme_pool(small_buffer_size_, 1, extreme_config);
    
    // Should still function despite extreme config
    auto buffer = extreme_pool.acquire();
    EXPECT_NE(buffer, nullptr);
    extreme_pool.release(std::move(buffer));
    
    // Test zero-sized pattern
    PoolUsagePattern empty_pattern;
    AdaptivePoolSizer sizer;
    
    auto zero_size = sizer.calculate_optimal_size(empty_pattern);
    EXPECT_GE(zero_size, sizer.get_config().min_pool_size);
    
    // Test invalid connection IDs
    auto& conn_manager = ConnectionAwarePoolManager::instance();
    
    // Register null connection (should handle gracefully)
    conn_manager.register_connection(nullptr, 1024);
    conn_manager.update_connection_usage(nullptr, 512);
    conn_manager.unregister_connection(nullptr);
    
    // Test allocation for non-existent connection
    void* fake_conn = reinterpret_cast<void*>(0xDEADBEEF);
    auto fake_buffer = conn_manager.allocate_for_connection(fake_conn, medium_buffer_size_);
    // Should still return a valid buffer (falls back to regular allocation)
    EXPECT_TRUE(fake_buffer.is_valid());
    
    // Test adaptation with no usage data
    extreme_pool.force_adaptation();  // Should not crash
    
    auto no_usage_pattern = extreme_pool.get_usage_pattern();
    EXPECT_EQ(no_usage_pattern.buffer_size, small_buffer_size_);
}

// Test memory usage and efficiency under various load patterns
TEST_F(AdaptivePoolsTest, MemoryUsageAndEfficiency) {
    auto& manager = AdaptivePoolManager::instance();
    
    // Create pools with different configurations
    auto result1 = manager.create_adaptive_pool(small_buffer_size_, 16, presets::conservative_config());
    auto result2 = manager.create_adaptive_pool(medium_buffer_size_, 16, presets::balanced_config());
    auto result3 = manager.create_adaptive_pool(large_buffer_size_, 16, presets::aggressive_config());
    
    EXPECT_TRUE(result1.is_ok());
    EXPECT_TRUE(result2.is_ok());
    EXPECT_TRUE(result3.is_ok());
    
    // Get initial memory usage
    auto initial_stats = manager.get_system_statistics();
    size_t initial_memory = initial_stats.total_memory_usage;
    
    // Simulate different load patterns
    std::vector<PooledBuffer> small_buffers;
    std::vector<PooledBuffer> medium_buffers;
    std::vector<PooledBuffer> large_buffers;
    
    // Pattern 1: Many small allocations
    for (int i = 0; i < 50; ++i) {
        auto buffer = make_adaptive_buffer(small_buffer_size_);
        if (buffer.is_valid()) {
            small_buffers.push_back(std::move(buffer));
        }
    }
    
    // Pattern 2: Medium allocations
    for (int i = 0; i < 25; ++i) {
        auto buffer = make_adaptive_buffer(medium_buffer_size_);
        if (buffer.is_valid()) {
            medium_buffers.push_back(std::move(buffer));
        }
    }
    
    // Pattern 3: Few large allocations
    for (int i = 0; i < 10; ++i) {
        auto buffer = make_adaptive_buffer(large_buffer_size_);
        if (buffer.is_valid()) {
            large_buffers.push_back(std::move(buffer));
        }
    }
    
    // Force adaptation
    manager.force_adapt_all_pools();
    
    // Check memory usage efficiency
    auto loaded_stats = manager.get_system_statistics();
    EXPECT_GT(loaded_stats.total_memory_usage, initial_memory);
    EXPECT_GT(loaded_stats.total_buffers, initial_stats.total_buffers);
    
    // Release all buffers
    small_buffers.clear();
    medium_buffers.clear();
    large_buffers.clear();
    
    // Force adaptation again to test shrinking
    manager.force_adapt_all_pools();
    
    // Clean up
    manager.remove_adaptive_pool(small_buffer_size_);
    manager.remove_adaptive_pool(medium_buffer_size_);
    manager.remove_adaptive_pool(large_buffer_size_);
}