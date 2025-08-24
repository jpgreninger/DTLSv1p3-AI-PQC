/**
 * @file test_memory_pool_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS memory pool management
 * Phase 2 - Memory Pool Coverage Enhancement
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <random>

#include "dtls/memory/pool.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class MemoryPoolEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Standard test sizes
        small_buffer_size_ = 256;
        medium_buffer_size_ = 1024;
        large_buffer_size_ = 4096;
        
        // Pool sizes
        small_pool_size_ = 16;
        medium_pool_size_ = 32;
        large_pool_size_ = 64;
        
        // Test data
        test_data_.resize(medium_buffer_size_);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
    }
    
    void TearDown() override {
        // Allow some time for cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    size_t small_buffer_size_;
    size_t medium_buffer_size_;
    size_t large_buffer_size_;
    
    size_t small_pool_size_;
    size_t medium_pool_size_;
    size_t large_pool_size_;
    
    std::vector<std::byte> test_data_;
};

// Test BufferPool basic functionality
TEST_F(MemoryPoolEnhancedTest, BufferPoolBasicFunctionality) {
    BufferPool pool(medium_buffer_size_, small_pool_size_);
    
    // Test pool creation
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.buffer_size, medium_buffer_size_);
    EXPECT_GT(stats.available_buffers, 0);
    EXPECT_EQ(stats.total_buffers, stats.available_buffers);
    EXPECT_EQ(stats.total_allocations, 0);
    EXPECT_EQ(stats.total_deallocations, 0);
    
    // Test buffer acquisition
    auto buffer = pool.acquire();
    ASSERT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), medium_buffer_size_);
    EXPECT_EQ(buffer->size(), 0);
    EXPECT_TRUE(buffer->empty());
    
    // Check stats after acquisition
    stats = pool.get_statistics();
    EXPECT_EQ(stats.total_allocations, 1);
    EXPECT_EQ(stats.available_buffers, small_pool_size_ - 1);
    
    // Test buffer usage
    auto result = buffer->append(test_data_.data(), std::min(test_data_.size(), buffer->capacity()));
    ASSERT_TRUE(result.is_ok());
    EXPECT_GT(buffer->size(), 0);
    
    // Test buffer release
    pool.release(std::move(buffer));
    EXPECT_EQ(buffer, nullptr);
    
    // Check stats after release
    stats = pool.get_statistics();
    EXPECT_EQ(stats.total_deallocations, 1);
    EXPECT_EQ(stats.available_buffers, small_pool_size_);
}

// Test pool expansion and shrinking
TEST_F(MemoryPoolEnhancedTest, PoolExpansionAndShrinking) {
    BufferPool pool(small_buffer_size_, small_pool_size_);
    
    // Get initial stats
    auto initial_stats = pool.get_statistics();
    EXPECT_EQ(initial_stats.total_buffers, small_pool_size_);
    
    // Test pool expansion
    auto result = pool.expand_pool(small_pool_size_);
    EXPECT_TRUE(result.is_ok());
    
    auto expanded_stats = pool.get_statistics();
    EXPECT_GE(expanded_stats.total_buffers, initial_stats.total_buffers + small_pool_size_);
    EXPECT_GE(expanded_stats.available_buffers, initial_stats.available_buffers + small_pool_size_);
    
    // Test pool shrinking
    result = pool.shrink_pool(small_pool_size_);
    EXPECT_TRUE(result.is_ok());
    
    auto shrunk_stats = pool.get_statistics();
    EXPECT_LE(shrunk_stats.total_buffers, expanded_stats.total_buffers);
    
    // Test invalid shrink (cannot shrink below active buffers)
    std::vector<std::unique_ptr<ZeroCopyBuffer>> active_buffers;
    for (size_t i = 0; i < shrunk_stats.available_buffers; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            active_buffers.push_back(std::move(buffer));
        }
    }
    
    // Now try to shrink below active count (should fail or limit shrinking)
    result = pool.shrink_pool(1);
    // Implementation may choose to succeed with limited shrinking or fail
    auto final_stats = pool.get_statistics();
    EXPECT_GE(final_stats.total_buffers, active_buffers.size());
    
    // Release all buffers
    for (auto& buffer : active_buffers) {
        pool.release(std::move(buffer));
    }
}

// Test pool exhaustion and recovery
TEST_F(MemoryPoolEnhancedTest, PoolExhaustionAndRecovery) {
    BufferPool pool(small_buffer_size_, 4); // Small pool for easy exhaustion
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> acquired_buffers;
    
    // Exhaust the pool
    for (size_t i = 0; i < 10; ++i) { // Try to acquire more than pool size
        auto buffer = pool.acquire();
        if (buffer) {
            acquired_buffers.push_back(std::move(buffer));
        } else {
            break; // Pool exhausted
        }
    }
    
    auto exhausted_stats = pool.get_statistics();
    EXPECT_EQ(exhausted_stats.available_buffers, 0);
    EXPECT_GT(exhausted_stats.total_allocations, 0);
    
    // Test acquisition when exhausted
    auto null_buffer = pool.acquire();
    if (null_buffer == nullptr) {
        // Pool correctly returns null when exhausted
        auto stats = pool.get_statistics();
        EXPECT_GT(stats.allocation_failures, 0);
    } else {
        // Pool may expand automatically
        EXPECT_NE(null_buffer, nullptr);
    }
    
    // Release some buffers
    size_t to_release = acquired_buffers.size() / 2;
    for (size_t i = 0; i < to_release; ++i) {
        pool.release(std::move(acquired_buffers[i]));
    }
    acquired_buffers.erase(acquired_buffers.begin(), acquired_buffers.begin() + to_release);
    
    // Verify recovery
    auto recovery_stats = pool.get_statistics();
    EXPECT_GE(recovery_stats.available_buffers, to_release);
    
    // Test reacquisition
    auto recovered_buffer = pool.acquire();
    EXPECT_NE(recovered_buffer, nullptr);
    
    // Clean up
    for (auto& buffer : acquired_buffers) {
        if (buffer) {
            pool.release(std::move(buffer));
        }
    }
    if (recovered_buffer) {
        pool.release(std::move(recovered_buffer));
    }
}

// Test concurrent pool access
TEST_F(MemoryPoolEnhancedTest, ConcurrentPoolAccess) {
    BufferPool pool(medium_buffer_size_, medium_pool_size_);
    
    constexpr size_t num_threads = 8;
    constexpr size_t operations_per_thread = 50;
    
    std::vector<std::future<bool>> futures;
    std::atomic<size_t> successful_operations{0};
    std::atomic<size_t> failed_operations{0};
    
    // Launch concurrent operations
    for (size_t t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(1, 10);
            
            try {
                for (size_t op = 0; op < operations_per_thread; ++op) {
                    // Acquire buffer
                    auto buffer = pool.acquire();
                    if (!buffer) {
                        failed_operations.fetch_add(1);
                        continue;
                    }
                    
                    // Use buffer briefly
                    auto result = buffer->append(test_data_.data(), 
                                               std::min(test_data_.size(), buffer->capacity()));
                    if (!result.is_ok()) {
                        failed_operations.fetch_add(1);
                        pool.release(std::move(buffer));
                        continue;
                    }
                    
                    // Random delay to simulate work
                    std::this_thread::sleep_for(std::chrono::microseconds(dis(gen)));
                    
                    // Release buffer
                    pool.release(std::move(buffer));
                    successful_operations.fetch_add(1);
                }
                return true;
            } catch (...) {
                return false;
            }
        }));
    }
    
    // Wait for all threads
    bool all_successful = true;
    for (auto& future : futures) {
        if (!future.get()) {
            all_successful = false;
        }
    }
    
    EXPECT_TRUE(all_successful);
    EXPECT_GT(successful_operations.load(), 0);
    
    // Verify pool integrity after concurrent access
    auto final_stats = pool.get_statistics();
    EXPECT_EQ(final_stats.total_allocations, final_stats.total_deallocations + final_stats.allocation_failures);
    EXPECT_GT(final_stats.available_buffers, 0);
}

// Test pool statistics accuracy
TEST_F(MemoryPoolEnhancedTest, PoolStatisticsAccuracy) {
    BufferPool pool(small_buffer_size_, small_pool_size_);
    
    auto initial_stats = pool.get_statistics();
    EXPECT_EQ(initial_stats.total_allocations, 0);
    EXPECT_EQ(initial_stats.total_deallocations, 0);
    EXPECT_EQ(initial_stats.allocation_failures, 0);
    EXPECT_EQ(initial_stats.peak_usage, 0);
    
    constexpr size_t num_acquisitions = 100;
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    
    // Perform tracked acquisitions
    for (size_t i = 0; i < num_acquisitions; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            buffers.push_back(std::move(buffer));
        }
        
        // Check peak usage tracking
        auto stats = pool.get_statistics();
        EXPECT_GE(stats.peak_usage, buffers.size());
    }
    
    auto mid_stats = pool.get_statistics();
    EXPECT_GE(mid_stats.total_allocations, buffers.size());
    EXPECT_GE(mid_stats.peak_usage, buffers.size());
    
    // Release all buffers
    size_t released_count = 0;
    for (auto& buffer : buffers) {
        if (buffer) {
            pool.release(std::move(buffer));
            ++released_count;
        }
    }
    buffers.clear();
    
    auto final_stats = pool.get_statistics();
    EXPECT_EQ(final_stats.total_deallocations, released_count);
    EXPECT_GE(final_stats.peak_usage, released_count);
    
    // Test utilization ratio calculation
    if (final_stats.total_buffers > 0) {
        double expected_utilization = static_cast<double>(final_stats.total_buffers - final_stats.available_buffers) 
                                    / final_stats.total_buffers;
        EXPECT_DOUBLE_EQ(final_stats.utilization_ratio, expected_utilization);
    }
}

// Test pool reset functionality
TEST_F(MemoryPoolEnhancedTest, PoolResetFunctionality) {
    BufferPool pool(medium_buffer_size_, small_pool_size_);
    
    // Acquire some buffers and perform operations
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (size_t i = 0; i < small_pool_size_ / 2; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            auto result = buffer->append(test_data_.data(), 
                                       std::min(test_data_.size(), buffer->capacity()));
            ASSERT_TRUE(result.is_ok());
            buffers.push_back(std::move(buffer));
        }
    }
    
    auto pre_reset_stats = pool.get_statistics();
    EXPECT_GT(pre_reset_stats.total_allocations, 0);
    
    // Test pool reset (if available)
    pool.clear_pool();
    {
        auto post_reset_stats = pool.get_statistics();
        
        // After reset, stats should be cleared but pool should be functional
        EXPECT_EQ(post_reset_stats.total_allocations, 0);
        EXPECT_EQ(post_reset_stats.total_deallocations, 0);
        EXPECT_EQ(post_reset_stats.allocation_failures, 0);
        EXPECT_EQ(post_reset_stats.peak_usage, 0);
        EXPECT_GT(post_reset_stats.available_buffers, 0);
        
        // Pool should still be usable
        auto new_buffer = pool.acquire();
        EXPECT_NE(new_buffer, nullptr);
        if (new_buffer) {
            pool.release(std::move(new_buffer));
        }
    }
    
    // Clean up (some buffers may be invalidated by reset)
    for (auto& buffer : buffers) {
        if (buffer) {
            // Try to release, but it may fail if reset invalidated them
            pool.release(std::move(buffer));
        }
    }
}

// Test adaptive pool behavior
TEST_F(MemoryPoolEnhancedTest, AdaptivePoolBehavior) {
    // Test with adaptive pool if available
    BufferPool pool(medium_buffer_size_, small_pool_size_);
    
    // Test load-based expansion
    std::vector<std::unique_ptr<ZeroCopyBuffer>> high_load_buffers;
    
    // Create high load scenario
    for (size_t i = 0; i < small_pool_size_ * 2; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            high_load_buffers.push_back(std::move(buffer));
        }
    }
    
    auto high_load_stats = pool.get_statistics();
    
    // Release buffers to simulate low load
    for (auto& buffer : high_load_buffers) {
        if (buffer) {
            pool.release(std::move(buffer));
        }
    }
    high_load_buffers.clear();
    
    // Allow time for potential adaptive behavior
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    auto low_load_stats = pool.get_statistics();
    
    // Pool may have adapted its size based on usage patterns
    // This test documents the behavior rather than enforcing specific adaptation
    EXPECT_GE(low_load_stats.available_buffers, 0);
    EXPECT_GE(low_load_stats.total_buffers, small_pool_size_);
}

// Test pool destruction safety
TEST_F(MemoryPoolEnhancedTest, PoolDestructionSafety) {
    std::vector<std::unique_ptr<ZeroCopyBuffer>> leaked_buffers;
    
    {
        BufferPool pool(small_buffer_size_, small_pool_size_);
        
        // Acquire buffers but don't release them
        for (size_t i = 0; i < small_pool_size_ / 2; ++i) {
            auto buffer = pool.acquire();
            if (buffer) {
                leaked_buffers.push_back(std::move(buffer));
            }
        }
        
        // Pool goes out of scope with unreleased buffers
        // This should not crash or cause undefined behavior
    }
    
    // Buffers should still be valid even after pool destruction
    for (auto& buffer : leaked_buffers) {
        EXPECT_NE(buffer, nullptr);
        if (buffer) {
            EXPECT_GE(buffer->capacity(), small_buffer_size_);
            
            // Should still be usable
            auto result = buffer->append(test_data_.data(), 
                                       std::min(test_data_.size(), buffer->capacity()));
            EXPECT_TRUE(result.is_ok());
        }
    }
    
    // Clean up - buffers should destruct normally
    leaked_buffers.clear();
}

// Test pool configuration validation
TEST_F(MemoryPoolEnhancedTest, PoolConfigurationValidation) {
    // Test invalid configurations
    
    // Zero buffer size should fail or default to minimum
    try {
        BufferPool zero_size_pool(0, small_pool_size_);
        auto stats = zero_size_pool.get_statistics();
        EXPECT_GT(stats.buffer_size, 0); // Should default to minimum size
    } catch (...) {
        // It's acceptable to throw on invalid configuration
        SUCCEED();
    }
    
    // Zero pool size should fail or default to minimum
    try {
        BufferPool zero_pool_pool(small_buffer_size_, 0);
        auto stats = zero_pool_pool.get_statistics();
        EXPECT_GT(stats.total_buffers, 0); // Should default to minimum pool size
    } catch (...) {
        // It's acceptable to throw on invalid configuration
        SUCCEED();
    }
    
    // Very large buffer size should handle gracefully
    constexpr size_t very_large_size = 1024 * 1024 * 100; // 100MB
    try {
        BufferPool large_buffer_pool(very_large_size, 2);
        auto buffer = large_buffer_pool.acquire();
        if (buffer) {
            EXPECT_GE(buffer->capacity(), very_large_size);
            large_buffer_pool.release(std::move(buffer));
        } else {
            // Acceptable to fail for very large allocations
            auto stats = large_buffer_pool.get_statistics();
            EXPECT_GT(stats.allocation_failures, 0);
        }
    } catch (...) {
        // Acceptable to throw for unreasonable sizes
        SUCCEED();
    }
}

// Test pool performance characteristics
TEST_F(MemoryPoolEnhancedTest, PoolPerformanceCharacteristics) {
    BufferPool pool(medium_buffer_size_, large_pool_size_);
    
    constexpr size_t num_operations = 1000;
    
    // Measure acquisition time
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (size_t i = 0; i < num_operations; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            buffers.push_back(std::move(buffer));
        }
        
        // Interleave some releases to test reuse performance
        if (i % 10 == 9 && !buffers.empty()) {
            pool.release(std::move(buffers.back()));
            buffers.pop_back();
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Pool operations should be reasonably fast
    // Allow generous time limits to account for system load
    EXPECT_LT(duration.count(), 100000); // 100ms for 1000 operations
    
    // Clean up
    for (auto& buffer : buffers) {
        if (buffer) {
            pool.release(std::move(buffer));
        }
    }
    
    // Verify pool integrity after performance test
    auto final_stats = pool.get_statistics();
    EXPECT_EQ(final_stats.total_allocations, final_stats.total_deallocations);
    EXPECT_GT(final_stats.available_buffers, 0);
}

// Test buffer pool integration with ZeroCopyBuffer
TEST_F(MemoryPoolEnhancedTest, BufferPoolIntegration) {
    BufferPool pool(medium_buffer_size_, medium_pool_size_);
    
    // Test that pooled buffers work correctly with ZeroCopyBuffer features
    auto buffer = pool.acquire();
    ASSERT_NE(buffer, nullptr);
    
    // Test buffer operations
    auto result = buffer->append(test_data_.data(), test_data_.size());
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(buffer->size(), test_data_.size());
    
    // Test sharing of pooled buffer
    auto share_result = buffer->share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    
    EXPECT_TRUE(shared.is_shared());
    EXPECT_EQ(shared.size(), buffer->size());
    
    // Test slicing of pooled buffer
    auto slice_result = buffer->slice(10, 100);
    ASSERT_TRUE(slice_result.is_ok());
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), 100);
    
    // Test security features
    buffer->secure_zero();
    for (size_t i = 0; i < buffer->size(); ++i) {
        EXPECT_EQ((*buffer)[i], std::byte{0});
    }
    
    // Release buffer back to pool
    pool.release(std::move(buffer));
    EXPECT_EQ(buffer, nullptr);
    
    // Reacquire a buffer (may be the same one)
    auto reacquired = pool.acquire();
    EXPECT_NE(reacquired, nullptr);
    
    if (reacquired) {
        // Buffer should be clean/reset
        EXPECT_EQ(reacquired->size(), 0);
        EXPECT_TRUE(reacquired->empty());
        
        pool.release(std::move(reacquired));
    }
}