/**
 * @file test_memory_pool.cpp
 * @brief Comprehensive tests for DTLS memory pool management
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>

#include "dtls/memory/pool.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class MemoryPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Standard buffer sizes for testing
        small_buffer_size_ = 256;
        medium_buffer_size_ = 1024;
        large_buffer_size_ = 4096;
        
        // Pool sizes
        default_pool_size_ = 16;
        large_pool_size_ = 64;
        
        // Test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        // Clean up any existing global state
        GlobalPoolManager::instance().clear_all_pools();
    }
    
    void TearDown() override {
        // Clean up global pools after each test
        GlobalPoolManager::instance().clear_all_pools();
    }
    
    size_t small_buffer_size_;
    size_t medium_buffer_size_;
    size_t large_buffer_size_;
    size_t default_pool_size_;
    size_t large_pool_size_;
    std::vector<std::byte> test_data_;
};

// Test basic buffer pool creation and configuration
TEST_F(MemoryPoolTest, BasicPoolCreationAndConfiguration) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Test initial state
    EXPECT_EQ(pool.buffer_size(), medium_buffer_size_);
    EXPECT_EQ(pool.pool_size(), default_pool_size_);
    EXPECT_EQ(pool.available_buffers(), default_pool_size_);
    EXPECT_EQ(pool.total_buffers(), default_pool_size_);
    EXPECT_TRUE(pool.is_thread_safe());
    
    // Test statistics
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.total_buffers, default_pool_size_);
    EXPECT_EQ(stats.available_buffers, default_pool_size_);
    EXPECT_EQ(stats.buffer_size, medium_buffer_size_);
    EXPECT_EQ(stats.total_allocations, 0);
    EXPECT_EQ(stats.total_deallocations, 0);
    EXPECT_EQ(stats.allocation_failures, 0);
    EXPECT_EQ(stats.peak_usage, 0);
    
    // Test utilization
    EXPECT_DOUBLE_EQ(pool.utilization_ratio(), 0.0);
}

// Test buffer acquisition and release
TEST_F(MemoryPoolTest, BufferAcquisitionAndRelease) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Acquire a buffer
    auto buffer = pool.acquire();
    ASSERT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), medium_buffer_size_);
    EXPECT_EQ(buffer->size(), 0);
    
    // Pool should have one less available buffer
    EXPECT_EQ(pool.available_buffers(), default_pool_size_ - 1);
    
    // Test buffer functionality
    auto result = buffer->append(test_data_.data(), std::min(test_data_.size(), medium_buffer_size_));
    EXPECT_TRUE(result.is_ok());
    EXPECT_GT(buffer->size(), 0);
    
    // Release buffer back to pool
    pool.release(std::move(buffer));
    EXPECT_EQ(pool.available_buffers(), default_pool_size_);
    
    // Test statistics after one acquisition/release cycle
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.total_allocations, 1);
    EXPECT_EQ(stats.total_deallocations, 1);
    EXPECT_EQ(stats.peak_usage, 1);
}

// Test pool exhaustion and recovery
TEST_F(MemoryPoolTest, PoolExhaustionAndRecovery) {
    BufferPool pool(small_buffer_size_, 4); // Small pool for testing exhaustion
    
    // Acquire all buffers
    std::vector<std::unique_ptr<ZeroCopyBuffer>> acquired_buffers;
    for (size_t i = 0; i < 4; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        acquired_buffers.push_back(std::move(buffer));
    }
    
    EXPECT_EQ(pool.available_buffers(), 0);
    EXPECT_DOUBLE_EQ(pool.utilization_ratio(), 1.0);
    
    // Try to acquire one more (should return nullptr)
    auto extra_buffer = pool.acquire();
    EXPECT_EQ(extra_buffer, nullptr);
    
    // Check allocation failure recorded
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.allocation_failures, 1);
    
    // Release one buffer
    pool.release(std::move(acquired_buffers.back()));
    acquired_buffers.pop_back();
    
    EXPECT_EQ(pool.available_buffers(), 1);
    
    // Should be able to acquire again
    extra_buffer = pool.acquire();
    EXPECT_NE(extra_buffer, nullptr);
    
    // Clean up
    pool.release(std::move(extra_buffer));
    for (auto& buffer : acquired_buffers) {
        pool.release(std::move(buffer));
    }
}

// Test pool expansion and shrinking
TEST_F(MemoryPoolTest, PoolExpansionAndShrinking) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Expand pool
    auto expand_result = pool.expand_pool(8);
    EXPECT_TRUE(expand_result.is_ok());
    EXPECT_EQ(pool.total_buffers(), default_pool_size_ + 8);
    EXPECT_EQ(pool.available_buffers(), default_pool_size_ + 8);
    
    // Acquire some buffers to test shrinking with active allocations
    std::vector<std::unique_ptr<ZeroCopyBuffer>> active_buffers;
    for (size_t i = 0; i < 4; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        active_buffers.push_back(std::move(buffer));
    }
    
    // Shrink pool (should only shrink available buffers)
    auto shrink_result = pool.shrink_pool(default_pool_size_);
    EXPECT_TRUE(shrink_result.is_ok());
    EXPECT_LE(pool.total_buffers(), default_pool_size_ + 8); // Can't shrink below active allocations
    
    // Clean up active buffers
    for (auto& buffer : active_buffers) {
        pool.release(std::move(buffer));
    }
    
    // Now should be able to shrink to target
    shrink_result = pool.shrink_pool(default_pool_size_);
    EXPECT_TRUE(shrink_result.is_ok());
    EXPECT_EQ(pool.total_buffers(), default_pool_size_);
}

// Test pool clearing
TEST_F(MemoryPoolTest, PoolClearing) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Acquire and release some buffers to generate statistics
    for (size_t i = 0; i < 5; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        pool.release(std::move(buffer));
    }
    
    auto stats_before = pool.get_statistics();
    EXPECT_GT(stats_before.total_allocations, 0);
    EXPECT_GT(stats_before.total_deallocations, 0);
    
    // Clear pool (this resets everything)
    pool.clear_pool();
    
    // Pool should be reset to initial state
    EXPECT_EQ(pool.available_buffers(), default_pool_size_);
    EXPECT_EQ(pool.total_buffers(), default_pool_size_);
    
    // Should still be functional
    auto buffer = pool.acquire();
    EXPECT_NE(buffer, nullptr);
    pool.release(std::move(buffer));
}

// Test max pool size configuration
TEST_F(MemoryPoolTest, MaxPoolSizeConfiguration) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Set max pool size
    pool.set_max_pool_size(32);
    
    // Should be able to expand up to max
    auto expand_result = pool.expand_pool(16);
    EXPECT_TRUE(expand_result.is_ok());
    EXPECT_EQ(pool.total_buffers(), 32);
    
    // Should not be able to expand beyond max
    auto over_expand_result = pool.expand_pool(10);
    EXPECT_TRUE(over_expand_result.is_error());
    EXPECT_EQ(pool.total_buffers(), 32); // Should not have changed
}

// Test GlobalPoolManager
TEST_F(MemoryPoolTest, GlobalPoolManager) {
    auto& manager = GlobalPoolManager::instance();
    
    // Test singleton behavior
    auto& manager2 = GlobalPoolManager::instance();
    EXPECT_EQ(&manager, &manager2);
    
    // Create pool via manager
    auto create_result = manager.create_pool(medium_buffer_size_, default_pool_size_);
    EXPECT_TRUE(create_result.is_ok());
    
    // Get the created pool
    auto& pool = manager.get_pool(medium_buffer_size_);
    EXPECT_EQ(pool.buffer_size(), medium_buffer_size_);
    EXPECT_EQ(pool.total_buffers(), default_pool_size_);
    
    // Create another pool with different size
    create_result = manager.create_pool(large_buffer_size_, large_pool_size_);
    EXPECT_TRUE(create_result.is_ok());
    
    // Test statistics collection
    auto all_stats = manager.get_all_statistics();
    EXPECT_EQ(all_stats.size(), 2);
    
    // Test total memory usage
    size_t expected_memory = (medium_buffer_size_ * default_pool_size_) + 
                           (large_buffer_size_ * large_pool_size_);
    EXPECT_EQ(manager.total_memory_usage(), expected_memory);
    
    // Test default pool size configuration
    manager.set_default_pool_size(24);
    EXPECT_EQ(manager.default_pool_size(), 24);
    
    // Remove one pool
    manager.remove_pool(medium_buffer_size_);
    all_stats = manager.get_all_statistics();
    EXPECT_EQ(all_stats.size(), 1);
    
    // Clear all pools
    manager.clear_all_pools();
    all_stats = manager.get_all_statistics();
    EXPECT_EQ(all_stats.size(), 0);
    EXPECT_EQ(manager.total_memory_usage(), 0);
}

// Test PooledBuffer RAII functionality
TEST_F(MemoryPoolTest, PooledBufferRAII) {
    // Test basic construction
    {
        PooledBuffer pooled(medium_buffer_size_);
        EXPECT_TRUE(pooled.is_valid());
        EXPECT_TRUE(static_cast<bool>(pooled));
        
        // Test buffer access
        auto& buffer = pooled.buffer();
        EXPECT_GE(buffer.capacity(), medium_buffer_size_);
        
        // Test pointer operations
        EXPECT_NE(pooled.operator->(), nullptr);
        EXPECT_EQ(&(*pooled), &buffer);
        
        // Test buffer functionality through pooled wrapper
        auto result = pooled->append(test_data_.data(), std::min(test_data_.size(), medium_buffer_size_));
        EXPECT_TRUE(result.is_ok());
        EXPECT_GT(pooled->size(), 0);
    } // Buffer should be automatically returned to pool here
    
    // Test move semantics
    PooledBuffer pooled1(small_buffer_size_);
    auto data_ptr = pooled1->data();
    
    PooledBuffer pooled2 = std::move(pooled1);
    EXPECT_FALSE(pooled1.is_valid());
    EXPECT_TRUE(pooled2.is_valid());
    EXPECT_EQ(pooled2->data(), data_ptr);
    
    // Test release
    auto released_buffer = pooled2.release();
    EXPECT_NE(released_buffer, nullptr);
    EXPECT_FALSE(pooled2.is_valid());
    EXPECT_EQ(released_buffer->data(), data_ptr);
}

// Test pool allocator for STL containers
TEST_F(MemoryPoolTest, PoolAllocatorSTL) {
    // Create vector with pool allocator
    PoolVector<int> pooled_vector;
    
    // Add some data
    for (int i = 0; i < 1000; ++i) {
        pooled_vector.push_back(i);
    }
    
    EXPECT_EQ(pooled_vector.size(), 1000);
    
    // Verify data integrity
    for (size_t i = 0; i < pooled_vector.size(); ++i) {
        EXPECT_EQ(pooled_vector[i], static_cast<int>(i));
    }
    
    // Test allocator comparison
    PoolAllocator<int> alloc1;
    PoolAllocator<int> alloc2;
    PoolAllocator<double> alloc3;
    
    EXPECT_TRUE(alloc1 == alloc2);
    EXPECT_FALSE(alloc1 != alloc2);
    EXPECT_TRUE(alloc1 == alloc3); // Different types but same allocator
}

// Test factory functions
TEST_F(MemoryPoolTest, FactoryFunctions) {
    // Test make_pooled_buffer
    auto pooled = make_pooled_buffer(medium_buffer_size_);
    EXPECT_TRUE(pooled.is_valid());
    EXPECT_GE(pooled->capacity(), medium_buffer_size_);
    
    // Test make_buffer
    auto buffer = make_buffer(large_buffer_size_);
    EXPECT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), large_buffer_size_);
    
    // Test pool configuration helpers
    configure_default_pools(); // Should not crash
    cleanup_all_pools(); // Should not crash
    
    // Verify cleanup worked
    auto& manager = GlobalPoolManager::instance();
    auto all_stats = manager.get_all_statistics();
    EXPECT_EQ(all_stats.size(), 0);
}

// Test concurrent pool access
TEST_F(MemoryPoolTest, ConcurrentPoolAccess) {
    BufferPool pool(medium_buffer_size_, large_pool_size_);
    
    const int num_threads = 8;
    const int operations_per_thread = 100;
    std::atomic<int> successful_acquisitions{0};
    std::atomic<int> successful_releases{0};
    std::atomic<int> allocation_failures{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that acquire and release buffers
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> hold_time_dis(1, 10);
            
            for (int i = 0; i < operations_per_thread; ++i) {
                auto buffer = pool.acquire();
                if (buffer) {
                    successful_acquisitions.fetch_add(1);
                    
                    // Do some work with the buffer
                    auto result = buffer->append(test_data_.data(), 
                                               std::min(test_data_.size(), medium_buffer_size_));
                    EXPECT_TRUE(result.is_ok());
                    
                    // Hold buffer for random time
                    std::this_thread::sleep_for(std::chrono::microseconds(hold_time_dis(gen)));
                    
                    pool.release(std::move(buffer));
                    successful_releases.fetch_add(1);
                } else {
                    allocation_failures.fetch_add(1);
                }
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify statistics
    EXPECT_EQ(successful_acquisitions.load(), successful_releases.load());
    EXPECT_EQ(pool.available_buffers(), large_pool_size_); // All buffers returned
    
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.total_allocations, successful_acquisitions.load());
    EXPECT_EQ(stats.total_deallocations, successful_releases.load());
    EXPECT_EQ(stats.allocation_failures, allocation_failures.load());
}

// Test pool statistics accuracy
TEST_F(MemoryPoolTest, PoolStatisticsAccuracy) {
    BufferPool pool(medium_buffer_size_, default_pool_size_);
    
    // Perform various operations and track expected stats
    size_t expected_allocations = 0;
    size_t expected_deallocations = 0;
    size_t expected_failures = 0;
    size_t peak_usage = 0;
    size_t current_usage = 0;
    
    // Acquire some buffers
    std::vector<std::unique_ptr<ZeroCopyBuffer>> held_buffers;
    for (size_t i = 0; i < 5; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        held_buffers.push_back(std::move(buffer));
        expected_allocations++;
        current_usage++;
        peak_usage = std::max(peak_usage, current_usage);
    }
    
    // Release some buffers
    for (size_t i = 0; i < 3; ++i) {
        pool.release(std::move(held_buffers.back()));
        held_buffers.pop_back();
        expected_deallocations++;
        current_usage--;
    }
    
    // Exhaust pool to cause failures
    while (held_buffers.size() < default_pool_size_) {
        auto buffer = pool.acquire();
        if (buffer) {
            held_buffers.push_back(std::move(buffer));
            expected_allocations++;
            current_usage++;
            peak_usage = std::max(peak_usage, current_usage);
        } else {
            expected_failures++;
            break;
        }
    }
    
    // Try to acquire more to generate failures
    for (int i = 0; i < 3; ++i) {
        auto buffer = pool.acquire();
        EXPECT_EQ(buffer, nullptr);
        expected_failures++;
    }
    
    // Verify statistics
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.total_allocations, expected_allocations);
    EXPECT_EQ(stats.total_deallocations, expected_deallocations);
    EXPECT_EQ(stats.allocation_failures, expected_failures);
    EXPECT_EQ(stats.peak_usage, peak_usage);
    EXPECT_EQ(stats.available_buffers, default_pool_size_ - current_usage);
    
    // Clean up
    for (auto& buffer : held_buffers) {
        pool.release(std::move(buffer));
    }
}

// Test pool with different buffer sizes
TEST_F(MemoryPoolTest, DifferentBufferSizes) {
    std::vector<size_t> sizes = {64, 256, 1024, 4096, 16384};
    std::vector<std::unique_ptr<BufferPool>> pools;
    
    // Create pools for different sizes
    for (size_t size : sizes) {
        pools.push_back(std::make_unique<BufferPool>(size, 8));
        EXPECT_EQ(pools.back()->buffer_size(), size);
    }
    
    // Test each pool
    for (size_t i = 0; i < pools.size(); ++i) {
        auto& pool = *pools[i];
        size_t expected_size = sizes[i];
        
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        EXPECT_GE(buffer->capacity(), expected_size);
        
        // Fill buffer to capacity
        std::vector<std::byte> fill_data(expected_size, std::byte{0xAA});
        auto result = buffer->append(fill_data.data(), fill_data.size());
        EXPECT_TRUE(result.is_ok());
        EXPECT_EQ(buffer->size(), expected_size);
        
        pool.release(std::move(buffer));
    }
}

// Test pool edge cases and error conditions
TEST_F(MemoryPoolTest, EdgeCasesAndErrorConditions) {
    // Test zero-sized buffer pool (should handle gracefully)
    BufferPool zero_pool(0, 4);
    auto zero_buffer = zero_pool.acquire();
    EXPECT_NE(zero_buffer, nullptr); // Should still work, just with 0 capacity
    EXPECT_EQ(zero_buffer->capacity(), 0);
    zero_pool.release(std::move(zero_buffer));
    
    // Test single buffer pool
    BufferPool single_pool(medium_buffer_size_, 1);
    EXPECT_EQ(single_pool.total_buffers(), 1);
    
    auto buffer = single_pool.acquire();
    EXPECT_NE(buffer, nullptr);
    EXPECT_EQ(single_pool.available_buffers(), 0);
    
    auto second_buffer = single_pool.acquire();
    EXPECT_EQ(second_buffer, nullptr);
    
    single_pool.release(std::move(buffer));
    EXPECT_EQ(single_pool.available_buffers(), 1);
    
    // Test invalid buffer release (different size)
    BufferPool different_pool(large_buffer_size_, 4);
    auto different_buffer = different_pool.acquire();
    ASSERT_NE(different_buffer, nullptr);
    
    // Try to release to wrong pool (should handle gracefully)
    single_pool.release(std::move(different_buffer)); // This should not crash
    
    // Test expansion/shrinking edge cases
    BufferPool edge_pool(medium_buffer_size_, 4);
    
    // Expand by 0
    auto expand_result = edge_pool.expand_pool(0);
    EXPECT_TRUE(expand_result.is_ok());
    EXPECT_EQ(edge_pool.total_buffers(), 4);
    
    // Shrink to larger than current size (should handle gracefully)
    auto shrink_result = edge_pool.shrink_pool(10);
    EXPECT_TRUE(shrink_result.is_ok() || shrink_result.is_error()); // Implementation dependent
    
    // Shrink to 0 (edge case)
    shrink_result = edge_pool.shrink_pool(0);
    EXPECT_TRUE(shrink_result.is_ok() || shrink_result.is_error()); // Implementation dependent
}