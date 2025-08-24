/**
 * @file test_memory_comprehensive.cpp
 * @brief Comprehensive Memory Management Tests for DTLS v1.3
 * 
 * This file implements comprehensive test coverage for all memory management components:
 * 1. Memory Pool Management
 * 2. Adaptive Pool Systems  
 * 3. Buffer Management
 * 4. Memory Security
 * 5. Performance Edge Cases
 * 6. Zero-Copy Crypto Operations
 * 
 * Target: >95% code coverage for memory management subsystem
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <random>
#include <algorithm>
#include <functional>

#include "dtls/memory/pool.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

namespace {

// Test fixture for comprehensive memory tests
class ComprehensiveMemoryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_data_.resize(4096);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        // Common buffer sizes
        small_size_ = 256;
        medium_size_ = 1024;  
        large_size_ = 4096;
        
        // Pool configurations
        small_pool_size_ = 8;
        medium_pool_size_ = 16;
        large_pool_size_ = 32;
        
        // Random number generation for stress tests
        generator_.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }
    
    void TearDown() override {
        // Clean up any global state
        GlobalPoolManager::instance().clear_all_pools();
    }
    
    // Helper functions
    std::vector<std::byte> generate_random_data(size_t size) {
        std::vector<std::byte> data(size);
        std::uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>(dist(generator_));
        }
        return data;
    }
    
    void simulate_high_load(size_t num_operations, size_t buffer_size) {
        std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
        
        for (size_t i = 0; i < num_operations; ++i) {
            auto& pool = GlobalPoolManager::instance().get_pool(buffer_size);
            auto buffer = pool.acquire();
            if (buffer) {
                // Simulate some work with the buffer
                auto test_data = generate_random_data(std::min(buffer_size, buffer->capacity()));
                if (test_data.size() <= buffer->capacity()) {
                    std::memcpy(buffer->mutable_data(), test_data.data(), test_data.size());
                }
                buffers.push_back(std::move(buffer));
            }
            
            // Randomly release some buffers
            if (!buffers.empty() && (i % 5 == 0)) {
                size_t idx = i % buffers.size();
                buffers.erase(buffers.begin() + idx);
            }
        }
    }
    
    // Test data
    std::vector<std::byte> test_data_;
    size_t small_size_;
    size_t medium_size_;
    size_t large_size_;
    size_t small_pool_size_;
    size_t medium_pool_size_;
    size_t large_pool_size_;
    std::mt19937 generator_;
};

// =============================================================================
// 1. MEMORY POOL MANAGEMENT TESTS
// =============================================================================

TEST_F(ComprehensiveMemoryTest, PoolLifecycleManagement) {
    // Test pool creation with various configurations
    BufferPool small_pool(small_size_, small_pool_size_);
    BufferPool medium_pool(medium_size_, medium_pool_size_);
    BufferPool large_pool(large_size_, large_pool_size_);
    
    // Verify initial state
    EXPECT_EQ(small_pool.buffer_size(), small_size_);
    EXPECT_EQ(small_pool.total_buffers(), small_pool_size_);
    EXPECT_EQ(small_pool.available_buffers(), small_pool_size_);
    EXPECT_DOUBLE_EQ(small_pool.utilization_ratio(), 0.0);
    
    // Test buffer acquisition and release cycle
    std::vector<std::unique_ptr<ZeroCopyBuffer>> acquired_buffers;
    
    // Acquire all buffers
    for (size_t i = 0; i < small_pool_size_; ++i) {
        auto buffer = small_pool.acquire();
        ASSERT_NE(buffer, nullptr);
        EXPECT_EQ(buffer->capacity(), small_size_);
        acquired_buffers.push_back(std::move(buffer));
    }
    
    EXPECT_EQ(small_pool.available_buffers(), 0);
    EXPECT_DOUBLE_EQ(small_pool.utilization_ratio(), 1.0);
    
    // Release half the buffers
    size_t half = acquired_buffers.size() / 2;
    for (size_t i = 0; i < half; ++i) {
        small_pool.release(std::move(acquired_buffers[i]));
    }
    acquired_buffers.erase(acquired_buffers.begin(), acquired_buffers.begin() + half);
    
    EXPECT_EQ(small_pool.available_buffers(), half);
    EXPECT_DOUBLE_EQ(small_pool.utilization_ratio(), 0.5);
}

TEST_F(ComprehensiveMemoryTest, PoolExpansionAndShrinking) {
    BufferPool pool(medium_size_, medium_pool_size_);
    
    // Test pool expansion
    auto expand_result = pool.expand_pool(8);
    EXPECT_TRUE(expand_result.is_ok());
    EXPECT_EQ(pool.total_buffers(), medium_pool_size_ + 8);
    
    // Test pool shrinking
    auto shrink_result = pool.shrink_pool(medium_pool_size_);
    EXPECT_TRUE(shrink_result.is_ok());
    EXPECT_EQ(pool.total_buffers(), medium_pool_size_);
    
    // Test shrinking below available buffers (should fail gracefully)
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (size_t i = 0; i < medium_pool_size_; ++i) {
        buffers.push_back(pool.acquire());
    }
    
    auto invalid_shrink = pool.shrink_pool(5);
    EXPECT_TRUE(invalid_shrink.is_error()); // Cannot shrink below in-use buffers
}

TEST_F(ComprehensiveMemoryTest, GlobalPoolManagerOperations) {
    auto& manager = GlobalPoolManager::instance();
    
    // Test pool creation and retrieval
    auto create_result = manager.create_pool(1024, 16);
    EXPECT_TRUE(create_result.is_ok());
    
    auto& pool = manager.get_pool(1024);
    EXPECT_EQ(pool.buffer_size(), 1024);
    
    // Test multiple pools
    manager.create_pool(512, 8);
    manager.create_pool(2048, 32);
    
    auto stats = manager.get_all_statistics();
    EXPECT_GE(stats.size(), 3); // At least 3 pools created
    
    size_t total_memory = manager.total_memory_usage();
    EXPECT_GT(total_memory, 0);
    
    // Test pool removal
    manager.remove_pool(512);
    auto stats_after_removal = manager.get_all_statistics();
    EXPECT_EQ(stats_after_removal.size(), stats.size() - 1);
}

TEST_F(ComprehensiveMemoryTest, PooledBufferRAII) {
    {
        PooledBuffer buffer(medium_size_);
        EXPECT_TRUE(buffer.is_valid());
        EXPECT_EQ(buffer->capacity(), medium_size_);
        
        // Test buffer operations
        auto test_data = generate_random_data(100);
        std::memcpy(buffer->mutable_data(), test_data.data(), test_data.size());
        
        // Verify data integrity
        EXPECT_EQ(std::memcmp(buffer->data(), test_data.data(), test_data.size()), 0);
    } // Buffer should be automatically returned to pool
    
    // Verify pool statistics show buffer was returned
    auto& pool = GlobalPoolManager::instance().get_pool(medium_size_);
    auto stats = pool.get_statistics();
    EXPECT_GT(stats.total_deallocations, 0);
}

// =============================================================================
// 2. BUFFER MANAGEMENT TESTS  
// =============================================================================

TEST_F(ComprehensiveMemoryTest, ZeroCopyBufferOperations) {
    // Test buffer creation with various methods
    ZeroCopyBuffer buffer1(1024);
    EXPECT_EQ(buffer1.capacity(), 1024);
    EXPECT_EQ(buffer1.size(), 0);
    EXPECT_TRUE(buffer1.empty());
    
    // Test buffer with initial data
    auto init_data = generate_random_data(512);
    ZeroCopyBuffer buffer2(init_data.data(), init_data.size());
    EXPECT_EQ(buffer2.size(), init_data.size());
    EXPECT_EQ(std::memcmp(buffer2.data(), init_data.data(), init_data.size()), 0);
    
    // Test buffer operations
    auto append_data = generate_random_data(256);
    auto append_result = buffer1.append(append_data.data(), append_data.size());
    EXPECT_TRUE(append_result.is_ok());
    EXPECT_EQ(buffer1.size(), append_data.size());
    
    // Test buffer slicing
    auto slice_result = buffer1.slice(0, 128);
    EXPECT_TRUE(slice_result.is_ok());
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), 128);
    EXPECT_EQ(std::memcmp(slice.data(), buffer1.data(), 128), 0);
}

TEST_F(ComprehensiveMemoryTest, BufferSharingAndCopyOnWrite) {
    // Create original buffer
    auto original_data = generate_random_data(1024);
    ZeroCopyBuffer original(original_data.data(), original_data.size());
    
    // Test buffer sharing
    auto share_result = original.share_buffer();
    EXPECT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    
    EXPECT_TRUE(shared.is_shared());
    EXPECT_EQ(shared.reference_count(), original.reference_count());
    EXPECT_EQ(shared.size(), original.size());
    
    // Verify data is shared (same memory)
    EXPECT_EQ(shared.data(), original.data());
    
    // Test copy-on-write behavior
    auto make_unique_result = shared.make_unique();
    EXPECT_TRUE(make_unique_result.is_ok());
    
    // After make_unique, data should be different memory but same content
    EXPECT_NE(shared.data(), original.data());
    EXPECT_EQ(std::memcmp(shared.data(), original.data(), shared.size()), 0);
    EXPECT_FALSE(shared.is_shared());
}

TEST_F(ComprehensiveMemoryTest, BufferViewOperations) {
    auto test_data = generate_random_data(1024);
    ZeroCopyBuffer buffer(test_data.data(), test_data.size());
    
    // Test immutable buffer view
    BufferView view(buffer);
    EXPECT_EQ(view.size(), buffer.size());
    EXPECT_EQ(view.data(), buffer.data());
    
    // Test buffer view slicing
    auto slice_view = view.slice(100, 200);
    EXPECT_EQ(slice_view.size(), 200);
    EXPECT_EQ(slice_view.data(), buffer.data() + 100);
    
    // Test mutable buffer view
    MutableBufferView mut_view(buffer);
    EXPECT_EQ(mut_view.size(), buffer.size());
    EXPECT_EQ(mut_view.data(), buffer.mutable_data());
    
    // Test view operations
    mut_view.fill(std::byte{0xAA});
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], std::byte{0xAA});
    }
    
    mut_view.zero();
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], std::byte{0x00});
    }
}

TEST_F(ComprehensiveMemoryTest, BufferUtilityFunctions) {
    auto data1 = generate_random_data(256);
    auto data2 = data1; // Same data
    auto data3 = generate_random_data(256); // Different data
    
    BufferView view1(data1.data(), data1.size());
    BufferView view2(data2.data(), data2.size());
    BufferView view3(data3.data(), data3.size());
    
    // Test constant-time comparison
    EXPECT_TRUE(constant_time_compare(view1, view2));
    EXPECT_FALSE(constant_time_compare(view1, view3));
    
    // Test hex encoding/decoding
    auto hex_string = to_hex_string(view1);
    EXPECT_FALSE(hex_string.empty());
    
    auto decode_result = from_hex_string(hex_string);
    EXPECT_TRUE(decode_result.is_ok());
    auto decoded = decode_result.value();
    
    BufferView decoded_view(decoded);
    EXPECT_TRUE(constant_time_compare(view1, decoded_view));
    
    // Test buffer concatenation
    std::vector<BufferView> views = {view1, view2};
    auto concat_result = concatenate_buffers(views);
    EXPECT_TRUE(concat_result.is_ok());
    auto concatenated = concat_result.value();
    EXPECT_EQ(concatenated.size(), data1.size() + data2.size());
}

// =============================================================================
// 3. MEMORY SECURITY TESTS
// =============================================================================

TEST_F(ComprehensiveMemoryTest, BufferOverflowProtection) {
    ZeroCopyBuffer buffer(256);
    
    // Test append beyond capacity
    auto large_data = generate_random_data(512);
    auto overflow_result = buffer.append(large_data.data(), large_data.size());
    
    // Implementation should either resize or return error, not crash
    if (overflow_result.is_error()) {
        // Buffer rejected overflow - good
        EXPECT_LT(buffer.size(), large_data.size());
    } else {
        // Buffer expanded to accommodate - also good
        EXPECT_GE(buffer.capacity(), large_data.size());
    }
}

TEST_F(ComprehensiveMemoryTest, SecureMemoryZeroing) {
    ZeroCopyBuffer buffer(1024);
    
    // Fill with sensitive data
    auto sensitive_data = generate_random_data(512);
    buffer.append(sensitive_data.data(), sensitive_data.size());
    
    // Verify data is present
    EXPECT_EQ(std::memcmp(buffer.data(), sensitive_data.data(), sensitive_data.size()), 0);
    
    // Secure zero the buffer
    buffer.secure_zero();
    
    // Verify all data is zeroed
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], std::byte{0x00});
    }
}

TEST_F(ComprehensiveMemoryTest, PoolExhaustionHandling) {
    // Create a small pool to force exhaustion
    BufferPool pool(256, 4);
    
    // Prevent pool expansion to ensure exhaustion testing
    pool.set_max_pool_size(4);
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    
    // Acquire all buffers
    for (size_t i = 0; i < 4; ++i) {
        auto buffer = pool.acquire();
        EXPECT_NE(buffer, nullptr);
        buffers.push_back(std::move(buffer));
    }
    
    // Next acquisition should fail gracefully
    auto exhausted_buffer = pool.acquire();
    EXPECT_EQ(exhausted_buffer, nullptr);
    
    // Pool statistics should reflect exhaustion
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.available_buffers, 0);
    EXPECT_GT(stats.allocation_failures, 0);
    
    // Release one buffer and verify recovery
    pool.release(std::move(buffers[0]));
    buffers.erase(buffers.begin());
    
    auto recovered_buffer = pool.acquire();
    EXPECT_NE(recovered_buffer, nullptr);
}

// =============================================================================
// 4. PERFORMANCE EDGE CASES TESTS
// =============================================================================

TEST_F(ComprehensiveMemoryTest, HighConcurrencyStressTest) {
    const size_t num_threads = 8;
    const size_t operations_per_thread = 1000;
    const size_t buffer_size = 1024;
    
    // Create a pool for the test
    auto& pool = GlobalPoolManager::instance().get_pool(buffer_size);
    
    std::vector<std::thread> threads;
    std::atomic<size_t> successful_operations{0};
    std::atomic<size_t> failed_operations{0};
    
    auto worker = [&]() {
        for (size_t i = 0; i < operations_per_thread; ++i) {
            auto buffer = pool.acquire();
            if (buffer) {
                // Simulate work
                auto data = generate_random_data(std::min(buffer_size, buffer->capacity()));
                if (data.size() <= buffer->capacity()) {
                    std::memcpy(buffer->mutable_data(), data.data(), data.size());
                }
                
                // Random delay
                std::this_thread::sleep_for(std::chrono::microseconds(1));
                
                pool.release(std::move(buffer));
                successful_operations++;
            } else {
                failed_operations++;
            }
        }
    };
    
    // Start all threads
    for (size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }
    
    // Wait for completion
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify results
    EXPECT_GT(successful_operations.load(), 0);
    
    // Pool should be in consistent state
    auto stats = pool.get_statistics();
    EXPECT_EQ(stats.total_allocations, stats.total_deallocations);
}

TEST_F(ComprehensiveMemoryTest, MemoryFragmentationHandling) {
    // Test with many different buffer sizes to create fragmentation
    std::vector<size_t> sizes = {64, 128, 256, 512, 1024, 2048};
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    
    // Create fragmentation by allocating and releasing randomly
    for (size_t round = 0; round < 10; ++round) {
        for (auto size : sizes) {
            auto& pool = GlobalPoolManager::instance().get_pool(size);
            for (size_t i = 0; i < 5; ++i) {
                auto buffer = pool.acquire();
                if (buffer) {
                    buffers.push_back(std::move(buffer));
                }
            }
        }
        
        // Randomly release some buffers
        if (!buffers.empty()) {
            size_t to_release = buffers.size() / 3;
            for (size_t i = 0; i < to_release; ++i) {
                size_t idx = generator_() % buffers.size();
                buffers.erase(buffers.begin() + idx);
            }
        }
    }
    
    // Verify system is still functional
    auto& test_pool = GlobalPoolManager::instance().get_pool(1024);
    auto test_buffer = test_pool.acquire();
    EXPECT_NE(test_buffer, nullptr);
}

TEST_F(ComprehensiveMemoryTest, LargeBufferHandling) {
    // Test with very large buffers
    const size_t large_size = 16 * 1024 * 1024; // 16MB
    
    // This should either work or fail gracefully
    ZeroCopyBuffer large_buffer(large_size);
    
    if (large_buffer.capacity() > 0) {
        // If allocation succeeded, test basic operations
        auto test_data = generate_random_data(1024);
        auto result = large_buffer.append(test_data.data(), test_data.size());
        EXPECT_TRUE(result.is_ok());
        
        // Test slicing large buffer
        auto slice_result = large_buffer.slice(0, 1024);
        EXPECT_TRUE(slice_result.is_ok());
    }
    
    // Test pool with large buffers
    try {
        BufferPool large_pool(large_size, 2);
        auto buffer1 = large_pool.acquire();
        auto buffer2 = large_pool.acquire();
        
        // Should be able to acquire at least some large buffers
        EXPECT_TRUE(buffer1 != nullptr || buffer2 != nullptr);
    } catch (...) {
        // Large allocations might fail - that's acceptable
        GTEST_SKIP() << "Large buffer allocation failed - expected on constrained systems";
    }
}

// =============================================================================
// 5. COMPREHENSIVE INTEGRATION TESTS
// =============================================================================

TEST_F(ComprehensiveMemoryTest, MemorySystemIntegration) {
    // Test complete memory system workflow
    const size_t num_connections = 16;
    const size_t buffers_per_connection = 8;
    
    struct MockConnection {
        std::vector<PooledBuffer> buffers;
        size_t bytes_processed{0};
    };
    
    std::vector<MockConnection> connections(num_connections);
    
    // Simulate connection setup
    for (auto& conn : connections) {
        conn.buffers.reserve(buffers_per_connection);
        
        for (size_t i = 0; i < buffers_per_connection; ++i) {
            // Vary buffer sizes to simulate real usage
            size_t buffer_size = (i % 3 == 0) ? small_size_ : 
                                (i % 3 == 1) ? medium_size_ : large_size_;
            
            PooledBuffer buffer(buffer_size);
            EXPECT_TRUE(buffer.is_valid());
            
            // Simulate data processing
            auto data = generate_random_data(std::min(buffer_size / 2, buffer->capacity()));
            if (data.size() <= buffer->capacity()) {
                std::memcpy(buffer->mutable_data(), data.data(), data.size());
                conn.bytes_processed += data.size();
            }
            
            conn.buffers.push_back(std::move(buffer));
        }
    }
    
    // Verify system state
    size_t total_bytes = 0;
    for (const auto& conn : connections) {
        total_bytes += conn.bytes_processed;
    }
    EXPECT_GT(total_bytes, 0);
    
    // Test cleanup - buffers should be automatically returned
    connections.clear();
    
    // Verify pools are in good state
    auto stats = GlobalPoolManager::instance().get_all_statistics();
    for (const auto& stat : stats) {
        // All buffers should be available again
        EXPECT_EQ(stat.available_buffers, stat.total_buffers);
    }
}

TEST_F(ComprehensiveMemoryTest, ErrorConditionHandling) {
    // Test various error conditions and recovery
    
    // Test invalid buffer operations
    ZeroCopyBuffer buffer(0); // Zero-sized buffer
    auto append_result = buffer.append(test_data_.data(), 100);
    
    // Test invalid slicing
    ZeroCopyBuffer valid_buffer(256);
    auto invalid_slice = valid_buffer.slice(300, 100); // Beyond buffer size
    EXPECT_TRUE(invalid_slice.is_error());
    
    // Test pool with invalid parameters
    try {
        BufferPool invalid_pool(0, 10); // Zero buffer size
        EXPECT_EQ(invalid_pool.buffer_size(), 0);
    } catch (...) {
        // Constructor might throw for invalid parameters
    }
    
    // Test memory pressure simulation
    std::vector<PooledBuffer> pressure_buffers;
    try {
        // Try to allocate many buffers to create pressure
        for (size_t i = 0; i < 1000; ++i) {
            PooledBuffer buffer(4096);
            if (buffer.is_valid()) {
                pressure_buffers.push_back(std::move(buffer));
            } else {
                break; // Stop when allocation fails
            }
        }
    } catch (...) {
        // Memory pressure might cause exceptions
    }
    
    // System should recover after releasing buffers
    pressure_buffers.clear();
    
    // Verify we can still allocate normally
    PooledBuffer recovery_buffer(1024);
    EXPECT_TRUE(recovery_buffer.is_valid());
}

} // anonymous namespace