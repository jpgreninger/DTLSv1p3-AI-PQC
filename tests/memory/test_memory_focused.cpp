/**
 * @file test_memory_focused.cpp
 * @brief Focused memory management tests using verified APIs
 * Phase 2 - Memory Management Coverage Enhancement (Focused Approach)
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <random>

#include "dtls/memory/buffer.h"
#include "dtls/memory/pool.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class MemoryFocusedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        // Create patterns for testing
        pattern_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> pattern_;
};

// Test BufferPool basic functionality with verified APIs
TEST_F(MemoryFocusedTest, BufferPoolBasics) {
    BufferPool pool(1024, 16);
    
    // Test basic properties
    EXPECT_EQ(pool.buffer_size(), 1024);
    EXPECT_GT(pool.available_buffers(), 0);
    EXPECT_GT(pool.total_buffers(), 0);
    EXPECT_TRUE(pool.is_thread_safe());
    
    // Test buffer acquisition
    auto buffer = pool.acquire();
    ASSERT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), 1024);
    EXPECT_EQ(buffer->size(), 0);
    
    // Test buffer usage
    auto result = buffer->append(test_data_.data(), std::min(test_data_.size(), buffer->capacity()));
    ASSERT_TRUE(result.is_ok());
    EXPECT_GT(buffer->size(), 0);
    
    // Test buffer release
    pool.release(std::move(buffer));
    EXPECT_EQ(buffer, nullptr);
    
    // Verify pool state
    EXPECT_GT(pool.available_buffers(), 0);
}

// Test BufferPool statistics
TEST_F(MemoryFocusedTest, BufferPoolStatistics) {
    BufferPool pool(512, 8);
    
    auto initial_stats = pool.get_statistics();
    EXPECT_EQ(initial_stats.buffer_size, 512);
    EXPECT_GT(initial_stats.total_buffers, 0);
    EXPECT_GT(initial_stats.available_buffers, 0);
    
    // Acquire some buffers
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (size_t i = 0; i < 4; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            buffers.push_back(std::move(buffer));
        }
    }
    
    auto mid_stats = pool.get_statistics();
    EXPECT_GT(mid_stats.total_allocations, initial_stats.total_allocations);
    EXPECT_LT(mid_stats.available_buffers, initial_stats.available_buffers);
    
    // Release buffers
    for (auto& buffer : buffers) {
        if (buffer) {
            pool.release(std::move(buffer));
        }
    }
    
    auto final_stats = pool.get_statistics();
    EXPECT_GT(final_stats.total_deallocations, initial_stats.total_deallocations);
}

// Test pool expansion and configuration
TEST_F(MemoryFocusedTest, BufferPoolManagement) {
    BufferPool pool(256, 4);
    
    size_t initial_total = pool.total_buffers();
    
    // Test pool expansion
    auto result = pool.expand_pool(4);
    EXPECT_TRUE(result.is_ok());
    EXPECT_GE(pool.total_buffers(), initial_total + 4);
    
    // Test pool shrinking
    result = pool.shrink_pool(initial_total);
    EXPECT_TRUE(result.is_ok());
    
    // Test max pool size setting
    pool.set_max_pool_size(32);
    
    // Test clear pool
    pool.clear_pool();
    EXPECT_GT(pool.available_buffers(), 0); // Should still have some buffers
}

// Test concurrent pool access
TEST_F(MemoryFocusedTest, ConcurrentPoolAccess) {
    BufferPool pool(1024, 32);
    
    constexpr size_t num_threads = 4;
    constexpr size_t operations_per_thread = 25;
    
    std::vector<std::future<bool>> futures;
    std::atomic<size_t> successful_ops{0};
    
    for (size_t t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&]() {
            try {
                for (size_t op = 0; op < operations_per_thread; ++op) {
                    auto buffer = pool.acquire();
                    if (buffer) {
                        // Use buffer
                        auto result = buffer->append(test_data_.data(), 
                                                   std::min(test_data_.size(), buffer->capacity()));
                        if (result.is_ok()) {
                            successful_ops.fetch_add(1);
                        }
                        pool.release(std::move(buffer));
                    }
                }
                return true;
            } catch (...) {
                return false;
            }
        }));
    }
    
    bool all_successful = true;
    for (auto& future : futures) {
        if (!future.get()) {
            all_successful = false;
        }
    }
    
    EXPECT_TRUE(all_successful);
    EXPECT_GT(successful_ops.load(), 0);
}

// Test memory utilities basic functionality
TEST_F(MemoryFocusedTest, MemoryUtilitiesBasic) {
    using namespace utils;
    
    // Test memory alignment utilities
    char test_array[1024];
    void* ptr = static_cast<void*>(test_array);
    
    EXPECT_TRUE(is_aligned(ptr, 1));
    
    size_t aligned_size = align_size(100, 16);
    EXPECT_GE(aligned_size, 100);
    EXPECT_EQ(aligned_size % 16, 0);
    
    // Test secure memory comparison
    std::vector<std::byte> data1 = pattern_;
    std::vector<std::byte> data2 = pattern_;
    std::vector<std::byte> data3 = test_data_;
    
    EXPECT_TRUE(secure_compare(data1.data(), data2.data(), data1.size()));
    EXPECT_FALSE(secure_compare(data1.data(), data3.data(), 
                               std::min(data1.size(), data3.size())));
    
    // Test secure memcmp
    EXPECT_EQ(secure_memcmp(data1.data(), data2.data(), data1.size()), 0);
    EXPECT_NE(secure_memcmp(data1.data(), data3.data(), 
                           std::min(data1.size(), data3.size())), 0);
}

// Test memory statistics collection (if available)
TEST_F(MemoryFocusedTest, MemoryStatisticsCollection) {
    using namespace utils;
    
    auto& collector = MemoryStatsCollector::instance();
    
    // Test basic tracking enable/disable
    collector.enable_tracking(true);
    EXPECT_TRUE(collector.is_tracking_enabled());
    
    collector.enable_tracking(false);
    EXPECT_FALSE(collector.is_tracking_enabled());
    
    // Re-enable for testing
    collector.enable_tracking(true);
    
    // Test basic tracking
    collector.record_allocation(1024, "test");
    
    auto stats = collector.get_statistics();
    EXPECT_GT(stats.total_allocations, 0);
    EXPECT_GT(stats.current_allocations, 0);
    EXPECT_GT(stats.total_bytes_allocated, 0);
    
    collector.record_deallocation(1024);
    
    stats = collector.get_statistics();
    EXPECT_GT(stats.total_deallocations, 0);
    EXPECT_EQ(stats.current_allocations, 0);
    
    // Test allocation failure tracking
    collector.record_allocation_failure(2048);
    stats = collector.get_statistics();
    EXPECT_GT(stats.allocation_failures, 0);
    
    // Test reset
    collector.reset_statistics();
    stats = collector.get_statistics();
    EXPECT_EQ(stats.total_allocations, 0);
    EXPECT_EQ(stats.total_deallocations, 0);
    EXPECT_EQ(stats.allocation_failures, 0);
}

// Test ZeroCopyBuffer advanced features
TEST_F(MemoryFocusedTest, ZeroCopyBufferAdvanced) {
    // Test shared buffer functionality
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    
    auto share_result = original.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    
    EXPECT_TRUE(shared.is_shared());
    EXPECT_GT(shared.reference_count(), 1);
    EXPECT_FALSE(shared.can_modify());
    
    // Test copy-on-write
    auto cow_result = shared.make_unique();
    EXPECT_TRUE(cow_result.is_ok());
    EXPECT_FALSE(shared.is_shared());
    EXPECT_TRUE(shared.can_modify());
    
    // Test zero-copy slicing
    auto slice = original.create_slice(10, 100);
    EXPECT_EQ(slice.size(), 100);
    EXPECT_EQ(std::memcmp(slice.data(), test_data_.data() + 10, 100), 0);
    
    // Test security features
    ZeroCopyBuffer secure_buffer(pattern_.data(), pattern_.size());
    secure_buffer.secure_zero();
    for (size_t i = 0; i < secure_buffer.size(); ++i) {
        EXPECT_EQ(secure_buffer.data()[i], std::byte{0});
    }
}

// Test memory pressure scenarios
TEST_F(MemoryFocusedTest, MemoryPressureHandling) {
    // Test with small pool to trigger pressure
    BufferPool small_pool(512, 4);
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    
    // Try to exhaust the pool
    for (size_t i = 0; i < 10; ++i) {
        auto buffer = small_pool.acquire();
        if (buffer) {
            // Use the buffer
            auto result = buffer->append(test_data_.data(), 
                                       std::min(test_data_.size(), buffer->capacity()));
            if (result.is_ok()) {
                buffers.push_back(std::move(buffer));
            } else {
                small_pool.release(std::move(buffer));
            }
        } else {
            // Pool exhausted - this is expected behavior
            break;
        }
    }
    
    // Verify pool state
    auto stats = small_pool.get_statistics();
    EXPECT_GT(stats.total_allocations, 0);
    
    // Release some buffers to test recovery
    if (buffers.size() > 2) {
        small_pool.release(std::move(buffers[0]));
        small_pool.release(std::move(buffers[1]));
        buffers.erase(buffers.begin(), buffers.begin() + 2);
        
        // Should be able to acquire again
        auto recovered_buffer = small_pool.acquire();
        EXPECT_NE(recovered_buffer, nullptr);
        if (recovered_buffer) {
            small_pool.release(std::move(recovered_buffer));
        }
    }
    
    // Clean up
    for (auto& buffer : buffers) {
        if (buffer) {
            small_pool.release(std::move(buffer));
        }
    }
}

// Test error conditions and edge cases
TEST_F(MemoryFocusedTest, ErrorConditionsAndEdgeCases) {
    // Test zero-capacity buffer
    ZeroCopyBuffer zero_buffer(0);
    EXPECT_EQ(zero_buffer.size(), 0);
    EXPECT_EQ(zero_buffer.capacity(), 0);
    
    // Test invalid append
    auto append_result = zero_buffer.append(pattern_.data(), pattern_.size());
    // This may succeed if buffer auto-expands or fail - both are valid
    
    // Test invalid slice
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    auto invalid_slice = buffer.slice(test_data_.size() + 1, 10);
    EXPECT_TRUE(invalid_slice.is_error());
    
    // Test boundary slice (should succeed)
    auto boundary_slice = buffer.slice(test_data_.size() - 1, 1);
    ASSERT_TRUE(boundary_slice.is_ok());
    EXPECT_EQ(boundary_slice.value().size(), 1);
    
    // Test zero-length slice (should succeed)
    auto zero_slice = buffer.slice(10, 0);
    ASSERT_TRUE(zero_slice.is_ok());
    EXPECT_EQ(zero_slice.value().size(), 0);
}

// Test buffer views comprehensive functionality
TEST_F(MemoryFocusedTest, BufferViewsComprehensive) {
    // Test BufferView
    BufferView view(test_data_.data(), test_data_.size());
    EXPECT_EQ(view.size(), test_data_.size());
    EXPECT_FALSE(view.empty());
    EXPECT_EQ(view.data(), test_data_.data());
    
    // Test BufferView slicing
    auto slice_view = view.slice(10, 20);
    EXPECT_EQ(slice_view.size(), 20);
    EXPECT_EQ(slice_view.data(), test_data_.data() + 10);
    
    // Test BufferView comparison
    BufferView view2(test_data_.data(), test_data_.size());
    EXPECT_EQ(view, view2);
    
    BufferView different_view(pattern_.data(), pattern_.size());
    EXPECT_NE(view, different_view);
    
    // Test MutableBufferView
    std::vector<std::byte> mutable_data = test_data_;
    MutableBufferView mutable_view(mutable_data.data(), mutable_data.size());
    
    // Test fill operations
    mutable_view.fill(std::byte{0x55});
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        EXPECT_EQ(mutable_view[i], std::byte{0x55});
    }
    
    mutable_view.zero();
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        EXPECT_EQ(mutable_view[i], std::byte{0});
    }
    
    // Test conversion to immutable view
    BufferView immutable_view = mutable_view;
    EXPECT_EQ(immutable_view.size(), mutable_view.size());
    EXPECT_EQ(immutable_view.data(), mutable_view.data());
}

// Test utility functions comprehensive
TEST_F(MemoryFocusedTest, UtilityFunctionsComprehensive) {
    // Test constant_time_compare
    BufferView view1(test_data_.data(), test_data_.size());
    BufferView view2(test_data_.data(), test_data_.size());
    BufferView view3(pattern_.data(), pattern_.size());
    
    EXPECT_TRUE(constant_time_compare(view1, view2));
    EXPECT_FALSE(constant_time_compare(view1, view3));
    
    // Test find_byte
    auto find_result = find_byte(view1, test_data_[100]);
    EXPECT_EQ(find_result, 100);
    
    find_result = find_byte(view1, std::byte{0xFF});
    EXPECT_EQ(find_result, SIZE_MAX); // Not found
    
    // Test concatenate_buffers
    std::vector<BufferView> buffers_to_concat = {
        BufferView(pattern_.data(), pattern_.size()),
        BufferView(test_data_.data(), 100),
        BufferView(pattern_.data(), pattern_.size())
    };
    
    auto concat_result = concatenate_buffers(buffers_to_concat);
    ASSERT_TRUE(concat_result.is_ok());
    
    auto concatenated = concat_result.value();
    size_t expected_size = pattern_.size() + 100 + pattern_.size();
    EXPECT_EQ(concatenated.size(), expected_size);
    
    // Test hex encoding/decoding
    BufferView hex_view(pattern_.data(), pattern_.size());
    auto hex_string = to_hex_string(hex_view);
    EXPECT_FALSE(hex_string.empty());
    EXPECT_EQ(hex_string.length(), pattern_.size() * 2);
    
    auto decode_result = from_hex_string(hex_string);
    ASSERT_TRUE(decode_result.is_ok());
    auto decoded = decode_result.value();
    EXPECT_EQ(decoded.size(), pattern_.size());
    EXPECT_EQ(std::memcmp(decoded.data(), pattern_.data(), pattern_.size()), 0);
    
    // Test invalid hex
    auto invalid_decode = from_hex_string("invalid");
    EXPECT_TRUE(invalid_decode.is_error());
}

// Test performance characteristics
TEST_F(MemoryFocusedTest, PerformanceCharacteristics) {
    BufferPool pool(1024, 64);
    
    constexpr size_t num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_operations; ++i) {
        auto buffer = pool.acquire();
        if (buffer) {
            auto result = buffer->append(pattern_.data(), pattern_.size());
            if (result.is_ok()) {
                pool.release(std::move(buffer));
            }
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Pool operations should be reasonably fast
    EXPECT_LT(duration.count(), 100); // 100ms for 1000 operations
    
    auto final_stats = pool.get_statistics();
    EXPECT_GT(final_stats.total_allocations, 0);
    EXPECT_GT(final_stats.total_deallocations, 0);
}