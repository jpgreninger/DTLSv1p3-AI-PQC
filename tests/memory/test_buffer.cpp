/**
 * @file test_buffer.cpp
 * @brief Comprehensive tests for DTLS memory buffer management
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <cstring>
#include <random>
#include <thread>
#include <future>

#include "dtls/memory/buffer.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class BufferTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        // Create patterns for testing
        small_pattern_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        large_pattern_.resize(4096);
        for (size_t i = 0; i < large_pattern_.size(); ++i) {
            large_pattern_[i] = static_cast<std::byte>(i % 256);
        }
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> small_pattern_;
    std::vector<std::byte> large_pattern_;
};

// Test basic buffer construction and properties
TEST_F(BufferTest, BasicConstruction) {
    // Default construction
    ZeroCopyBuffer buffer1;
    EXPECT_EQ(buffer1.size(), 0);
    EXPECT_GE(buffer1.capacity(), 0);
    EXPECT_TRUE(buffer1.empty());
    
    // Construction with capacity
    ZeroCopyBuffer buffer2(1024);
    EXPECT_EQ(buffer2.size(), 0);
    EXPECT_GE(buffer2.capacity(), 1024);
    EXPECT_TRUE(buffer2.empty());
    EXPECT_EQ(buffer2.available_space(), buffer2.capacity());
}

// Test buffer data operations
TEST_F(BufferTest, DataOperations) {
    ZeroCopyBuffer buffer(1024);
    
    // Test append
    auto result = buffer.append(small_pattern_.data(), small_pattern_.size());
    ASSERT_TRUE(result.is_ok());
    
    EXPECT_EQ(buffer.size(), small_pattern_.size());
    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(std::memcmp(buffer.data(), small_pattern_.data(), small_pattern_.size()), 0);
    
    // Test append another buffer
    ZeroCopyBuffer buffer2(small_pattern_.data(), small_pattern_.size());
    result = buffer.append(buffer2);
    ASSERT_TRUE(result.is_ok());
    
    EXPECT_EQ(buffer.size(), small_pattern_.size() * 2);
    EXPECT_EQ(std::memcmp(buffer.data(), small_pattern_.data(), small_pattern_.size()), 0);
    EXPECT_EQ(std::memcmp(buffer.data() + small_pattern_.size(), small_pattern_.data(), small_pattern_.size()), 0);
}

// Test prepend operations
TEST_F(BufferTest, PrependOperations) {
    ZeroCopyBuffer buffer(1024);
    
    // Add initial data
    auto result = buffer.append(small_pattern_.data(), small_pattern_.size());
    ASSERT_TRUE(result.is_ok());
    
    // Prepend different data
    std::vector<std::byte> prefix = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    result = buffer.prepend(prefix.data(), prefix.size());
    ASSERT_TRUE(result.is_ok());
    
    EXPECT_EQ(buffer.size(), small_pattern_.size() + prefix.size());
    EXPECT_EQ(std::memcmp(buffer.data(), prefix.data(), prefix.size()), 0);
    EXPECT_EQ(std::memcmp(buffer.data() + prefix.size(), small_pattern_.data(), small_pattern_.size()), 0);
}

// Test slicing operations
TEST_F(BufferTest, SlicingOperations) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Test basic slice
    auto slice_result = buffer.slice(10, 20);
    ASSERT_TRUE(slice_result.is_ok());
    
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), 20);
    EXPECT_EQ(std::memcmp(slice.data(), test_data_.data() + 10, 20), 0);
    
    // Test zero-copy slice
    auto zero_copy_slice = buffer.create_slice(50, 30);
    EXPECT_EQ(zero_copy_slice.size(), 30);
    EXPECT_EQ(std::memcmp(zero_copy_slice.data(), test_data_.data() + 50, 30), 0);
    
    // Test slice bounds
    auto invalid_slice = buffer.slice(test_data_.size() + 1, 10);
    EXPECT_TRUE(invalid_slice.is_error());
    
    auto invalid_slice2 = buffer.slice(10, test_data_.size());
    EXPECT_TRUE(invalid_slice2.is_error());
}

// Test buffer sharing and reference counting
TEST_F(BufferTest, BufferSharing) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    
    // Test sharing
    auto share_result = original.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    
    auto shared = share_result.value();
    EXPECT_TRUE(shared.is_shared());
    EXPECT_GT(shared.reference_count(), 1);
    
    // Verify data integrity
    EXPECT_EQ(shared.size(), original.size());
    EXPECT_EQ(std::memcmp(shared.data(), original.data(), original.size()), 0);
    
    // Test copy semantics
    ZeroCopyBuffer copied = shared;
    EXPECT_TRUE(copied.is_shared());
    EXPECT_EQ(copied.reference_count(), shared.reference_count());
    
    // Test move semantics
    ZeroCopyBuffer moved = std::move(copied);
    EXPECT_TRUE(moved.is_shared());
    EXPECT_EQ(moved.size(), original.size());
}

// Test memory management operations
TEST_F(BufferTest, MemoryManagement) {
    ZeroCopyBuffer buffer(100);
    
    // Test reserve
    auto result = buffer.reserve(2048);
    EXPECT_TRUE(result.is_ok());
    EXPECT_GE(buffer.capacity(), 2048);
    
    // Add some data
    result = buffer.append(small_pattern_.data(), small_pattern_.size());
    ASSERT_TRUE(result.is_ok());
    
    // Test resize
    result = buffer.resize(512);
    EXPECT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), 512);
    
    // Test shrink_to_fit
    buffer.shrink_to_fit();
    EXPECT_GE(buffer.capacity(), buffer.size());
    
    // Test clear
    buffer.clear();
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_TRUE(buffer.empty());
}

// Test error conditions and edge cases
TEST_F(BufferTest, ErrorConditions) {
    ZeroCopyBuffer small_buffer(10);
    
    // Test buffer overflow
    auto result = small_buffer.append(large_pattern_.data(), large_pattern_.size());
    EXPECT_TRUE(result.is_error());
    
    // Test null data append
    result = small_buffer.append(nullptr, 10);
    EXPECT_TRUE(result.is_error());
    
    // Test prepend overflow
    result = small_buffer.prepend(large_pattern_.data(), large_pattern_.size());
    EXPECT_TRUE(result.is_error());
    
    // Test invalid resize
    result = small_buffer.resize(SIZE_MAX);
    EXPECT_TRUE(result.is_error());
}

// Test buffer security features
TEST_F(BufferTest, SecurityFeatures) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Test zero memory
    buffer.zero_memory();
    
    // Verify data is zeroed
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], std::byte{0});
    }
}

// Test copy-on-write behavior
TEST_F(BufferTest, CopyOnWrite) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    auto shared_result = original.share_buffer();
    ASSERT_TRUE(shared_result.is_ok());
    
    auto shared = shared_result.value();
    
    // Initially both should reference same data
    EXPECT_TRUE(shared.is_shared());
    EXPECT_FALSE(shared.can_modify());
    
    // Make unique should trigger copy
    auto result = shared.make_unique();
    EXPECT_TRUE(result.is_ok());
    EXPECT_FALSE(shared.is_shared());
    EXPECT_TRUE(shared.can_modify());
    
    // Verify data integrity after copy
    EXPECT_EQ(shared.size(), original.size());
    EXPECT_EQ(std::memcmp(shared.data(), test_data_.data(), test_data_.size()), 0);
}

// Test iterator support
TEST_F(BufferTest, IteratorSupport) {
    ZeroCopyBuffer buffer(small_pattern_.data(), small_pattern_.size());
    
    // Test mutable iterator
    auto* begin = buffer.begin();
    auto* end = buffer.end();
    
    EXPECT_EQ(end - begin, static_cast<ptrdiff_t>(buffer.size()));
    
    // Verify iterator values
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(begin[i], small_pattern_[i]);
    }
    
    // Test const iterator
    const auto& const_buffer = buffer;
    auto* const_begin = const_buffer.cbegin();
    auto* const_end = const_buffer.cend();
    
    EXPECT_EQ(const_end - const_begin, static_cast<ptrdiff_t>(buffer.size()));
    
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(const_begin[i], small_pattern_[i]);
    }
}

// Test large buffer operations
TEST_F(BufferTest, LargeBufferOperations) {
    constexpr size_t large_size = 1024 * 1024; // 1MB
    ZeroCopyBuffer large_buffer(large_size);
    
    // Fill with pattern
    std::vector<std::byte> pattern(1024);
    for (size_t i = 0; i < pattern.size(); ++i) {
        pattern[i] = static_cast<std::byte>(i % 256);
    }
    
    for (size_t i = 0; i < large_size / pattern.size(); ++i) {
        auto result = large_buffer.append(pattern.data(), pattern.size());
        ASSERT_TRUE(result.is_ok());
    }
    
    EXPECT_EQ(large_buffer.size(), large_size);
    
    // Test large slice
    auto slice_result = large_buffer.slice(1024, 2048);
    ASSERT_TRUE(slice_result.is_ok());
    
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), 2048);
}

// Test concurrent access patterns
TEST_F(BufferTest, ConcurrentAccess) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    
    // Create multiple shared references
    std::vector<ZeroCopyBuffer> shared_buffers;
    for (int i = 0; i < 10; ++i) {
        auto result = original.share_buffer();
        ASSERT_TRUE(result.is_ok());
        shared_buffers.push_back(result.value());
    }
    
    // Verify all references are valid
    for (const auto& buffer : shared_buffers) {
        EXPECT_TRUE(buffer.is_shared());
        EXPECT_GT(buffer.reference_count(), 1);
        EXPECT_EQ(buffer.size(), original.size());
        EXPECT_EQ(std::memcmp(buffer.data(), original.data(), original.size()), 0);
    }
    
    // Test concurrent slicing
    std::vector<std::future<void>> futures;
    std::atomic<int> errors{0};
    
    for (size_t i = 0; i < shared_buffers.size(); ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            const size_t offset = i * 10;
            const size_t length = 50;
            
            if (offset + length <= shared_buffers[i].size()) {
                auto slice = shared_buffers[i].create_slice(offset, length);
                if (slice.size() != length) {
                    errors.fetch_add(1);
                }
            }
        }));
    }
    
    for (auto& future : futures) {
        future.wait();
    }
    
    EXPECT_EQ(errors.load(), 0);
}

// Test memory alignment and performance characteristics
TEST_F(BufferTest, AlignmentAndPerformance) {
    ZeroCopyBuffer buffer(1024);
    
    // Test data alignment
    const auto* data_ptr = buffer.data();
    EXPECT_TRUE(data_ptr != nullptr);
    
    // Test that operations are reasonably fast
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 1000; ++i) {
        auto result = buffer.append(small_pattern_.data(), small_pattern_.size());
        if (result.is_error()) {
            buffer.clear();
            result = buffer.append(small_pattern_.data(), small_pattern_.size());
        }
        ASSERT_TRUE(result.is_ok());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Should be able to do 1000 appends in less than 100ms
    EXPECT_LT(duration.count(), 100);
}

// Test BufferView comprehensive functionality
TEST_F(BufferTest, BufferViewComprehensive) {
    // Test default construction
    BufferView empty_view;
    EXPECT_TRUE(empty_view.empty());
    EXPECT_EQ(empty_view.size(), 0);
    EXPECT_EQ(empty_view.data(), nullptr);
    
    // Test construction from data
    BufferView data_view(test_data_.data(), test_data_.size());
    EXPECT_FALSE(data_view.empty());
    EXPECT_EQ(data_view.size(), test_data_.size());
    EXPECT_NE(data_view.data(), nullptr);
    
    // Test construction from ZeroCopyBuffer
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    BufferView buffer_view(buffer);
    EXPECT_EQ(buffer_view.size(), buffer.size());
    EXPECT_EQ(buffer_view.data(), buffer.data());
    
    // Test slicing
    auto slice_view = data_view.slice(10, 20);
    EXPECT_EQ(slice_view.size(), 20);
    EXPECT_EQ(slice_view.data(), test_data_.data() + 10);
    
    // Test subview
    auto sub_view = data_view.subview(50);
    EXPECT_EQ(sub_view.size(), test_data_.size() - 50);
    EXPECT_EQ(sub_view.data(), test_data_.data() + 50);
    
    // Test iterator support
    size_t index = 0;
    for (auto byte : data_view) {
        EXPECT_EQ(byte, test_data_[index]);
        ++index;
    }
    EXPECT_EQ(index, test_data_.size());
    
    // Test indexing
    for (size_t i = 0; i < data_view.size(); ++i) {
        EXPECT_EQ(data_view[i], test_data_[i]);
    }
    
    // Test comparison
    BufferView identical_view(test_data_.data(), test_data_.size());
    EXPECT_EQ(data_view, identical_view);
    EXPECT_FALSE(data_view != identical_view);
    
    BufferView different_view(small_pattern_.data(), small_pattern_.size());
    EXPECT_NE(data_view, different_view);
    EXPECT_TRUE(data_view != different_view);
}

// Test MutableBufferView comprehensive functionality
TEST_F(BufferTest, MutableBufferViewComprehensive) {
    // Create mutable test data
    std::vector<std::byte> mutable_data = test_data_;
    
    // Test default construction
    MutableBufferView empty_view;
    EXPECT_TRUE(empty_view.empty());
    EXPECT_EQ(empty_view.size(), 0);
    EXPECT_EQ(empty_view.data(), nullptr);
    
    // Test construction from data
    MutableBufferView data_view(mutable_data.data(), mutable_data.size());
    EXPECT_FALSE(data_view.empty());
    EXPECT_EQ(data_view.size(), mutable_data.size());
    EXPECT_NE(data_view.data(), nullptr);
    
    // Test construction from ZeroCopyBuffer
    ZeroCopyBuffer buffer(1024);
    auto result = buffer.append(test_data_.data(), test_data_.size());
    ASSERT_TRUE(result.is_ok());
    
    MutableBufferView buffer_view(buffer);
    EXPECT_EQ(buffer_view.size(), buffer.size());
    EXPECT_EQ(buffer_view.data(), buffer.mutable_data());
    
    // Test slicing
    auto slice_view = data_view.slice(10, 20);
    EXPECT_EQ(slice_view.size(), 20);
    EXPECT_EQ(slice_view.data(), mutable_data.data() + 10);
    
    // Test subview
    auto sub_view = data_view.subview(50);
    EXPECT_EQ(sub_view.size(), mutable_data.size() - 50);
    EXPECT_EQ(sub_view.data(), mutable_data.data() + 50);
    
    // Test mutable operations
    data_view.fill(std::byte{0xFF});
    for (size_t i = 0; i < data_view.size(); ++i) {
        EXPECT_EQ(data_view[i], std::byte{0xFF});
        EXPECT_EQ(mutable_data[i], std::byte{0xFF});
    }
    
    // Test zero operation
    data_view.zero();
    for (size_t i = 0; i < data_view.size(); ++i) {
        EXPECT_EQ(data_view[i], std::byte{0});
        EXPECT_EQ(mutable_data[i], std::byte{0});
    }
    
    // Test iterator support (mutable)
    size_t index = 0;
    for (auto& byte : data_view) {
        byte = static_cast<std::byte>(index % 256);
        ++index;
    }
    
    // Verify changes were applied
    for (size_t i = 0; i < data_view.size(); ++i) {
        EXPECT_EQ(data_view[i], static_cast<std::byte>(i % 256));
        EXPECT_EQ(mutable_data[i], static_cast<std::byte>(i % 256));
    }
    
    // Test conversion to immutable view
    BufferView immutable_view = data_view;
    EXPECT_EQ(immutable_view.size(), data_view.size());
    EXPECT_EQ(immutable_view.data(), data_view.data());
}

// Test BufferSharedState functionality
TEST_F(BufferTest, BufferSharedState) {
    // Create shared state
    auto data = std::make_unique<std::byte[]>(1024);
    std::memcpy(data.get(), test_data_.data(), std::min(test_data_.size(), size_t{1024}));
    
    auto shared_state = std::make_shared<BufferSharedState>(std::move(data), 1024);
    
    EXPECT_EQ(shared_state->capacity(), 1024);
    EXPECT_NE(shared_state->data(), nullptr);
    EXPECT_NE(shared_state->mutable_data(), nullptr);
    EXPECT_EQ(shared_state->ref_count.load(), 1);
    
    // Test data integrity
    EXPECT_EQ(std::memcmp(shared_state->data(), test_data_.data(), 
                         std::min(test_data_.size(), size_t{1024})), 0);
    
    // Test secure zero
    shared_state->secure_zero();
    for (size_t i = 0; i < shared_state->capacity(); ++i) {
        EXPECT_EQ(shared_state->data()[i], std::byte{0});
    }
}

// Test utility functions
TEST_F(BufferTest, UtilityFunctions) {
    // Test constant_time_compare
    BufferView view1(test_data_.data(), test_data_.size());
    BufferView view2(test_data_.data(), test_data_.size());
    BufferView view3(small_pattern_.data(), small_pattern_.size());
    
    EXPECT_TRUE(constant_time_compare(view1, view2));
    EXPECT_FALSE(constant_time_compare(view1, view3));
    
    // Test different sized buffers
    BufferView short_view(test_data_.data(), 10);
    EXPECT_FALSE(constant_time_compare(view1, short_view));
    
    // Test find_byte
    auto find_result = find_byte(view1, test_data_[100]);
    EXPECT_EQ(find_result, 100);
    
    find_result = find_byte(view1, std::byte{0xFF});
    EXPECT_EQ(find_result, SIZE_MAX); // Not found
    
    // Test concatenate_buffers
    std::vector<BufferView> buffers_to_concat = {
        BufferView(small_pattern_.data(), small_pattern_.size()),
        BufferView(test_data_.data(), 100),
        BufferView(small_pattern_.data(), small_pattern_.size())
    };
    
    auto concat_result = concatenate_buffers(buffers_to_concat);
    ASSERT_TRUE(concat_result.is_ok());
    
    auto concatenated = concat_result.value();
    size_t expected_size = small_pattern_.size() + 100 + small_pattern_.size();
    EXPECT_EQ(concatenated.size(), expected_size);
    
    // Verify concatenated data
    EXPECT_EQ(std::memcmp(concatenated.data(), small_pattern_.data(), small_pattern_.size()), 0);
    EXPECT_EQ(std::memcmp(concatenated.data() + small_pattern_.size(), 
                         test_data_.data(), 100), 0);
    EXPECT_EQ(std::memcmp(concatenated.data() + small_pattern_.size() + 100, 
                         small_pattern_.data(), small_pattern_.size()), 0);
    
    // Test hex encoding/decoding
    BufferView hex_view(small_pattern_.data(), small_pattern_.size());
    auto hex_string = to_hex_string(hex_view);
    EXPECT_FALSE(hex_string.empty());
    EXPECT_EQ(hex_string.length(), small_pattern_.size() * 2);
    
    // Test hex decoding
    auto decode_result = from_hex_string(hex_string);
    ASSERT_TRUE(decode_result.is_ok());
    
    auto decoded = decode_result.value();
    EXPECT_EQ(decoded.size(), small_pattern_.size());
    EXPECT_EQ(std::memcmp(decoded.data(), small_pattern_.data(), small_pattern_.size()), 0);
    
    // Test invalid hex string
    auto invalid_decode = from_hex_string("invalid_hex_string");
    EXPECT_TRUE(invalid_decode.is_error());
}

// Test buffer performance hints
TEST_F(BufferTest, PerformanceHints) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Test hints (these shouldn't crash or change functionality)
    buffer.hint_sequential_access();
    buffer.hint_random_access();
    buffer.hint_read_only();
    
    // Verify buffer is still functional
    EXPECT_EQ(buffer.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(buffer.data(), test_data_.data(), test_data_.size()), 0);
}

// Test buffer state queries
TEST_F(BufferTest, BufferStateQueries) {
    // Test owning buffer
    ZeroCopyBuffer owning_buffer(test_data_.data(), test_data_.size());
    EXPECT_TRUE(owning_buffer.is_owning());
    
    // Test shared buffer
    auto share_result = owning_buffer.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    
    auto shared_buffer = share_result.value();
    EXPECT_TRUE(shared_buffer.is_shared());
    EXPECT_FALSE(shared_buffer.can_modify());
    
    // Test reference counting
    EXPECT_GT(shared_buffer.reference_count(), 1);
    
    // Test make_unique
    auto make_unique_result = shared_buffer.make_unique();
    EXPECT_TRUE(make_unique_result.is_ok());
    EXPECT_FALSE(shared_buffer.is_shared());
    EXPECT_TRUE(shared_buffer.can_modify());
}

// Test edge cases and error conditions for buffer operations
TEST_F(BufferTest, EdgeCasesAndErrorConditions) {
    // Test zero-capacity buffer
    ZeroCopyBuffer zero_buffer(0);
    EXPECT_EQ(zero_buffer.capacity(), 0);
    EXPECT_EQ(zero_buffer.size(), 0);
    EXPECT_TRUE(zero_buffer.empty());
    
    // Test append to zero-capacity buffer
    auto append_result = zero_buffer.append(small_pattern_.data(), small_pattern_.size());
    EXPECT_TRUE(append_result.is_error());
    
    // Test slice with invalid parameters
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Offset beyond size
    auto invalid_slice1 = buffer.slice(test_data_.size() + 1, 10);
    EXPECT_TRUE(invalid_slice1.is_error());
    
    // Length extending beyond buffer
    auto invalid_slice2 = buffer.slice(test_data_.size() - 5, 10);
    EXPECT_TRUE(invalid_slice2.is_error());
    
    // Zero length slice (should be ok)
    auto zero_slice = buffer.slice(10, 0);
    EXPECT_TRUE(zero_slice.is_ok());
    EXPECT_EQ(zero_slice.value().size(), 0);
    
    // Test resize to larger than capacity
    ZeroCopyBuffer small_buffer(10);
    auto invalid_resize = small_buffer.resize(1000000); // Very large
    EXPECT_TRUE(invalid_resize.is_error());
    
    // Test reserve with invalid size
    auto invalid_reserve = small_buffer.reserve(SIZE_MAX);
    EXPECT_TRUE(invalid_reserve.is_error());
    
    // Test operations on shared buffer that require modification
    auto shared_result = buffer.share_buffer();
    ASSERT_TRUE(shared_result.is_ok());
    auto shared = shared_result.value();
    
    // These should not modify the shared buffer
    EXPECT_FALSE(shared.can_modify());
}

// Test memory security features
TEST_F(BufferTest, MemorySecurityFeatures) {
    // Test secure_zero_memory utility
    std::vector<std::byte> sensitive_data(100);
    std::fill(sensitive_data.begin(), sensitive_data.end(), std::byte{0xAA});
    
    secure_zero_memory(sensitive_data.data(), sensitive_data.size());
    
    for (const auto& byte : sensitive_data) {
        EXPECT_EQ(byte, std::byte{0});
    }
    
    // Test buffer secure_zero
    ZeroCopyBuffer secure_buffer(test_data_.data(), test_data_.size());
    secure_buffer.secure_zero();
    
    for (size_t i = 0; i < secure_buffer.size(); ++i) {
        EXPECT_EQ(secure_buffer.data()[i], std::byte{0});
    }
    
    // Test shared state secure_zero
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    auto share_result = original.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    
    auto shared = share_result.value();
    
    // Get the shared state and test secure zero
    if (shared.is_shared()) {
        // Create a buffer from shared state
        auto data = std::make_unique<std::byte[]>(1024);
        std::memcpy(data.get(), test_data_.data(), std::min(test_data_.size(), size_t{1024}));
        
        auto shared_state = std::make_shared<BufferSharedState>(std::move(data), 1024);
        shared_state->secure_zero();
        
        for (size_t i = 0; i < shared_state->capacity(); ++i) {
            EXPECT_EQ(shared_state->data()[i], std::byte{0});
        }
    }
}