/**
 * @file test_buffer_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS memory buffer management
 * Phase 2 - Memory Management Coverage Enhancement
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <cstring>
#include <random>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <limits>

#include "dtls/memory/buffer.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class BufferEnhancedTest : public ::testing::Test {
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
        
        // Security-focused test data
        sensitive_data_.resize(512);
        for (size_t i = 0; i < sensitive_data_.size(); ++i) {
            sensitive_data_[i] = static_cast<std::byte>(0xAA + (i % 16));
        }
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> small_pattern_;
    std::vector<std::byte> large_pattern_;
    std::vector<std::byte> sensitive_data_;
};

// Test BufferSharedState lifecycle and security features
TEST_F(BufferEnhancedTest, BufferSharedStateLifecycle) {
    // Test constructor with valid data
    auto data = std::make_unique<std::byte[]>(1024);
    std::memcpy(data.get(), test_data_.data(), std::min(test_data_.size(), size_t{1024}));
    
    auto shared_state = std::make_shared<BufferSharedState>(std::move(data), 1024);
    
    // Test basic properties
    EXPECT_EQ(shared_state->capacity(), 1024);
    EXPECT_NE(shared_state->data(), nullptr);
    EXPECT_NE(shared_state->mutable_data(), nullptr);
    EXPECT_EQ(shared_state->ref_count.load(), 1);
    
    // Test data integrity
    EXPECT_EQ(std::memcmp(shared_state->data(), test_data_.data(), 
                         std::min(test_data_.size(), size_t{1024})), 0);
    
    // Test mutable data access
    shared_state->mutable_data()[0] = std::byte{0xFF};
    EXPECT_EQ(shared_state->data()[0], std::byte{0xFF});
    
    // Test reference counting behavior
    {
        auto copy_ref = shared_state;
        EXPECT_EQ(shared_state->ref_count.load(), 1); // shared_ptr handles this, not our counter
    }
    
    // Test secure zero
    shared_state->secure_zero();
    for (size_t i = 0; i < shared_state->capacity(); ++i) {
        EXPECT_EQ(shared_state->data()[i], std::byte{0});
    }
}

// Test ZeroCopyBuffer constructor variations and edge cases
TEST_F(BufferEnhancedTest, ZeroCopyBufferConstructors) {
    // Test default constructor
    ZeroCopyBuffer buffer1;
    EXPECT_EQ(buffer1.size(), 0);
    EXPECT_EQ(buffer1.capacity(), 0);
    EXPECT_TRUE(buffer1.empty());
    EXPECT_TRUE(buffer1.is_owning());
    EXPECT_FALSE(buffer1.is_shared());
    EXPECT_FALSE(buffer1.is_pooled());
    
    // Test capacity constructor with zero capacity
    ZeroCopyBuffer buffer2(0);
    EXPECT_EQ(buffer2.size(), 0);
    EXPECT_EQ(buffer2.capacity(), 0);
    EXPECT_TRUE(buffer2.empty());
    
    // Test capacity constructor with valid capacity
    ZeroCopyBuffer buffer3(512);
    EXPECT_EQ(buffer3.size(), 0);
    EXPECT_GE(buffer3.capacity(), 512);
    EXPECT_TRUE(buffer3.empty());
    EXPECT_EQ(buffer3.available_space(), buffer3.capacity());
    
    // Test data constructor with unique_ptr
    auto data = std::make_unique<std::byte[]>(256);
    std::memcpy(data.get(), small_pattern_.data(), small_pattern_.size());
    ZeroCopyBuffer buffer4(std::move(data), small_pattern_.size(), 256);
    EXPECT_EQ(buffer4.size(), small_pattern_.size());
    EXPECT_EQ(buffer4.capacity(), 256);
    EXPECT_EQ(std::memcmp(buffer4.data(), small_pattern_.data(), small_pattern_.size()), 0);
    
    // Test copy constructor from raw data
    ZeroCopyBuffer buffer5(test_data_.data(), test_data_.size());
    EXPECT_EQ(buffer5.size(), test_data_.size());
    EXPECT_GE(buffer5.capacity(), test_data_.size());
    EXPECT_EQ(std::memcmp(buffer5.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test copy constructor from raw data with empty data
    ZeroCopyBuffer buffer6(nullptr, 0);
    EXPECT_EQ(buffer6.size(), 0);
    EXPECT_EQ(buffer6.capacity(), 0);
    EXPECT_TRUE(buffer6.empty());
}

// Test buffer operations under various conditions
TEST_F(BufferEnhancedTest, BufferOperationsRobustness) {
    ZeroCopyBuffer buffer(2048);
    
    // Test append operations
    auto result = buffer.append(small_pattern_.data(), small_pattern_.size());
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), small_pattern_.size());
    
    // Test append to self (should work)
    ZeroCopyBuffer buffer2(small_pattern_.data(), small_pattern_.size());
    result = buffer.append(buffer2);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), small_pattern_.size() * 2);
    
    // Test append with null data - should fail gracefully
    result = buffer.append(nullptr, 10);
    EXPECT_TRUE(result.is_error());
    
    // Test append with zero length - should succeed
    result = buffer.append(small_pattern_.data(), 0);
    EXPECT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), small_pattern_.size() * 2); // Size unchanged
    
    // Test prepend operations
    result = buffer.prepend(test_data_.data(), 100);
    ASSERT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), small_pattern_.size() * 2 + 100);
    
    // Verify data integrity after prepend
    EXPECT_EQ(std::memcmp(buffer.data(), test_data_.data(), 100), 0);
    EXPECT_EQ(std::memcmp(buffer.data() + 100, small_pattern_.data(), small_pattern_.size()), 0);
}

// Test slicing operations thoroughly
TEST_F(BufferEnhancedTest, SlicingOperationsComprehensive) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Test valid slices
    auto slice_result = buffer.slice(10, 20);
    ASSERT_TRUE(slice_result.is_ok());
    auto slice = slice_result.value();
    EXPECT_EQ(slice.size(), 20);
    EXPECT_EQ(std::memcmp(slice.data(), test_data_.data() + 10, 20), 0);
    
    // Test slice at buffer boundary
    slice_result = buffer.slice(test_data_.size() - 10, 10);
    ASSERT_TRUE(slice_result.is_ok());
    slice = slice_result.value();
    EXPECT_EQ(slice.size(), 10);
    
    // Test zero-length slice (should be valid)
    slice_result = buffer.slice(50, 0);
    ASSERT_TRUE(slice_result.is_ok());
    slice = slice_result.value();
    EXPECT_EQ(slice.size(), 0);
    EXPECT_TRUE(slice.empty());
    
    // Test slice starting at end (zero length)
    slice_result = buffer.slice(test_data_.size(), 0);
    ASSERT_TRUE(slice_result.is_ok());
    slice = slice_result.value();
    EXPECT_EQ(slice.size(), 0);
    
    // Test invalid slices
    // Offset beyond buffer
    auto invalid_slice = buffer.slice(test_data_.size() + 1, 10);
    EXPECT_TRUE(invalid_slice.is_error());
    
    // Length extending beyond buffer  
    invalid_slice = buffer.slice(test_data_.size() - 5, 10);
    EXPECT_TRUE(invalid_slice.is_error());
    
    // Test zero-copy slicing
    auto zero_copy_slice = buffer.create_slice(50, 30);
    EXPECT_EQ(zero_copy_slice.size(), 30);
    EXPECT_EQ(std::memcmp(zero_copy_slice.data(), test_data_.data() + 50, 30), 0);
    
    // Test zero-copy slice edge cases
    auto edge_slice = buffer.create_slice(test_data_.size() - 1, 1);
    EXPECT_EQ(edge_slice.size(), 1);
    EXPECT_EQ(edge_slice.data()[0], test_data_[test_data_.size() - 1]);
}

// Test memory management with reasonable limits
TEST_F(BufferEnhancedTest, MemoryManagementSafety) {
    ZeroCopyBuffer buffer(100);
    
    // Test normal reserve
    auto result = buffer.reserve(1024);
    EXPECT_TRUE(result.is_ok());
    EXPECT_GE(buffer.capacity(), 1024);
    
    // Test reserve with unreasonable size (but not overflow)
    constexpr size_t large_but_reasonable = 1024 * 1024; // 1MB
    result = buffer.reserve(large_but_reasonable);
    if (result.is_ok()) {
        EXPECT_GE(buffer.capacity(), large_but_reasonable);
    } else {
        // It's acceptable to fail with out of memory for large allocations
        EXPECT_EQ(result.error(), DTLSError::OUT_OF_MEMORY);
    }
    
    // Test resize with valid sizes
    result = buffer.resize(512);
    EXPECT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), 512);
    
    // Test resize larger than capacity (should reserve)
    size_t old_capacity = buffer.capacity();
    result = buffer.resize(old_capacity + 256);
    EXPECT_TRUE(result.is_ok());
    EXPECT_EQ(buffer.size(), old_capacity + 256);
    EXPECT_GE(buffer.capacity(), old_capacity + 256);
    
    // Test shrink_to_fit
    buffer.shrink_to_fit();
    EXPECT_GE(buffer.capacity(), buffer.size());
    
    // Test clear
    buffer.clear();
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_TRUE(buffer.empty());
}

// Test sharing and copy-on-write behavior
TEST_F(BufferEnhancedTest, SharingAndCopyOnWrite) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    
    // Test basic sharing
    auto share_result = original.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    
    EXPECT_TRUE(shared.is_shared());
    EXPECT_GT(shared.reference_count(), 1);
    EXPECT_FALSE(shared.can_modify());
    
    // Test data integrity
    EXPECT_EQ(shared.size(), original.size());
    EXPECT_EQ(std::memcmp(shared.data(), original.data(), original.size()), 0);
    
    // Test copy semantics
    ZeroCopyBuffer copied = shared;
    EXPECT_TRUE(copied.is_shared());
    EXPECT_EQ(copied.size(), shared.size());
    
    // Test move semantics
    ZeroCopyBuffer moved = std::move(copied);
    EXPECT_TRUE(moved.is_shared());
    EXPECT_EQ(moved.size(), shared.size());
    
    // Test copy-on-write
    auto make_unique_result = shared.make_unique();
    EXPECT_TRUE(make_unique_result.is_ok());
    EXPECT_FALSE(shared.is_shared());
    EXPECT_TRUE(shared.can_modify());
    
    // Verify data integrity after COW
    EXPECT_EQ(shared.size(), original.size());
    EXPECT_EQ(std::memcmp(shared.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test modification after COW
    if (shared.can_modify() && shared.size() > 0) {
        shared.mutable_data()[0] = std::byte{0xFF};
        EXPECT_EQ(shared.data()[0], std::byte{0xFF});
        // Original should be unchanged
        EXPECT_NE(original.data()[0], std::byte{0xFF});
    }
}

// Test iterator support and data access
TEST_F(BufferEnhancedTest, IteratorAndDataAccess) {
    ZeroCopyBuffer buffer(small_pattern_.data(), small_pattern_.size());
    
    // Test mutable iterators
    size_t index = 0;
    for (auto& byte : buffer) {
        EXPECT_EQ(byte, small_pattern_[index]);
        ++index;
    }
    EXPECT_EQ(index, small_pattern_.size());
    
    // Test const iterators
    const auto& const_buffer = buffer;
    index = 0;
    for (const auto& byte : const_buffer) {
        EXPECT_EQ(byte, small_pattern_[index]);
        ++index;
    }
    EXPECT_EQ(index, small_pattern_.size());
    
    // Test explicit iterator methods
    auto begin = buffer.begin();
    auto end = buffer.end();
    EXPECT_EQ(std::distance(begin, end), static_cast<ptrdiff_t>(buffer.size()));
    
    auto cbegin = buffer.cbegin();
    auto cend = buffer.cend();
    EXPECT_EQ(std::distance(cbegin, cend), static_cast<ptrdiff_t>(buffer.size()));
    
    // Test array access operator
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer[i], small_pattern_[i]);
        EXPECT_EQ(const_buffer[i], small_pattern_[i]);
    }
}

// Test security features comprehensively
TEST_F(BufferEnhancedTest, SecurityFeatures) {
    // Test secure_zero on buffer
    ZeroCopyBuffer buffer(sensitive_data_.data(), sensitive_data_.size());
    
    // Verify data was copied correctly
    EXPECT_EQ(std::memcmp(buffer.data(), sensitive_data_.data(), sensitive_data_.size()), 0);
    
    // Test buffer secure_zero
    buffer.secure_zero();
    for (size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], std::byte{0});
    }
    
    // Test zero_memory (regular)
    ZeroCopyBuffer buffer2(sensitive_data_.data(), sensitive_data_.size());
    buffer2.zero_memory();
    for (size_t i = 0; i < buffer2.size(); ++i) {
        EXPECT_EQ(buffer2.data()[i], std::byte{0});
    }
    
    // Test secure_zero_memory utility function
    std::vector<std::byte> test_vector = sensitive_data_;
    secure_zero_memory(test_vector.data(), test_vector.size());
    for (const auto& byte : test_vector) {
        EXPECT_EQ(byte, std::byte{0});
    }
    
    // Test that original sensitive data is unchanged
    bool has_non_zero = false;
    for (const auto& byte : sensitive_data_) {
        if (byte != std::byte{0}) {
            has_non_zero = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero);
}

// Test buffer view functionality comprehensively
TEST_F(BufferEnhancedTest, BufferViewOperations) {
    // Test BufferView construction and operations
    BufferView view(test_data_.data(), test_data_.size());
    EXPECT_EQ(view.size(), test_data_.size());
    EXPECT_FALSE(view.empty());
    EXPECT_EQ(view.data(), test_data_.data());
    
    // Test BufferView from ZeroCopyBuffer
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    BufferView buffer_view(buffer);
    EXPECT_EQ(buffer_view.size(), buffer.size());
    EXPECT_EQ(buffer_view.data(), buffer.data());
    
    // Test BufferView slicing
    auto slice_view = view.slice(10, 20);
    EXPECT_EQ(slice_view.size(), 20);
    EXPECT_EQ(slice_view.data(), test_data_.data() + 10);
    
    // Test BufferView subview
    auto sub_view = view.subview(50);
    EXPECT_EQ(sub_view.size(), test_data_.size() - 50);
    EXPECT_EQ(sub_view.data(), test_data_.data() + 50);
    
    // Test BufferView comparison
    BufferView view2(test_data_.data(), test_data_.size());
    EXPECT_EQ(view, view2);
    EXPECT_FALSE(view != view2);
    
    BufferView different_view(small_pattern_.data(), small_pattern_.size());
    EXPECT_NE(view, different_view);
    EXPECT_TRUE(view != different_view);
    
    // Test BufferView iterators
    size_t index = 0;
    for (auto byte : view) {
        EXPECT_EQ(byte, test_data_[index]);
        ++index;
    }
    EXPECT_EQ(index, test_data_.size());
}

// Test MutableBufferView functionality
TEST_F(BufferEnhancedTest, MutableBufferViewOperations) {
    std::vector<std::byte> mutable_data = test_data_;
    
    // Test MutableBufferView construction
    MutableBufferView mutable_view(mutable_data.data(), mutable_data.size());
    EXPECT_EQ(mutable_view.size(), mutable_data.size());
    EXPECT_FALSE(mutable_view.empty());
    
    // Test MutableBufferView from ZeroCopyBuffer
    ZeroCopyBuffer buffer(2048);
    auto result = buffer.append(test_data_.data(), test_data_.size());
    ASSERT_TRUE(result.is_ok());
    
    MutableBufferView buffer_view(buffer);
    EXPECT_EQ(buffer_view.size(), buffer.size());
    EXPECT_EQ(buffer_view.data(), buffer.mutable_data());
    
    // Test MutableBufferView slicing
    auto slice_view = mutable_view.slice(10, 20);
    EXPECT_EQ(slice_view.size(), 20);
    EXPECT_EQ(slice_view.data(), mutable_data.data() + 10);
    
    // Test MutableBufferView subview
    auto sub_view = mutable_view.subview(50);
    EXPECT_EQ(sub_view.size(), mutable_data.size() - 50);
    EXPECT_EQ(sub_view.data(), mutable_data.data() + 50);
    
    // Test fill operations
    mutable_view.fill(std::byte{0xFF});
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        EXPECT_EQ(mutable_view[i], std::byte{0xFF});
        EXPECT_EQ(mutable_data[i], std::byte{0xFF});
    }
    
    // Test zero operation
    mutable_view.zero();
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        EXPECT_EQ(mutable_view[i], std::byte{0});
        EXPECT_EQ(mutable_data[i], std::byte{0});
    }
    
    // Test conversion to immutable view
    BufferView immutable_view = mutable_view;
    EXPECT_EQ(immutable_view.size(), mutable_view.size());
    EXPECT_EQ(immutable_view.data(), mutable_view.data());
    
    // Test mutable iteration
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        mutable_view[i] = static_cast<std::byte>(i % 256);
    }
    
    for (size_t i = 0; i < mutable_view.size(); ++i) {
        EXPECT_EQ(mutable_view[i], static_cast<std::byte>(i % 256));
        EXPECT_EQ(mutable_data[i], static_cast<std::byte>(i % 256));
    }
}

// Test utility functions
TEST_F(BufferEnhancedTest, UtilityFunctions) {
    // Test constant_time_compare
    BufferView view1(test_data_.data(), test_data_.size());
    BufferView view2(test_data_.data(), test_data_.size());
    EXPECT_TRUE(constant_time_compare(view1, view2));
    
    BufferView view3(small_pattern_.data(), small_pattern_.size());
    EXPECT_FALSE(constant_time_compare(view1, view3));
    
    // Test different sizes
    BufferView short_view(test_data_.data(), 10);
    EXPECT_FALSE(constant_time_compare(view1, short_view));
    
    // Test empty buffers
    BufferView empty1, empty2;
    EXPECT_TRUE(constant_time_compare(empty1, empty2));
    
    // Test find_byte
    auto find_result = find_byte(view1, test_data_[100]);
    EXPECT_EQ(find_result, 100);
    
    find_result = find_byte(view1, std::byte{0xFF});
    EXPECT_EQ(find_result, SIZE_MAX); // Not found
    
    // Test find_byte in empty buffer
    find_result = find_byte(empty1, std::byte{0x00});
    EXPECT_EQ(find_result, SIZE_MAX);
    
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
    
    // Test hex encoding/decoding
    BufferView hex_view(small_pattern_.data(), small_pattern_.size());
    auto hex_string = to_hex_string(hex_view);
    EXPECT_FALSE(hex_string.empty());
    EXPECT_EQ(hex_string.length(), small_pattern_.size() * 2);
    
    // Verify hex string content
    EXPECT_EQ(hex_string, "deadbeef");
    
    // Test hex decoding
    auto decode_result = from_hex_string(hex_string);
    ASSERT_TRUE(decode_result.is_ok());
    
    auto decoded = decode_result.value();
    EXPECT_EQ(decoded.size(), small_pattern_.size());
    EXPECT_EQ(std::memcmp(decoded.data(), small_pattern_.data(), small_pattern_.size()), 0);
    
    // Test invalid hex strings
    auto invalid_decode = from_hex_string("invalid_hex_string");
    EXPECT_TRUE(invalid_decode.is_error());
    
    auto odd_length_decode = from_hex_string("abc");
    EXPECT_TRUE(odd_length_decode.is_error());
    
    auto empty_decode = from_hex_string("");
    EXPECT_TRUE(empty_decode.is_ok());
    EXPECT_EQ(empty_decode.value().size(), 0);
}

// Test performance hints and state queries
TEST_F(BufferEnhancedTest, PerformanceHintsAndStateQueries) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    
    // Test performance hints (should not affect functionality)
    buffer.hint_sequential_access();
    buffer.hint_random_access();
    buffer.hint_read_only();
    
    // Verify buffer is still functional
    EXPECT_EQ(buffer.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(buffer.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test state queries
    EXPECT_TRUE(buffer.is_owning());
    EXPECT_FALSE(buffer.is_shared());
    EXPECT_FALSE(buffer.is_pooled());
    EXPECT_TRUE(buffer.can_modify());
    
    // Test with shared buffer
    auto share_result = buffer.share_buffer();
    ASSERT_TRUE(share_result.is_ok());
    auto shared = share_result.value();
    
    EXPECT_TRUE(shared.is_shared());
    EXPECT_FALSE(shared.can_modify());
    EXPECT_GT(shared.reference_count(), 1);
}

// Test concurrent access safety
TEST_F(BufferEnhancedTest, ConcurrentAccessSafety) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    
    // Create multiple shared references
    std::vector<ZeroCopyBuffer> shared_buffers;
    for (int i = 0; i < 10; ++i) {
        auto result = original.share_buffer();
        ASSERT_TRUE(result.is_ok());
        shared_buffers.push_back(result.value());
    }
    
    // Test concurrent read access
    std::vector<std::future<bool>> futures;
    std::atomic<int> errors{0};
    
    for (size_t i = 0; i < shared_buffers.size(); ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            try {
                const auto& buffer = shared_buffers[i];
                
                // Verify data integrity
                if (buffer.size() != test_data_.size()) {
                    errors.fetch_add(1);
                    return false;
                }
                
                if (std::memcmp(buffer.data(), test_data_.data(), test_data_.size()) != 0) {
                    errors.fetch_add(1);
                    return false;
                }
                
                // Test slicing
                if (buffer.size() >= 100) {
                    auto slice = buffer.create_slice(10, 50);
                    if (slice.size() != 50) {
                        errors.fetch_add(1);
                        return false;
                    }
                }
                
                return true;
            } catch (...) {
                errors.fetch_add(1);
                return false;
            }
        }));
    }
    
    // Wait for all operations to complete
    bool all_successful = true;
    for (auto& future : futures) {
        if (!future.get()) {
            all_successful = false;
        }
    }
    
    EXPECT_TRUE(all_successful);
    EXPECT_EQ(errors.load(), 0);
}

// Test edge cases and boundary conditions
TEST_F(BufferEnhancedTest, EdgeCasesAndBoundaryConditions) {
    // Test with empty data
    ZeroCopyBuffer empty_buffer;
    EXPECT_EQ(empty_buffer.size(), 0);
    EXPECT_EQ(empty_buffer.capacity(), 0);
    EXPECT_TRUE(empty_buffer.empty());
    
    // Test operations on empty buffer
    auto slice_result = empty_buffer.slice(0, 0);
    EXPECT_TRUE(slice_result.is_ok());
    EXPECT_EQ(slice_result.value().size(), 0);
    
    auto append_result = empty_buffer.append(nullptr, 0);
    EXPECT_TRUE(append_result.is_ok());
    
    auto zero_slice = empty_buffer.create_slice(0, 0);
    EXPECT_EQ(zero_slice.size(), 0);
    
    // Test with single byte
    std::byte single_byte{0x42};
    ZeroCopyBuffer single_buffer(&single_byte, 1);
    EXPECT_EQ(single_buffer.size(), 1);
    EXPECT_EQ(single_buffer.data()[0], std::byte{0x42});
    
    // Test slice operations on single byte
    auto single_slice = single_buffer.slice(0, 1);
    ASSERT_TRUE(single_slice.is_ok());
    EXPECT_EQ(single_slice.value().size(), 1);
    EXPECT_EQ(single_slice.value().data()[0], std::byte{0x42});
    
    // Test invalid slice on single byte
    auto invalid_single_slice = single_buffer.slice(1, 1);
    EXPECT_TRUE(invalid_single_slice.is_error());
    
    // Test boundary append
    ZeroCopyBuffer boundary_buffer(10);
    std::vector<std::byte> ten_bytes(10, std::byte{0xAA});
    auto boundary_append_result = boundary_buffer.append(ten_bytes.data(), ten_bytes.size());
    EXPECT_TRUE(boundary_append_result.is_ok());
    EXPECT_EQ(boundary_buffer.size(), 10);
    EXPECT_EQ(boundary_buffer.available_space(), 0);
    
    // Appending one more byte should trigger capacity expansion or fail
    std::byte extra_byte{0xBB};
    auto extra_append_result = boundary_buffer.append(&extra_byte, 1);
    if (extra_append_result.is_ok()) {
        EXPECT_GT(boundary_buffer.capacity(), 10);
        EXPECT_EQ(boundary_buffer.size(), 11);
    } else {
        EXPECT_EQ(extra_append_result.error(), DTLSError::OUT_OF_MEMORY);
    }
}

// Test memory pressure scenarios
TEST_F(BufferEnhancedTest, MemoryPressureScenarios) {
    std::vector<ZeroCopyBuffer> buffers;
    constexpr size_t buffer_size = 1024;
    constexpr size_t max_buffers = 100;
    
    // Create many buffers to test memory management
    for (size_t i = 0; i < max_buffers; ++i) {
        ZeroCopyBuffer buffer(buffer_size);
        
        // Fill with test pattern
        auto result = buffer.append(test_data_.data(), 
                                  std::min(test_data_.size(), buffer_size));
        if (result.is_ok()) {
            buffers.push_back(std::move(buffer));
        } else {
            // It's acceptable to fail under memory pressure
            EXPECT_EQ(result.error(), DTLSError::OUT_OF_MEMORY);
            break;
        }
    }
    
    // Verify all created buffers are valid
    for (const auto& buffer : buffers) {
        EXPECT_GT(buffer.size(), 0);
        EXPECT_GE(buffer.capacity(), buffer.size());
        EXPECT_EQ(std::memcmp(buffer.data(), test_data_.data(),
                             std::min(test_data_.size(), buffer.size())), 0);
    }
}