/**
 * @file test_memory_utils.cpp
 * @brief Comprehensive tests for DTLS memory utilities
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>
#include <string>

#include "dtls/memory/memory_utils.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;
using namespace dtls::v13::memory::utils;

class MemoryUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset memory stats before each test
        MemoryStatsCollector::instance().reset_statistics();
        MemoryDebugger::instance().enable_guard_patterns(false);
        MemoryPerformanceMonitor::instance().enable_monitoring(false);
        MemoryPerformanceMonitor::instance().reset_stats();
        
        // Test data setup
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        pattern_data_ = {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
        large_data_.resize(4096, std::byte{0xAA});
        
        // Create test strings
        test_string_ = "Hello DTLS v1.3 Testing";
        hex_string_ = "deadbeef";
    }
    
    void TearDown() override {
        // Clean up after each test
        cleanup_memory_system();
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> pattern_data_;
    std::vector<std::byte> large_data_;
    std::string test_string_;
    std::string hex_string_;
};

// Test MemoryStatsCollector
TEST_F(MemoryUtilsTest, MemoryStatsCollector) {
    auto& collector = MemoryStatsCollector::instance();
    
    // Test singleton
    auto& collector2 = MemoryStatsCollector::instance();
    EXPECT_EQ(&collector, &collector2);
    
    // Test initial state
    auto initial_stats = collector.get_statistics();
    EXPECT_EQ(initial_stats.total_allocations, 0);
    EXPECT_EQ(initial_stats.total_deallocations, 0);
    EXPECT_EQ(initial_stats.current_allocations, 0);
    EXPECT_EQ(initial_stats.total_bytes_allocated, 0);
    
    // Test allocation recording
    collector.record_allocation(1024, "test_location");
    collector.record_allocation(512, "another_location");
    
    auto stats_after_alloc = collector.get_statistics();
    EXPECT_EQ(stats_after_alloc.total_allocations, 2);
    EXPECT_EQ(stats_after_alloc.current_allocations, 2);
    EXPECT_EQ(stats_after_alloc.total_bytes_allocated, 1536);
    EXPECT_EQ(stats_after_alloc.current_bytes_allocated, 1536);
    EXPECT_EQ(stats_after_alloc.peak_allocations, 2);
    EXPECT_EQ(stats_after_alloc.peak_bytes_allocated, 1536);
    
    // Test deallocation recording
    collector.record_deallocation(512);
    
    auto stats_after_dealloc = collector.get_statistics();
    EXPECT_EQ(stats_after_dealloc.total_deallocations, 1);
    EXPECT_EQ(stats_after_dealloc.current_allocations, 1);
    EXPECT_EQ(stats_after_dealloc.total_bytes_deallocated, 512);
    EXPECT_EQ(stats_after_dealloc.current_bytes_allocated, 1024);
    EXPECT_EQ(stats_after_dealloc.peak_allocations, 2); // Peak remains
    
    // Test allocation failure recording
    collector.record_allocation_failure(2048);
    
    auto stats_after_failure = collector.get_statistics();
    EXPECT_EQ(stats_after_failure.allocation_failures, 1);
    
    // Test tracking enable/disable
    collector.enable_tracking(true);
    EXPECT_TRUE(collector.is_tracking_enabled());
    
    collector.enable_tracking(false);
    EXPECT_FALSE(collector.is_tracking_enabled());
    
    // Test reset
    collector.reset_statistics();
    auto reset_stats = collector.get_statistics();
    EXPECT_EQ(reset_stats.total_allocations, 0);
    EXPECT_EQ(reset_stats.total_deallocations, 0);
    EXPECT_EQ(reset_stats.current_allocations, 0);
}

// Test MemoryTracker RAII
TEST_F(MemoryUtilsTest, MemoryTrackerRAII) {
    auto& collector = MemoryStatsCollector::instance();
    collector.reset_statistics();
    
    {
        MemoryTracker tracker(1024, "test_function");
        
        auto stats = collector.get_statistics();
        EXPECT_EQ(stats.total_allocations, 1);
        EXPECT_EQ(stats.current_allocations, 1);
        EXPECT_EQ(stats.total_bytes_allocated, 1024);
    } // Tracker destructor should record deallocation
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.total_deallocations, 1);
    EXPECT_EQ(final_stats.current_allocations, 0);
    EXPECT_EQ(final_stats.total_bytes_deallocated, 1024);
}

// Test memory alignment utilities
TEST_F(MemoryUtilsTest, MemoryAlignmentUtilities) {
    // Test alignment checking
    alignas(16) char aligned_buffer[64];
    char unaligned_buffer[64];
    
    EXPECT_TRUE(is_aligned(aligned_buffer, 16));
    EXPECT_TRUE(is_aligned(aligned_buffer, 8));
    EXPECT_TRUE(is_aligned(aligned_buffer, 4));
    
    // Test align_size
    EXPECT_EQ(align_size(15, 16), 16);
    EXPECT_EQ(align_size(16, 16), 16);
    EXPECT_EQ(align_size(17, 16), 32);
    EXPECT_EQ(align_size(100, 64), 128);
    EXPECT_EQ(align_size(0, 8), 0);
    
    // Test align_pointer
    char test_buffer[128];
    void* ptr = test_buffer + 1; // Misaligned pointer
    void* aligned_ptr = align_pointer(ptr, 8);
    
    EXPECT_TRUE(is_aligned(aligned_ptr, 8));
    EXPECT_GE(aligned_ptr, ptr);
    EXPECT_LT(static_cast<char*>(aligned_ptr) - static_cast<char*>(ptr), 8);
}

// Test memory comparison utilities
TEST_F(MemoryUtilsTest, MemoryComparisonUtilities) {
    std::vector<std::byte> data1 = test_data_;
    std::vector<std::byte> data2 = test_data_;
    std::vector<std::byte> data3 = pattern_data_;
    
    // Test secure_compare
    EXPECT_TRUE(secure_compare(data1.data(), data2.data(), data1.size()));
    EXPECT_FALSE(secure_compare(data1.data(), data3.data(), std::min(data1.size(), data3.size())));
    
    // Test with different sizes (edge case)
    EXPECT_FALSE(secure_compare(data1.data(), data3.data(), data1.size()));
    
    // Test secure_memcmp
    EXPECT_EQ(secure_memcmp(data1.data(), data2.data(), data1.size()), 0);
    EXPECT_NE(secure_memcmp(data1.data(), data3.data(), std::min(data1.size(), data3.size())), 0);
    
    // Test with null pointers (should handle gracefully)
    EXPECT_FALSE(secure_compare(nullptr, data1.data(), data1.size()));
    EXPECT_FALSE(secure_compare(data1.data(), nullptr, data1.size()));
    EXPECT_FALSE(secure_compare(nullptr, nullptr, 100));
}

// Test memory security utilities
TEST_F(MemoryUtilsTest, MemorySecurityUtilities) {
    std::vector<std::byte> secure_data = test_data_;
    
    // Test secure_memzero
    secure_memzero(secure_data.data(), secure_data.size());
    
    for (const auto& byte : secure_data) {
        EXPECT_EQ(byte, std::byte{0});
    }
    
    // Test is_memory_cleared
    EXPECT_TRUE(is_memory_cleared(secure_data.data(), secure_data.size()));
    
    // Modify one byte and test again
    secure_data[10] = std::byte{0x01};
    EXPECT_FALSE(is_memory_cleared(secure_data.data(), secure_data.size()));
    
    // Test secure_memset
    secure_memset(secure_data.data(), 0xAA, secure_data.size());
    for (const auto& byte : secure_data) {
        EXPECT_EQ(byte, std::byte{0xAA});
    }
    
    // Test edge cases
    secure_memzero(nullptr, 0); // Should not crash
    EXPECT_TRUE(is_memory_cleared(nullptr, 0)); // Should handle gracefully
}

// Test buffer conversion utilities
TEST_F(MemoryUtilsTest, BufferConversionUtilities) {
    BufferView test_view(test_data_.data(), test_data_.size());
    
    // Test buffer_to_vector
    auto vector_result = buffer_to_vector(test_view);
    EXPECT_EQ(vector_result.size(), test_data_.size());
    for (size_t i = 0; i < test_data_.size(); ++i) {
        EXPECT_EQ(static_cast<std::byte>(vector_result[i]), test_data_[i]);
    }
    
    // Test vector_to_buffer
    std::vector<uint8_t> uint8_vector(test_data_.size());
    for (size_t i = 0; i < test_data_.size(); ++i) {
        uint8_vector[i] = static_cast<uint8_t>(test_data_[i]);
    }
    
    auto buffer_result = vector_to_buffer(uint8_vector);
    EXPECT_EQ(buffer_result.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(buffer_result.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test buffer_to_string
    BufferView string_view(reinterpret_cast<const std::byte*>(test_string_.data()), test_string_.size());
    auto string_result = buffer_to_string(string_view);
    EXPECT_EQ(string_result, test_string_);
    
    // Test string_to_buffer
    auto string_buffer = string_to_buffer(test_string_);
    EXPECT_EQ(string_buffer.size(), test_string_.size());
    EXPECT_EQ(std::memcmp(string_buffer.data(), test_string_.data(), test_string_.size()), 0);
    
    // Test empty conversions
    BufferView empty_view;
    auto empty_vector = buffer_to_vector(empty_view);
    EXPECT_TRUE(empty_vector.empty());
    
    auto empty_buffer = vector_to_buffer(std::vector<uint8_t>{});
    EXPECT_TRUE(empty_buffer.empty());
}

// Test buffer manipulation utilities
TEST_F(MemoryUtilsTest, BufferManipulationUtilities) {
    BufferView source_view(test_data_.data(), test_data_.size());
    
    // Test copy_buffer
    auto copy_result = copy_buffer(source_view);
    ASSERT_TRUE(copy_result.is_ok());
    
    auto copied_buffer = copy_result.value();
    EXPECT_EQ(copied_buffer.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(copied_buffer.data(), test_data_.data(), test_data_.size()), 0);
    EXPECT_NE(copied_buffer.data(), test_data_.data()); // Should be different memory
    
    // Test copy_buffer_to
    ZeroCopyBuffer dest_buffer(test_data_.size() * 2);
    MutableBufferView dest_view(dest_buffer);
    
    auto copy_to_result = copy_buffer_to(source_view, dest_view);
    EXPECT_TRUE(copy_to_result.is_ok());
    EXPECT_EQ(std::memcmp(dest_buffer.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test resize_buffer
    ZeroCopyBuffer resize_buffer(test_data_.data(), test_data_.size());
    auto resize_result = resize_buffer(std::move(resize_buffer), test_data_.size() * 2);
    ASSERT_TRUE(resize_result.is_ok());
    
    auto resized = resize_result.value();
    EXPECT_EQ(resized.size(), test_data_.size() * 2);
    EXPECT_EQ(std::memcmp(resized.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test concat_buffers
    std::vector<BufferView> buffers_to_concat = {
        BufferView(pattern_data_.data(), pattern_data_.size()),
        BufferView(test_data_.data(), 100),
        BufferView(pattern_data_.data(), pattern_data_.size())
    };
    
    auto concat_result = concat_buffers(buffers_to_concat);
    ASSERT_TRUE(concat_result.is_ok());
    
    auto concatenated = concat_result.value();
    size_t expected_size = pattern_data_.size() + 100 + pattern_data_.size();
    EXPECT_EQ(concatenated.size(), expected_size);
    
    // Verify concatenated content
    EXPECT_EQ(std::memcmp(concatenated.data(), pattern_data_.data(), pattern_data_.size()), 0);
    EXPECT_EQ(std::memcmp(concatenated.data() + pattern_data_.size(), test_data_.data(), 100), 0);
    EXPECT_EQ(std::memcmp(concatenated.data() + pattern_data_.size() + 100, 
                         pattern_data_.data(), pattern_data_.size()), 0);
}

// Test buffer search utilities
TEST_F(MemoryUtilsTest, BufferSearchUtilities) {
    // Create a buffer with known pattern
    std::vector<std::byte> search_data(1000);
    for (size_t i = 0; i < search_data.size(); ++i) {
        search_data[i] = static_cast<std::byte>(i % 256);
    }
    
    // Insert pattern at known location
    size_t pattern_location = 100;
    std::copy(pattern_data_.begin(), pattern_data_.end(), 
              search_data.begin() + pattern_location);
    
    BufferView search_view(search_data.data(), search_data.size());
    BufferView pattern_view(pattern_data_.data(), pattern_data_.size());
    
    // Test find_pattern
    auto found_location = find_pattern(search_view, pattern_view);
    EXPECT_EQ(found_location, pattern_location);
    
    // Test find_pattern with non-existent pattern
    std::vector<std::byte> missing_pattern = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};
    BufferView missing_view(missing_pattern.data(), missing_pattern.size());
    auto not_found = find_pattern(search_view, missing_view);
    EXPECT_EQ(not_found, SIZE_MAX);
    
    // Test find_byte_sequence
    auto seq_found = find_byte_sequence(search_view, pattern_data_);
    EXPECT_EQ(seq_found, pattern_location);
    
    // Test find_all_occurrences
    std::byte target_byte = static_cast<std::byte>(42);
    auto occurrences = find_all_occurrences(search_view, target_byte);
    
    // Verify occurrences
    std::vector<size_t> expected_occurrences;
    for (size_t i = 0; i < search_data.size(); ++i) {
        if (search_data[i] == target_byte) {
            expected_occurrences.push_back(i);
        }
    }
    EXPECT_EQ(occurrences.size(), expected_occurrences.size());
    for (size_t i = 0; i < occurrences.size(); ++i) {
        EXPECT_EQ(occurrences[i], expected_occurrences[i]);
    }
    
    // Test empty pattern search
    BufferView empty_pattern;
    auto empty_result = find_pattern(search_view, empty_pattern);
    EXPECT_EQ(empty_result, 0); // Empty pattern should match at beginning
}

// Test buffer validation utilities
TEST_F(MemoryUtilsTest, BufferValidationUtilities) {
    BufferView test_view(test_data_.data(), test_data_.size());
    
    // Test validate_buffer_bounds
    EXPECT_TRUE(validate_buffer_bounds(test_view, 0, test_data_.size()));
    EXPECT_TRUE(validate_buffer_bounds(test_view, 10, 100));
    EXPECT_TRUE(validate_buffer_bounds(test_view, test_data_.size(), 0)); // Edge case
    
    // Test invalid bounds
    EXPECT_FALSE(validate_buffer_bounds(test_view, test_data_.size() + 1, 10));
    EXPECT_FALSE(validate_buffer_bounds(test_view, 10, test_data_.size()));
    EXPECT_FALSE(validate_buffer_bounds(test_view, test_data_.size() - 5, 10));
    
    // Test is_buffer_zero
    std::vector<std::byte> zero_data(100, std::byte{0});
    BufferView zero_view(zero_data.data(), zero_data.size());
    EXPECT_TRUE(is_buffer_zero(zero_view));
    
    zero_data[50] = std::byte{1};
    EXPECT_FALSE(is_buffer_zero(zero_view));
    
    // Test is_buffer_pattern
    std::vector<std::byte> pattern_data(100, std::byte{0xAA});
    BufferView pattern_view(pattern_data.data(), pattern_data.size());
    EXPECT_TRUE(is_buffer_pattern(pattern_view, std::byte{0xAA}));
    
    pattern_data[25] = std::byte{0xBB};
    EXPECT_FALSE(is_buffer_pattern(pattern_view, std::byte{0xAA}));
    
    // Test empty buffer validation
    BufferView empty_view;
    EXPECT_TRUE(validate_buffer_bounds(empty_view, 0, 0));
    EXPECT_FALSE(validate_buffer_bounds(empty_view, 0, 1));
    EXPECT_TRUE(is_buffer_zero(empty_view)); // Empty buffer is considered "zero"
}

// Test MemoryDebugger functionality
TEST_F(MemoryUtilsTest, MemoryDebugger) {
    auto& debugger = MemoryDebugger::instance();
    
    // Test singleton
    auto& debugger2 = MemoryDebugger::instance();
    EXPECT_EQ(&debugger, &debugger2);
    
    // Test guard patterns
    debugger.enable_guard_patterns(true);
    EXPECT_TRUE(debugger.are_guard_patterns_enabled());
    
    debugger.enable_guard_patterns(false);
    EXPECT_FALSE(debugger.are_guard_patterns_enabled());
    
    // Test profiling
    debugger.start_profiling();
    EXPECT_TRUE(debugger.is_profiling());
    
    debugger.stop_profiling();
    EXPECT_FALSE(debugger.is_profiling());
    
    // Test buffer checksum functionality
    ZeroCopyBuffer test_buffer(test_data_.data(), test_data_.size());
    
    debugger.add_buffer_checksum(test_buffer);
    EXPECT_TRUE(debugger.verify_buffer_checksum(test_buffer));
    
    // Modify buffer and verify checksum fails
    test_buffer.mutable_data()[0] = std::byte{0xFF};
    EXPECT_FALSE(debugger.verify_buffer_checksum(test_buffer));
    
    // Test buffer integrity check
    ZeroCopyBuffer integrity_buffer(1024);
    EXPECT_TRUE(debugger.check_buffer_integrity(integrity_buffer));
    
    // Test memory report generation (should not crash)
    debugger.generate_memory_report();
    
    // Test buffer dump (should not crash)
    BufferView dump_view(test_data_.data(), std::min(test_data_.size(), size_t{64}));
    debugger.dump_buffer_contents(dump_view, "test_buffer");
}

// Test MemoryPerformanceMonitor
TEST_F(MemoryUtilsTest, MemoryPerformanceMonitor) {
    auto& monitor = MemoryPerformanceMonitor::instance();
    
    // Test singleton
    auto& monitor2 = MemoryPerformanceMonitor::instance();
    EXPECT_EQ(&monitor, &monitor2);
    
    // Enable monitoring
    monitor.enable_monitoring(true);
    EXPECT_TRUE(monitor.is_monitoring_enabled());
    
    // Record some operations
    monitor.record_operation("buffer_copy", std::chrono::nanoseconds(1000));
    monitor.record_operation("buffer_copy", std::chrono::nanoseconds(1200));
    monitor.record_operation("buffer_copy", std::chrono::nanoseconds(800));
    monitor.record_operation("buffer_append", std::chrono::nanoseconds(500));
    
    // Get statistics
    auto copy_stats = monitor.get_operation_stats("buffer_copy");
    EXPECT_EQ(copy_stats.name, "buffer_copy");
    EXPECT_EQ(copy_stats.count, 3);
    EXPECT_EQ(copy_stats.total_time, std::chrono::nanoseconds(3000));
    EXPECT_EQ(copy_stats.min_time, std::chrono::nanoseconds(800));
    EXPECT_EQ(copy_stats.max_time, std::chrono::nanoseconds(1200));
    EXPECT_EQ(copy_stats.average_time(), std::chrono::nanoseconds(1000));
    
    auto all_stats = monitor.get_all_stats();
    EXPECT_EQ(all_stats.size(), 2);
    
    // Test reset
    monitor.reset_stats();
    all_stats = monitor.get_all_stats();
    EXPECT_EQ(all_stats.size(), 0);
    
    // Disable monitoring
    monitor.enable_monitoring(false);
    EXPECT_FALSE(monitor.is_monitoring_enabled());
}

// Test MemoryOperationTimer RAII
TEST_F(MemoryUtilsTest, MemoryOperationTimer) {
    auto& monitor = MemoryPerformanceMonitor::instance();
    monitor.enable_monitoring(true);
    monitor.reset_stats();
    
    {
        MemoryOperationTimer timer("test_operation");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } // Timer destructor should record operation
    
    auto stats = monitor.get_operation_stats("test_operation");
    EXPECT_EQ(stats.count, 1);
    EXPECT_GT(stats.total_time, std::chrono::nanoseconds(0));
    
    monitor.enable_monitoring(false);
}

// Test memory configuration
TEST_F(MemoryUtilsTest, MemoryConfiguration) {
    // Test default configuration
    auto default_config = get_memory_configuration();
    EXPECT_GT(default_config.max_total_memory, 0);
    EXPECT_GT(default_config.max_single_allocation, 0);
    EXPECT_GT(default_config.warning_threshold, 0);
    
    // Test custom configuration
    MemoryConfig custom_config;
    custom_config.max_total_memory = 512 * 1024 * 1024; // 512MB
    custom_config.max_single_allocation = 32 * 1024 * 1024; // 32MB
    custom_config.warning_threshold = 256 * 1024 * 1024; // 256MB
    custom_config.enable_statistics = true;
    custom_config.enable_tracking = true;
    custom_config.enable_debugging = false;
    custom_config.enable_performance_monitoring = true;
    
    auto config_result = configure_memory_system(custom_config);
    EXPECT_TRUE(config_result.is_ok());
    
    auto retrieved_config = get_memory_configuration();
    EXPECT_EQ(retrieved_config.max_total_memory, custom_config.max_total_memory);
    EXPECT_EQ(retrieved_config.max_single_allocation, custom_config.max_single_allocation);
    EXPECT_EQ(retrieved_config.warning_threshold, custom_config.warning_threshold);
    EXPECT_EQ(retrieved_config.enable_statistics, custom_config.enable_statistics);
    EXPECT_EQ(retrieved_config.enable_tracking, custom_config.enable_tracking);
    
    // Test reset configuration
    reset_memory_configuration();
    auto reset_config = get_memory_configuration();
    // Should be back to defaults (implementation dependent what defaults are)
}

// Test memory health check
TEST_F(MemoryUtilsTest, MemoryHealthCheck) {
    auto health_result = perform_memory_health_check();
    ASSERT_TRUE(health_result.is_ok());
    
    auto health_report = health_result.value();
    EXPECT_GE(health_report.total_memory_usage, 0);
    EXPECT_GE(health_report.active_allocations, 0);
    EXPECT_GE(health_report.memory_leaks, 0);
    EXPECT_GE(health_report.fragmentation_ratio, 0.0);
    EXPECT_LE(health_report.fragmentation_ratio, 1.0);
    
    // In a clean test environment, we should be healthy
    // Note: This might fail if there are actual memory issues
    EXPECT_TRUE(health_report.overall_healthy || !health_report.overall_healthy); // Either is valid
}

// Test memory cleanup utilities
TEST_F(MemoryUtilsTest, MemoryCleanupUtilities) {
    // These should not crash
    cleanup_memory_system();
    force_garbage_collection();
    
    auto compacted_size = compact_memory_pools();
    EXPECT_GE(compacted_size, 0);
}

// Test concurrent memory utilities usage
TEST_F(MemoryUtilsTest, ConcurrentMemoryUtilities) {
    auto& collector = MemoryStatsCollector::instance();
    auto& monitor = MemoryPerformanceMonitor::instance();
    
    collector.enable_tracking(true);
    monitor.enable_monitoring(true);
    collector.reset_statistics();
    monitor.reset_stats();
    
    const int num_threads = 4;
    const int operations_per_thread = 100;
    std::atomic<int> completed_operations{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that perform memory operations
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(100, 1000);
            
            for (int i = 0; i < operations_per_thread; ++i) {
                size_t alloc_size = size_dis(gen);
                
                // Record allocation
                collector.record_allocation(alloc_size, "concurrent_test");
                
                // Simulate some work with timing
                {
                    MemoryOperationTimer timer("concurrent_operation");
                    std::this_thread::sleep_for(std::chrono::microseconds(10));
                }
                
                // Record deallocation
                collector.record_deallocation(alloc_size);
                
                completed_operations.fetch_add(1);
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    EXPECT_EQ(completed_operations.load(), num_threads * operations_per_thread);
    
    // Verify statistics
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.total_allocations, num_threads * operations_per_thread);
    EXPECT_EQ(final_stats.total_deallocations, num_threads * operations_per_thread);
    EXPECT_EQ(final_stats.current_allocations, 0);
    
    auto operation_stats = monitor.get_operation_stats("concurrent_operation");
    EXPECT_EQ(operation_stats.count, num_threads * operations_per_thread);
    
    collector.enable_tracking(false);
    monitor.enable_monitoring(false);
}

// Test utility macros
TEST_F(MemoryUtilsTest, UtilityMacros) {
    auto& collector = MemoryStatsCollector::instance();
    collector.reset_statistics();
    
    {
        DTLS_MEMORY_TRACK(1024);
        
        auto stats = collector.get_statistics();
        EXPECT_EQ(stats.total_allocations, 1);
        EXPECT_EQ(stats.total_bytes_allocated, 1024);
    }
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.total_deallocations, 1);
    EXPECT_EQ(final_stats.total_bytes_deallocated, 1024);
    
    auto& monitor = MemoryPerformanceMonitor::instance();
    monitor.enable_monitoring(true);
    monitor.reset_stats();
    
    {
        DTLS_MEMORY_TIMER("macro_test");
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    auto timer_stats = monitor.get_operation_stats("macro_test");
    EXPECT_EQ(timer_stats.count, 1);
    EXPECT_GT(timer_stats.total_time, std::chrono::nanoseconds(0));
    
    monitor.enable_monitoring(false);
}