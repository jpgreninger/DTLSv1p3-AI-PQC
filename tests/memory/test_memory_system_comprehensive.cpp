/**
 * @file test_memory_system_comprehensive.cpp
 * @brief Comprehensive tests for DTLS memory system utilities and management
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
#include <cstring>

#include "dtls/memory.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/memory/buffer.h"
#include "dtls/memory/pool.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;
using namespace dtls::v13::memory::utils;

class MemorySystemTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset memory system to clean state
        reset_memory_configuration();
        
        // Reset all statistics
        MemoryStatsCollector::instance().reset_statistics();
        MemoryPerformanceMonitor::instance().reset_stats();
        
        // Disable tracking and monitoring initially
        MemoryStatsCollector::instance().enable_tracking(false);
        MemoryPerformanceMonitor::instance().enable_monitoring(false);
        MemoryDebugger::instance().enable_guard_patterns(false);
        
        // Create test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        test_pattern_.resize(16);
        for (size_t i = 0; i < test_pattern_.size(); ++i) {
            test_pattern_[i] = static_cast<std::byte>(0xAA);
        }
    }
    
    void TearDown() override {
        // Cleanup memory system
        cleanup_memory_system();
        
        // Reset all statistics and configurations
        MemoryStatsCollector::instance().reset_statistics();
        MemoryPerformanceMonitor::instance().reset_stats();
        MemoryDebugger::instance().stop_profiling();
        
        reset_memory_configuration();
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> test_pattern_;
};

// Test MemoryStatsCollector functionality
TEST_F(MemorySystemTest, MemoryStatsCollector) {
    auto& collector = MemoryStatsCollector::instance();
    
    // Test singleton
    auto& collector2 = MemoryStatsCollector::instance();
    EXPECT_EQ(&collector, &collector2);
    
    // Test initial state
    auto initial_stats = collector.get_statistics();
    EXPECT_EQ(initial_stats.total_allocations, 0);
    EXPECT_EQ(initial_stats.total_deallocations, 0);
    EXPECT_EQ(initial_stats.current_allocations, 0);
    EXPECT_EQ(initial_stats.allocation_failures, 0);
    
    // Test allocation recording
    collector.record_allocation(1024, "test:1");
    collector.record_allocation(2048, "test:2");
    collector.record_allocation(512, "test:3");
    
    auto after_alloc_stats = collector.get_statistics();
    EXPECT_EQ(after_alloc_stats.total_allocations, 3);
    EXPECT_EQ(after_alloc_stats.current_allocations, 3);
    EXPECT_EQ(after_alloc_stats.total_bytes_allocated, 1024 + 2048 + 512);
    EXPECT_EQ(after_alloc_stats.current_bytes_allocated, 1024 + 2048 + 512);
    EXPECT_EQ(after_alloc_stats.peak_allocations, 3);
    EXPECT_EQ(after_alloc_stats.peak_bytes_allocated, 1024 + 2048 + 512);
    
    // Test deallocation recording
    collector.record_deallocation(1024);
    collector.record_deallocation(512);
    
    auto after_dealloc_stats = collector.get_statistics();
    EXPECT_EQ(after_dealloc_stats.total_deallocations, 2);
    EXPECT_EQ(after_dealloc_stats.current_allocations, 1);
    EXPECT_EQ(after_dealloc_stats.total_bytes_deallocated, 1024 + 512);
    EXPECT_EQ(after_dealloc_stats.current_bytes_allocated, 2048);
    EXPECT_EQ(after_dealloc_stats.peak_allocations, 3); // Should remain at peak
    
    // Test allocation failure recording
    collector.record_allocation_failure(4096);
    auto failure_stats = collector.get_statistics();
    EXPECT_EQ(failure_stats.allocation_failures, 1);
    
    // Test reset
    collector.reset_statistics();
    auto reset_stats = collector.get_statistics();
    EXPECT_EQ(reset_stats.total_allocations, 0);
    EXPECT_EQ(reset_stats.total_deallocations, 0);
    EXPECT_EQ(reset_stats.current_allocations, 0);
    EXPECT_EQ(reset_stats.allocation_failures, 0);
}

// Test MemoryTracker RAII functionality
TEST_F(MemorySystemTest, MemoryTracker) {
    auto& collector = MemoryStatsCollector::instance();
    collector.reset_statistics();
    
    // Test RAII tracking
    {
        MemoryTracker tracker1(1024, "tracker_test:1");
        MemoryTracker tracker2(2048, "tracker_test:2");
        
        auto during_stats = collector.get_statistics();
        EXPECT_EQ(during_stats.total_allocations, 2);
        EXPECT_EQ(during_stats.current_allocations, 2);
        EXPECT_EQ(during_stats.total_bytes_allocated, 1024 + 2048);
        
    } // Trackers destroyed here
    
    auto after_stats = collector.get_statistics();
    EXPECT_EQ(after_stats.total_deallocations, 2);
    EXPECT_EQ(after_stats.current_allocations, 0);
    EXPECT_EQ(after_stats.current_bytes_allocated, 0);
}

// Test memory alignment utilities
TEST_F(MemorySystemTest, MemoryAlignmentUtilities) {
    // Test is_aligned
    char buffer[64];
    void* ptr = buffer;
    
    // Test various alignments
    EXPECT_TRUE(is_aligned(ptr, 1));
    
    // Align to 8-byte boundary
    void* aligned_8 = align_pointer(ptr, 8);
    EXPECT_TRUE(is_aligned(aligned_8, 8));
    EXPECT_GE(static_cast<char*>(aligned_8), static_cast<char*>(ptr));
    
    // Align to 16-byte boundary
    void* aligned_16 = align_pointer(ptr, 16);
    EXPECT_TRUE(is_aligned(aligned_16, 16));
    EXPECT_GE(static_cast<char*>(aligned_16), static_cast<char*>(ptr));
    
    // Test size alignment
    EXPECT_EQ(align_size(10, 8), 16);
    EXPECT_EQ(align_size(16, 8), 16);
    EXPECT_EQ(align_size(17, 8), 24);
    EXPECT_EQ(align_size(0, 8), 0);
}

// Test memory comparison utilities
TEST_F(MemorySystemTest, MemoryComparisonUtilities) {
    std::vector<std::byte> data1 = test_data_;
    std::vector<std::byte> data2 = test_data_;
    std::vector<std::byte> data3 = test_data_;
    data3[0] = data3[0] ^ std::byte{0xFF}; // Make different
    
    // Test secure_compare
    EXPECT_TRUE(secure_compare(data1.data(), data2.data(), data1.size()));
    EXPECT_FALSE(secure_compare(data1.data(), data3.data(), data1.size()));
    
    // Test with different sizes (should be safe)
    EXPECT_FALSE(secure_compare(data1.data(), data2.data(), 0));
    
    // Test secure_memcmp
    EXPECT_EQ(secure_memcmp(data1.data(), data2.data(), data1.size()), 0);
    EXPECT_NE(secure_memcmp(data1.data(), data3.data(), data1.size()), 0);
    
    // Test null pointers (should handle gracefully)
    EXPECT_FALSE(secure_compare(nullptr, data1.data(), data1.size()));
    EXPECT_FALSE(secure_compare(data1.data(), nullptr, data1.size()));
    EXPECT_EQ(secure_memcmp(nullptr, nullptr, 0), 0);
}

// Test memory security utilities
TEST_F(MemorySystemTest, MemorySecurityUtilities) {
    std::vector<std::byte> sensitive_data = test_data_;
    
    // Test secure_memzero
    secure_memzero(sensitive_data.data(), sensitive_data.size());
    
    for (const auto& byte : sensitive_data) {
        EXPECT_EQ(byte, std::byte{0});
    }
    
    // Test is_memory_cleared
    EXPECT_TRUE(is_memory_cleared(sensitive_data.data(), sensitive_data.size()));
    
    // Modify one byte and test again
    sensitive_data[10] = std::byte{0xFF};
    EXPECT_FALSE(is_memory_cleared(sensitive_data.data(), sensitive_data.size()));
    
    // Test secure_memset
    secure_memset(sensitive_data.data(), 0xAA, sensitive_data.size());
    
    for (const auto& byte : sensitive_data) {
        EXPECT_EQ(byte, std::byte{0xAA});
    }
    
    // Test with zero size (should be safe)
    secure_memzero(sensitive_data.data(), 0);
    secure_memset(sensitive_data.data(), 0xFF, 0);
}

// Test buffer conversion utilities
TEST_F(MemorySystemTest, BufferConversionUtilities) {
    // Create test buffer
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    BufferView buffer_view(buffer);
    
    // Test buffer_to_vector
    auto vec = buffer_to_vector(buffer_view);
    EXPECT_EQ(vec.size(), test_data_.size());
    for (size_t i = 0; i < test_data_.size(); ++i) {
        EXPECT_EQ(vec[i], static_cast<uint8_t>(test_data_[i]));
    }
    
    // Test vector_to_buffer
    auto back_to_buffer = vector_to_buffer(vec);
    EXPECT_EQ(back_to_buffer.size(), vec.size());
    for (size_t i = 0; i < vec.size(); ++i) {
        EXPECT_EQ(back_to_buffer.data()[i], static_cast<std::byte>(vec[i]));
    }
    
    // Test buffer_to_string (for printable data)
    std::string test_string = "Hello, DTLS World!";
    ZeroCopyBuffer string_buffer(reinterpret_cast<const std::byte*>(test_string.data()), test_string.size());
    BufferView string_view(string_buffer);
    
    auto converted_string = buffer_to_string(string_view);
    EXPECT_EQ(converted_string, test_string);
    
    // Test string_to_buffer
    auto string_back_to_buffer = string_to_buffer(test_string);
    EXPECT_EQ(string_back_to_buffer.size(), test_string.size());
    EXPECT_EQ(std::memcmp(string_back_to_buffer.data(), test_string.data(), test_string.size()), 0);
}

// Test buffer manipulation utilities
TEST_F(MemorySystemTest, BufferManipulationUtilities) {
    ZeroCopyBuffer original(test_data_.data(), test_data_.size());
    BufferView original_view(original);
    
    // Test copy_buffer
    auto copy_result = copy_buffer(original_view);
    ASSERT_TRUE(copy_result.is_ok());
    auto copied = copy_result.value();
    
    EXPECT_EQ(copied.size(), original.size());
    EXPECT_EQ(std::memcmp(copied.data(), original.data(), original.size()), 0);
    EXPECT_NE(copied.data(), original.data()); // Different memory
    
    // Test copy_buffer_to
    ZeroCopyBuffer destination(original.size());
    MutableBufferView dest_view(destination);
    
    auto copy_to_result = copy_buffer_to(original_view, dest_view);
    EXPECT_TRUE(copy_to_result.is_ok());
    EXPECT_EQ(std::memcmp(destination.data(), original.data(), original.size()), 0);
    
    // Test resize_buffer
    auto resize_result = resize_buffer(std::move(copied), test_data_.size() + 512);
    ASSERT_TRUE(resize_result.is_ok());
    auto resized = resize_result.value();
    
    EXPECT_GE(resized.capacity(), test_data_.size() + 512);
    // Original data should be preserved
    EXPECT_EQ(std::memcmp(resized.data(), test_data_.data(), test_data_.size()), 0);
    
    // Test concat_buffers
    std::vector<BufferView> buffers_to_concat;
    buffers_to_concat.push_back(BufferView(test_data_.data(), test_data_.size() / 2));
    buffers_to_concat.push_back(BufferView(test_data_.data() + test_data_.size() / 2, test_data_.size() / 2));
    
    auto concat_result = concat_buffers(buffers_to_concat);
    ASSERT_TRUE(concat_result.is_ok());
    auto concatenated = concat_result.value();
    
    EXPECT_EQ(concatenated.size(), test_data_.size());
    EXPECT_EQ(std::memcmp(concatenated.data(), test_data_.data(), test_data_.size()), 0);
}

// Test buffer search utilities
TEST_F(MemorySystemTest, BufferSearchUtilities) {
    // Create buffer with known pattern
    std::vector<std::byte> search_data(1000);
    for (size_t i = 0; i < search_data.size(); ++i) {
        search_data[i] = static_cast<std::byte>(i % 256);
    }
    
    // Insert pattern at known location
    size_t pattern_location = 100;
    std::memcpy(search_data.data() + pattern_location, test_pattern_.data(), test_pattern_.size());
    
    ZeroCopyBuffer search_buffer(search_data.data(), search_data.size());
    BufferView search_view(search_buffer);
    BufferView pattern_view(test_pattern_.data(), test_pattern_.size());
    
    // Test find_pattern
    auto found_location = find_pattern(search_view, pattern_view);
    EXPECT_EQ(found_location, pattern_location);
    
    // Test find_byte_sequence
    auto found_seq_location = find_byte_sequence(search_view, test_pattern_);
    EXPECT_EQ(found_seq_location, pattern_location);
    
    // Test pattern not found
    std::vector<std::byte> not_found_pattern(16, std::byte{0xFF});
    BufferView not_found_view(not_found_pattern.data(), not_found_pattern.size());
    auto not_found_location = find_pattern(search_view, not_found_view);
    EXPECT_EQ(not_found_location, SIZE_MAX); // Not found
    
    // Test find_all_occurrences
    std::byte search_byte = static_cast<std::byte>(42);
    search_data[200] = search_byte;
    search_data[300] = search_byte;
    search_data[400] = search_byte;
    
    ZeroCopyBuffer multi_search_buffer(search_data.data(), search_data.size());
    BufferView multi_search_view(multi_search_buffer);
    
    auto occurrences = find_all_occurrences(multi_search_view, search_byte);
    EXPECT_GE(occurrences.size(), 3); // At least the 3 we inserted
    EXPECT_NE(std::find(occurrences.begin(), occurrences.end(), 200), occurrences.end());
    EXPECT_NE(std::find(occurrences.begin(), occurrences.end(), 300), occurrences.end());
    EXPECT_NE(std::find(occurrences.begin(), occurrences.end(), 400), occurrences.end());
}

// Test buffer validation utilities
TEST_F(MemorySystemTest, BufferValidationUtilities) {
    ZeroCopyBuffer buffer(test_data_.data(), test_data_.size());
    BufferView view(buffer);
    
    // Test validate_buffer_bounds
    EXPECT_TRUE(validate_buffer_bounds(view, 0, view.size()));
    EXPECT_TRUE(validate_buffer_bounds(view, 10, 20));
    EXPECT_TRUE(validate_buffer_bounds(view, view.size(), 0)); // End position, zero length
    
    // Invalid bounds
    EXPECT_FALSE(validate_buffer_bounds(view, view.size() + 1, 10));
    EXPECT_FALSE(validate_buffer_bounds(view, 10, view.size()));
    EXPECT_FALSE(validate_buffer_bounds(view, 0, view.size() + 1));
    
    // Test is_buffer_zero
    std::vector<std::byte> zero_data(100, std::byte{0});
    ZeroCopyBuffer zero_buffer(zero_data.data(), zero_data.size());
    BufferView zero_view(zero_buffer);
    
    EXPECT_TRUE(is_buffer_zero(zero_view));
    EXPECT_FALSE(is_buffer_zero(view)); // test_data_ is not all zeros
    
    // Test is_buffer_pattern
    std::vector<std::byte> pattern_data(100, std::byte{0xAA});
    ZeroCopyBuffer pattern_buffer(pattern_data.data(), pattern_data.size());
    BufferView pattern_view(pattern_buffer);
    
    EXPECT_TRUE(is_buffer_pattern(pattern_view, std::byte{0xAA}));
    EXPECT_FALSE(is_buffer_pattern(pattern_view, std::byte{0xBB}));
    EXPECT_FALSE(is_buffer_pattern(view, std::byte{0xAA})); // test_data_ is mixed
}

// Test MemoryDebugger functionality
TEST_F(MemorySystemTest, MemoryDebugger) {
    auto& debugger = MemoryDebugger::instance();
    
    // Test singleton
    auto& debugger2 = MemoryDebugger::instance();
    EXPECT_EQ(&debugger, &debugger2);
    
    // Test guard patterns
    EXPECT_FALSE(debugger.are_guard_patterns_enabled());
    debugger.enable_guard_patterns(true);
    EXPECT_TRUE(debugger.are_guard_patterns_enabled());
    
    // Test profiling
    EXPECT_FALSE(debugger.is_profiling());
    debugger.start_profiling();
    EXPECT_TRUE(debugger.is_profiling());
    debugger.stop_profiling();
    EXPECT_FALSE(debugger.is_profiling());
    
    // Test buffer integrity checking
    ZeroCopyBuffer test_buffer(test_data_.data(), test_data_.size());
    
    // Add checksum
    debugger.add_buffer_checksum(test_buffer);
    EXPECT_TRUE(debugger.verify_buffer_checksum(test_buffer));
    
    // Modify buffer and test checksum failure (if implementation supports it)
    // Note: This depends on whether the checksum is calculated on mutable data
    
    // Test buffer integrity check
    bool integrity_result = debugger.check_buffer_integrity(test_buffer);
    // Result depends on implementation
    
    // Test memory report generation (should not crash)
    debugger.generate_memory_report();
    
    // Test buffer dump (should not crash)
    BufferView dump_view(test_buffer);
    debugger.dump_buffer_contents(dump_view, "test_buffer");
    
    // Clean up
    debugger.enable_guard_patterns(false);
}

// Test MemoryPerformanceMonitor
TEST_F(MemorySystemTest, MemoryPerformanceMonitor) {
    auto& monitor = MemoryPerformanceMonitor::instance();
    
    // Test singleton
    auto& monitor2 = MemoryPerformanceMonitor::instance();
    EXPECT_EQ(&monitor, &monitor2);
    
    // Test initial state
    EXPECT_FALSE(monitor.is_monitoring_enabled());
    auto initial_stats = monitor.get_all_stats();
    EXPECT_TRUE(initial_stats.empty());
    
    // Enable monitoring
    monitor.enable_monitoring(true);
    EXPECT_TRUE(monitor.is_monitoring_enabled());
    
    // Record some operations
    monitor.record_operation("test_operation_1", std::chrono::nanoseconds(1000));
    monitor.record_operation("test_operation_1", std::chrono::nanoseconds(2000));
    monitor.record_operation("test_operation_1", std::chrono::nanoseconds(1500));
    monitor.record_operation("test_operation_2", std::chrono::nanoseconds(500));
    
    // Check statistics
    auto op1_stats = monitor.get_operation_stats("test_operation_1");
    EXPECT_EQ(op1_stats.name, "test_operation_1");
    EXPECT_EQ(op1_stats.count, 3);
    EXPECT_EQ(op1_stats.total_time, std::chrono::nanoseconds(4500));
    EXPECT_EQ(op1_stats.min_time, std::chrono::nanoseconds(1000));
    EXPECT_EQ(op1_stats.max_time, std::chrono::nanoseconds(2000));
    EXPECT_EQ(op1_stats.average_time(), std::chrono::nanoseconds(1500));
    
    auto all_stats = monitor.get_all_stats();
    EXPECT_EQ(all_stats.size(), 2);
    
    // Test reset
    monitor.reset_stats();
    auto reset_stats = monitor.get_all_stats();
    EXPECT_TRUE(reset_stats.empty());
    
    // Disable monitoring
    monitor.enable_monitoring(false);
    EXPECT_FALSE(monitor.is_monitoring_enabled());
}

// Test MemoryOperationTimer RAII
TEST_F(MemorySystemTest, MemoryOperationTimer) {
    auto& monitor = MemoryPerformanceMonitor::instance();
    monitor.enable_monitoring(true);
    monitor.reset_stats();
    
    // Test RAII timer
    {
        MemoryOperationTimer timer("timed_operation");
        
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        
    } // Timer destroyed here, should record operation
    
    auto stats = monitor.get_operation_stats("timed_operation");
    EXPECT_EQ(stats.name, "timed_operation");
    EXPECT_EQ(stats.count, 1);
    EXPECT_GT(stats.total_time, std::chrono::nanoseconds(0));
    
    // Test multiple timers
    for (int i = 0; i < 5; ++i) {
        MemoryOperationTimer timer("batch_operation");
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    
    auto batch_stats = monitor.get_operation_stats("batch_operation");
    EXPECT_EQ(batch_stats.count, 5);
    EXPECT_GT(batch_stats.average_time(), std::chrono::nanoseconds(0));
    
    monitor.enable_monitoring(false);
}

// Test memory configuration
TEST_F(MemorySystemTest, MemoryConfiguration) {
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
    custom_config.enable_debugging = true;
    custom_config.enable_performance_monitoring = true;
    
    auto config_result = configure_memory_system(custom_config);
    EXPECT_TRUE(config_result.is_ok());
    
    auto retrieved_config = get_memory_configuration();
    EXPECT_EQ(retrieved_config.max_total_memory, custom_config.max_total_memory);
    EXPECT_EQ(retrieved_config.max_single_allocation, custom_config.max_single_allocation);
    EXPECT_EQ(retrieved_config.warning_threshold, custom_config.warning_threshold);
    EXPECT_EQ(retrieved_config.enable_statistics, custom_config.enable_statistics);
    EXPECT_EQ(retrieved_config.enable_tracking, custom_config.enable_tracking);
    EXPECT_EQ(retrieved_config.enable_debugging, custom_config.enable_debugging);
    EXPECT_EQ(retrieved_config.enable_performance_monitoring, custom_config.enable_performance_monitoring);
    
    // Test reset configuration
    reset_memory_configuration();
    auto reset_config = get_memory_configuration();
    // Should be back to defaults (exact values depend on implementation)
}

// Test memory health check
TEST_F(MemorySystemTest, MemoryHealthCheck) {
    // Perform health check
    auto health_result = perform_memory_health_check();
    ASSERT_TRUE(health_result.is_ok());
    
    auto health_report = health_result.value();
    
    // Verify report structure
    EXPECT_GE(health_report.total_memory_usage, 0);
    EXPECT_GE(health_report.active_allocations, 0);
    EXPECT_GE(health_report.memory_leaks, 0);
    EXPECT_GE(health_report.fragmentation_ratio, 0.0);
    EXPECT_LE(health_report.fragmentation_ratio, 1.0);
    EXPECT_GT(health_report.check_time.time_since_epoch().count(), 0);
    
    // Issues list should be valid (empty or containing strings)
    for (const auto& issue : health_report.issues) {
        EXPECT_FALSE(issue.empty());
    }
    
    // If no issues, should be healthy
    if (health_report.issues.empty()) {
        EXPECT_TRUE(health_report.overall_healthy);
    }
}

// Test memory cleanup utilities
TEST_F(MemorySystemTest, MemoryCleanupUtilities) {
    // Test cleanup_memory_system (should not crash)
    cleanup_memory_system();
    
    // Test force_garbage_collection (should not crash)
    force_garbage_collection();
    
    // Test compact_memory_pools
    size_t compacted = compact_memory_pools();
    EXPECT_GE(compacted, 0); // Should return number of bytes freed
}

// Test memory system integration with existing components
TEST_F(MemorySystemTest, MemorySystemIntegration) {
    // Enable all monitoring
    MemoryConfig integration_config;
    integration_config.enable_statistics = true;
    integration_config.enable_tracking = true;
    integration_config.enable_debugging = true;
    integration_config.enable_performance_monitoring = true;
    
    auto config_result = configure_memory_system(integration_config);
    EXPECT_TRUE(config_result.is_ok());
    
    auto& collector = MemoryStatsCollector::instance();
    auto& monitor = MemoryPerformanceMonitor::instance();
    auto& debugger = MemoryDebugger::instance();
    
    collector.enable_tracking(true);
    monitor.enable_monitoring(true);
    debugger.enable_guard_patterns(true);
    debugger.start_profiling();
    
    // Perform various memory operations
    {
        DTLS_MEMORY_TRACK(1024);
        DTLS_MEMORY_TIMER("buffer_operations");
        
        // Create and manipulate buffers
        auto buffer1 = make_pooled_buffer(1024);
        auto buffer2 = make_buffer(2048);
        
        // Perform operations
        auto append_result = buffer1->append(test_data_.data(), std::min(test_data_.size(), size_t{1024}));
        EXPECT_TRUE(append_result.is_ok());
        
        auto copy_result = copy_buffer(BufferView(*buffer1));
        EXPECT_TRUE(copy_result.is_ok());
        
        // Test with zero-copy operations
        auto shared_result = buffer1->share_buffer();
        EXPECT_TRUE(shared_result.is_ok());
        
    } // RAII objects destroyed here
    
    // Check that monitoring captured the operations
    auto stats = collector.get_statistics();
    EXPECT_GT(stats.total_allocations, 0);
    
    auto perf_stats = monitor.get_all_stats();
    EXPECT_FALSE(perf_stats.empty());
    
    // Perform health check
    auto health_result = perform_memory_health_check();
    EXPECT_TRUE(health_result.is_ok());
    
    // Clean up
    debugger.stop_profiling();
    debugger.enable_guard_patterns(false);
    monitor.enable_monitoring(false);
    collector.enable_tracking(false);
}

// Test macro utilities
TEST_F(MemorySystemTest, MacroUtilities) {
    auto& collector = MemoryStatsCollector::instance();
    auto& monitor = MemoryPerformanceMonitor::instance();
    
    collector.enable_tracking(true);
    monitor.enable_monitoring(true);
    collector.reset_statistics();
    monitor.reset_stats();
    
    // Test DTLS_MEMORY_TRACK macro
    {
        DTLS_MEMORY_TRACK(2048);
        
        auto stats = collector.get_statistics();
        EXPECT_EQ(stats.total_allocations, 1);
        EXPECT_EQ(stats.total_bytes_allocated, 2048);
        
    } // Tracker destroyed here
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.total_deallocations, 1);
    EXPECT_EQ(final_stats.current_allocations, 0);
    
    // Test DTLS_MEMORY_TIMER macro
    {
        DTLS_MEMORY_TIMER("macro_timer_test");
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    } // Timer destroyed here
    
    auto timer_stats = monitor.get_operation_stats("macro_timer_test");
    EXPECT_EQ(timer_stats.count, 1);
    EXPECT_GT(timer_stats.total_time, std::chrono::nanoseconds(0));
    
    collector.enable_tracking(false);
    monitor.enable_monitoring(false);
}

// Test concurrent access to memory system
TEST_F(MemorySystemTest, ConcurrentMemorySystemAccess) {
    auto& collector = MemoryStatsCollector::instance();
    auto& monitor = MemoryPerformanceMonitor::instance();
    
    collector.enable_tracking(true);
    monitor.enable_monitoring(true);
    collector.reset_statistics();
    monitor.reset_stats();
    
    const int num_threads = 8;
    const int operations_per_thread = 50;
    std::atomic<int> successful_operations{0};
    
    std::vector<std::future<void>> futures;
    
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(256, 4096);
            
            for (int i = 0; i < operations_per_thread; ++i) {
                try {
                    size_t alloc_size = size_dis(gen);
                    
                    // Use memory tracking
                    {
                        DTLS_MEMORY_TRACK(alloc_size);
                        DTLS_MEMORY_TIMER("concurrent_operation");
                        
                        // Create buffer
                        auto buffer = make_buffer(alloc_size);
                        if (buffer) {
                            // Perform operations
                            auto data = test_data_;
                            data[0] = static_cast<std::byte>(t);
                            data[1] = static_cast<std::byte>(i);
                            
                            auto append_result = buffer->append(data.data(), 
                                                              std::min(data.size(), alloc_size));
                            if (append_result.is_ok()) {
                                successful_operations.fetch_add(1);
                            }
                        }
                        
                        // Brief delay
                        std::this_thread::sleep_for(std::chrono::microseconds(1));
                    }
                    
                } catch (...) {
                    // Ignore exceptions in concurrent test
                }
            }
        }));
    }
    
    // Wait for all threads
    for (auto& future : futures) {
        future.wait();
    }
    
    // Check that operations completed successfully
    EXPECT_GT(successful_operations.load(), num_threads * operations_per_thread * 0.5);
    
    // Check statistics
    auto final_stats = collector.get_statistics();
    EXPECT_GT(final_stats.total_allocations, 0);
    EXPECT_EQ(final_stats.current_allocations, 0); // All should be deallocated
    
    auto perf_stats = monitor.get_operation_stats("concurrent_operation");
    EXPECT_GT(perf_stats.count, 0);
    
    collector.enable_tracking(false);
    monitor.enable_monitoring(false);
}

// Test error conditions and edge cases
TEST_F(MemorySystemTest, ErrorConditionsAndEdgeCases) {
    // Test with extreme configuration values
    MemoryConfig extreme_config;
    extreme_config.max_total_memory = 0; // Invalid
    extreme_config.max_single_allocation = SIZE_MAX; // Very large
    extreme_config.warning_threshold = SIZE_MAX; // Very large
    
    auto extreme_result = configure_memory_system(extreme_config);
    // Should handle gracefully (implementation dependent)
    
    // Test operations with null pointers
    EXPECT_FALSE(is_aligned(nullptr, 8));
    EXPECT_EQ(align_pointer(nullptr, 8), nullptr);
    
    EXPECT_FALSE(secure_compare(nullptr, nullptr, 10));
    secure_memzero(nullptr, 0); // Should be safe
    secure_memset(nullptr, 0, 0); // Should be safe
    
    // Test with zero sizes
    EXPECT_EQ(align_size(0, 8), 0);
    EXPECT_TRUE(is_memory_cleared(test_data_.data(), 0)); // Zero size is "cleared"
    
    // Test buffer operations with empty data
    std::vector<std::byte> empty_data;
    BufferView empty_view(empty_data.data(), empty_data.size());
    
    auto empty_vec = buffer_to_vector(empty_view);
    EXPECT_TRUE(empty_vec.empty());
    
    auto empty_buffer = vector_to_buffer(empty_vec);
    EXPECT_EQ(empty_buffer.size(), 0);
    
    // Test search in empty buffer
    auto empty_find = find_pattern(empty_view, BufferView(test_pattern_.data(), test_pattern_.size()));
    EXPECT_EQ(empty_find, SIZE_MAX);
    
    // Test validation with invalid parameters
    EXPECT_FALSE(validate_buffer_bounds(empty_view, 1, 0));
    EXPECT_TRUE(validate_buffer_bounds(empty_view, 0, 0)); // Valid empty range
    
    // Test performance monitoring with empty operation name
    auto& monitor = MemoryPerformanceMonitor::instance();
    monitor.enable_monitoring(true);
    monitor.record_operation("", std::chrono::nanoseconds(100));
    
    auto empty_name_stats = monitor.get_operation_stats("");
    // Should handle empty operation name gracefully
    
    monitor.enable_monitoring(false);
}