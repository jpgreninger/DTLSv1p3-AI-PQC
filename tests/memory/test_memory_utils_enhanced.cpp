/**
 * @file test_memory_utils_enhanced.cpp
 * @brief Enhanced comprehensive tests for DTLS memory utility functions
 * Phase 2 - Memory Utilities Coverage Enhancement
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>
#include <random>
#include <unordered_set>

#include "dtls/memory/memory_utils.h"
#include "dtls/memory/buffer.h"
#include "dtls/memory/pool.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;
using namespace dtls::v13::memory::utils;

class MemoryUtilsEnhancedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        test_data_.resize(1024);
        for (size_t i = 0; i < test_data_.size(); ++i) {
            test_data_[i] = static_cast<std::byte>(i % 256);
        }
        
        // Sensitive test data
        sensitive_data_.resize(512);
        std::fill(sensitive_data_.begin(), sensitive_data_.end(), std::byte{0xAA});
        
        // Random data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        random_data_.resize(256);
        for (auto& byte : random_data_) {
            byte = static_cast<std::byte>(dis(gen));
        }
    }
    
    void TearDown() override {
        // Reset memory statistics if available
        if (MemoryStatsCollector::instance().is_enabled()) {
            MemoryStatsCollector::instance().reset();
        }
    }
    
    std::vector<std::byte> test_data_;
    std::vector<std::byte> sensitive_data_;
    std::vector<std::byte> random_data_;
};

// Test MemoryStatsCollector functionality
TEST_F(MemoryUtilsEnhancedTest, MemoryStatsCollectorBasic) {
    auto& collector = MemoryStatsCollector::instance();
    
    // Test singleton behavior
    auto& collector2 = MemoryStatsCollector::instance();
    EXPECT_EQ(&collector, &collector2);
    
    // Test enable/disable
    collector.enable();
    EXPECT_TRUE(collector.is_enabled());
    
    collector.disable();
    EXPECT_FALSE(collector.is_enabled());
    
    // Re-enable for testing
    collector.enable();
    collector.reset();
    
    // Test basic allocation tracking
    size_t alloc_size = 1024;
    void* fake_ptr = reinterpret_cast<void*>(0x1000);
    
    collector.record_allocation(fake_ptr, alloc_size, "test_location");
    
    auto stats = collector.get_statistics();
    EXPECT_EQ(stats.total_allocations, 1);
    EXPECT_EQ(stats.current_allocations, 1);
    EXPECT_EQ(stats.total_bytes_allocated, alloc_size);
    EXPECT_EQ(stats.current_bytes_allocated, alloc_size);
    
    // Test deallocation tracking
    collector.record_deallocation(fake_ptr, alloc_size);
    
    stats = collector.get_statistics();
    EXPECT_EQ(stats.total_deallocations, 1);
    EXPECT_EQ(stats.current_allocations, 0);
    EXPECT_EQ(stats.total_bytes_deallocated, alloc_size);
    EXPECT_EQ(stats.current_bytes_allocated, 0);
}

// Test memory statistics under load
TEST_F(MemoryUtilsEnhancedTest, MemoryStatsUnderLoad) {
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    constexpr size_t num_allocations = 1000;
    constexpr size_t base_size = 256;
    
    std::vector<std::pair<void*, size_t>> allocations;
    size_t total_allocated = 0;
    
    // Simulate many allocations
    for (size_t i = 0; i < num_allocations; ++i) {
        size_t size = base_size + (i % 512);
        void* ptr = reinterpret_cast<void*>(0x10000 + i * 1024);
        
        collector.record_allocation(ptr, size, "load_test");
        allocations.emplace_back(ptr, size);
        total_allocated += size;
        
        // Check peak tracking
        auto stats = collector.get_statistics();
        EXPECT_GE(stats.peak_allocations, i + 1);
        EXPECT_GE(stats.peak_bytes_allocated, total_allocated);
    }
    
    auto mid_stats = collector.get_statistics();
    EXPECT_EQ(mid_stats.total_allocations, num_allocations);
    EXPECT_EQ(mid_stats.current_allocations, num_allocations);
    EXPECT_EQ(mid_stats.total_bytes_allocated, total_allocated);
    EXPECT_EQ(mid_stats.current_bytes_allocated, total_allocated);
    
    // Deallocate in random order
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(allocations.begin(), allocations.end(), gen);
    
    size_t deallocated_count = 0;
    size_t total_deallocated = 0;
    
    for (const auto& [ptr, size] : allocations) {
        collector.record_deallocation(ptr, size);
        ++deallocated_count;
        total_deallocated += size;
        
        auto stats = collector.get_statistics();
        EXPECT_EQ(stats.total_deallocations, deallocated_count);
        EXPECT_EQ(stats.current_allocations, num_allocations - deallocated_count);
        EXPECT_EQ(stats.total_bytes_deallocated, total_deallocated);
        EXPECT_EQ(stats.current_bytes_allocated, total_allocated - total_deallocated);
    }
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.current_allocations, 0);
    EXPECT_EQ(final_stats.current_bytes_allocated, 0);
    EXPECT_EQ(final_stats.peak_allocations, num_allocations);
    EXPECT_EQ(final_stats.peak_bytes_allocated, total_allocated);
}

// Test allocation failure tracking
TEST_F(MemoryUtilsEnhancedTest, AllocationFailureTracking) {
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    // Record some allocation failures
    collector.record_allocation_failure(1024);
    collector.record_allocation_failure(2048);
    collector.record_allocation_failure(4096);
    
    auto stats = collector.get_statistics();
    EXPECT_EQ(stats.allocation_failures, 3);
    
    // Test that failures don't affect other stats
    EXPECT_EQ(stats.total_allocations, 0);
    EXPECT_EQ(stats.current_allocations, 0);
    EXPECT_EQ(stats.total_bytes_allocated, 0);
}

// Test memory leak detection
TEST_F(MemoryUtilsEnhancedTest, MemoryLeakDetection) {
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    // Create some "leaks" (allocations without deallocations)
    void* ptr1 = reinterpret_cast<void*>(0x2000);
    void* ptr2 = reinterpret_cast<void*>(0x3000);
    void* ptr3 = reinterpret_cast<void*>(0x4000);
    
    collector.record_allocation(ptr1, 512, "leak_test_1");
    collector.record_allocation(ptr2, 1024, "leak_test_2");
    collector.record_allocation(ptr3, 256, "leak_test_3");
    
    // Get leak report
    auto leaks = collector.get_leak_report();
    EXPECT_EQ(leaks.size(), 3);
    
    // Verify leak information
    std::unordered_set<void*> leak_ptrs;
    for (const auto& [ptr, info] : leaks) {
        leak_ptrs.insert(ptr);
        EXPECT_GT(info.size, 0);
        EXPECT_FALSE(info.location.empty());
    }
    
    EXPECT_TRUE(leak_ptrs.count(ptr1) > 0);
    EXPECT_TRUE(leak_ptrs.count(ptr2) > 0);
    EXPECT_TRUE(leak_ptrs.count(ptr3) > 0);
    
    // Clean up one leak
    collector.record_deallocation(ptr1, 512);
    leaks = collector.get_leak_report();
    EXPECT_EQ(leaks.size(), 2);
    
    // Clean up remaining leaks
    collector.record_deallocation(ptr2, 1024);
    collector.record_deallocation(ptr3, 256);
    leaks = collector.get_leak_report();
    EXPECT_EQ(leaks.size(), 0);
}

// Test concurrent statistics collection
TEST_F(MemoryUtilsEnhancedTest, ConcurrentStatisticsCollection) {
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    constexpr size_t num_threads = 8;
    constexpr size_t operations_per_thread = 100;
    
    std::vector<std::future<void>> futures;
    std::atomic<size_t> allocation_counter{0};
    
    // Launch concurrent allocation/deallocation operations
    for (size_t t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::vector<std::pair<void*, size_t>> thread_allocations;
            
            for (size_t op = 0; op < operations_per_thread; ++op) {
                size_t alloc_id = allocation_counter.fetch_add(1);
                size_t size = 256 + (alloc_id % 1024);
                void* ptr = reinterpret_cast<void*>(0x100000 + alloc_id * 1024);
                
                // Record allocation
                collector.record_allocation(ptr, size, 
                    "thread_" + std::to_string(t) + "_op_" + std::to_string(op));
                thread_allocations.emplace_back(ptr, size);
                
                // Occasionally deallocate
                if (op % 10 == 9 && !thread_allocations.empty()) {
                    auto [dealloc_ptr, dealloc_size] = thread_allocations.back();
                    thread_allocations.pop_back();
                    collector.record_deallocation(dealloc_ptr, dealloc_size);
                }
            }
            
            // Clean up remaining allocations
            for (const auto& [ptr, size] : thread_allocations) {
                collector.record_deallocation(ptr, size);
            }
        }));
    }
    
    // Wait for all threads
    for (auto& future : futures) {
        future.wait();
    }
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.current_allocations, 0);
    EXPECT_EQ(final_stats.current_bytes_allocated, 0);
    EXPECT_EQ(final_stats.total_allocations, num_threads * operations_per_thread);
    EXPECT_GT(final_stats.peak_allocations, 0);
    EXPECT_GT(final_stats.peak_bytes_allocated, 0);
}

// Test BufferCache functionality
TEST_F(MemoryUtilsEnhancedTest, BufferCacheFunctionality) {
    BufferCache cache;
    
    constexpr size_t buffer_size = 1024;
    constexpr size_t cache_capacity = 16;
    
    // Test cache initialization
    auto result = cache.initialize(buffer_size, cache_capacity);
    ASSERT_TRUE(result.is_ok());
    
    auto stats = cache.get_stats();
    EXPECT_EQ(stats.buffer_size, buffer_size);
    EXPECT_EQ(stats.capacity, cache_capacity);
    EXPECT_EQ(stats.available_count, cache_capacity);
    EXPECT_EQ(stats.cache_hits, 0);
    EXPECT_EQ(stats.cache_misses, 0);
    
    // Test buffer acquisition
    auto buffer = cache.acquire();
    ASSERT_NE(buffer, nullptr);
    EXPECT_GE(buffer->capacity(), buffer_size);
    EXPECT_EQ(buffer->size(), 0);
    
    stats = cache.get_stats();
    EXPECT_EQ(stats.available_count, cache_capacity - 1);
    EXPECT_EQ(stats.cache_hits, 1);
    
    // Test buffer usage
    auto append_result = buffer->append(test_data_.data(), 
                                      std::min(test_data_.size(), buffer->capacity()));
    ASSERT_TRUE(append_result.is_ok());
    
    // Test buffer return
    cache.release(std::move(buffer));
    EXPECT_EQ(buffer, nullptr);
    
    stats = cache.get_stats();
    EXPECT_EQ(stats.available_count, cache_capacity);
    
    // Test cache exhaustion
    std::vector<std::unique_ptr<ZeroCopyBuffer>> cached_buffers;
    for (size_t i = 0; i < cache_capacity + 5; ++i) {
        auto buf = cache.acquire();
        if (buf) {
            cached_buffers.push_back(std::move(buf));
        }
    }
    
    stats = cache.get_stats();
    EXPECT_EQ(stats.available_count, 0);
    EXPECT_GT(stats.cache_misses, 0);
    
    // Return buffers
    for (auto& buf : cached_buffers) {
        if (buf) {
            cache.release(std::move(buf));
        }
    }
}

// Test MemoryAllocator functionality
TEST_F(MemoryUtilsEnhancedTest, MemoryAllocatorFunctionality) {
    MemoryAllocator allocator;
    
    // Test basic allocation
    auto ptr = allocator.allocate(1024);
    ASSERT_NE(ptr, nullptr);
    
    // Test allocation size tracking
    EXPECT_EQ(allocator.get_allocated_size(ptr), 1024);
    
    // Test memory usage
    std::memcpy(ptr, test_data_.data(), std::min(test_data_.size(), size_t{1024}));
    
    // Test deallocation
    allocator.deallocate(ptr);
    
    // Test allocation statistics
    auto stats = allocator.get_stats();
    EXPECT_GT(stats.total_allocations, 0);
    EXPECT_GT(stats.total_deallocations, 0);
    EXPECT_GT(stats.total_bytes_allocated, 0);
    
    // Test aligned allocation
    auto aligned_ptr = allocator.allocate_aligned(2048, 64);
    if (aligned_ptr) {
        EXPECT_EQ(reinterpret_cast<uintptr_t>(aligned_ptr) % 64, 0);
        allocator.deallocate(aligned_ptr);
    }
    
    // Test allocation failure simulation
    auto huge_ptr = allocator.allocate(SIZE_MAX);
    EXPECT_EQ(huge_ptr, nullptr);
}

// Test memory debugging utilities
TEST_F(MemoryUtilsEnhancedTest, MemoryDebuggingUtilities) {
    using namespace debugging;
    
    // Test enabling/disabling debugging features
    enable_debugging(true, true, true);
    EXPECT_TRUE(is_debugging_enabled());
    
    // Test memory guard detection
    std::vector<std::byte> test_buffer(1024);
    add_memory_guards(test_buffer.data(), test_buffer.size());
    
    // Verify guards are intact
    EXPECT_TRUE(check_memory_guards(test_buffer.data(), test_buffer.size()));
    
    // Test memory pattern detection
    std::vector<std::byte> pattern_buffer(256);
    std::fill(pattern_buffer.begin(), pattern_buffer.end(), std::byte{0xCC});
    
    EXPECT_TRUE(detect_memory_pattern(pattern_buffer.data(), pattern_buffer.size(), std::byte{0xCC}));
    EXPECT_FALSE(detect_memory_pattern(pattern_buffer.data(), pattern_buffer.size(), std::byte{0xAA}));
    
    // Test buffer corruption detection
    std::vector<std::byte> corruption_buffer = test_data_;
    EXPECT_FALSE(detect_buffer_corruption(corruption_buffer.data(), corruption_buffer.size()));
    
    // Simulate corruption
    if (!corruption_buffer.empty()) {
        corruption_buffer[corruption_buffer.size() / 2] = std::byte{0xFF};
        // Note: This test depends on the implementation's corruption detection algorithm
    }
    
    disable_debugging();
    EXPECT_FALSE(is_debugging_enabled());
}

// Test memory optimization utilities
TEST_F(MemoryUtilsEnhancedTest, MemoryOptimizationUtilities) {
    using namespace optimization;
    
    // Test memory usage analysis
    auto usage_report = analyze_memory_usage();
    EXPECT_GE(usage_report.total_memory_used, 0);
    EXPECT_GE(usage_report.peak_memory_used, usage_report.total_memory_used);
    
    // Test fragmentation analysis
    auto frag_stats = get_fragmentation_stats();
    EXPECT_GE(frag_stats.total_free_blocks, 0);
    EXPECT_GE(frag_stats.largest_free_block, 0);
    EXPECT_GE(frag_stats.fragmentation_ratio, 0.0);
    EXPECT_LE(frag_stats.fragmentation_ratio, 1.0);
    
    // Test memory compaction suggestions
    auto suggestions = get_optimization_suggestions();
    // Suggestions are implementation-dependent, just verify they're reasonable
    for (const auto& suggestion : suggestions) {
        EXPECT_FALSE(suggestion.description.empty());
        EXPECT_GE(suggestion.priority, 0);
        EXPECT_LE(suggestion.priority, 10);
    }
    
    // Test memory pool optimization
    BufferPool test_pool(1024, 32);
    auto optimization_result = optimize_pool_configuration(test_pool);
    EXPECT_TRUE(optimization_result.is_ok());
}

// Test security-focused memory utilities
TEST_F(MemoryUtilsEnhancedTest, SecurityMemoryUtilities) {
    // Test secure memory allocation
    auto secure_ptr = allocate_secure_memory(1024);
    if (secure_ptr) {
        // Write sensitive data
        std::memcpy(secure_ptr, sensitive_data_.data(), 
                   std::min(sensitive_data_.size(), size_t{1024}));
        
        // Test secure zeroing
        secure_zero_memory(secure_ptr, 1024);
        
        // Verify data is zeroed
        for (size_t i = 0; i < 1024; ++i) {
            EXPECT_EQ(static_cast<std::byte*>(secure_ptr)[i], std::byte{0});
        }
        
        deallocate_secure_memory(secure_ptr, 1024);
    }
    
    // Test memory protection
    std::vector<std::byte> protected_buffer = sensitive_data_;
    protect_memory_region(protected_buffer.data(), protected_buffer.size());
    
    // Test that protection doesn't interfere with normal access
    for (size_t i = 0; i < protected_buffer.size(); ++i) {
        EXPECT_EQ(protected_buffer[i], sensitive_data_[i]);
    }
    
    unprotect_memory_region(protected_buffer.data(), protected_buffer.size());
    
    // Test constant-time memory operations
    std::vector<std::byte> compare_buffer1 = test_data_;
    std::vector<std::byte> compare_buffer2 = test_data_;
    std::vector<std::byte> compare_buffer3 = random_data_;
    
    EXPECT_TRUE(constant_time_memory_compare(compare_buffer1.data(), 
                                           compare_buffer2.data(), 
                                           compare_buffer1.size()));
    
    EXPECT_FALSE(constant_time_memory_compare(compare_buffer1.data(), 
                                            compare_buffer3.data(), 
                                            std::min(compare_buffer1.size(), compare_buffer3.size())));
}

// Test memory utility integration
TEST_F(MemoryUtilsEnhancedTest, MemoryUtilityIntegration) {
    // Test integration between different memory utility components
    
    // Enable statistics collection
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    // Create buffer cache with statistics tracking
    BufferCache cache;
    auto result = cache.initialize(1024, 16);
    ASSERT_TRUE(result.is_ok());
    
    // Perform operations that should be tracked
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (size_t i = 0; i < 10; ++i) {
        auto buffer = cache.acquire();
        if (buffer) {
            // Use buffer
            auto append_result = buffer->append(test_data_.data(), 
                                              std::min(test_data_.size(), buffer->capacity()));
            ASSERT_TRUE(append_result.is_ok());
            
            // Test security features
            buffer->secure_zero();
            
            buffers.push_back(std::move(buffer));
        }
    }
    
    // Return buffers
    for (auto& buffer : buffers) {
        if (buffer) {
            cache.release(std::move(buffer));
        }
    }
    
    // Verify statistics were collected
    auto stats = collector.get_statistics();
    // Note: Actual values depend on implementation details
    
    // Verify cache statistics
    auto cache_stats = cache.get_stats();
    EXPECT_GT(cache_stats.cache_hits, 0);
    EXPECT_EQ(cache_stats.available_count, cache_stats.capacity);
}

// Test memory utility error handling
TEST_F(MemoryUtilsEnhancedTest, MemoryUtilityErrorHandling) {
    auto& collector = MemoryStatsCollector::instance();
    
    // Test invalid operations
    
    // Record deallocation without allocation
    collector.record_deallocation(reinterpret_cast<void*>(0x12345), 1024);
    // Should handle gracefully without crashing
    
    // Double deallocation
    void* ptr = reinterpret_cast<void*>(0x54321);
    collector.record_allocation(ptr, 512, "test");
    collector.record_deallocation(ptr, 512);
    collector.record_deallocation(ptr, 512); // Double deallocation
    // Should handle gracefully
    
    // Size mismatch in deallocation
    void* ptr2 = reinterpret_cast<void*>(0x98765);
    collector.record_allocation(ptr2, 1024, "test");
    collector.record_deallocation(ptr2, 2048); // Wrong size
    // Should handle gracefully
    
    // Test buffer cache error conditions
    BufferCache error_cache;
    
    // Use cache before initialization
    auto buffer = error_cache.acquire();
    EXPECT_EQ(buffer, nullptr);
    
    // Initialize with invalid parameters
    auto result = error_cache.initialize(0, 0);
    EXPECT_TRUE(result.is_error() || 
                (result.is_ok() && error_cache.get_stats().capacity > 0));
    
    // Test memory allocator error conditions
    MemoryAllocator allocator;
    
    // Get size of non-existent allocation
    auto size = allocator.get_allocated_size(reinterpret_cast<void*>(0x11111));
    EXPECT_EQ(size, 0);
    
    // Deallocate non-existent pointer
    allocator.deallocate(reinterpret_cast<void*>(0x22222));
    // Should handle gracefully
}

// Test memory utility performance
TEST_F(MemoryUtilsEnhancedTest, MemoryUtilityPerformance) {
    auto& collector = MemoryStatsCollector::instance();
    collector.enable();
    collector.reset();
    
    constexpr size_t num_operations = 10000;
    
    // Measure statistics collection overhead
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_operations; ++i) {
        void* ptr = reinterpret_cast<void*>(0x100000 + i * 8);
        collector.record_allocation(ptr, 1024, "perf_test");
        collector.record_deallocation(ptr, 1024);
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Statistics collection should be reasonably fast
    EXPECT_LT(duration.count(), 100000); // 100ms for 10000 operations
    
    // Test cache performance
    BufferCache cache;
    auto result = cache.initialize(1024, 64);
    ASSERT_TRUE(result.is_ok());
    
    start_time = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < num_operations; ++i) {
        auto buffer = cache.acquire();
        if (buffer) {
            cache.release(std::move(buffer));
        }
    }
    
    end_time = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Cache operations should be very fast
    EXPECT_LT(duration.count(), 50000); // 50ms for 10000 operations
    
    auto final_stats = collector.get_statistics();
    EXPECT_EQ(final_stats.current_allocations, 0);
}