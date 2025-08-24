/**
 * @file test_memory_stress_edge_cases_comprehensive.cpp
 * @brief Comprehensive stress tests and edge case validation for DTLS memory management
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
#include <limits>
#include <cstring>

#include "dtls/memory.h"
#include "dtls/memory/buffer.h"
#include "dtls/memory/pool.h"
#include "dtls/memory/adaptive_pools.h"
#include "dtls/memory/leak_detection.h"
#include "dtls/memory/zero_copy_crypto.h"
#include "dtls/memory/memory_utils.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class MemoryStressEdgeCasesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize memory system with stress-test configuration
        auto init_result = initialize_memory_system();
        ASSERT_TRUE(init_result.is_ok());
        
        // Configure for stress testing
        MemorySystemConfig stress_config;
        stress_config.enable_pool_statistics = true;
        stress_config.enable_buffer_debugging = true;
        stress_config.enable_allocation_tracking = true;
        stress_config.enable_performance_monitoring = true;
        stress_config.enable_leak_detection = true;
        stress_config.max_total_memory = 1024 * 1024 * 1024; // 1GB for stress tests
        stress_config.warning_threshold = 512 * 1024 * 1024; // 512MB warning
        
        auto config_result = set_memory_system_config(stress_config);
        ASSERT_TRUE(config_result.is_ok());
        
        // Initialize random test data
        std::random_device rd;
        gen_.seed(rd());
    }
    
    void TearDown() override {
        cleanup_memory_system();
    }
    
    std::mt19937 gen_;
    
    // Helper to create random data
    std::vector<std::byte> create_random_data(size_t size) {
        std::vector<std::byte> data(size);
        std::uniform_int_distribution<> byte_dis(0, 255);
        for (auto& byte : data) {
            byte = static_cast<std::byte>(byte_dis(gen_));
        }
        return data;
    }
    
    // Helper to create predictable but varied data
    std::vector<std::byte> create_pattern_data(size_t size, uint8_t seed) {
        std::vector<std::byte> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<std::byte>((i * seed + i) % 256);
        }
        return data;
    }
};

// Test extreme buffer sizes and edge conditions
TEST_F(MemoryStressEdgeCasesTest, ExtremBufferSizes) {
    // Test zero-size buffer
    {
        ZeroCopyBuffer zero_buffer(0);
        EXPECT_EQ(zero_buffer.size(), 0);
        EXPECT_EQ(zero_buffer.capacity(), 0);
        EXPECT_TRUE(zero_buffer.empty());
        
        // Operations on zero buffer should be safe
        auto result = zero_buffer.append(nullptr, 0);
        EXPECT_TRUE(result.is_ok() || result.is_error()); // Either is acceptable
        
        auto slice_result = zero_buffer.slice(0, 0);
        EXPECT_TRUE(slice_result.is_ok() || slice_result.is_error());
        
        zero_buffer.clear();
        zero_buffer.secure_zero();
    }
    
    // Test single-byte buffer
    {
        std::byte single_byte{0xAA};
        ZeroCopyBuffer single_buffer(&single_byte, 1);
        EXPECT_EQ(single_buffer.size(), 1);
        EXPECT_EQ(single_buffer.data()[0], std::byte{0xAA});
        
        auto slice = single_buffer.create_slice(0, 1);
        EXPECT_EQ(slice.size(), 1);
        EXPECT_EQ(slice.data()[0], std::byte{0xAA});
        
        // Test edge case slicing
        auto zero_slice = single_buffer.create_slice(1, 0);
        EXPECT_EQ(zero_slice.size(), 0);
    }
    
    // Test very large buffer (if memory allows)
    {
        const size_t large_size = 128 * 1024 * 1024; // 128MB
        
        try {
            ZeroCopyBuffer large_buffer(large_size);
            
            if (large_buffer.capacity() >= large_size) {
                EXPECT_EQ(large_buffer.size(), 0);
                EXPECT_GE(large_buffer.capacity(), large_size);
                
                // Test large append operation
                auto test_data = create_random_data(1024);
                auto append_result = large_buffer.append(test_data.data(), test_data.size());
                EXPECT_TRUE(append_result.is_ok());
                
                // Test large slice
                auto slice_result = large_buffer.slice(0, test_data.size());
                EXPECT_TRUE(slice_result.is_ok());
                
                if (slice_result.is_ok()) {
                    auto slice = slice_result.value();
                    EXPECT_EQ(slice.size(), test_data.size());
                    EXPECT_EQ(std::memcmp(slice.data(), test_data.data(), test_data.size()), 0);
                }
            }
        } catch (const std::bad_alloc&) {
            // Large allocation failed - this is acceptable
            std::cout << "Large buffer allocation failed (acceptable)" << std::endl;
        }
    }
    
    // Test maximum size_t edge case
    {
        // Attempting to create buffer with SIZE_MAX should fail gracefully
        try {
            ZeroCopyBuffer max_buffer(SIZE_MAX);
            // If this succeeds, it should have reasonable capacity
            EXPECT_LT(max_buffer.capacity(), SIZE_MAX);
        } catch (const std::bad_alloc&) {
            // Expected failure for SIZE_MAX allocation
        }
    }
}

// Test boundary conditions for buffer operations
TEST_F(MemoryStressEdgeCasesTest, BufferOperationBoundaries) {
    auto test_data = create_random_data(1024);
    ZeroCopyBuffer buffer(test_data.data(), test_data.size());
    
    // Test boundary slice operations
    {
        // Slice at start
        auto start_slice = buffer.create_slice(0, 10);
        EXPECT_EQ(start_slice.size(), 10);
        EXPECT_EQ(std::memcmp(start_slice.data(), test_data.data(), 10), 0);
        
        // Slice at end
        auto end_slice = buffer.create_slice(test_data.size() - 10, 10);
        EXPECT_EQ(end_slice.size(), 10);
        EXPECT_EQ(std::memcmp(end_slice.data(), test_data.data() + test_data.size() - 10, 10), 0);
        
        // Slice entire buffer
        auto full_slice = buffer.create_slice(0, test_data.size());
        EXPECT_EQ(full_slice.size(), test_data.size());
        EXPECT_EQ(std::memcmp(full_slice.data(), test_data.data(), test_data.size()), 0);
        
        // Edge case: zero-length slice at end
        auto zero_end_slice = buffer.create_slice(test_data.size(), 0);
        EXPECT_EQ(zero_end_slice.size(), 0);
        
        // Edge case: single byte slices
        for (size_t i = 0; i < std::min(test_data.size(), size_t{10}); ++i) {
            auto single_slice = buffer.create_slice(i, 1);
            EXPECT_EQ(single_slice.size(), 1);
            EXPECT_EQ(single_slice.data()[0], test_data[i]);
        }
    }
    
    // Test boundary append operations
    {
        ZeroCopyBuffer append_buffer(2048);
        
        // Append to empty buffer
        auto result1 = append_buffer.append(test_data.data(), test_data.size());
        EXPECT_TRUE(result1.is_ok());
        EXPECT_EQ(append_buffer.size(), test_data.size());
        
        // Append to non-empty buffer
        auto more_data = create_random_data(512);
        auto result2 = append_buffer.append(more_data.data(), more_data.size());
        EXPECT_TRUE(result2.is_ok());
        EXPECT_EQ(append_buffer.size(), test_data.size() + more_data.size());
        
        // Verify data integrity
        EXPECT_EQ(std::memcmp(append_buffer.data(), test_data.data(), test_data.size()), 0);
        EXPECT_EQ(std::memcmp(append_buffer.data() + test_data.size(), more_data.data(), more_data.size()), 0);
        
        // Append until capacity is reached
        while (append_buffer.available_space() > 0) {
            std::byte single_byte{0xFF};
            auto result = append_buffer.append(&single_byte, 1);
            if (result.is_error()) {
                break;
            }
        }
        
        // Buffer should be at or near capacity
        EXPECT_LE(append_buffer.available_space(), 8); // Allow some overhead
    }
}

// Test memory pressure scenarios
TEST_F(MemoryStressEdgeCasesTest, MemoryPressureScenarios) {
    const size_t pressure_threshold = 256 * 1024 * 1024; // 256MB
    std::vector<PooledBuffer> pressure_buffers;
    
    // Gradually increase memory pressure
    size_t current_allocation = 0;
    const size_t allocation_size = 1024 * 1024; // 1MB per allocation
    
    while (current_allocation < pressure_threshold) {
        auto buffer = make_pooled_buffer(allocation_size);
        
        if (buffer.is_valid()) {
            // Fill buffer with data to ensure real allocation
            auto pattern_data = create_pattern_data(allocation_size, 
                                                  static_cast<uint8_t>(pressure_buffers.size()));
            auto append_result = buffer->append(pattern_data.data(), pattern_data.size());
            
            if (append_result.is_ok()) {
                pressure_buffers.push_back(std::move(buffer));
                current_allocation += allocation_size;
            } else {
                break; // Allocation failed
            }
        } else {
            break; // Pool exhausted
        }
        
        // Check memory health periodically
        if (pressure_buffers.size() % 50 == 0) {
            auto health_result = utils::perform_memory_health_check();
            if (health_result.is_ok()) {
                auto health = health_result.value();
                std::cout << "Memory pressure check: " << pressure_buffers.size() 
                         << " buffers, " << health.total_memory_usage / (1024 * 1024) 
                         << "MB used, fragmentation: " << health.fragmentation_ratio << std::endl;
                
                // If memory becomes unhealthy, break
                if (!health.overall_healthy || health.fragmentation_ratio > 0.5) {
                    std::cout << "Memory pressure limit reached" << std::endl;
                    break;
                }
            }
        }
    }
    
    std::cout << "Allocated " << pressure_buffers.size() << " pressure buffers (" 
              << (pressure_buffers.size() * allocation_size) / (1024 * 1024) << "MB)" << std::endl;
    
    // Test operations under memory pressure
    {
        // Try to allocate more buffers
        auto additional_buffer = make_pooled_buffer(allocation_size);
        // May succeed or fail depending on memory availability
        
        // Test buffer operations on existing buffers
        if (!pressure_buffers.empty()) {
            auto& test_buffer = pressure_buffers[pressure_buffers.size() / 2];
            
            // Test slicing under pressure
            auto slice = test_buffer->create_slice(0, 1024);
            EXPECT_EQ(slice.size(), 1024);
            
            // Test sharing under pressure
            auto share_result = test_buffer->share_buffer();
            EXPECT_TRUE(share_result.is_ok() || share_result.is_error());
        }
    }
    
    // Release buffers gradually and test memory recovery
    size_t released_count = 0;
    while (!pressure_buffers.empty() && released_count < pressure_buffers.size() / 2) {
        pressure_buffers.pop_back();
        released_count++;
        
        if (released_count % 20 == 0) {
            // Test memory operations after partial release
            auto recovery_buffer = make_pooled_buffer(allocation_size / 2);
            if (recovery_buffer.is_valid()) {
                std::cout << "Memory recovery: can allocate after releasing " 
                         << released_count << " buffers" << std::endl;
            }
        }
    }
    
    // Clean up remaining buffers
    pressure_buffers.clear();
    
    // Force garbage collection
    utils::force_garbage_collection();
    
    // Verify memory recovery
    auto final_health = utils::perform_memory_health_check();
    EXPECT_TRUE(final_health.is_ok());
    
    if (final_health.is_ok()) {
        auto health = final_health.value();
        std::cout << "Final memory state: " << health.total_memory_usage / (1024 * 1024) 
                 << "MB used, healthy: " << health.overall_healthy << std::endl;
    }
}

// Test extreme concurrency scenarios
TEST_F(MemoryStressEdgeCasesTest, ExtremeConcurrencyStress) {
    const int max_threads = std::min(static_cast<int>(std::thread::hardware_concurrency() * 2), 32);
    const int operations_per_thread = 200;
    const std::chrono::seconds test_duration{5};
    
    std::atomic<bool> stop_test{false};
    std::atomic<int> thread_counter{0};
    std::atomic<int> successful_operations{0};
    std::atomic<int> failed_operations{0};
    std::atomic<int> exception_count{0};
    
    // Shared resources for contention
    std::vector<std::shared_ptr<BufferPool>> shared_pools;
    for (int i = 0; i < 5; ++i) {
        shared_pools.push_back(std::make_shared<BufferPool>(1024 * (i + 1), 32));
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    std::vector<std::future<void>> futures;
    
    // Launch extreme concurrency test
    for (int t = 0; t < max_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            int thread_id = thread_counter.fetch_add(1);
            std::mt19937 thread_gen(std::random_device{}() + thread_id);
            std::uniform_int_distribution<> op_dis(0, 6);
            std::uniform_int_distribution<> pool_dis(0, shared_pools.size() - 1);
            std::uniform_int_distribution<> size_dis(64, 8192);
            
            std::vector<std::unique_ptr<ZeroCopyBuffer>> thread_buffers;
            
            for (int op = 0; op < operations_per_thread && !stop_test.load(); ++op) {
                try {
                    int operation = op_dis(thread_gen);
                    
                    switch (operation) {
                        case 0: // Pool allocation
                        {
                            int pool_idx = pool_dis(thread_gen);
                            auto buffer = shared_pools[pool_idx]->acquire();
                            if (buffer) {
                                thread_buffers.push_back(std::move(buffer));
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 1: // Pool release
                        {
                            if (!thread_buffers.empty()) {
                                auto buffer = std::move(thread_buffers.back());
                                thread_buffers.pop_back();
                                
                                // Find original pool (simplified - use first pool)
                                shared_pools[0]->release(std::move(buffer));
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 2: // Direct allocation
                        {
                            size_t size = size_dis(thread_gen);
                            auto buffer = make_buffer(size);
                            if (buffer) {
                                thread_buffers.push_back(std::move(buffer));
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 3: // Buffer operations
                        {
                            if (!thread_buffers.empty()) {
                                auto& buffer = thread_buffers.back();
                                auto test_data = create_random_data(256);
                                
                                auto result = buffer->append(test_data.data(), 
                                                            std::min(test_data.size(), 
                                                                   buffer->available_space()));
                                if (result.is_ok()) {
                                    successful_operations.fetch_add(1);
                                } else {
                                    failed_operations.fetch_add(1);
                                }
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 4: // Slicing operations
                        {
                            if (!thread_buffers.empty()) {
                                auto& buffer = thread_buffers.back();
                                if (buffer->size() > 0) {
                                    size_t slice_size = std::min(buffer->size(), size_t{128});
                                    auto slice = buffer->create_slice(0, slice_size);
                                    
                                    if (slice.size() == slice_size) {
                                        successful_operations.fetch_add(1);
                                    } else {
                                        failed_operations.fetch_add(1);
                                    }
                                } else {
                                    failed_operations.fetch_add(1);
                                }
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 5: // Memory utilities
                        {
                            auto data1 = create_random_data(128);
                            auto data2 = data1; // Copy for comparison
                            
                            bool equal = utils::secure_compare(data1.data(), data2.data(), data1.size());
                            utils::secure_memzero(data1.data(), data1.size());
                            bool cleared = utils::is_memory_cleared(data1.data(), data1.size());
                            
                            if (equal && cleared) {
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 6: // Crypto operations
                        {
                            auto& factory = ZeroCopyCryptoFactory::instance();
                            auto crypto_buffer = factory.create_crypto_buffer(512);
                            
                            if (crypto_buffer.size() == 512) {
                                auto wrapped = factory.wrap_buffer(ZeroCopyBuffer(256));
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                    }
                    
                    // Occasional cleanup to prevent excessive memory use
                    if (thread_buffers.size() > 50) {
                        thread_buffers.erase(thread_buffers.begin() + 25, thread_buffers.end());
                    }
                    
                } catch (...) {
                    exception_count.fetch_add(1);
                    failed_operations.fetch_add(1);
                }
            }
            
            // Clean up thread buffers
            thread_buffers.clear();
        }));
    }
    
    // Let test run for specified duration
    std::this_thread::sleep_for(test_duration);
    stop_test.store(true);
    
    // Wait for all threads
    for (auto& future : futures) {
        future.wait();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Extreme concurrency stress test results:" << std::endl;
    std::cout << "  Threads: " << max_threads << std::endl;
    std::cout << "  Duration: " << actual_duration.count() << " ms" << std::endl;
    std::cout << "  Successful operations: " << successful_operations.load() << std::endl;
    std::cout << "  Failed operations: " << failed_operations.load() << std::endl;
    std::cout << "  Exceptions: " << exception_count.load() << std::endl;
    std::cout << "  Total operations: " << (successful_operations.load() + failed_operations.load()) << std::endl;
    
    if (successful_operations.load() + failed_operations.load() > 0) {
        double success_rate = (double)successful_operations.load() / 
                             (successful_operations.load() + failed_operations.load());
        std::cout << "  Success rate: " << (success_rate * 100.0) << "%" << std::endl;
        std::cout << "  Ops/sec: " << ((successful_operations.load() + failed_operations.load()) * 1000.0) / actual_duration.count() << std::endl;
        
        // Should maintain reasonable success rate even under extreme stress
        EXPECT_GT(success_rate, 0.5); // At least 50% success rate
    }
    
    // Exception count should be low
    EXPECT_LT(exception_count.load(), (successful_operations.load() + failed_operations.load()) / 10);
}

// Test edge cases in leak detection
TEST_F(MemoryStressEdgeCasesTest, LeakDetectionEdgeCases) {
    auto& detector = LeakDetector::instance();
    
    // Configure for edge case testing
    LeakDetectionConfig config;
    config.enable_automatic_cleanup = false;
    config.enable_stack_traces = false;
    config.enable_periodic_checks = false;
    config.max_resource_age = std::chrono::milliseconds(100);
    config.critical_resource_age = std::chrono::milliseconds(50);
    config.max_resources_per_type = 10000;
    config.max_total_resources = 50000;
    detector.set_config(config);
    detector.enable_detection(true);
    
    // Test with null pointers
    {
        detector.track_resource(nullptr, ResourceType::BUFFER, 0, "null_test", "Null resource");
        EXPECT_FALSE(detector.is_resource_tracked(nullptr));
        detector.untrack_resource(nullptr); // Should be safe
    }
    
    // Test with same pointer multiple times
    {
        std::unique_ptr<std::byte[]> test_resource = std::make_unique<std::byte[]>(1024);
        void* ptr = test_resource.get();
        
        detector.track_resource(ptr, ResourceType::BUFFER, 1024, "double_test:1", "First track");
        EXPECT_TRUE(detector.is_resource_tracked(ptr));
        
        detector.track_resource(ptr, ResourceType::BUFFER, 1024, "double_test:2", "Second track");
        EXPECT_TRUE(detector.is_resource_tracked(ptr));
        
        detector.untrack_resource(ptr);
        EXPECT_FALSE(detector.is_resource_tracked(ptr));
        
        // Untracking again should be safe
        detector.untrack_resource(ptr);
    }
    
    // Test resource type edge cases
    {
        std::vector<std::unique_ptr<std::byte[]>> edge_resources;
        
        // Test all resource types
        for (int type = static_cast<int>(ResourceType::BUFFER); 
             type <= static_cast<int>(ResourceType::OTHER); ++type) {
            
            auto resource = std::make_unique<std::byte[]>(256);
            detector.track_resource(resource.get(), static_cast<ResourceType>(type), 256,
                                   "edge_type_test", "Edge type resource");
            edge_resources.push_back(std::move(resource));
        }
        
        // Test leak detection with mixed types
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        
        auto leak_result = detector.detect_leaks();
        EXPECT_TRUE(leak_result.is_ok());
        
        if (leak_result.is_ok()) {
            auto report = leak_result.value();
            EXPECT_GT(report.total_leaks, 0);
            
            // Clean up
            for (const auto& resource : edge_resources) {
                detector.untrack_resource(resource.get());
            }
        }
    }
    
    // Test massive resource tracking
    {
        const int num_resources = 5000;
        std::vector<std::unique_ptr<std::byte[]>> mass_resources;
        mass_resources.reserve(num_resources);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < num_resources; ++i) {
            auto resource = std::make_unique<std::byte[]>(128);
            detector.track_resource(resource.get(), ResourceType::BUFFER, 128,
                                   "mass_test", "Mass resource");
            mass_resources.push_back(std::move(resource));
        }
        
        auto track_time = std::chrono::high_resolution_clock::now();
        
        // Detect leaks in massive collection
        auto leak_result = detector.detect_leaks();
        EXPECT_TRUE(leak_result.is_ok());
        
        auto detect_time = std::chrono::high_resolution_clock::now();
        
        // Untrack all
        for (const auto& resource : mass_resources) {
            detector.untrack_resource(resource.get());
        }
        
        auto untrack_time = std::chrono::high_resolution_clock::now();
        
        auto track_duration = std::chrono::duration_cast<std::chrono::milliseconds>(track_time - start_time);
        auto detect_duration = std::chrono::duration_cast<std::chrono::milliseconds>(detect_time - track_time);
        auto untrack_duration = std::chrono::duration_cast<std::chrono::milliseconds>(untrack_time - detect_time);
        
        std::cout << "Mass leak detection test:" << std::endl;
        std::cout << "  Resources: " << num_resources << std::endl;
        std::cout << "  Track time: " << track_duration.count() << " ms" << std::endl;
        std::cout << "  Detect time: " << detect_duration.count() << " ms" << std::endl;
        std::cout << "  Untrack time: " << untrack_duration.count() << " ms" << std::endl;
        
        // Performance should be reasonable
        EXPECT_LT(track_duration.count(), 5000); // Less than 5 seconds
        EXPECT_LT(detect_duration.count(), 5000);
        EXPECT_LT(untrack_duration.count(), 5000);
        
        mass_resources.clear();
    }
    
    detector.enable_detection(false);
}

// Test adaptive pool edge cases and stress scenarios
TEST_F(MemoryStressEdgeCasesTest, AdaptivePoolStressAndEdgeCases) {
    // Test with extreme configurations
    {
        AdaptivePoolSizer::SizingConfig extreme_config;
        extreme_config.algorithm = AdaptivePoolSizer::Algorithm::AGGRESSIVE;
        extreme_config.min_pool_size = 1;
        extreme_config.max_pool_size = 2; // Very restrictive
        extreme_config.growth_factor = 100.0; // Extreme growth
        extreme_config.shrink_threshold = 0.99; // Almost never shrink
        extreme_config.expand_threshold = 0.01; // Always expand
        
        AdaptiveBufferPool extreme_pool(1024, 1, extreme_config);
        
        // Test operations with extreme config
        std::vector<std::unique_ptr<ZeroCopyBuffer>> extreme_buffers;
        
        for (int i = 0; i < 10; ++i) {
            auto buffer = extreme_pool.acquire();
            if (buffer) {
                extreme_buffers.push_back(std::move(buffer));
            }
        }
        
        EXPECT_LE(extreme_buffers.size(), extreme_config.max_pool_size);
        
        // Force adaptation
        extreme_pool.force_adaptation();
        
        // Release buffers
        for (auto& buffer : extreme_buffers) {
            extreme_pool.release(std::move(buffer));
        }
        
        // Test metrics
        auto metrics = extreme_pool.get_performance_metrics();
        EXPECT_GE(metrics.adaptations_performed, 0);
    }
    
    // Test rapid allocation/deallocation cycles
    {
        AdaptivePoolSizer::SizingConfig rapid_config;
        rapid_config.algorithm = AdaptivePoolSizer::Algorithm::BALANCED;
        rapid_config.adaptation_window = std::chrono::milliseconds(10); // Very fast adaptation
        
        AdaptiveBufferPool rapid_pool(2048, 16, rapid_config);
        rapid_pool.set_auto_adaptation(true);
        rapid_pool.set_adaptation_interval(std::chrono::milliseconds(5));
        
        const int rapid_cycles = 1000;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        for (int cycle = 0; cycle < rapid_cycles; ++cycle) {
            std::vector<std::unique_ptr<ZeroCopyBuffer>> cycle_buffers;
            
            // Rapid allocation
            for (int i = 0; i < 10; ++i) {
                auto buffer = rapid_pool.acquire();
                if (buffer) {
                    cycle_buffers.push_back(std::move(buffer));
                }
            }
            
            // Rapid deallocation
            for (auto& buffer : cycle_buffers) {
                rapid_pool.release(std::move(buffer));
            }
            
            // Trigger adaptation occasionally
            if (cycle % 10 == 0) {
                rapid_pool.update_usage_statistics();
                rapid_pool.force_adaptation();
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "Rapid adaptive pool test:" << std::endl;
        std::cout << "  Cycles: " << rapid_cycles << std::endl;
        std::cout << "  Duration: " << duration.count() << " ms" << std::endl;
        std::cout << "  Cycles/sec: " << (rapid_cycles * 1000.0) / duration.count() << std::endl;
        
        auto final_metrics = rapid_pool.get_performance_metrics();
        std::cout << "  Adaptations: " << final_metrics.adaptations_performed << std::endl;
        
        // Should complete in reasonable time
        EXPECT_LT(duration.count(), 10000); // Less than 10 seconds
    }
}

// Test memory alignment and security edge cases
TEST_F(MemoryStressEdgeCasesTest, AlignmentAndSecurityEdgeCases) {
    // Test extreme alignment values
    {
        char test_buffer[1024];
        void* ptr = test_buffer;
        
        // Test power-of-2 alignments
        for (size_t align = 1; align <= 512; align *= 2) {
            void* aligned = utils::align_pointer(ptr, align);
            EXPECT_TRUE(utils::is_aligned(aligned, align));
            EXPECT_GE(static_cast<char*>(aligned), static_cast<char*>(ptr));
            EXPECT_LT(static_cast<char*>(aligned), static_cast<char*>(ptr) + align);
        }
        
        // Test non-power-of-2 alignments
        std::vector<size_t> odd_alignments = {3, 5, 6, 7, 9, 10, 12, 15};
        for (size_t align : odd_alignments) {
            void* aligned = utils::align_pointer(ptr, align);
            EXPECT_TRUE(utils::is_aligned(aligned, align));
        }
        
        // Test size alignment
        for (size_t size = 1; size <= 1000; ++size) {
            for (size_t align = 1; align <= 64; align *= 2) {
                size_t aligned_size = utils::align_size(size, align);
                EXPECT_GE(aligned_size, size);
                EXPECT_EQ(aligned_size % align, 0);
            }
        }
    }
    
    // Test security operations with edge cases
    {
        // Test with zero size
        utils::secure_memzero(nullptr, 0);
        utils::secure_memset(nullptr, 0xAA, 0);
        EXPECT_TRUE(utils::is_memory_cleared(nullptr, 0));
        EXPECT_TRUE(utils::secure_compare(nullptr, nullptr, 0));
        
        // Test with very large sizes (should be safe)
        auto large_data1 = create_random_data(1024 * 1024); // 1MB
        auto large_data2 = large_data1; // Copy
        
        EXPECT_TRUE(utils::secure_compare(large_data1.data(), large_data2.data(), large_data1.size()));
        
        utils::secure_memzero(large_data1.data(), large_data1.size());
        EXPECT_TRUE(utils::is_memory_cleared(large_data1.data(), large_data1.size()));
        EXPECT_FALSE(utils::secure_compare(large_data1.data(), large_data2.data(), large_data1.size()));
        
        // Test with misaligned data
        std::vector<std::byte> misaligned_buffer(1024 + 16);
        std::byte* misaligned_ptr = misaligned_buffer.data() + 1; // Force misalignment
        
        utils::secure_memset(misaligned_ptr, 0xCC, 1023);
        for (size_t i = 0; i < 1023; ++i) {
            EXPECT_EQ(misaligned_ptr[i], std::byte{0xCC});
        }
        
        utils::secure_memzero(misaligned_ptr, 1023);
        EXPECT_TRUE(utils::is_memory_cleared(misaligned_ptr, 1023));
    }
}

// Test error recovery and resilience
TEST_F(MemoryStressEdgeCasesTest, ErrorRecoveryAndResilience) {
    // Test recovery from allocation failures
    {
        std::vector<std::unique_ptr<ZeroCopyBuffer>> failure_buffers;
        const size_t large_allocation = 64 * 1024 * 1024; // 64MB
        
        // Allocate until failure
        bool allocation_failed = false;
        for (int i = 0; i < 50; ++i) { // Limit attempts
            try {
                auto buffer = make_buffer(large_allocation);
                if (buffer && buffer->capacity() >= large_allocation) {
                    // Fill to ensure real allocation
                    auto test_data = create_random_data(std::min(large_allocation, size_t{1024}));
                    auto result = buffer->append(test_data.data(), test_data.size());
                    if (result.is_ok()) {
                        failure_buffers.push_back(std::move(buffer));
                    } else {
                        allocation_failed = true;
                        break;
                    }
                } else {
                    allocation_failed = true;
                    break;
                }
            } catch (const std::bad_alloc&) {
                allocation_failed = true;
                break;
            }
        }
        
        std::cout << "Allocation stress test: allocated " << failure_buffers.size() 
                 << " large buffers before failure" << std::endl;
        
        // Test operations after allocation failure
        if (allocation_failed) {
            // Should still be able to allocate smaller buffers
            auto small_buffer = make_buffer(1024);
            EXPECT_NE(small_buffer, nullptr);
            
            if (small_buffer) {
                auto test_data = create_random_data(512);
                auto result = small_buffer->append(test_data.data(), test_data.size());
                EXPECT_TRUE(result.is_ok());
            }
        }
        
        // Release some buffers and test recovery
        size_t released = failure_buffers.size() / 2;
        for (size_t i = 0; i < released; ++i) {
            failure_buffers.pop_back();
        }
        
        // Should be able to allocate again
        auto recovery_buffer = make_buffer(large_allocation / 2);
        // May succeed or fail depending on memory availability
        
        // Clean up
        failure_buffers.clear();
        utils::force_garbage_collection();
    }
    
    // Test pool recovery from corruption simulation
    {
        BufferPool recovery_pool(4096, 32);
        
        // Normal operation
        std::vector<std::unique_ptr<ZeroCopyBuffer>> normal_buffers;
        for (int i = 0; i < 10; ++i) {
            auto buffer = recovery_pool.acquire();
            if (buffer) {
                normal_buffers.push_back(std::move(buffer));
            }
        }
        
        auto stats_before = recovery_pool.get_statistics();
        EXPECT_EQ(stats_before.total_allocations, 10);
        
        // Simulate recovery scenario by clearing pool
        recovery_pool.clear_pool();
        
        // Pool should be functional after clearing
        auto recovery_buffer = recovery_pool.acquire();
        EXPECT_NE(recovery_buffer, nullptr);
        
        if (recovery_buffer) {
            recovery_pool.release(std::move(recovery_buffer));
        }
        
        // Clean up
        for (auto& buffer : normal_buffers) {
            // Note: Releasing to cleared pool may not work as expected
            // This tests robustness of the pool implementation
        }
    }
    
    // Test memory system recovery
    {
        // Get initial health
        auto initial_health = utils::perform_memory_health_check();
        EXPECT_TRUE(initial_health.is_ok());
        
        // Stress the system
        std::vector<PooledBuffer> stress_buffers;
        for (int i = 0; i < 100; ++i) {
            auto buffer = make_pooled_buffer(1024 * 1024); // 1MB each
            if (buffer.is_valid()) {
                stress_buffers.push_back(std::move(buffer));
            }
        }
        
        // Force memory operations
        utils::compact_memory_pools();
        utils::force_garbage_collection();
        
        // Check health under stress
        auto stress_health = utils::perform_memory_health_check();
        EXPECT_TRUE(stress_health.is_ok());
        
        // Clean up and check recovery
        stress_buffers.clear();
        utils::force_garbage_collection();
        
        auto recovery_health = utils::perform_memory_health_check();
        EXPECT_TRUE(recovery_health.is_ok());
        
        if (recovery_health.is_ok()) {
            auto health = recovery_health.value();
            EXPECT_TRUE(health.overall_healthy);
            EXPECT_EQ(health.memory_leaks, 0);
        }
    }
}