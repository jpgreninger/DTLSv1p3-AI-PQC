/**
 * @file test_memory_performance_security_comprehensive.cpp
 * @brief Comprehensive performance and security tests for DTLS memory management
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
#include <numeric>

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

class MemoryPerformanceSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize memory system for testing
        auto init_result = initialize_memory_system();
        ASSERT_TRUE(init_result.is_ok());
        
        // Configure for performance testing
        MemorySystemConfig config;
        config.enable_pool_statistics = true;
        config.enable_buffer_debugging = false; // Disable for performance
        config.enable_allocation_tracking = true;
        config.enable_performance_monitoring = true;
        config.enable_leak_detection = false; // Disable for performance tests
        config.max_total_memory = 2 * 1024 * 1024 * 1024; // 2GB for testing
        
        auto config_result = set_memory_system_config(config);
        ASSERT_TRUE(config_result.is_ok());
        
        // Create test data patterns
        small_data_.resize(256);
        medium_data_.resize(4096);
        large_data_.resize(65536);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> byte_dis(0, 255);
        
        for (auto& data_vec : {&small_data_, &medium_data_, &large_data_}) {
            for (auto& byte : *data_vec) {
                byte = static_cast<std::byte>(byte_dis(gen));
            }
        }
        
        // Security test patterns
        crypto_key_.resize(32);
        crypto_nonce_.resize(12);
        sensitive_data_.resize(1024);
        
        for (auto& byte : crypto_key_) {
            byte = static_cast<std::byte>(byte_dis(gen));
        }
        for (auto& byte : crypto_nonce_) {
            byte = static_cast<std::byte>(byte_dis(gen));
        }
        for (auto& byte : sensitive_data_) {
            byte = static_cast<std::byte>(byte_dis(gen));
        }
    }
    
    void TearDown() override {
        cleanup_memory_system();
    }
    
    // Performance measurement helpers
    template<typename Func>
    std::chrono::nanoseconds measure_time(Func&& func) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    }
    
    template<typename Func>
    std::chrono::nanoseconds measure_average_time(Func&& func, int iterations) {
        std::vector<std::chrono::nanoseconds> times;
        times.reserve(iterations);
        
        for (int i = 0; i < iterations; ++i) {
            times.push_back(measure_time(func));
        }
        
        auto total = std::accumulate(times.begin(), times.end(), std::chrono::nanoseconds{0});
        return total / iterations;
    }
    
    std::vector<std::byte> small_data_;
    std::vector<std::byte> medium_data_;
    std::vector<std::byte> large_data_;
    std::vector<std::byte> crypto_key_;
    std::vector<std::byte> crypto_nonce_;
    std::vector<std::byte> sensitive_data_;
};

// Test buffer allocation performance
TEST_F(MemoryPerformanceSecurityTest, BufferAllocationPerformance) {
    const int num_iterations = 10000;
    const std::vector<size_t> test_sizes = {256, 1024, 4096, 16384, 65536};
    
    for (size_t size : test_sizes) {
        // Test regular allocation
        auto regular_time = measure_average_time([size]() {
            auto buffer = std::make_unique<ZeroCopyBuffer>(size);
            // Touch the memory to ensure allocation
            volatile auto dummy = buffer->mutable_data()[0];
            (void)dummy;
        }, num_iterations);
        
        // Test pooled allocation
        auto pooled_time = measure_average_time([size]() {
            auto buffer = make_pooled_buffer(size);
            // Touch the memory to ensure allocation
            if (buffer.is_valid()) {
                volatile auto dummy = buffer->mutable_data()[0];
                (void)dummy;
            }
        }, num_iterations);
        
        std::cout << "Size " << size << " bytes:" << std::endl;
        std::cout << "  Regular allocation: " << regular_time.count() << " ns avg" << std::endl;
        std::cout << "  Pooled allocation:  " << pooled_time.count() << " ns avg" << std::endl;
        std::cout << "  Pool speedup: " << (double)regular_time.count() / pooled_time.count() << "x" << std::endl;
        
        // Pooled allocation should generally be faster or comparable
        // Allow 10x worse performance for pool allocation due to overhead in small tests
        EXPECT_LT(pooled_time.count(), regular_time.count() * 10);
    }
}

// Test buffer operations performance
TEST_F(MemoryPerformanceSecurityTest, BufferOperationsPerformance) {
    const int num_iterations = 1000;
    
    // Test data for different operations
    std::vector<std::pair<std::string, std::vector<std::byte>*>> test_cases = {
        {"small", &small_data_},
        {"medium", &medium_data_},
        {"large", &large_data_}
    };
    
    for (const auto& [name, data] : test_cases) {
        ZeroCopyBuffer source_buffer(data->data(), data->size());
        
        // Test copy performance
        auto copy_time = measure_average_time([&source_buffer]() {
            auto result = source_buffer.slice(0, source_buffer.size());
            EXPECT_TRUE(result.is_ok());
            auto copy = result.value();
            // Touch the copy to ensure it's created
            volatile auto dummy = copy.data()[0];
            (void)dummy;
        }, num_iterations);
        
        // Test append performance
        auto append_time = measure_average_time([data]() {
            ZeroCopyBuffer buffer(data->size() * 2);
            auto result = buffer.append(data->data(), data->size());
            EXPECT_TRUE(result.is_ok());
        }, num_iterations);
        
        // Test zero-copy slice performance
        auto slice_time = measure_average_time([&source_buffer]() {
            auto slice = source_buffer.create_slice(10, source_buffer.size() - 20);
            // Touch the slice
            volatile auto dummy = slice.data()[0];
            (void)dummy;
        }, num_iterations);
        
        std::cout << name << " data (" << data->size() << " bytes):" << std::endl;
        std::cout << "  Copy time:   " << copy_time.count() << " ns avg" << std::endl;
        std::cout << "  Append time: " << append_time.count() << " ns avg" << std::endl;
        std::cout << "  Slice time:  " << slice_time.count() << " ns avg" << std::endl;
        
        // Zero-copy slice should be much faster than copy
        EXPECT_LT(slice_time.count(), copy_time.count());
    }
}

// Test pool performance under contention
TEST_F(MemoryPerformanceSecurityTest, PoolContentionPerformance) {
    const int num_threads = std::thread::hardware_concurrency();
    const int operations_per_thread = 1000;
    const size_t buffer_size = 4096;
    
    // Test regular buffer pool
    {
        BufferPool regular_pool(buffer_size, 32);
        std::atomic<int> completed_operations{0};
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<std::future<void>> futures;
        for (int t = 0; t < num_threads; ++t) {
            futures.push_back(std::async(std::launch::async, [&]() {
                for (int i = 0; i < operations_per_thread; ++i) {
                    auto buffer = regular_pool.acquire();
                    if (buffer) {
                        // Simulate work
                        volatile auto dummy = buffer->mutable_data()[0];
                        (void)dummy;
                        regular_pool.release(std::move(buffer));
                        completed_operations.fetch_add(1);
                    }
                }
            }));
        }
        
        for (auto& future : futures) {
            future.wait();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        std::cout << "Regular pool contention test:" << std::endl;
        std::cout << "  Threads: " << num_threads << std::endl;
        std::cout << "  Operations: " << completed_operations.load() << std::endl;
        std::cout << "  Total time: " << total_time.count() << " μs" << std::endl;
        std::cout << "  Ops/sec: " << (completed_operations.load() * 1000000.0) / total_time.count() << std::endl;
        
        EXPECT_EQ(completed_operations.load(), num_threads * operations_per_thread);
    }
    
    // Test adaptive buffer pool
    {
        AdaptivePoolSizer::SizingConfig config;
        config.algorithm = AdaptivePoolSizer::Algorithm::BALANCED;
        config.min_pool_size = 16;
        config.max_pool_size = 128;
        
        AdaptiveBufferPool adaptive_pool(buffer_size, 32, config);
        adaptive_pool.set_auto_adaptation(true);
        std::atomic<int> completed_operations{0};
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        std::vector<std::future<void>> futures;
        for (int t = 0; t < num_threads; ++t) {
            futures.push_back(std::async(std::launch::async, [&]() {
                for (int i = 0; i < operations_per_thread; ++i) {
                    auto buffer = adaptive_pool.acquire();
                    if (buffer) {
                        // Simulate work
                        volatile auto dummy = buffer->mutable_data()[0];
                        (void)dummy;
                        adaptive_pool.release(std::move(buffer));
                        completed_operations.fetch_add(1);
                    }
                }
            }));
        }
        
        for (auto& future : futures) {
            future.wait();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        std::cout << "Adaptive pool contention test:" << std::endl;
        std::cout << "  Operations: " << completed_operations.load() << std::endl;
        std::cout << "  Total time: " << total_time.count() << " μs" << std::endl;
        std::cout << "  Ops/sec: " << (completed_operations.load() * 1000000.0) / total_time.count() << std::endl;
        
        EXPECT_EQ(completed_operations.load(), num_threads * operations_per_thread);
        
        // Check that adaptation occurred
        auto metrics = adaptive_pool.get_performance_metrics();
        EXPECT_GT(metrics.adaptations_performed, 0);
    }
}

// Test zero-copy crypto performance
TEST_F(MemoryPerformanceSecurityTest, ZeroCryptPerformance) {
    const int num_iterations = 1000;
    
    auto& factory = ZeroCopyCryptoFactory::instance();
    
    // Test crypto buffer creation performance
    auto create_time = measure_average_time([&factory]() {
        auto buffer = factory.create_crypto_buffer(4096, true);
        // Touch the buffer
        volatile auto dummy = buffer.mutable_data()[0];
        (void)dummy;
    }, num_iterations);
    
    // Test buffer wrapping performance
    ZeroCopyBuffer regular_buffer(medium_data_.data(), medium_data_.size());
    auto wrap_time = measure_average_time([&factory, &regular_buffer]() {
        auto crypto_buffer = factory.wrap_buffer(regular_buffer);
        // Touch the buffer
        volatile auto dummy = crypto_buffer.data()[0];
        (void)dummy;
    }, num_iterations);
    
    // Test data copying vs zero-copy
    auto copy_time = measure_average_time([&factory, this]() {
        auto buffer = factory.create_crypto_buffer(medium_data_.size());
        auto data = buffer.mutable_data();
        std::memcpy(data, medium_data_.data(), medium_data_.size());
    }, num_iterations);
    
    auto zero_copy_time = measure_average_time([&factory, this]() {
        auto buffer = factory.wrap_data(medium_data_.data(), medium_data_.size());
        // Touch the buffer to ensure it's accessed
        volatile auto dummy = buffer.data()[0];
        (void)dummy;
    }, num_iterations);
    
    std::cout << "Crypto buffer performance:" << std::endl;
    std::cout << "  Create time:    " << create_time.count() << " ns avg" << std::endl;
    std::cout << "  Wrap time:      " << wrap_time.count() << " ns avg" << std::endl;
    std::cout << "  Copy time:      " << copy_time.count() << " ns avg" << std::endl;
    std::cout << "  Zero-copy time: " << zero_copy_time.count() << " ns avg" << std::endl;
    std::cout << "  Zero-copy speedup: " << (double)copy_time.count() / zero_copy_time.count() << "x" << std::endl;
    
    // Zero-copy should be significantly faster than copying
    EXPECT_LT(zero_copy_time.count(), copy_time.count());
    // Wrapping should be faster than creating new buffers
    EXPECT_LT(wrap_time.count(), create_time.count());
}

// Test memory security - sensitive data handling
TEST_F(MemoryPerformanceSecurityTest, SensitiveDataSecurity) {
    // Test secure memory clearing
    {
        std::vector<std::byte> sensitive_copy = sensitive_data_;
        
        // Verify data is not all zeros initially
        bool has_non_zero = false;
        for (const auto& byte : sensitive_copy) {
            if (byte != std::byte{0}) {
                has_non_zero = true;
                break;
            }
        }
        EXPECT_TRUE(has_non_zero);
        
        // Clear securely
        utils::secure_memzero(sensitive_copy.data(), sensitive_copy.size());
        
        // Verify all bytes are zero
        for (const auto& byte : sensitive_copy) {
            EXPECT_EQ(byte, std::byte{0});
        }
        
        // Verify it's detected as cleared
        EXPECT_TRUE(utils::is_memory_cleared(sensitive_copy.data(), sensitive_copy.size()));
    }
    
    // Test secure comparison
    {
        std::vector<std::byte> data1 = crypto_key_;
        std::vector<std::byte> data2 = crypto_key_;
        std::vector<std::byte> data3 = crypto_key_;
        data3[0] = data3[0] ^ std::byte{0xFF}; // Make different
        
        // Test timing-safe comparison
        auto compare_time_1 = measure_average_time([&]() {
            return utils::secure_compare(data1.data(), data2.data(), data1.size());
        }, 10000);
        
        auto compare_time_2 = measure_average_time([&]() {
            return utils::secure_compare(data1.data(), data3.data(), data1.size());
        }, 10000);
        
        std::cout << "Secure comparison timing:" << std::endl;
        std::cout << "  Equal data:     " << compare_time_1.count() << " ns avg" << std::endl;
        std::cout << "  Different data: " << compare_time_2.count() << " ns avg" << std::endl;
        std::cout << "  Timing ratio:   " << (double)compare_time_2.count() / compare_time_1.count() << std::endl;
        
        // Timing should be similar (constant-time operation)
        // Allow up to 50% difference due to measurement noise
        double timing_ratio = (double)std::max(compare_time_1.count(), compare_time_2.count()) / 
                             std::min(compare_time_1.count(), compare_time_2.count());
        EXPECT_LT(timing_ratio, 1.5);
    }
    
    // Test buffer secure zero
    {
        ZeroCopyBuffer secure_buffer(sensitive_data_.data(), sensitive_data_.size());
        
        // Verify buffer has data
        bool has_data = false;
        for (size_t i = 0; i < secure_buffer.size(); ++i) {
            if (secure_buffer.data()[i] != std::byte{0}) {
                has_data = true;
                break;
            }
        }
        EXPECT_TRUE(has_data);
        
        // Secure zero
        secure_buffer.secure_zero();
        
        // Verify all bytes are zero
        for (size_t i = 0; i < secure_buffer.size(); ++i) {
            EXPECT_EQ(secure_buffer.data()[i], std::byte{0});
        }
    }
}

// Test memory leak detection performance
TEST_F(MemoryPerformanceSecurityTest, LeakDetectionPerformance) {
    auto& detector = LeakDetector::instance();
    
    // Configure for performance testing
    LeakDetectionConfig config;
    config.enable_automatic_cleanup = false;
    config.enable_stack_traces = false; // Disable expensive features
    config.enable_periodic_checks = false;
    config.max_resource_age = std::chrono::minutes(60);
    detector.set_config(config);
    
    const int num_resources = 10000;
    std::vector<std::unique_ptr<std::byte[]>> resources;
    resources.reserve(num_resources);
    
    // Test tracking performance
    detector.enable_detection(true);
    
    auto tracking_time = measure_time([&]() {
        for (int i = 0; i < num_resources; ++i) {
            auto resource = std::make_unique<std::byte[]>(1024);
            auto* ptr = resource.get();
            resources.push_back(std::move(resource));
            
            detector.track_resource(ptr, ResourceType::BUFFER, 1024,
                                   "performance_test", "Test resource");
        }
    });
    
    std::cout << "Leak detection tracking performance:" << std::endl;
    std::cout << "  Resources tracked: " << num_resources << std::endl;
    std::cout << "  Total time: " << tracking_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Time per resource: " << tracking_time.count() / num_resources << " ns" << std::endl;
    
    // Test leak detection performance
    auto detection_time = measure_time([&detector]() {
        auto result = detector.detect_leaks();
        EXPECT_TRUE(result.is_ok());
    });
    
    std::cout << "  Leak detection time: " << detection_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Detection per resource: " << detection_time.count() / num_resources << " ns" << std::endl;
    
    // Test untracking performance
    auto untracking_time = measure_time([&]() {
        for (const auto& resource : resources) {
            detector.untrack_resource(resource.get());
        }
    });
    
    std::cout << "  Untracking time: " << untracking_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Untrack per resource: " << untracking_time.count() / num_resources << " ns" << std::endl;
    
    // Cleanup
    resources.clear();
    detector.enable_detection(false);
}

// Test memory fragmentation and compaction
TEST_F(MemoryPerformanceSecurityTest, MemoryFragmentationTest) {
    const int num_pools = 10;
    const int allocations_per_pool = 100;
    
    std::vector<std::unique_ptr<BufferPool>> pools;
    std::vector<std::vector<std::unique_ptr<ZeroCopyBuffer>>> allocated_buffers(num_pools);
    
    // Create pools of different sizes
    for (int i = 0; i < num_pools; ++i) {
        size_t buffer_size = 256 * (i + 1); // 256, 512, 768, etc.
        pools.push_back(std::make_unique<BufferPool>(buffer_size, 64));
        allocated_buffers[i].reserve(allocations_per_pool);
    }
    
    // Allocate many buffers to cause fragmentation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> pool_dis(0, num_pools - 1);
    
    auto allocation_time = measure_time([&]() {
        for (int i = 0; i < num_pools * allocations_per_pool; ++i) {
            int pool_idx = pool_dis(gen);
            auto buffer = pools[pool_idx]->acquire();
            if (buffer) {
                allocated_buffers[pool_idx].push_back(std::move(buffer));
            }
        }
    });
    
    // Randomly release some buffers to create fragmentation
    auto fragmentation_time = measure_time([&]() {
        std::uniform_int_distribution<> release_dis(0, 1);
        for (auto& pool_buffers : allocated_buffers) {
            auto it = pool_buffers.begin();
            while (it != pool_buffers.end()) {
                if (release_dis(gen) == 0) {
                    int pool_idx = &pool_buffers - &allocated_buffers[0];
                    pools[pool_idx]->release(std::move(*it));
                    it = pool_buffers.erase(it);
                } else {
                    ++it;
                }
            }
        }
    });
    
    // Measure memory compaction
    auto compaction_time = measure_time([&]() {
        auto compacted_bytes = utils::compact_memory_pools();
        std::cout << "  Compacted bytes: " << compacted_bytes << std::endl;
    });
    
    std::cout << "Memory fragmentation test:" << std::endl;
    std::cout << "  Allocation time: " << allocation_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Fragmentation time: " << fragmentation_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Compaction time: " << compaction_time.count() / 1000000.0 << " ms" << std::endl;
    
    // Clean up remaining buffers
    for (size_t i = 0; i < allocated_buffers.size(); ++i) {
        for (auto& buffer : allocated_buffers[i]) {
            pools[i]->release(std::move(buffer));
        }
    }
    
    // Performance should be reasonable
    EXPECT_LT(allocation_time.count(), std::chrono::seconds(1).count());
    EXPECT_LT(compaction_time.count(), std::chrono::seconds(1).count());
}

// Test memory DoS protection
TEST_F(MemoryPerformanceSecurityTest, MemoryDoSProtection) {
    // Configure memory limits for DoS protection
    MemorySystemConfig dos_config;
    dos_config.max_total_memory = 64 * 1024 * 1024; // 64MB limit
    dos_config.warning_threshold = 32 * 1024 * 1024; // 32MB warning
    dos_config.enable_pool_statistics = true;
    
    auto config_result = set_memory_system_config(dos_config);
    EXPECT_TRUE(config_result.is_ok());
    
    std::vector<PooledBuffer> attack_buffers;
    const size_t attack_buffer_size = 1024 * 1024; // 1MB per buffer
    const int max_buffers = 100; // Try to allocate 100MB (exceeds limit)
    
    // Simulate memory exhaustion attack
    auto attack_time = measure_time([&]() {
        for (int i = 0; i < max_buffers; ++i) {
            auto buffer = make_pooled_buffer(attack_buffer_size);
            if (buffer.is_valid()) {
                // Fill with data to ensure real allocation
                auto result = buffer->append(medium_data_.data(), 
                                           std::min(medium_data_.size(), attack_buffer_size));
                if (result.is_ok()) {
                    attack_buffers.push_back(std::move(buffer));
                }
            } else {
                // Allocation failed - DoS protection kicked in
                break;
            }
        }
    });
    
    std::cout << "DoS protection test:" << std::endl;
    std::cout << "  Attack duration: " << attack_time.count() / 1000000.0 << " ms" << std::endl;
    std::cout << "  Buffers allocated: " << attack_buffers.size() << std::endl;
    std::cout << "  Memory allocated: " << (attack_buffers.size() * attack_buffer_size) / (1024 * 1024) << " MB" << std::endl;
    
    // DoS protection should have prevented allocation of all buffers
    EXPECT_LT(attack_buffers.size(), max_buffers);
    EXPECT_LT(attack_buffers.size() * attack_buffer_size, dos_config.max_total_memory);
    
    // Check memory health after attack
    auto health_result = utils::perform_memory_health_check();
    EXPECT_TRUE(health_result.is_ok());
    
    auto health_report = health_result.value();
    std::cout << "  Memory usage after attack: " << health_report.total_memory_usage / (1024 * 1024) << " MB" << std::endl;
    std::cout << "  Fragmentation ratio: " << health_report.fragmentation_ratio << std::endl;
    
    // Clean up attack buffers
    attack_buffers.clear();
    
    // Force cleanup
    utils::force_garbage_collection();
    
    // Memory should be healthy after cleanup
    auto cleanup_health = utils::perform_memory_health_check();
    EXPECT_TRUE(cleanup_health.is_ok());
}

// Test concurrent memory operations under stress
TEST_F(MemoryPerformanceSecurityTest, ConcurrentMemoryStress) {
    const int num_threads = std::min(static_cast<int>(std::thread::hardware_concurrency()), 16);
    const int operations_per_thread = 500;
    const std::chrono::seconds test_duration{10};
    
    std::atomic<bool> stop_test{false};
    std::atomic<int> total_operations{0};
    std::atomic<int> successful_operations{0};
    std::atomic<int> failed_operations{0};
    
    auto start_time = std::chrono::steady_clock::now();
    
    std::vector<std::future<void>> futures;
    
    // Launch stress threads
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(256, 16384);
            std::uniform_int_distribution<> op_dis(0, 4);
            
            std::vector<PooledBuffer> thread_buffers;
            
            while (!stop_test.load()) {
                total_operations.fetch_add(1);
                
                try {
                    int operation = op_dis(gen);
                    
                    switch (operation) {
                        case 0: // Allocate buffer
                        {
                            size_t size = size_dis(gen);
                            auto buffer = make_pooled_buffer(size);
                            if (buffer.is_valid()) {
                                thread_buffers.push_back(std::move(buffer));
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 1: // Release buffer
                        {
                            if (!thread_buffers.empty()) {
                                thread_buffers.pop_back();
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 2: // Copy buffer
                        {
                            if (!thread_buffers.empty()) {
                                auto& source = thread_buffers.back();
                                auto copy_result = utils::copy_buffer(BufferView(*source));
                                if (copy_result.is_ok()) {
                                    successful_operations.fetch_add(1);
                                } else {
                                    failed_operations.fetch_add(1);
                                }
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                        
                        case 3: // Append data
                        {
                            if (!thread_buffers.empty()) {
                                auto& buffer = thread_buffers.back();
                                auto result = buffer->append(small_data_.data(), 
                                                            std::min(small_data_.size(), 
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
                        
                        case 4: // Secure operations
                        {
                            std::vector<std::byte> temp_data = sensitive_data_;
                            utils::secure_memzero(temp_data.data(), temp_data.size());
                            
                            if (utils::is_memory_cleared(temp_data.data(), temp_data.size())) {
                                successful_operations.fetch_add(1);
                            } else {
                                failed_operations.fetch_add(1);
                            }
                            break;
                        }
                    }
                    
                    // Occasional cleanup
                    if (thread_buffers.size() > 100) {
                        thread_buffers.erase(thread_buffers.begin() + 50, thread_buffers.end());
                    }
                    
                } catch (...) {
                    failed_operations.fetch_add(1);
                }
            }
            
            // Clean up thread buffers
            thread_buffers.clear();
        }));
    }
    
    // Run test for specified duration
    std::this_thread::sleep_for(test_duration);
    stop_test.store(true);
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Concurrent stress test results:" << std::endl;
    std::cout << "  Threads: " << num_threads << std::endl;
    std::cout << "  Duration: " << actual_duration.count() << " ms" << std::endl;
    std::cout << "  Total operations: " << total_operations.load() << std::endl;
    std::cout << "  Successful operations: " << successful_operations.load() << std::endl;
    std::cout << "  Failed operations: " << failed_operations.load() << std::endl;
    std::cout << "  Success rate: " << (100.0 * successful_operations.load()) / total_operations.load() << "%" << std::endl;
    std::cout << "  Ops/sec: " << (total_operations.load() * 1000.0) / actual_duration.count() << std::endl;
    
    // Check final memory health
    auto final_health = utils::perform_memory_health_check();
    EXPECT_TRUE(final_health.is_ok());
    
    if (final_health.is_ok()) {
        auto health_report = final_health.value();
        std::cout << "  Final memory usage: " << health_report.total_memory_usage / (1024 * 1024) << " MB" << std::endl;
        std::cout << "  Active allocations: " << health_report.active_allocations << std::endl;
        std::cout << "  Memory leaks: " << health_report.memory_leaks << std::endl;
        std::cout << "  Overall healthy: " << (health_report.overall_healthy ? "Yes" : "No") << std::endl;
        
        // System should remain healthy
        EXPECT_TRUE(health_report.overall_healthy);
        EXPECT_EQ(health_report.memory_leaks, 0);
    }
    
    // Success rate should be reasonable
    double success_rate = (double)successful_operations.load() / total_operations.load();
    EXPECT_GT(success_rate, 0.8); // At least 80% success rate
    
    // Should complete a reasonable number of operations
    EXPECT_GT(total_operations.load(), num_threads * 100);
}