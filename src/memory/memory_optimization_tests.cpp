#include <dtls/memory/buffer.h>
#include <dtls/memory/adaptive_pools.h>
#include <dtls/memory/connection_pools.h>
#include <dtls/memory/dos_protection.h>
#include <dtls/memory/handshake_buffers.h>
#include <dtls/memory/leak_detection.h>
#include <dtls/memory/smart_recycling.h>
#include <dtls/memory/zero_copy_crypto.h>
#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <thread>

namespace dtls {
namespace v13 {
namespace memory {
namespace tests {

// Test zero-copy buffer operations
TEST(MemoryOptimizationTest, ZeroCopyBufferSharing) {
    // Create original buffer
    ZeroCopyBuffer original(1024);
    auto resize_result = original.resize(512);
    ASSERT_TRUE(resize_result);
    
    // Fill with test data
    std::memset(original.mutable_data(), 0xAA, 512);
    
    // Test zero-copy sharing
    ZeroCopyBuffer shared_copy = original;
    EXPECT_TRUE(shared_copy.is_shared());
    EXPECT_EQ(shared_copy.reference_count(), 2);
    
    // Test zero-copy slicing
    auto slice = original.create_slice(100, 200);
    EXPECT_EQ(slice.size(), 200);
    
    // Verify data integrity
    EXPECT_EQ(std::memcmp(original.data() + 100, slice.data(), 200), 0);
    
    // Test copy-on-write
    auto make_unique_result = shared_copy.make_unique();
    ASSERT_TRUE(make_unique_result);
    EXPECT_FALSE(shared_copy.is_shared());
    EXPECT_EQ(original.reference_count(), 1);
}

// Test adaptive pool behavior
TEST(MemoryOptimizationTest, AdaptivePoolSizing) {
    auto& pool_manager = AdaptivePoolManager::instance();
    
    // Create adaptive pool for 1KB buffers
    auto create_result = pool_manager.create_adaptive_pool(1024, 4);
    ASSERT_TRUE(create_result);
    
    auto& pool = pool_manager.get_adaptive_pool(1024);
    
    // Allocate buffers to trigger adaptation
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    for (int i = 0; i < 10; ++i) {
        auto buffer = pool.acquire();
        ASSERT_NE(buffer, nullptr);
        buffers.push_back(std::move(buffer));
    }
    
    // Force adaptation
    pool.force_adaptation();
    
    // Check that pool has adapted
    auto metrics = pool.get_performance_metrics();
    EXPECT_GT(metrics.adaptations_performed, 0);
    
    // Release buffers
    for (auto& buffer : buffers) {
        pool.release(std::move(buffer));
    }
    
    pool_manager.remove_adaptive_pool(1024);
}

// Test connection-specific memory pools
TEST(MemoryOptimizationTest, ConnectionSpecificPools) {
    void* connection_id = reinterpret_cast<void*>(0x12345);
    std::string source_ip = "192.168.1.100";
    
    // Create connection characteristics
    ConnectionCharacteristics characteristics;
    characteristics.connection_id = connection_id;
    characteristics.type = ConnectionCharacteristics::ConnectionType::HIGH_THROUGHPUT;
    
    // Create connection pool
    auto create_result = create_connection_memory_pool(connection_id, characteristics);
    ASSERT_TRUE(create_result);
    
    // Allocate connection-specific buffers
    auto message_buffer = allocate_message_buffer(connection_id);
    ASSERT_NE(message_buffer.get(), nullptr);
    EXPECT_GT(message_buffer->size(), 0);
    
    auto header_buffer = allocate_header_buffer(connection_id);
    ASSERT_NE(header_buffer.get(), nullptr);
    
    auto payload_buffer = allocate_payload_buffer(connection_id);
    ASSERT_NE(payload_buffer.get(), nullptr);
    
    // Cleanup
    destroy_connection_memory_pool(connection_id);
}

// Test DoS protection mechanisms
TEST(MemoryOptimizationTest, DoSProtection) {
    auto& dos_engine = DoSProtectionEngine::instance();
    
    // Configure aggressive limits for testing
    DoSProtectionConfig config;
    config.max_per_connection_memory = 4096;  // 4KB limit
    config.max_buffer_size = 2048;            // 2KB max buffer
    config.max_connections_per_ip = 2;        // 2 connections per IP
    dos_engine.set_config(config);
    dos_engine.enable_protection(true);
    
    std::string test_ip = "10.0.0.1";
    
    // Test connection limit enforcement
    EXPECT_TRUE(dos_engine.check_connection_allowed(test_ip));
    dos_engine.track_connection_start(test_ip, reinterpret_cast<void*>(1));
    dos_engine.track_connection_start(test_ip, reinterpret_cast<void*>(2));
    
    // Third connection should be rejected
    auto connection_result = dos_engine.check_connection_allowed(test_ip);
    EXPECT_FALSE(connection_result);
    
    // Test memory allocation limits
    auto memory_result = dos_engine.check_memory_allocation(5000, test_ip);
    EXPECT_FALSE(memory_result); // Should exceed per-connection limit
    
    // Test legitimate allocation
    memory_result = dos_engine.check_memory_allocation(1024, test_ip);
    EXPECT_TRUE(memory_result);
    
    dos_engine.track_connection_end(test_ip, reinterpret_cast<void*>(1));
    dos_engine.track_connection_end(test_ip, reinterpret_cast<void*>(2));
}

// Test protected buffer allocation
TEST(MemoryOptimizationTest, ProtectedBufferAllocation) {
    std::string source_ip = "172.16.1.50";
    
    // Test normal allocation
    auto buffer_result = make_protected_buffer(1024, source_ip, "test");
    ASSERT_TRUE(buffer_result);
    
    auto buffer = buffer_result.take_value();
    EXPECT_EQ(buffer->capacity(), 1024);
    
    // Test oversized allocation (should be rejected)
    auto oversized_result = make_protected_buffer(1024 * 1024, source_ip, "test");
    EXPECT_FALSE(oversized_result); // Should be rejected by DoS protection
}

// Test handshake buffer management
TEST(MemoryOptimizationTest, HandshakeBufferManagement) {
    auto& handshake_manager = HandshakeBufferManager::instance();
    
    void* connection_id = reinterpret_cast<void*>(0x54321);
    std::string source_ip = "203.0.113.10";
    
    handshake_manager.on_handshake_start(connection_id, source_ip);
    
    // Test handshake buffer allocation
    auto buffer_result = handshake_manager.allocate_handshake_buffer(connection_id, source_ip, 2048);
    ASSERT_TRUE(buffer_result);
    
    auto buffer = buffer_result.take_value();
    EXPECT_GE(buffer->capacity(), 2048);
    
    // Test certificate buffer allocation
    auto cert_buffer_result = handshake_manager.allocate_certificate_buffer(connection_id, source_ip);
    ASSERT_TRUE(cert_buffer_result);
    
    // Test fragment handling
    HandshakeFragment fragment;
    fragment.message_type = 1;  // ClientHello
    fragment.message_length = 1000;
    fragment.fragment_offset = 0;
    fragment.fragment_length = 500;
    fragment.message_sequence = 1;
    fragment.fragment_data = std::make_shared<ZeroCopyBuffer>(500);
    fragment.received_time = std::chrono::steady_clock::now();
    
    auto store_result = handshake_manager.store_handshake_fragment(connection_id, source_ip, fragment);
    EXPECT_TRUE(store_result);
    
    // Test memory usage tracking
    size_t memory_usage = handshake_manager.get_connection_memory_usage(connection_id);
    EXPECT_GT(memory_usage, 0);
    
    handshake_manager.cleanup_connection(connection_id);
}

// Test leak detection system
TEST(MemoryOptimizationTest, LeakDetection) {
    auto& leak_detector = LeakDetector::instance();
    
    leak_detector.enable_detection(true);
    
    // Allocate a tracked resource
    void* test_resource = malloc(1024);
    leak_detector.track_resource(test_resource, ResourceType::BUFFER, 1024, 
                                "test_allocation", "Unit test allocation");
    
    EXPECT_TRUE(leak_detector.is_resource_tracked(test_resource));
    
    // Update access time
    leak_detector.update_resource_access(test_resource);
    
    auto resource_info = leak_detector.get_resource_info(test_resource);
    EXPECT_EQ(resource_info.size, 1024);
    EXPECT_EQ(resource_info.type, ResourceType::BUFFER);
    
    // Test leak detection
    auto leak_report_result = leak_detector.detect_leaks();
    ASSERT_TRUE(leak_report_result);
    
    auto leak_report = leak_report_result.take_value();
    EXPECT_GE(leak_report.total_leaks, 1); // Our test resource should be detected as a leak
    
    // Clean up
    leak_detector.untrack_resource(test_resource);
    free(test_resource);
}

// Test smart recycling system
TEST(MemoryOptimizationTest, SmartRecycling) {
    auto& recycling_manager = BufferRecyclingManager::instance();
    auto& smart_factory = SmartBufferFactory::instance();
    
    recycling_manager.enable_aggressive_recycling(false);
    smart_factory.enable_size_optimization(true);
    
    // Track buffer usage pattern
    size_t buffer_size = 2048;
    for (int i = 0; i < 10; ++i) {
        recycling_manager.track_buffer_usage(buffer_size, std::chrono::steady_clock::now());
    }
    
    // Check recycling decision
    bool should_recycle = recycling_manager.should_recycle_buffer(buffer_size);
    EXPECT_TRUE(should_recycle);
    
    // Test smart buffer creation
    auto smart_buffer = smart_factory.create_smart_buffer(buffer_size);
    EXPECT_NE(smart_buffer.get(), nullptr);
    
    // Test buffer type recommendation
    auto buffer_type = smart_factory.recommend_buffer_type(buffer_size, false);
    EXPECT_NE(buffer_type, SmartBufferFactory::BufferType::SHARED); // Should not recommend shared for small buffer
    
    // Test memory pressure response
    auto& pressure_detector = MemoryPressureDetector::instance();
    pressure_detector.update_memory_statistics(100 * 1024 * 1024, 128 * 1024 * 1024); // ~78% usage
    
    auto pressure_level = pressure_detector.detect_memory_pressure();
    EXPECT_GE(pressure_level, MemoryPressureDetector::PressureLevel::LOW);
}

// Test zero-copy crypto operations
TEST(MemoryOptimizationTest, ZeroCopyCrypto) {
    auto& crypto_factory = ZeroCopyCryptoFactory::instance();
    auto& crypto_pool = CryptoBufferPool::instance();
    
    // Test crypto buffer creation
    auto crypto_buffer = crypto_factory.create_crypto_buffer(256, true);
    EXPECT_GE(crypto_buffer.size(), 256);
    EXPECT_FALSE(crypto_buffer.empty());
    
    // Test buffer pool
    auto pooled_buffer = crypto_pool.acquire_buffer(512, false);
    EXPECT_GE(pooled_buffer.size(), 512);
    
    // Test buffer wrapping
    ZeroCopyBuffer regular_buffer(1024);
    auto wrapped_crypto = crypto_factory.wrap_buffer(regular_buffer);
    EXPECT_EQ(wrapped_crypto.size(), regular_buffer.size());
    
    crypto_pool.release_buffer(std::move(pooled_buffer));
    
    // Check pool statistics
    auto pool_stats = crypto_pool.get_statistics();
    EXPECT_GT(pool_stats.total_crypto_buffers, 0);
}

// Performance test for memory allocation speed
TEST(MemoryOptimizationTest, AllocationPerformance) {
    const size_t num_allocations = 1000;
    const size_t buffer_size = 1024;
    
    // Test regular allocation performance
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers;
    buffers.reserve(num_allocations);
    
    for (size_t i = 0; i < num_allocations; ++i) {
        buffers.push_back(std::make_unique<ZeroCopyBuffer>(buffer_size));
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Should complete allocations reasonably quickly
    EXPECT_LT(duration.count(), 50000); // Less than 50ms for 1000 allocations
    
    buffers.clear();
    
    // Test pooled allocation performance
    auto& pool_manager = AdaptivePoolManager::instance();
    auto create_result = pool_manager.create_adaptive_pool(buffer_size, 16);
    ASSERT_TRUE(create_result);
    
    auto& pool = pool_manager.get_adaptive_pool(buffer_size);
    
    start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::unique_ptr<ZeroCopyBuffer>> pooled_buffers;
    pooled_buffers.reserve(num_allocations);
    
    for (size_t i = 0; i < num_allocations; ++i) {
        pooled_buffers.push_back(pool.acquire());
    }
    
    end_time = std::chrono::high_resolution_clock::now();
    auto pooled_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Pooled allocation should be faster or similar
    EXPECT_LE(pooled_duration.count(), duration.count() * 1.2); // Allow 20% margin
    
    // Return buffers to pool
    for (auto& buffer : pooled_buffers) {
        pool.release(std::move(buffer));
    }
    
    pool_manager.remove_adaptive_pool(buffer_size);
}

// Test memory pressure handling
TEST(MemoryOptimizationTest, MemoryPressureHandling) {
    auto& pressure_response = MemoryPressureResponse::instance();
    
    // Register a test callback
    size_t callback_invoked = 0;
    pressure_response.register_pressure_callback("test_callback", 
        [&callback_invoked](MemoryPressureResponse::PressureLevel level) -> size_t {
            callback_invoked++;
            return 1024; // Pretend we freed 1KB
        });
    
    // Simulate high memory pressure
    pressure_response.handle_pressure_level(MemoryPressureResponse::PressureLevel::HIGH_PRESSURE);
    
    EXPECT_GT(callback_invoked, 0);
    
    // Test emergency memory reclaim
    size_t bytes_freed = pressure_response.emergency_memory_reclaim();
    EXPECT_GE(bytes_freed, 1024); // Should include our callback's contribution
    
    pressure_response.unregister_pressure_callback("test_callback");
}

} // namespace tests
} // namespace memory
} // namespace v13
} // namespace dtls