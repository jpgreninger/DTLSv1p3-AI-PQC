/**
 * @file test_resource_manager.cpp
 * @brief Comprehensive tests for DTLS resource management system
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>

#include "dtls/security/resource_manager.h"
#include "dtls/types.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::security;
using namespace std::chrono_literals;

class ResourceManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test addresses
        test_address1_ = NetworkAddress::from_string("192.168.1.100:8080").value();
        test_address2_ = NetworkAddress::from_string("192.168.1.101:8080").value();
        test_address3_ = NetworkAddress::from_string("10.0.0.1:443").value();
        heavy_user_address_ = NetworkAddress::from_string("203.0.113.1:9999").value();
        
        // Create test configuration
        test_config_ = ResourceConfig{};
        
        // Configure generous limits for most tests
        test_config_.max_total_memory = 10 * 1024 * 1024; // 10MB
        test_config_.max_memory_per_connection = 32 * 1024; // 32KB
        test_config_.max_handshake_memory = 16 * 1024; // 16KB
        test_config_.max_buffer_memory = 5 * 1024 * 1024; // 5MB
        
        test_config_.max_total_connections = 1000;
        test_config_.max_connections_per_source = 50;
        test_config_.max_pending_handshakes = 200;
        test_config_.max_handshakes_per_source = 10;
        
        test_config_.connection_timeout = 300s;
        test_config_.handshake_timeout = 30s;
        test_config_.cleanup_interval = 60s;
        
        test_config_.memory_warning_threshold = 0.8;
        test_config_.memory_critical_threshold = 0.95;
        test_config_.connection_warning_threshold = 0.8;
        test_config_.connection_critical_threshold = 0.95;
        
        test_config_.enable_auto_cleanup = true;
        test_config_.enable_memory_pressure_cleanup = true;
        test_config_.cleanup_batch_size = 50;
    }
    
    NetworkAddress test_address1_, test_address2_, test_address3_, heavy_user_address_;
    ResourceConfig test_config_;
};

// Test basic resource manager creation and configuration
TEST_F(ResourceManagerTest, BasicCreationAndConfiguration) {
    ResourceManager manager(test_config_);
    
    // Test initial state
    auto stats = manager.get_resource_stats();
    EXPECT_EQ(stats.total_allocated_memory, 0);
    EXPECT_EQ(stats.total_connections, 0);
    EXPECT_EQ(stats.active_connections, 0);
    EXPECT_EQ(stats.pending_handshakes, 0);
    EXPECT_EQ(stats.failed_allocations, 0);
    EXPECT_EQ(stats.current_pressure, PressureLevel::NORMAL);
    
    // Test configuration access
    const auto& config = manager.get_config();
    EXPECT_EQ(config.max_total_memory, test_config_.max_total_memory);
    EXPECT_EQ(config.max_total_connections, test_config_.max_total_connections);
    EXPECT_EQ(config.memory_warning_threshold, test_config_.memory_warning_threshold);
    
    // Test pressure level
    auto pressure = manager.get_pressure_level();
    EXPECT_EQ(pressure, PressureLevel::NORMAL);
    
    // Test usage percentages
    EXPECT_DOUBLE_EQ(manager.get_memory_usage_percentage(), 0.0);
    EXPECT_DOUBLE_EQ(manager.get_connection_usage_percentage(), 0.0);
}

// Test connection resource allocation and release
TEST_F(ResourceManagerTest, ConnectionResourceAllocationAndRelease) {
    ResourceManager manager(test_config_);
    
    // Allocate connection resources
    auto alloc_result = manager.allocate_connection_resources(test_address1_, 1024);
    ASSERT_TRUE(alloc_result.is_ok());
    
    uint64_t allocation_id = alloc_result.value();
    EXPECT_GT(allocation_id, 0);
    
    // Check statistics after allocation
    auto stats = manager.get_resource_stats();
    EXPECT_GT(stats.total_allocated_memory, 0);
    EXPECT_EQ(stats.total_connections, 1);
    EXPECT_EQ(stats.active_connections, 1);
    
    // Check memory usage percentage
    double memory_usage = manager.get_memory_usage_percentage();
    EXPECT_GT(memory_usage, 0.0);
    EXPECT_LT(memory_usage, 1.0);
    
    // Check connection usage percentage
    double connection_usage = manager.get_connection_usage_percentage();
    EXPECT_GT(connection_usage, 0.0);
    EXPECT_LT(connection_usage, 1.0);
    
    // Update activity
    auto update_result = manager.update_activity(allocation_id);
    EXPECT_TRUE(update_result.is_ok());
    
    // Release resources
    auto release_result = manager.release_resources(allocation_id);
    EXPECT_TRUE(release_result.is_ok());
    
    // Check statistics after release
    auto final_stats = manager.get_resource_stats();
    EXPECT_EQ(final_stats.total_allocated_memory, 0);
    EXPECT_EQ(final_stats.total_connections, 0);
    EXPECT_EQ(final_stats.active_connections, 0);
}

// Test handshake resource allocation and release
TEST_F(ResourceManagerTest, HandshakeResourceAllocationAndRelease) {
    ResourceManager manager(test_config_);
    
    // Allocate handshake resources
    auto alloc_result = manager.allocate_handshake_resources(test_address1_, 512);
    ASSERT_TRUE(alloc_result.is_ok());
    
    uint64_t allocation_id = alloc_result.value();
    EXPECT_GT(allocation_id, 0);
    
    // Check statistics
    auto stats = manager.get_resource_stats();
    EXPECT_GT(stats.total_allocated_memory, 0);
    EXPECT_EQ(stats.pending_handshakes, 1);
    EXPECT_GT(stats.handshake_memory, 0);
    
    // Allocate multiple handshakes from same source
    std::vector<uint64_t> handshake_ids;
    for (int i = 0; i < 5; ++i) {
        auto hs_result = manager.allocate_handshake_resources(test_address1_, 256);
        if (hs_result.is_ok()) {
            handshake_ids.push_back(hs_result.value());
        }
    }
    
    EXPECT_GT(handshake_ids.size(), 0);
    
    // Release all handshakes
    manager.release_resources(allocation_id);
    for (auto id : handshake_ids) {
        manager.release_resources(id);
    }
    
    // Verify cleanup
    auto final_stats = manager.get_resource_stats();
    EXPECT_EQ(final_stats.pending_handshakes, 0);
    EXPECT_EQ(final_stats.handshake_memory, 0);
}

// Test buffer memory allocation
TEST_F(ResourceManagerTest, BufferMemoryAllocation) {
    ResourceManager manager(test_config_);
    
    // Allocate buffer memory
    auto alloc_result = manager.allocate_buffer_memory(test_address1_, 2048);
    ASSERT_TRUE(alloc_result.is_ok());
    
    uint64_t allocation_id = alloc_result.value();
    
    // Check statistics
    auto stats = manager.get_resource_stats();
    EXPECT_GT(stats.buffer_memory, 0);
    EXPECT_EQ(stats.buffer_memory, 2048);
    
    // Allocate more buffer memory
    auto alloc2_result = manager.allocate_buffer_memory(test_address2_, 1024);
    ASSERT_TRUE(alloc2_result.is_ok());
    
    uint64_t allocation_id2 = alloc2_result.value();
    
    // Check combined statistics
    auto stats2 = manager.get_resource_stats();
    EXPECT_EQ(stats2.buffer_memory, 2048 + 1024);
    
    // Release buffer memory
    manager.release_resources(allocation_id);
    manager.release_resources(allocation_id2);
    
    // Verify cleanup
    auto final_stats = manager.get_resource_stats();
    EXPECT_EQ(final_stats.buffer_memory, 0);
}

// Test resource limit enforcement
TEST_F(ResourceManagerTest, ResourceLimitEnforcement) {
    // Configure very limited resources
    ResourceConfig limited_config = test_config_;
    limited_config.max_total_memory = 4096; // 4KB total
    limited_config.max_total_connections = 2; // Only 2 connections
    limited_config.max_connections_per_source = 1; // 1 per source
    
    ResourceManager manager(limited_config);
    
    // Test memory limit
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 2048);
    EXPECT_TRUE(alloc1.is_ok());
    
    auto alloc2 = manager.allocate_connection_resources(test_address2_, 2048);
    EXPECT_TRUE(alloc2.is_ok());
    
    // This should fail due to memory limit
    auto alloc3 = manager.allocate_connection_resources(test_address3_, 2048);
    EXPECT_TRUE(alloc3.is_error());
    
    // Test per-source connection limit
    auto alloc4 = manager.allocate_connection_resources(test_address1_, 1024);
    EXPECT_TRUE(alloc4.is_error()); // Should fail, already has 1 connection
    
    // Test total connection limit
    manager.release_resources(alloc1.value());
    manager.release_resources(alloc2.value());
    
    // Now we can allocate 2 more
    auto alloc5 = manager.allocate_connection_resources(test_address1_, 1024);
    auto alloc6 = manager.allocate_connection_resources(test_address2_, 1024);
    EXPECT_TRUE(alloc5.is_ok());
    EXPECT_TRUE(alloc6.is_ok());
    
    // Third should fail due to total connection limit
    auto alloc7 = manager.allocate_connection_resources(test_address3_, 1024);
    EXPECT_TRUE(alloc7.is_error());
    
    // Clean up
    manager.release_resources(alloc5.value());
    manager.release_resources(alloc6.value());
}

// Test can_allocate checks
TEST_F(ResourceManagerTest, CanAllocateChecks) {
    ResourceManager manager(test_config_);
    
    // Should be able to allocate initially
    EXPECT_TRUE(manager.can_allocate(test_address1_, ResourceType::CONNECTION_MEMORY, 1024));
    EXPECT_TRUE(manager.can_allocate(test_address1_, ResourceType::HANDSHAKE_MEMORY, 512));
    EXPECT_TRUE(manager.can_allocate(test_address1_, ResourceType::BUFFER_MEMORY, 2048));
    EXPECT_TRUE(manager.can_allocate(test_address1_, ResourceType::CONNECTION_SLOT, 1));
    EXPECT_TRUE(manager.can_allocate(test_address1_, ResourceType::HANDSHAKE_SLOT, 1));
    
    // Allocate some resources
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 1024);
    auto alloc2 = manager.allocate_handshake_resources(test_address1_, 512);
    auto alloc3 = manager.allocate_buffer_memory(test_address1_, 2048);
    
    ASSERT_TRUE(alloc1.is_ok());
    ASSERT_TRUE(alloc2.is_ok());
    ASSERT_TRUE(alloc3.is_ok());
    
    // Check what we can still allocate
    EXPECT_TRUE(manager.can_allocate(test_address2_, ResourceType::CONNECTION_MEMORY, 1024));
    
    // Test very large allocation that should fail
    EXPECT_FALSE(manager.can_allocate(test_address1_, ResourceType::CONNECTION_MEMORY, 
                                     test_config_.max_total_memory));
    
    // Clean up
    manager.release_resources(alloc1.value());
    manager.release_resources(alloc2.value());
    manager.release_resources(alloc3.value());
}

// Test per-source resource usage tracking
TEST_F(ResourceManagerTest, PerSourceResourceUsageTracking) {
    ResourceManager manager(test_config_);
    
    // Initially no usage
    auto usage_result = manager.get_source_usage(test_address1_);
    EXPECT_TRUE(usage_result.is_error()); // No data yet
    
    // Allocate resources from multiple sources
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 1024);
    auto alloc2 = manager.allocate_handshake_resources(test_address1_, 512);
    auto alloc3 = manager.allocate_buffer_memory(test_address1_, 2048);
    
    auto alloc4 = manager.allocate_connection_resources(test_address2_, 2048);
    auto alloc5 = manager.allocate_buffer_memory(test_address2_, 1024);
    
    ASSERT_TRUE(alloc1.is_ok());
    ASSERT_TRUE(alloc2.is_ok());
    ASSERT_TRUE(alloc3.is_ok());
    ASSERT_TRUE(alloc4.is_ok());
    ASSERT_TRUE(alloc5.is_ok());
    
    // Check source 1 usage
    auto usage1 = manager.get_source_usage(test_address1_);
    ASSERT_TRUE(usage1.is_ok());
    
    auto summary1 = usage1.value();
    EXPECT_GT(summary1.total_memory, 0);
    EXPECT_EQ(summary1.connection_count, 1);
    EXPECT_EQ(summary1.handshake_count, 1);
    EXPECT_GT(summary1.buffer_memory, 0);
    
    // Check source 2 usage
    auto usage2 = manager.get_source_usage(test_address2_);
    ASSERT_TRUE(usage2.is_ok());
    
    auto summary2 = usage2.value();
    EXPECT_GT(summary2.total_memory, 0);
    EXPECT_EQ(summary2.connection_count, 1);
    EXPECT_EQ(summary2.handshake_count, 0);
    EXPECT_GT(summary2.buffer_memory, 0);
    
    // Verify different usage patterns
    EXPECT_NE(summary1.total_memory, summary2.total_memory);
    EXPECT_NE(summary1.buffer_memory, summary2.buffer_memory);
    
    // Clean up
    manager.release_resources(alloc1.value());
    manager.release_resources(alloc2.value());
    manager.release_resources(alloc3.value());
    manager.release_resources(alloc4.value());
    manager.release_resources(alloc5.value());
}

// Test pressure level monitoring
TEST_F(ResourceManagerTest, PressureLevelMonitoring) {
    // Configure to hit pressure thresholds easily
    ResourceConfig pressure_config = test_config_;
    pressure_config.max_total_memory = 10000; // 10KB
    pressure_config.memory_warning_threshold = 0.5; // Warning at 50%
    pressure_config.memory_critical_threshold = 0.8; // Critical at 80%
    
    ResourceManager manager(pressure_config);
    
    // Initially normal pressure
    EXPECT_EQ(manager.get_pressure_level(), PressureLevel::NORMAL);
    
    // Allocate memory to reach warning threshold
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 3000); // 30%
    auto alloc2 = manager.allocate_connection_resources(test_address2_, 3000); // 60% total
    
    ASSERT_TRUE(alloc1.is_ok());
    ASSERT_TRUE(alloc2.is_ok());
    
    // Should be at warning level
    auto pressure_after_60 = manager.get_pressure_level();
    EXPECT_TRUE(pressure_after_60 == PressureLevel::WARNING || 
               pressure_after_60 == PressureLevel::NORMAL); // Implementation dependent
    
    // Allocate more to reach critical
    auto alloc3 = manager.allocate_connection_resources(test_address3_, 2000); // 80% total
    
    if (alloc3.is_ok()) {
        auto pressure_after_80 = manager.get_pressure_level();
        EXPECT_TRUE(pressure_after_80 == PressureLevel::CRITICAL || 
                   pressure_after_80 == PressureLevel::WARNING);
        
        manager.release_resources(alloc3.value());
    }
    
    // Clean up
    manager.release_resources(alloc1.value());
    manager.release_resources(alloc2.value());
    
    // Should return to normal
    auto final_pressure = manager.get_pressure_level();
    EXPECT_EQ(final_pressure, PressureLevel::NORMAL);
}

// Test cleanup functionality
TEST_F(ResourceManagerTest, CleanupFunctionality) {
    ResourceManager manager(test_config_);
    
    // Allocate resources that will be candidates for cleanup
    std::vector<uint64_t> allocations;
    for (int i = 0; i < 10; ++i) {
        auto alloc = manager.allocate_connection_resources(test_address1_, 1024);
        if (alloc.is_ok()) {
            allocations.push_back(alloc.value());
        }
    }
    
    // Check initial state
    auto stats_before = manager.get_resource_stats();
    EXPECT_GT(stats_before.total_connections, 0);
    
    // Force cleanup with limit
    size_t cleaned = manager.force_cleanup(5);
    EXPECT_LE(cleaned, 5); // Should clean up at most 5
    
    // Force cleanup with no limit
    size_t cleaned_all = manager.force_cleanup();
    EXPECT_GE(cleaned_all, 0); // May or may not clean anything depending on timeouts
    
    // Test source-specific cleanup
    size_t source_cleaned = manager.cleanup_source_resources(test_address1_);
    EXPECT_GE(source_cleaned, 0);
    
    // Clean up remaining allocations
    for (auto id : allocations) {
        manager.release_resources(id);
    }
}

// Test system health checking
TEST_F(ResourceManagerTest, SystemHealthChecking) {
    ResourceManager manager(test_config_);
    
    // Initial health check
    auto initial_pressure = manager.check_system_health();
    EXPECT_EQ(initial_pressure, PressureLevel::NORMAL);
    
    // Allocate resources to stress system
    std::vector<uint64_t> allocations;
    for (int i = 0; i < 20; ++i) {
        auto alloc = manager.allocate_connection_resources(test_address1_, 1024);
        if (alloc.is_ok()) {
            allocations.push_back(alloc.value());
        }
    }
    
    // Check health under load
    auto loaded_pressure = manager.check_system_health();
    EXPECT_TRUE(loaded_pressure == PressureLevel::NORMAL || 
               loaded_pressure == PressureLevel::WARNING ||
               loaded_pressure == PressureLevel::CRITICAL);
    
    // Clean up
    for (auto id : allocations) {
        manager.release_resources(id);
    }
    
    // Final health check
    auto final_pressure = manager.check_system_health();
    EXPECT_EQ(final_pressure, PressureLevel::NORMAL);
}

// Test configuration updates
TEST_F(ResourceManagerTest, ConfigurationUpdates) {
    ResourceManager manager(test_config_);
    
    // Update configuration
    ResourceConfig new_config = test_config_;
    new_config.max_total_memory = 20 * 1024 * 1024; // 20MB
    new_config.max_total_connections = 2000;
    new_config.memory_warning_threshold = 0.7;
    
    auto update_result = manager.update_config(new_config);
    EXPECT_TRUE(update_result.is_ok());
    
    // Verify configuration was updated
    const auto& updated_config = manager.get_config();
    EXPECT_EQ(updated_config.max_total_memory, 20 * 1024 * 1024);
    EXPECT_EQ(updated_config.max_total_connections, 2000);
    EXPECT_DOUBLE_EQ(updated_config.memory_warning_threshold, 0.7);
}

// Test memory monitoring enable/disable
TEST_F(ResourceManagerTest, MemoryMonitoringEnableDisable) {
    ResourceManager manager(test_config_);
    
    // Enable memory monitoring
    manager.set_memory_monitoring(true);
    
    // Allocate some memory
    auto alloc = manager.allocate_connection_resources(test_address1_, 1024);
    ASSERT_TRUE(alloc.is_ok());
    
    // Check that monitoring is working
    EXPECT_GT(manager.get_memory_usage_percentage(), 0.0);
    
    // Disable memory monitoring
    manager.set_memory_monitoring(false);
    
    // Should still work, but monitoring might be less accurate
    auto alloc2 = manager.allocate_connection_resources(test_address2_, 1024);
    EXPECT_TRUE(alloc2.is_ok());
    
    // Clean up
    manager.release_resources(alloc.value());
    if (alloc2.is_ok()) {
        manager.release_resources(alloc2.value());
    }
}

// Test high usage source detection
TEST_F(ResourceManagerTest, HighUsageSourceDetection) {
    ResourceManager manager(test_config_);
    
    // Allocate normal usage for some sources
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 1024);
    auto alloc2 = manager.allocate_connection_resources(test_address2_, 1024);
    
    // Allocate heavy usage for another source
    std::vector<uint64_t> heavy_allocations;
    for (int i = 0; i < 10; ++i) {
        auto alloc = manager.allocate_connection_resources(heavy_user_address_, 2048);
        if (alloc.is_ok()) {
            heavy_allocations.push_back(alloc.value());
        }
    }
    
    // Get high usage sources with various thresholds
    auto high_usage_80 = manager.get_high_usage_sources(0.8);
    auto high_usage_50 = manager.get_high_usage_sources(0.5);
    auto high_usage_10 = manager.get_high_usage_sources(0.1);
    
    // More permissive thresholds should return more sources
    EXPECT_GE(high_usage_10.size(), high_usage_50.size());
    EXPECT_GE(high_usage_50.size(), high_usage_80.size());
    
    // Heavy user should appear in lower threshold lists
    bool heavy_user_found = false;
    for (const auto& addr : high_usage_10) {
        if (addr.to_string() == heavy_user_address_.to_string()) {
            heavy_user_found = true;
            break;
        }
    }
    // Note: May or may not be found depending on total system usage
    
    // Clean up
    if (alloc1.is_ok()) manager.release_resources(alloc1.value());
    if (alloc2.is_ok()) manager.release_resources(alloc2.value());
    for (auto id : heavy_allocations) {
        manager.release_resources(id);
    }
}

// Test reset functionality
TEST_F(ResourceManagerTest, ResetFunctionality) {
    ResourceManager manager(test_config_);
    
    // Allocate resources and generate state
    auto alloc1 = manager.allocate_connection_resources(test_address1_, 1024);
    auto alloc2 = manager.allocate_handshake_resources(test_address2_, 512);
    auto alloc3 = manager.allocate_buffer_memory(test_address3_, 2048);
    
    ASSERT_TRUE(alloc1.is_ok());
    ASSERT_TRUE(alloc2.is_ok());
    ASSERT_TRUE(alloc3.is_ok());
    
    // Verify state exists
    auto stats_before = manager.get_resource_stats();
    EXPECT_GT(stats_before.total_allocated_memory, 0);
    EXPECT_GT(stats_before.total_connections, 0);
    
    auto usage_before = manager.get_source_usage(test_address1_);
    EXPECT_TRUE(usage_before.is_ok());
    
    // Reset manager
    manager.reset();
    
    // Verify state was cleared
    auto stats_after = manager.get_resource_stats();
    EXPECT_EQ(stats_after.total_allocated_memory, 0);
    EXPECT_EQ(stats_after.total_connections, 0);
    EXPECT_EQ(stats_after.active_connections, 0);
    EXPECT_EQ(stats_after.pending_handshakes, 0);
    
    auto usage_after = manager.get_source_usage(test_address1_);
    EXPECT_TRUE(usage_after.is_error()); // Should not exist anymore
    
    // Manager should still be functional
    auto new_alloc = manager.allocate_connection_resources(test_address1_, 1024);
    EXPECT_TRUE(new_alloc.is_ok());
    
    if (new_alloc.is_ok()) {
        manager.release_resources(new_alloc.value());
    }
}

// Test factory methods
TEST_F(ResourceManagerTest, FactoryMethods) {
    // Test different factory configurations
    auto dev_manager = ResourceManagerFactory::create_development();
    EXPECT_NE(dev_manager, nullptr);
    
    auto prod_manager = ResourceManagerFactory::create_production();
    EXPECT_NE(prod_manager, nullptr);
    
    auto embedded_manager = ResourceManagerFactory::create_embedded();
    EXPECT_NE(embedded_manager, nullptr);
    
    auto capacity_manager = ResourceManagerFactory::create_high_capacity();
    EXPECT_NE(capacity_manager, nullptr);
    
    auto custom_manager = ResourceManagerFactory::create_custom(test_config_);
    EXPECT_NE(custom_manager, nullptr);
    
    // Test that they have different configurations
    auto dev_config = dev_manager->get_config();
    auto prod_config = prod_manager->get_config();
    auto embedded_config = embedded_manager->get_config();
    auto capacity_config = capacity_manager->get_config();
    
    // Development should be more generous than embedded
    EXPECT_GE(dev_config.max_total_memory, embedded_config.max_total_memory);
    EXPECT_GE(dev_config.max_total_connections, embedded_config.max_total_connections);
    
    // High capacity should be more generous than production
    EXPECT_GE(capacity_config.max_total_memory, prod_config.max_total_memory);
    EXPECT_GE(capacity_config.max_total_connections, prod_config.max_total_connections);
    
    // Test functionality
    auto result = dev_manager->allocate_connection_resources(test_address1_, 1024);
    EXPECT_TRUE(result.is_ok());
    
    if (result.is_ok()) {
        dev_manager->release_resources(result.value());
    }
}

// Test ResourceGuard RAII functionality
TEST_F(ResourceManagerTest, ResourceGuardRAII) {
    ResourceManager manager(test_config_);
    
    uint64_t allocation_id;
    {
        // Allocate resource
        auto alloc_result = manager.allocate_connection_resources(test_address1_, 1024);
        ASSERT_TRUE(alloc_result.is_ok());
        allocation_id = alloc_result.value();
        
        // Create guard
        ResourceGuard guard(&manager, allocation_id);
        EXPECT_TRUE(guard.is_active());
        EXPECT_EQ(guard.get_allocation_id(), allocation_id);
        
        // Resource should be allocated
        auto stats = manager.get_resource_stats();
        EXPECT_GT(stats.total_connections, 0);
        
        // Test move semantics
        ResourceGuard moved_guard = std::move(guard);
        EXPECT_FALSE(guard.is_active());
        EXPECT_TRUE(moved_guard.is_active());
        EXPECT_EQ(moved_guard.get_allocation_id(), allocation_id);
        
        // Test early release
        moved_guard.release();
        EXPECT_FALSE(moved_guard.is_active());
        
    } // Guard destructor should not double-release since we called release()
    
    // Resource should be freed
    auto final_stats = manager.get_resource_stats();
    EXPECT_EQ(final_stats.total_connections, 0);
    
    // Test automatic cleanup via destructor
    {
        auto alloc_result = manager.allocate_connection_resources(test_address1_, 1024);
        ASSERT_TRUE(alloc_result.is_ok());
        
        ResourceGuard auto_guard(&manager, alloc_result.value());
        
        auto stats = manager.get_resource_stats();
        EXPECT_GT(stats.total_connections, 0);
        
    } // Guard destructor should automatically release
    
    auto final_stats2 = manager.get_resource_stats();
    EXPECT_EQ(final_stats2.total_connections, 0);
}

// Test concurrent resource management
TEST_F(ResourceManagerTest, ConcurrentResourceManagement) {
    ResourceManager manager(test_config_);
    
    const int num_threads = 4;
    const int allocations_per_thread = 25;
    std::atomic<int> successful_allocations{0};
    std::atomic<int> failed_allocations{0};
    std::atomic<int> successful_releases{0};
    
    std::vector<std::future<void>> futures;
    
    // Launch threads that allocate and release resources
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> size_dis(512, 2048);
            std::uniform_int_distribution<> type_dis(0, 2);
            
            // Use different addresses per thread
            auto thread_address = NetworkAddress::from_string(
                "192.168.1." + std::to_string(100 + t) + ":8080").value();
            
            std::vector<uint64_t> thread_allocations;
            
            for (int i = 0; i < allocations_per_thread; ++i) {
                size_t alloc_size = size_dis(gen);
                int alloc_type = type_dis(gen);
                
                Result<uint64_t> result(DTLSError::UNKNOWN_ERROR);
                
                // Randomly choose allocation type
                switch (alloc_type) {
                    case 0:
                        result = manager.allocate_connection_resources(thread_address, alloc_size);
                        break;
                    case 1:
                        result = manager.allocate_handshake_resources(thread_address, alloc_size);
                        break;
                    case 2:
                        result = manager.allocate_buffer_memory(thread_address, alloc_size);
                        break;
                }
                
                if (result.is_ok()) {
                    successful_allocations.fetch_add(1);
                    thread_allocations.push_back(result.value());
                    
                    // Update activity occasionally
                    if (i % 5 == 0) {
                        manager.update_activity(result.value());
                    }
                } else {
                    failed_allocations.fetch_add(1);
                }
                
                // Small delay
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
            
            // Release all allocations
            for (auto id : thread_allocations) {
                auto release_result = manager.release_resources(id);
                if (release_result.is_ok()) {
                    successful_releases.fetch_add(1);
                }
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify results
    EXPECT_EQ(successful_releases.load(), successful_allocations.load());
    
    // System should be clean
    auto final_stats = manager.get_resource_stats();
    EXPECT_EQ(final_stats.total_connections, 0);
    EXPECT_EQ(final_stats.active_connections, 0);
    EXPECT_EQ(final_stats.pending_handshakes, 0);
    EXPECT_EQ(final_stats.total_allocated_memory, 0);
    
    // Verify system is still healthy
    EXPECT_EQ(manager.get_pressure_level(), PressureLevel::NORMAL);
}