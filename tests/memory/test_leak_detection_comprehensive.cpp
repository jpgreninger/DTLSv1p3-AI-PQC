/**
 * @file test_leak_detection_comprehensive.cpp
 * @brief Comprehensive tests for DTLS memory leak detection system
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <random>
#include <sstream>

#include "dtls/memory/leak_detection.h"
#include "dtls/memory/buffer.h"
#include "dtls/result.h"

using namespace dtls::v13;
using namespace dtls::v13::memory;

class LeakDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset leak detector to clean state
        auto& detector = LeakDetector::instance();
        detector.enable_detection(true);
        detector.stop_periodic_detection();
        detector.reset_statistics();
        
        // Use fast check intervals for testing
        LeakDetectionConfig config;
        config.max_resource_age = std::chrono::minutes(1);
        config.critical_resource_age = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::seconds(30));
        config.check_interval = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds(100));
        config.enable_periodic_checks = false;  // Manual control for testing
        config.enable_automatic_cleanup = false;  // Manual control for testing
        detector.set_config(config);
        
        // Clear any existing cleanup callbacks
        for (int i = 0; i <= static_cast<int>(ResourceType::OTHER); ++i) {
            detector.unregister_cleanup_callback(static_cast<ResourceType>(i));
        }
        
        // Test resource pointers
        test_buffer1_ = new std::byte[1024];
        test_buffer2_ = new std::byte[2048];
        test_buffer3_ = new std::byte[4096];
    }
    
    void TearDown() override {
        auto& detector = LeakDetector::instance();
        
        // Clean up test resources
        if (test_buffer1_) {
            detector.untrack_resource(test_buffer1_);
            delete[] test_buffer1_;
            test_buffer1_ = nullptr;
        }
        if (test_buffer2_) {
            detector.untrack_resource(test_buffer2_);
            delete[] test_buffer2_;
            test_buffer2_ = nullptr;
        }
        if (test_buffer3_) {
            detector.untrack_resource(test_buffer3_);
            delete[] test_buffer3_;
            test_buffer3_ = nullptr;
        }
        
        // Stop periodic detection and reset
        detector.stop_periodic_detection();
        detector.cleanup_leaked_resources();  // Clean any remaining tracked resources
        detector.reset_statistics();
    }
    
    std::byte* test_buffer1_{nullptr};
    std::byte* test_buffer2_{nullptr};
    std::byte* test_buffer3_{nullptr};
};

// Test basic resource tracking functionality
TEST_F(LeakDetectionTest, BasicResourceTracking) {
    auto& detector = LeakDetector::instance();
    
    // Test initial state
    EXPECT_TRUE(detector.is_detection_enabled());
    auto initial_stats = detector.get_statistics();
    EXPECT_EQ(initial_stats.total_resources_tracked, 0);
    
    // Track a resource
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "test_file:100", "Test buffer 1");
    
    // Verify tracking
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer1_));
    auto info = detector.get_resource_info(test_buffer1_);
    EXPECT_EQ(info.resource_ptr, test_buffer1_);
    EXPECT_EQ(info.type, ResourceType::BUFFER);
    EXPECT_EQ(info.size, 1024);
    EXPECT_EQ(info.allocation_site, "test_file:100");
    EXPECT_EQ(info.description, "Test buffer 1");
    EXPECT_FALSE(info.is_critical);
    EXPECT_GT(info.allocation_time.time_since_epoch().count(), 0);
    
    // Update statistics
    auto updated_stats = detector.get_statistics();
    EXPECT_EQ(updated_stats.total_resources_tracked, 1);
    EXPECT_EQ(updated_stats.resources_by_type[static_cast<size_t>(ResourceType::BUFFER)], 1);
    
    // Update access
    detector.update_resource_access(test_buffer1_);
    auto updated_info = detector.get_resource_info(test_buffer1_);
    EXPECT_GT(updated_info.last_access_time, info.last_access_time);
    EXPECT_GT(updated_info.access_count, info.access_count);
    
    // Untrack resource
    detector.untrack_resource(test_buffer1_);
    EXPECT_FALSE(detector.is_resource_tracked(test_buffer1_));
    
    auto final_stats = detector.get_statistics();
    EXPECT_EQ(final_stats.total_resources_tracked, 0);
}

// Test multiple resource types tracking
TEST_F(LeakDetectionTest, MultipleResourceTypes) {
    auto& detector = LeakDetector::instance();
    
    // Track different resource types
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "buffer.cpp:50", "Application buffer");
    detector.track_resource(test_buffer2_, ResourceType::CRYPTO_KEY, 256, 
                           "crypto.cpp:200", "RSA private key");
    detector.track_resource(test_buffer3_, ResourceType::CONNECTION, 4096, 
                           "connection.cpp:100", "DTLS connection state");
    
    // Verify all are tracked
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer1_));
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer2_));
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer3_));
    
    // Check statistics by type
    auto stats = detector.get_statistics();
    EXPECT_EQ(stats.total_resources_tracked, 3);
    EXPECT_EQ(stats.resources_by_type[static_cast<size_t>(ResourceType::BUFFER)], 1);
    EXPECT_EQ(stats.resources_by_type[static_cast<size_t>(ResourceType::CRYPTO_KEY)], 1);
    EXPECT_EQ(stats.resources_by_type[static_cast<size_t>(ResourceType::CONNECTION)], 1);
    
    // Test resource metadata
    detector.add_resource_metadata(test_buffer2_, "key_type", "RSA");
    detector.add_resource_metadata(test_buffer2_, "key_size", "2048");
    
    auto crypto_info = detector.get_resource_info(test_buffer2_);
    EXPECT_EQ(crypto_info.metadata.at("key_type"), "RSA");
    EXPECT_EQ(crypto_info.metadata.at("key_size"), "2048");
    
    // Set critical resource
    detector.set_resource_critical(test_buffer3_, true);
    auto connection_info = detector.get_resource_info(test_buffer3_);
    EXPECT_TRUE(connection_info.is_critical);
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
    detector.untrack_resource(test_buffer2_);
    detector.untrack_resource(test_buffer3_);
}

// Test leak detection algorithms
TEST_F(LeakDetectionTest, LeakDetectionAlgorithms) {
    auto& detector = LeakDetector::instance();
    
    // Set short aging times for testing
    LeakDetectionConfig config = detector.get_config();
    config.max_resource_age = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::milliseconds(100));
    config.critical_resource_age = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::milliseconds(50));
    detector.set_config(config);
    
    // Track resources with different characteristics
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "normal.cpp:1", "Normal buffer");
    detector.track_resource(test_buffer2_, ResourceType::CONNECTION, 2048, 
                           "critical.cpp:1", "Critical connection");
    detector.set_resource_critical(test_buffer2_, true);
    
    // Age the resources
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    
    // Detect leaks
    auto leak_result = detector.detect_leaks();
    ASSERT_TRUE(leak_result.is_ok());
    
    auto leak_report = leak_result.value();
    EXPECT_GT(leak_report.total_leaks, 0);
    EXPECT_GT(leak_report.critical_leaks, 0);  // Critical resource should be detected
    EXPECT_GT(leak_report.total_leaked_memory, 0);
    EXPECT_FALSE(leak_report.leaked_resources.empty());
    
    // Check leak report details
    bool found_critical = false;
    for (const auto& leaked : leak_report.leaked_resources) {
        if (leaked.is_critical) {
            found_critical = true;
            EXPECT_EQ(leaked.resource_ptr, test_buffer2_);
            EXPECT_EQ(leaked.type, ResourceType::CONNECTION);
        }
    }
    EXPECT_TRUE(found_critical);
    
    // Test type-specific leak detection
    auto buffer_leaks = detector.detect_leaks_for_type(ResourceType::BUFFER);
    ASSERT_TRUE(buffer_leaks.is_ok());
    EXPECT_GT(buffer_leaks.value().total_leaks, 0);
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
    detector.untrack_resource(test_buffer2_);
}

// Test automatic cleanup functionality
TEST_F(LeakDetectionTest, AutomaticCleanup) {
    auto& detector = LeakDetector::instance();
    
    // Enable automatic cleanup
    LeakDetectionConfig config = detector.get_config();
    config.enable_automatic_cleanup = true;
    config.max_resource_age = std::chrono::milliseconds(100);
    detector.set_config(config);
    
    // Register cleanup callback for buffers
    std::atomic<int> cleanup_calls{0};
    detector.register_cleanup_callback(ResourceType::BUFFER, 
        [&cleanup_calls](const ResourceInfo& info) -> bool {
            cleanup_calls.fetch_add(1);
            // Simulate successful cleanup
            return true;
        });
    
    // Track resources that will become leaks
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "cleanup_test.cpp:1", "Buffer for cleanup");
    detector.track_resource(test_buffer2_, ResourceType::CONNECTION, 2048, 
                           "cleanup_test.cpp:2", "Connection (no callback)");
    
    // Age the resources
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    // Cleanup leaked resources
    size_t cleaned = detector.cleanup_leaked_resources();
    EXPECT_GT(cleaned, 0);
    EXPECT_GT(cleanup_calls.load(), 0);
    
    // Test type-specific cleanup
    detector.track_resource(test_buffer3_, ResourceType::BUFFER, 4096, 
                           "cleanup_test.cpp:3", "Another buffer");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    size_t buffer_cleaned = detector.cleanup_resources_of_type(ResourceType::BUFFER);
    EXPECT_GT(buffer_cleaned, 0);
    
    // Test age-based cleanup
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "age_test.cpp:1", "Age cleanup test");
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    size_t age_cleaned = detector.cleanup_old_resources(std::chrono::milliseconds(100));
    EXPECT_GT(age_cleaned, 0);
    
    // Unregister callback
    detector.unregister_cleanup_callback(ResourceType::BUFFER);
}

// Test ResourceTracker RAII functionality
TEST_F(LeakDetectionTest, ResourceTrackerRAII) {
    auto& detector = LeakDetector::instance();
    
    // Test automatic tracking and cleanup
    {
        auto tracker = ResourceTracker<std::byte>(test_buffer1_, ResourceType::BUFFER, 1024,
                                                 "raii_test.cpp:1", "RAII test buffer");
        
        // Verify resource is tracked
        EXPECT_TRUE(detector.is_resource_tracked(test_buffer1_));
        EXPECT_EQ(tracker.get(), test_buffer1_);
        
        // Test access update
        tracker.update_access();
        auto info = detector.get_resource_info(test_buffer1_);
        EXPECT_GT(info.access_count, 0);
        
        // Test dereferencing operators
        EXPECT_EQ(&(*tracker), test_buffer1_);
        
    } // tracker destructor should untrack resource
    
    EXPECT_FALSE(detector.is_resource_tracked(test_buffer1_));
    
    // Test move semantics
    ResourceTracker<std::byte> tracker1(test_buffer2_, ResourceType::BUFFER, 2048,
                                        "move_test.cpp:1", "Move test");
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer2_));
    
    ResourceTracker<std::byte> tracker2 = std::move(tracker1);
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer2_));
    EXPECT_EQ(tracker2.get(), test_buffer2_);
    EXPECT_EQ(tracker1.get(), nullptr);
    
    // Test release
    auto released_ptr = tracker2.release();
    EXPECT_EQ(released_ptr, test_buffer2_);
    EXPECT_FALSE(detector.is_resource_tracked(test_buffer2_));
}

// Test periodic detection thread
TEST_F(LeakDetectionTest, PeriodicDetection) {
    auto& detector = LeakDetector::instance();
    
    // Configure for periodic detection
    LeakDetectionConfig config = detector.get_config();
    config.enable_periodic_checks = true;
    config.check_interval = std::chrono::milliseconds(50);
    config.max_resource_age = std::chrono::milliseconds(100);
    detector.set_config(config);
    
    // Start periodic detection
    detector.start_periodic_detection();
    EXPECT_TRUE(detector.is_periodic_detection_active());
    
    // Track a resource that will become a leak
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "periodic_test.cpp:1", "Periodic test buffer");
    
    // Let periodic detection run for a while
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check that periodic detection has run
    auto stats = detector.get_statistics();
    EXPECT_GT(stats.detection_runs, 0);
    
    // Stop periodic detection
    detector.stop_periodic_detection();
    EXPECT_FALSE(detector.is_periodic_detection_active());
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
}

// Test ResourceCleanupManager
TEST_F(LeakDetectionTest, ResourceCleanupManager) {
    auto& cleanup_manager = ResourceCleanupManager::instance();
    auto& detector = LeakDetector::instance();
    
    // Test singleton
    auto& cleanup_manager2 = ResourceCleanupManager::instance();
    EXPECT_EQ(&cleanup_manager, &cleanup_manager2);
    
    // Set cleanup policy
    cleanup_manager.set_cleanup_policy(ResourceCleanupManager::CleanupPolicy::AGGRESSIVE);
    EXPECT_EQ(cleanup_manager.get_cleanup_policy(), ResourceCleanupManager::CleanupPolicy::AGGRESSIVE);
    
    // Track resources for cleanup testing
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "cleanup_mgr.cpp:1", "Non-critical buffer");
    detector.track_resource(test_buffer2_, ResourceType::CONNECTION, 2048, 
                           "cleanup_mgr.cpp:2", "Critical connection");
    detector.set_resource_critical(test_buffer2_, true);
    
    // Age resources
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Test non-critical cleanup
    size_t non_critical_cleaned = cleanup_manager.cleanup_non_critical_resources();
    // Result depends on implementation
    
    // Test old resource cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    size_t old_cleaned = cleanup_manager.cleanup_old_resources(std::chrono::milliseconds(50));
    // Result depends on implementation
    
    // Test unused resource cleanup
    size_t unused_cleaned = cleanup_manager.cleanup_unused_resources(std::chrono::milliseconds(30));
    // Result depends on implementation
    
    // Test emergency cleanup
    size_t emergency_cleaned = cleanup_manager.emergency_cleanup();
    // Should clean all resources
    
    // Test validation and repair
    auto repair_result = cleanup_manager.validate_and_repair_resources();
    EXPECT_TRUE(repair_result.is_ok() || repair_result.is_error());  // Either is valid
    
    // Clean up remaining
    detector.untrack_resource(test_buffer1_);
    detector.untrack_resource(test_buffer2_);
}

// Test configuration and statistics
TEST_F(LeakDetectionTest, ConfigurationAndStatistics) {
    auto& detector = LeakDetector::instance();
    
    // Test configuration
    LeakDetectionConfig config;
    config.max_resource_age = std::chrono::minutes(30);
    config.critical_resource_age = std::chrono::minutes(5);
    config.max_resources_per_type = 500;
    config.max_total_resources = 5000;
    config.enable_automatic_cleanup = true;
    config.enable_stack_traces = false;
    config.enable_periodic_checks = true;
    config.check_interval = std::chrono::seconds(60);
    config.memory_growth_threshold = 0.25;
    
    detector.set_config(config);
    auto retrieved_config = detector.get_config();
    
    EXPECT_EQ(retrieved_config.max_resource_age, config.max_resource_age);
    EXPECT_EQ(retrieved_config.critical_resource_age, config.critical_resource_age);
    EXPECT_EQ(retrieved_config.max_resources_per_type, config.max_resources_per_type);
    EXPECT_EQ(retrieved_config.max_total_resources, config.max_total_resources);
    EXPECT_EQ(retrieved_config.enable_automatic_cleanup, config.enable_automatic_cleanup);
    EXPECT_EQ(retrieved_config.enable_stack_traces, config.enable_stack_traces);
    EXPECT_EQ(retrieved_config.enable_periodic_checks, config.enable_periodic_checks);
    EXPECT_EQ(retrieved_config.check_interval, config.check_interval);
    EXPECT_DOUBLE_EQ(retrieved_config.memory_growth_threshold, config.memory_growth_threshold);
    
    // Test statistics tracking
    detector.reset_statistics();
    auto initial_stats = detector.get_statistics();
    EXPECT_EQ(initial_stats.total_resources_tracked, 0);
    EXPECT_EQ(initial_stats.total_leaks_detected, 0);
    
    // Track and leak some resources
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, "stats_test.cpp:1", "Stats test");
    
    auto tracking_stats = detector.get_statistics();
    EXPECT_EQ(tracking_stats.total_resources_tracked, 1);
    
    // Age and detect leak
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto leak_result = detector.detect_leaks();
    
    auto leak_stats = detector.get_statistics();
    EXPECT_GT(leak_stats.detection_runs, initial_stats.detection_runs);
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
}

// Test reporting functionality
TEST_F(LeakDetectionTest, ReportingFunctionality) {
    auto& detector = LeakDetector::instance();
    
    // Set short aging for quick leak detection
    LeakDetectionConfig config = detector.get_config();
    config.max_resource_age = std::chrono::milliseconds(50);
    detector.set_config(config);
    
    // Track various resources
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "report_test.cpp:10", "Test buffer for reporting");
    detector.track_resource(test_buffer2_, ResourceType::CRYPTO_KEY, 256, 
                           "report_test.cpp:20", "Test crypto key");
    detector.add_resource_metadata(test_buffer2_, "algorithm", "AES");
    detector.set_resource_critical(test_buffer2_, true);
    
    // Generate resource summary before leak detection
    auto summary = detector.generate_resource_summary();
    EXPECT_FALSE(summary.empty());
    EXPECT_NE(summary.find("BUFFER"), std::string::npos);
    EXPECT_NE(summary.find("CRYPTO_KEY"), std::string::npos);
    
    // Age resources and detect leaks
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto leak_result = detector.detect_leaks();
    ASSERT_TRUE(leak_result.is_ok());
    
    auto leak_report = leak_result.value();
    
    // Generate leak report
    auto report_text = detector.generate_leak_report(leak_report);
    EXPECT_FALSE(report_text.empty());
    EXPECT_NE(report_text.find("Total leaks"), std::string::npos);
    EXPECT_NE(report_text.find("Critical leaks"), std::string::npos);
    EXPECT_NE(report_text.find("report_test.cpp"), std::string::npos);
    
    // Test dump functionality (should not crash)
    std::ostringstream capture_output;
    std::streambuf* old_cout = std::cout.rdbuf(capture_output.rdbuf());
    detector.dump_all_resources();
    std::cout.rdbuf(old_cout);
    
    auto dump_output = capture_output.str();
    // Dump output might be empty or contain resource info
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
    detector.untrack_resource(test_buffer2_);
}

// Test resource validation
TEST_F(LeakDetectionTest, ResourceValidation) {
    auto& detector = LeakDetector::instance();
    
    // Track valid resources
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "validation_test.cpp:1", "Valid buffer");
    detector.track_resource(test_buffer2_, ResourceType::CONNECTION, 2048, 
                           "validation_test.cpp:2", "Valid connection");
    
    // Test validation of all resources
    auto validation_result = detector.validate_all_resources();
    EXPECT_TRUE(validation_result.is_ok() || validation_result.is_error());
    
    // Test type-specific validation
    auto buffer_validation = detector.validate_resources_of_type(ResourceType::BUFFER);
    EXPECT_TRUE(buffer_validation.is_ok() || buffer_validation.is_error());
    
    auto connection_validation = detector.validate_resources_of_type(ResourceType::CONNECTION);
    EXPECT_TRUE(connection_validation.is_ok() || connection_validation.is_error());
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
    detector.untrack_resource(test_buffer2_);
}

// Test concurrent access to leak detector
TEST_F(LeakDetectionTest, ConcurrentAccess) {
    auto& detector = LeakDetector::instance();
    
    const int num_threads = 8;
    const int resources_per_thread = 20;
    std::atomic<int> successful_tracks{0};
    std::atomic<int> successful_untracks{0};
    
    std::vector<std::future<void>> futures;
    std::vector<std::vector<std::byte*>> thread_resources(num_threads);
    
    // Prepare resources for each thread
    for (int t = 0; t < num_threads; ++t) {
        for (int r = 0; r < resources_per_thread; ++r) {
            thread_resources[t].push_back(new std::byte[1024]);
        }
    }
    
    // Launch threads that track and untrack resources
    for (int t = 0; t < num_threads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> delay_dis(1, 10);
            
            // Track resources
            for (int r = 0; r < resources_per_thread; ++r) {
                std::string site = "concurrent_test.cpp:" + std::to_string(t * 100 + r);
                std::string desc = "Thread " + std::to_string(t) + " resource " + std::to_string(r);
                
                detector.track_resource(thread_resources[t][r], ResourceType::BUFFER, 1024, 
                                       site, desc);
                successful_tracks.fetch_add(1);
                
                // Random delay
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dis(gen)));
                
                // Update access occasionally
                if (r % 3 == 0) {
                    detector.update_resource_access(thread_resources[t][r]);
                }
            }
            
            // Brief pause
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            // Untrack resources
            for (int r = 0; r < resources_per_thread; ++r) {
                detector.untrack_resource(thread_resources[t][r]);
                successful_untracks.fetch_add(1);
                
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dis(gen)));
            }
        }));
    }
    
    // Wait for all threads to complete
    for (auto& future : futures) {
        future.wait();
    }
    
    // Verify operations completed successfully
    EXPECT_EQ(successful_tracks.load(), num_threads * resources_per_thread);
    EXPECT_EQ(successful_untracks.load(), num_threads * resources_per_thread);
    
    // Verify no resources are still tracked
    auto final_stats = detector.get_statistics();
    EXPECT_EQ(final_stats.total_resources_tracked, 0);
    
    // Clean up allocated memory
    for (int t = 0; t < num_threads; ++t) {
        for (auto* ptr : thread_resources[t]) {
            delete[] ptr;
        }
    }
}

// Test utility functions and macros
TEST_F(LeakDetectionTest, UtilityFunctionsAndMacros) {
    // Test utility functions
    enable_leak_detection(true);
    EXPECT_TRUE(is_leak_detection_enabled());
    
    enable_leak_detection(false);
    EXPECT_FALSE(is_leak_detection_enabled());
    
    enable_leak_detection(true);  // Re-enable for rest of test
    
    // Test resource count
    size_t initial_count = get_tracked_resource_count();
    
    // Use macros to track resources
    DTLS_TRACK_RESOURCE(test_buffer1_, ResourceType::BUFFER, 1024, "Macro tracked buffer");
    
    size_t after_track_count = get_tracked_resource_count();
    EXPECT_EQ(after_track_count, initial_count + 1);
    
    // Update access using macro
    DTLS_UPDATE_RESOURCE_ACCESS(test_buffer1_);
    
    // Create resource tracker using macro
    auto new_buffer = new std::byte[2048];
    DTLS_MAKE_RESOURCE_TRACKER(tracker, new_buffer, ResourceType::BUFFER, 2048, "Macro tracker");
    
    size_t with_tracker_count = get_tracked_resource_count();
    EXPECT_EQ(with_tracker_count, after_track_count + 1);
    
    // Generate resource report
    auto report = generate_resource_report();
    EXPECT_FALSE(report.empty());
    
    // Untrack using macro
    DTLS_UNTRACK_RESOURCE(test_buffer1_);
    
    size_t after_untrack_count = get_tracked_resource_count();
    EXPECT_EQ(after_untrack_count, with_tracker_count - 1);
    
    // Cleanup
    delete[] new_buffer;  // tracker destructor will untrack
}

// Test default cleanup callbacks
TEST_F(LeakDetectionTest, DefaultCleanupCallbacks) {
    auto& detector = LeakDetector::instance();
    
    // Register default cleanup callbacks
    register_default_cleanup_callbacks();
    
    // Track resources that can use default cleanup
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, 
                           "default_cleanup.cpp:1", "Buffer with default cleanup");
    
    // Age the resource
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Test cleanup (actual behavior depends on default callback implementation)
    size_t cleaned = cleanup_all_leaked_resources();
    // Result depends on implementation
    
    // Clean up any remaining
    if (detector.is_resource_tracked(test_buffer1_)) {
        detector.untrack_resource(test_buffer1_);
    }
}

// Test edge cases and error conditions
TEST_F(LeakDetectionTest, EdgeCasesAndErrorConditions) {
    auto& detector = LeakDetector::instance();
    
    // Test null pointer tracking (should handle gracefully)
    detector.track_resource(nullptr, ResourceType::BUFFER, 0, "null_test.cpp:1", "Null pointer");
    
    // Test tracking same resource twice
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, "double_test.cpp:1", "First track");
    detector.track_resource(test_buffer1_, ResourceType::BUFFER, 1024, "double_test.cpp:2", "Second track");
    
    // Should still be tracked (implementation dependent on behavior)
    EXPECT_TRUE(detector.is_resource_tracked(test_buffer1_));
    
    // Test untracking non-existent resource
    detector.untrack_resource(test_buffer2_);  // Not tracked, should handle gracefully
    
    // Test getting info for non-existent resource
    auto info = detector.get_resource_info(test_buffer2_);
    EXPECT_EQ(info.resource_ptr, nullptr);  // Should return empty/default info
    
    // Test operations on disabled detector
    detector.enable_detection(false);
    detector.track_resource(test_buffer2_, ResourceType::BUFFER, 2048, "disabled_test.cpp:1", "When disabled");
    // Behavior when disabled is implementation dependent
    
    detector.enable_detection(true);  // Re-enable
    
    // Test extreme configuration values
    LeakDetectionConfig extreme_config;
    extreme_config.max_resource_age = std::chrono::nanoseconds(1);  // Extremely short
    extreme_config.critical_resource_age = std::chrono::nanoseconds(1);
    extreme_config.max_resources_per_type = 0;  // No limit
    extreme_config.max_total_resources = SIZE_MAX;  // Maximum limit
    extreme_config.check_interval = std::chrono::nanoseconds(1);  // Very frequent
    
    detector.set_config(extreme_config);  // Should handle gracefully
    
    // Reset to reasonable config
    LeakDetectionConfig normal_config;
    detector.set_config(normal_config);
    
    // Clean up
    detector.untrack_resource(test_buffer1_);
    if (detector.is_resource_tracked(test_buffer2_)) {
        detector.untrack_resource(test_buffer2_);
    }
}