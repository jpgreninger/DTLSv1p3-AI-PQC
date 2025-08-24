#include <gtest/gtest.h>
#include <dtls/core_protocol/anti_replay_core.h>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <vector>
#include <cstdlib>

using namespace dtls::v13::core_protocol;

class AntiReplayCoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        window_state_ = AntiReplayCore::WindowState(DEFAULT_WINDOW_SIZE);
    }
    
    static constexpr size_t DEFAULT_WINDOW_SIZE = 64;
    AntiReplayCore::WindowState window_state_;
};

TEST_F(AntiReplayCoreTest, FirstPacketIsValid) {
    // First packet should always be valid
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(1, window_state_));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(100, window_state_));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(0, window_state_));
}

TEST_F(AntiReplayCoreTest, UpdateFirstPacket) {
    EXPECT_TRUE(AntiReplayCore::update_window(42, window_state_));
    EXPECT_EQ(42, window_state_.highest_sequence_number);
    EXPECT_EQ(1, window_state_.received_count);
    EXPECT_EQ(0, window_state_.replay_count);
    
    // Window slot 0 should be marked as received
    EXPECT_TRUE(window_state_.window[0]);
}

TEST_F(AntiReplayCoreTest, FuturePacketsSlideWindow) {
    // Set initial packet
    EXPECT_TRUE(AntiReplayCore::update_window(10, window_state_));
    
    // Future packet should be valid and slide window
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(20, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(20, window_state_));
    
    EXPECT_EQ(20, window_state_.highest_sequence_number);
    EXPECT_EQ(2, window_state_.received_count);
}

TEST_F(AntiReplayCoreTest, WithinWindowRangeValidation) {
    // Initialize with sequence number 50
    EXPECT_TRUE(AntiReplayCore::update_window(50, window_state_));
    
    // Packets within window range should be valid if not already received
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(49, window_state_));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(40, window_state_));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(30, window_state_));
    
    // Mark one as received
    EXPECT_TRUE(AntiReplayCore::update_window(45, window_state_));
    
    // Now 45 should be invalid (replay)
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(45, window_state_));
}

TEST_F(AntiReplayCoreTest, TooOldPacketsRejected) {
    // Initialize with sequence number 100
    EXPECT_TRUE(AntiReplayCore::update_window(100, window_state_));
    
    // Packets outside window (64 or more positions behind) should be invalid
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(36, window_state_)); // 100 - 36 = 64 >= 64 (invalid)
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(35, window_state_)); // 100 - 35 = 65 >= 64 (invalid)
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(30, window_state_));
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(1, window_state_));
    
    // But 37 should still be valid (100 - 37 = 63, within window bounds)
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(37, window_state_));
}

TEST_F(AntiReplayCoreTest, ReplayDetection) {
    // Set up window with some received packets
    EXPECT_TRUE(AntiReplayCore::update_window(50, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(48, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(45, window_state_));
    
    // Replaying these should be detected
    EXPECT_FALSE(AntiReplayCore::update_window(50, window_state_));
    EXPECT_FALSE(AntiReplayCore::update_window(48, window_state_));
    EXPECT_FALSE(AntiReplayCore::update_window(45, window_state_));
    
    // Replay count should be incremented
    EXPECT_EQ(3, window_state_.replay_count);
    EXPECT_EQ(3, window_state_.received_count); // Should not increment for replays
}

TEST_F(AntiReplayCoreTest, CheckAndUpdateConvenience) {
    // Test the convenience method that checks and updates in one call
    
    // First packet
    EXPECT_TRUE(AntiReplayCore::check_and_update(10, window_state_));
    EXPECT_EQ(10, window_state_.highest_sequence_number);
    
    // New valid packet
    EXPECT_TRUE(AntiReplayCore::check_and_update(15, window_state_));
    EXPECT_EQ(15, window_state_.highest_sequence_number);
    
    // Within window
    EXPECT_TRUE(AntiReplayCore::check_and_update(12, window_state_));
    
    // Replay
    EXPECT_FALSE(AntiReplayCore::check_and_update(12, window_state_));
    EXPECT_EQ(1, window_state_.replay_count);
    
    // Too old - with window size 64 and highest 15, sequence 1 is actually valid (15-1=14 < 64)
    // But if we want to test "too old", we need a sequence number further back
    // For highest=15, anything <= (15-64) = sequence -49 or below would be too old
    // So let's test with a very small window or large gap
    AntiReplayCore::WindowState small_test_window(4);
    EXPECT_TRUE(AntiReplayCore::check_and_update(10, small_test_window));
    EXPECT_FALSE(AntiReplayCore::check_and_update(5, small_test_window)); // 10-5=5 > 4
    EXPECT_EQ(2, window_state_.replay_count + small_test_window.replay_count);
}

TEST_F(AntiReplayCoreTest, WindowReset) {
    // Set up window with some state
    EXPECT_TRUE(AntiReplayCore::update_window(50, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(48, window_state_));
    window_state_.replay_count = 5; // Simulate some replays
    
    // Reset should clear everything
    AntiReplayCore::reset_window(window_state_);
    
    EXPECT_EQ(0, window_state_.highest_sequence_number);
    EXPECT_EQ(0, window_state_.received_count);
    EXPECT_EQ(0, window_state_.replay_count);
    
    // All window slots should be false
    for (bool slot : window_state_.window) {
        EXPECT_FALSE(slot);
    }
    
    // Should be able to receive packets again
    EXPECT_TRUE(AntiReplayCore::update_window(1, window_state_));
}

TEST_F(AntiReplayCoreTest, WindowUtilization) {
    // Empty window should have 0 utilization
    EXPECT_EQ(0.0, AntiReplayCore::get_window_utilization(window_state_));
    
    // Add one packet
    EXPECT_TRUE(AntiReplayCore::update_window(10, window_state_));
    EXPECT_GT(AntiReplayCore::get_window_utilization(window_state_), 0.0);
    
    // Fill half the window
    // Start with a higher sequence number to avoid negative numbers
    EXPECT_TRUE(AntiReplayCore::update_window(100, window_state_));
    for (int i = 0; i < 31; ++i) { // 31 more to make 32 total
        AntiReplayCore::update_window(100 - i - 1, window_state_);
    }
    
    double utilization = AntiReplayCore::get_window_utilization(window_state_);
    EXPECT_GE(utilization, 0.5);
    EXPECT_LE(utilization, 1.0);
}

TEST_F(AntiReplayCoreTest, Statistics) {
    // Set up some window state
    EXPECT_TRUE(AntiReplayCore::update_window(100, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(98, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(95, window_state_));
    
    // Add a replay
    EXPECT_FALSE(AntiReplayCore::update_window(98, window_state_));
    
    auto stats = AntiReplayCore::get_stats(window_state_);
    
    EXPECT_EQ(100, stats.highest_sequence_number);
    EXPECT_EQ(DEFAULT_WINDOW_SIZE, stats.window_size);
    EXPECT_EQ(3, stats.received_count);
    EXPECT_EQ(1, stats.replay_count);
    EXPECT_GT(stats.utilization_ratio, 0.0);
    EXPECT_LE(stats.utilization_ratio, 1.0);
    
    // Lowest sequence number should be correctly calculated
    EXPECT_EQ(100 - DEFAULT_WINDOW_SIZE + 1, stats.lowest_sequence_number);
}

TEST_F(AntiReplayCoreTest, LargeWindowSlide) {
    // Test window sliding with large jumps
    EXPECT_TRUE(AntiReplayCore::update_window(10, window_state_));
    EXPECT_TRUE(AntiReplayCore::update_window(5, window_state_));
    
    // Jump way ahead (larger than window size)
    EXPECT_TRUE(AntiReplayCore::update_window(200, window_state_));
    
    // Old packets should now be invalid
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(10, window_state_));
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(5, window_state_));
    
    // Only recent packets should be valid
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(199, window_state_));
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(150, window_state_));
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(135, window_state_)); // Too old
}

TEST_F(AntiReplayCoreTest, DifferentWindowSizes) {
    // Test with different window sizes
    AntiReplayCore::WindowState small_window(8);
    
    EXPECT_TRUE(AntiReplayCore::update_window(10, small_window));
    
    // Only 8 slots (indices 0-7), so sequence numbers with difference >= 8 should be invalid
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(2, small_window)); // 10 - 2 = 8 >= 8 (invalid)
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(1, small_window)); // 10 - 1 = 9 >= 8 (invalid)
    
    // But sequence number 3 should be valid (difference = 7, within bounds)
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(3, small_window)); // 10 - 3 = 7 < 8 (valid)
}

// Performance test to ensure the algorithm is efficient
// Re-enabled with robust timing analysis and dynamic environment detection
TEST_F(AntiReplayCoreTest, PerformanceTest) {
    // Detect environment characteristics with a calibration run
    const int CALIBRATION_OPS = 10000;
    AntiReplayCore::WindowState calibration_window(DEFAULT_WINDOW_SIZE);
    
    auto calibration_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < CALIBRATION_OPS; ++i) {
        AntiReplayCore::check_and_update(i, calibration_window);
    }
    auto calibration_end = std::chrono::high_resolution_clock::now();
    auto calibration_duration = std::chrono::duration_cast<std::chrono::microseconds>(calibration_end - calibration_start);
    
    // Calculate operations per microsecond from calibration
    double calibration_ops_per_us = static_cast<double>(CALIBRATION_OPS) / calibration_duration.count();
    
    // Dynamically detect if we're in a constrained environment
    const bool is_constrained_env = 
        calibration_ops_per_us < 1.0 ||  // Less than 1 op per microsecond indicates constrained environment
        std::getenv("CI") != nullptr || 
        std::getenv("GITHUB_ACTIONS") != nullptr ||
        std::getenv("CONTINUOUS_INTEGRATION") != nullptr;
    
    const int NUM_OPERATIONS = is_constrained_env ? 10000 : 100000;
    const int num_runs = 3;
    
    std::cout << "Environment calibration: " << calibration_ops_per_us << " ops/μs" << std::endl;
    std::cout << "Using " << (is_constrained_env ? "constrained" : "high-performance") << " environment thresholds" << std::endl;
    
    std::vector<std::chrono::microseconds> run_durations;
    
    for (int run = 0; run < num_runs; ++run) {
        AntiReplayCore::WindowState test_window(DEFAULT_WINDOW_SIZE);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < NUM_OPERATIONS; ++i) {
            AntiReplayCore::check_and_update(i, test_window);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        run_durations.push_back(duration);
    }
    
    // Calculate median duration for robust timing measurement
    std::sort(run_durations.begin(), run_durations.end());
    auto median_duration = run_durations[run_durations.size() / 2];
    
    std::cout << "Median time for " << NUM_OPERATIONS << " operations: " 
              << median_duration.count() << " microseconds" << std::endl;
    
    // Calculate operations per microsecond
    double ops_per_microsecond = static_cast<double>(NUM_OPERATIONS) / median_duration.count();
    std::cout << "Performance: " << ops_per_microsecond << " ops/μs" << std::endl;
    
    if (is_constrained_env) {
        // Very lenient bounds for constrained environments (VM, containers, etc.)
        // Allow up to 500ms for 10k operations (20,000 ops/second minimum)
        EXPECT_LT(median_duration.count(), 500000) // Less than 500ms for 10k operations
            << "Anti-replay algorithm too slow even for constrained environment";
        
        // Very lenient throughput requirement - just ensure it's not completely broken
        EXPECT_GT(ops_per_microsecond, 0.002)  // At least 0.002 ops/μs (2,000 ops/second)
            << "Anti-replay throughput catastrophically low: " << ops_per_microsecond << " ops/μs";
    } else {
        // Stricter requirements for high-performance environments
        EXPECT_LT(median_duration.count(), 10000) // Less than 10ms for 100k operations
            << "Anti-replay performance regression detected";
        
        EXPECT_GT(ops_per_microsecond, 5.0)  // At least 5 ops/μs
            << "Anti-replay throughput too low for high-performance environment: " << ops_per_microsecond << " ops/μs";
    }
    
    // Always verify operations completed successfully
    AntiReplayCore::WindowState verification_window(DEFAULT_WINDOW_SIZE);
    int successful_ops = 0;
    for (int i = 0; i < std::min(1000, NUM_OPERATIONS); ++i) {
        if (AntiReplayCore::check_and_update(i, verification_window)) {
            successful_ops++;
        }
    }
    EXPECT_EQ(successful_ops, std::min(1000, NUM_OPERATIONS))
        << "Some operations failed during performance test";
    
    // Performance regression check - compare against calibration with very tolerant bounds
    double performance_ratio = ops_per_microsecond / calibration_ops_per_us;
    EXPECT_GT(performance_ratio, 0.2)  // Performance shouldn't degrade more than 80% from calibration
        << "Massive performance regression detected (ratio: " << performance_ratio << ")";
        
    // Additional sanity check: ensure the algorithm completes in reasonable time
    EXPECT_LT(median_duration.count(), 1000000)  // Less than 1 second total
        << "Anti-replay test taking unreasonably long: " << median_duration.count() << "μs";
}