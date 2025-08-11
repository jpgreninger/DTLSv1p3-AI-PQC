#include <gtest/gtest.h>
#include <dtls/core_protocol/anti_replay_core.h>

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
    
    // Packets outside window (more than 64 behind) should be invalid
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(35, window_state_)); // 100 - 35 = 65 > 64
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(30, window_state_));
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(1, window_state_));
    
    // But 36 should still be valid (100 - 36 = 64, exactly at boundary)
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(36, window_state_));
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
    
    // Only 8 slots, so sequence number 1 should be invalid
    EXPECT_FALSE(AntiReplayCore::is_valid_sequence_number(1, small_window)); // 10 - 1 = 9 > 8
    
    // But sequence number 2 should be valid
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(2, small_window)); // 10 - 2 = 8 == window size (boundary)
    
    EXPECT_TRUE(AntiReplayCore::is_valid_sequence_number(3, small_window)); // 10 - 3 = 7 < 8
}

// Performance test to ensure the algorithm is efficient
TEST_F(AntiReplayCoreTest, DISABLED_PerformanceTest) {
    const int NUM_OPERATIONS = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < NUM_OPERATIONS; ++i) {
        AntiReplayCore::check_and_update(i, window_state_);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    std::cout << "Time for " << NUM_OPERATIONS << " operations: " 
              << duration.count() << " microseconds" << std::endl;
    
    // Should be able to process at least 10,000 operations per millisecond
    EXPECT_LT(duration.count(), 10000); // Less than 10ms for 100k operations
}