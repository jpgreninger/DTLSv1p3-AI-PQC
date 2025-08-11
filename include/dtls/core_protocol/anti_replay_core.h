#pragma once

#include <cstdint>
#include <vector>

namespace dtls::v13::core_protocol {

/**
 * Pure Anti-Replay Logic Core
 * 
 * Contains the core sliding window algorithm for replay detection
 * with no dependencies on threading, SystemC, or networking.
 * This implementation is used by both the production library
 * and SystemC TLM model to ensure consistency.
 * 
 * Thread-safety: This class is NOT thread-safe by design.
 * Users must provide their own synchronization if needed.
 */
class AntiReplayCore {
public:
    static constexpr size_t DEFAULT_WINDOW_SIZE = 64;
    
    struct WindowState {
        uint64_t highest_sequence_number{0};
        std::vector<bool> window;
        size_t received_count{0};
        size_t replay_count{0};
        
        explicit WindowState(size_t window_size = DEFAULT_WINDOW_SIZE) 
            : window(window_size, false) {}
    };
    
    /**
     * Check if sequence number is valid (not a replay)
     * Does not modify state - use update_window() to record receipt
     * 
     * @param sequence_number The sequence number to check
     * @param state Current window state
     * @return true if valid, false if replay detected
     */
    static bool is_valid_sequence_number(uint64_t sequence_number, const WindowState& state);
    
    /**
     * Update window state to mark sequence number as received
     * This should only be called after is_valid_sequence_number() returns true
     * 
     * @param sequence_number The sequence number to mark as received
     * @param state Window state to update
     * @return true if state was updated, false on error
     */
    static bool update_window(uint64_t sequence_number, WindowState& state);
    
    /**
     * Check and update in single operation (convenience method)
     * 
     * @param sequence_number The sequence number to check and potentially mark
     * @param state Window state to check and update
     * @return true if valid and marked, false if replay detected
     */
    static bool check_and_update(uint64_t sequence_number, WindowState& state);
    
    /**
     * Reset window state (for epoch changes)
     */
    static void reset_window(WindowState& state);
    
    /**
     * Get window utilization ratio (0.0 to 1.0)
     */
    static double get_window_utilization(const WindowState& state);
    
    /**
     * Get statistics about the window state
     */
    struct WindowStats {
        uint64_t highest_sequence_number;
        uint64_t lowest_sequence_number; 
        size_t window_size;
        size_t received_count;
        size_t replay_count;
        double utilization_ratio;
    };
    
    static WindowStats get_stats(const WindowState& state);

private:
    // Internal helper for sliding the window
    static void slide_window(uint64_t new_highest, WindowState& state);
    
    // Disable instantiation - this is a pure static utility class
    AntiReplayCore() = delete;
    ~AntiReplayCore() = delete;
    AntiReplayCore(const AntiReplayCore&) = delete;
    AntiReplayCore& operator=(const AntiReplayCore&) = delete;
};

} // namespace dtls::v13::core_protocol