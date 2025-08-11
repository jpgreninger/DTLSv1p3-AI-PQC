#include "dtls/core_protocol/anti_replay_core.h"
#include <algorithm>

namespace dtls::v13::core_protocol {

bool AntiReplayCore::is_valid_sequence_number(uint64_t sequence_number, const WindowState& state) {
    // First packet is always valid
    if (state.highest_sequence_number == 0) {
        return true;
    }
    
    const size_t window_size = state.window.size();
    
    // Packet too old (outside window)
    if (sequence_number < state.highest_sequence_number && 
        (state.highest_sequence_number - sequence_number) > window_size) {
        return false;
    }
    
    // Future packet (always valid, will slide window)
    if (sequence_number > state.highest_sequence_number) {
        return true;
    }
    
    // Within current window - check if already received
    size_t window_index = static_cast<size_t>(state.highest_sequence_number - sequence_number);
    return !state.window[window_index];
}

bool AntiReplayCore::update_window(uint64_t sequence_number, WindowState& state) {
    // First packet
    if (state.highest_sequence_number == 0) {
        state.highest_sequence_number = sequence_number;
        if (!state.window.empty()) {
            state.window[0] = true;
        }
        state.received_count++;
        return true;
    }
    
    const size_t window_size = state.window.size();
    
    // Validate sequence number first
    if (sequence_number < state.highest_sequence_number && 
        (state.highest_sequence_number - sequence_number) > window_size) {
        // Too old - this is an error condition
        state.replay_count++;
        return false;
    }
    
    // Future packet - slide window
    if (sequence_number > state.highest_sequence_number) {
        slide_window(sequence_number, state);
        state.received_count++;
        return true;
    }
    
    // Within current window - mark as received
    size_t window_index = static_cast<size_t>(state.highest_sequence_number - sequence_number);
    if (window_index < window_size && !state.window[window_index]) {
        state.window[window_index] = true;
        state.received_count++;
        return true;
    }
    
    // Already received - replay
    state.replay_count++;
    return false;
}

bool AntiReplayCore::check_and_update(uint64_t sequence_number, WindowState& state) {
    if (is_valid_sequence_number(sequence_number, state)) {
        return update_window(sequence_number, state);
    }
    
    state.replay_count++;
    return false;
}

void AntiReplayCore::reset_window(WindowState& state) {
    state.highest_sequence_number = 0;
    std::fill(state.window.begin(), state.window.end(), false);
    state.received_count = 0;
    state.replay_count = 0;
}

double AntiReplayCore::get_window_utilization(const WindowState& state) {
    if (state.window.empty()) {
        return 0.0;
    }
    
    size_t used_slots = 0;
    for (bool slot : state.window) {
        if (slot) used_slots++;
    }
    
    return static_cast<double>(used_slots) / static_cast<double>(state.window.size());
}

AntiReplayCore::WindowStats AntiReplayCore::get_stats(const WindowState& state) {
    WindowStats stats;
    stats.highest_sequence_number = state.highest_sequence_number;
    stats.window_size = state.window.size();
    stats.received_count = state.received_count;
    stats.replay_count = state.replay_count;
    stats.utilization_ratio = get_window_utilization(state);
    
    // Calculate lowest sequence number in window
    if (state.highest_sequence_number == 0) {
        stats.lowest_sequence_number = 0;
    } else {
        size_t window_size = state.window.size();
        if (state.highest_sequence_number >= window_size) {
            stats.lowest_sequence_number = state.highest_sequence_number - window_size + 1;
        } else {
            stats.lowest_sequence_number = 1;
        }
    }
    
    return stats;
}

void AntiReplayCore::slide_window(uint64_t new_highest, WindowState& state) {
    if (new_highest <= state.highest_sequence_number || state.window.empty()) {
        return;
    }
    
    const size_t window_size = state.window.size();
    const uint64_t shift_amount = new_highest - state.highest_sequence_number;
    
    if (shift_amount >= window_size) {
        // Shift is larger than window - clear everything
        std::fill(state.window.begin(), state.window.end(), false);
    } else {
        // Shift window contents
        const size_t shift_size = static_cast<size_t>(shift_amount);
        
        // Shift existing bits
        for (size_t i = window_size - 1; i >= shift_size; --i) {
            state.window[i] = state.window[i - shift_size];
        }
        
        // Clear the newly opened slots
        std::fill(state.window.begin(), state.window.begin() + shift_size, false);
    }
    
    state.highest_sequence_number = new_highest;
    // Mark the new highest sequence number as received
    state.window[0] = true;
}

} // namespace dtls::v13::core_protocol