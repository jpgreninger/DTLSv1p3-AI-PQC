#include "dtls/core_protocol/systemc_timing_adapter.h"

#ifdef DTLS_BUILD_SYSTEMC

namespace dtls::v13::core_protocol {

SystemCTimingAdapter::SystemCTimingAdapter(const TimingConfig& config)
    : timing_config_(config) {
}

SystemCTimingAdapter::AntiReplayResult 
SystemCTimingAdapter::check_sequence_number_with_timing(
    uint64_t sequence_number,
    const AntiReplayCore::WindowState& state) const {
    
    AntiReplayResult result;
    result.is_valid = AntiReplayCore::is_valid_sequence_number(sequence_number, state);
    
    // Determine if operation would cause window sliding
    bool would_slide_window = (sequence_number > state.highest_sequence_number);
    result.window_slid = would_slide_window;
    
    // Calculate timing based on operation complexity
    result.processing_time = calculate_processing_time(would_slide_window);
    
    return result;
}

SystemCTimingAdapter::AntiReplayResult 
SystemCTimingAdapter::check_and_update_with_timing(
    uint64_t sequence_number,
    AntiReplayCore::WindowState& state) const {
    
    AntiReplayResult result;
    
    // Check if window would slide before the operation
    bool would_slide_window = (sequence_number > state.highest_sequence_number);
    result.window_slid = would_slide_window;
    
    // Perform the actual operation
    result.is_valid = AntiReplayCore::check_and_update(sequence_number, state);
    
    // Calculate timing based on what actually happened
    result.processing_time = calculate_processing_time(would_slide_window);
    
    return result;
}

sc_core::sc_time SystemCTimingAdapter::get_reset_timing() const {
    // Reset is a simple operation - just clearing state
    sc_core::sc_time base_time = timing_config_.statistics_update_time;
    
    if (timing_config_.hardware_accelerated) {
        base_time = sc_core::sc_time(
            base_time.to_double() * timing_config_.hw_acceleration_factor,
            base_time.get_time_unit());
    }
    
    return base_time;
}

sc_core::sc_time SystemCTimingAdapter::get_stats_timing() const {
    return timing_config_.statistics_update_time;
}

void SystemCTimingAdapter::set_timing_config(const TimingConfig& config) {
    timing_config_ = config;
}

const SystemCTimingAdapter::TimingConfig& 
SystemCTimingAdapter::get_timing_config() const {
    return timing_config_;
}

sc_core::sc_time SystemCTimingAdapter::calculate_processing_time(bool window_operation_needed) const {
    sc_core::sc_time base_time = timing_config_.anti_replay_check_time;
    
    if (window_operation_needed) {
        // Window sliding is more expensive
        base_time += timing_config_.window_slide_time;
    }
    
    if (timing_config_.hardware_accelerated) {
        base_time = sc_core::sc_time(
            base_time.to_double() * timing_config_.hw_acceleration_factor,
            base_time.get_time_unit());
    }
    
    return base_time;
}

} // namespace dtls::v13::core_protocol

#endif // DTLS_BUILD_SYSTEMC