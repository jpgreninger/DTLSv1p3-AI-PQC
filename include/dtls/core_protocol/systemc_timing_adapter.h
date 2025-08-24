#pragma once

#include "dtls/core_protocol/anti_replay_core.h"

#ifdef DTLS_BUILD_SYSTEMC
#include <systemc>

namespace dtls::v13::core_protocol {

/**
 * SystemC Timing Adapter for Protocol Core Operations
 * 
 * Provides timing information for core protocol operations
 * when used in SystemC TLM simulations. This adapter wraps
 * the pure protocol core functions with timing models.
 */
class SystemCTimingAdapter {
public:
    // Timing configuration
    struct TimingConfig {
        sc_core::sc_time anti_replay_check_time;
        sc_core::sc_time window_slide_time;
        sc_core::sc_time statistics_update_time;
        
        // Hardware acceleration can reduce timing
        bool hardware_accelerated;
        double hw_acceleration_factor; // 50% faster with HW acceleration
        
        // Constructor with default values
        TimingConfig() 
            : anti_replay_check_time(10, sc_core::SC_NS)
            , window_slide_time(50, sc_core::SC_NS)
            , statistics_update_time(5, sc_core::SC_NS)
            , hardware_accelerated(false)
            , hw_acceleration_factor(0.5)
        {}
    };

    explicit SystemCTimingAdapter(const TimingConfig& config = TimingConfig{});
    
    /**
     * Anti-replay operations with timing
     */
    struct AntiReplayResult {
        bool is_valid;
        sc_core::sc_time processing_time;
        bool window_slid;
    };
    
    AntiReplayResult check_sequence_number_with_timing(
        uint64_t sequence_number,
        const AntiReplayCore::WindowState& state) const;
        
    AntiReplayResult check_and_update_with_timing(
        uint64_t sequence_number,
        AntiReplayCore::WindowState& state) const;
        
    sc_core::sc_time get_reset_timing() const;
    sc_core::sc_time get_stats_timing() const;
    
    // Configuration
    void set_timing_config(const TimingConfig& config);
    const TimingConfig& get_timing_config() const;

private:
    TimingConfig timing_config_;
    
    sc_core::sc_time calculate_processing_time(bool window_operation_needed) const;
};

} // namespace dtls::v13::core_protocol

#endif // DTLS_BUILD_SYSTEMC