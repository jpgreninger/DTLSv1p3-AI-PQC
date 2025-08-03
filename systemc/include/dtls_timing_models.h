#ifndef DTLS_TIMING_MODELS_H
#define DTLS_TIMING_MODELS_H

#include "dtls_systemc_types.h"
#include <systemc>
#include <tlm.h>
#include <map>
#include <vector>
#include <mutex>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Cryptographic Timing Model
 * 
 * Models realistic timing for cryptographic operations including
 * cipher-specific timing parameters and load-based adjustments.
 * Supports both software and hardware acceleration timing.
 */
SC_MODULE(crypto_timing_model) {
public:
    // Configuration ports
    sc_in<bool> hardware_acceleration_enabled;
    sc_in<double> cpu_load_factor;
    sc_in<uint32_t> concurrent_operations;
    
    // Timing output ports
    sc_out<sc_time> current_aes_encrypt_time;
    sc_out<sc_time> current_aes_decrypt_time;
    sc_out<sc_time> current_ecdsa_sign_time;
    sc_out<sc_time> current_ecdsa_verify_time;
    sc_out<sc_time> current_hkdf_derive_time;
    sc_out<double> crypto_efficiency_factor;
    
    /**
     * Cipher-specific timing parameters
     */
    struct CipherTiming {
        sc_time base_time;
        sc_time per_byte_time;
        sc_time setup_time;
        sc_time teardown_time;
        double hardware_speedup_factor;
        uint32_t parallel_operations_limit;
    };
    
    /**
     * Load-based timing adjustment
     */
    struct LoadAdjustment {
        double light_load_factor{0.9};     // <25% CPU
        double medium_load_factor{1.0};    // 25-75% CPU
        double heavy_load_factor{1.5};     // 75-95% CPU
        double overload_factor{3.0};       // >95% CPU
    };
    
private:
    std::map<std::string, CipherTiming> cipher_timings;
    LoadAdjustment load_adjustment;
    mutable std::mutex timing_mutex;
    
    // Performance tracking
    uint64_t total_operations{0};
    sc_time total_processing_time{0, SC_NS};
    double average_efficiency{1.0};

public:
    SC_CTOR(crypto_timing_model);
    
    // SystemC processes
    void timing_update_process();
    void load_monitoring_process();
    
    // Timing calculation methods
    sc_time calculate_cipher_time(const std::string& cipher, size_t data_size) const;
    sc_time calculate_signature_time(const std::string& algorithm, size_t data_size) const;
    sc_time calculate_key_derivation_time(const std::string& algorithm, uint32_t key_length) const;
    sc_time calculate_random_generation_time(size_t bytes) const;
    sc_time calculate_hash_time(const std::string& algorithm, size_t data_size) const;
    
    // Load adjustment methods
    double get_current_load_factor() const;
    void update_load_factor(double cpu_utilization);
    
    // Hardware acceleration methods
    bool is_hardware_accelerated(const std::string& operation) const;
    double get_hardware_speedup(const std::string& operation) const;
    
    // Configuration methods
    void configure_cipher_timing(const std::string& cipher, const CipherTiming& timing);
    void set_load_adjustment(const LoadAdjustment& adjustment);
    
private:
    void initialize_cipher_timings();
    sc_time apply_load_adjustment(sc_time base_time) const;
    sc_time apply_hardware_acceleration(sc_time base_time, const std::string& operation) const;
};

/**
 * Network Timing Model
 * 
 * Models network latency, bandwidth limitations, and packet loss simulation.
 * Includes realistic network conditions and congestion modeling.
 */
SC_MODULE(network_timing_model) {
public:
    // Configuration ports
    sc_in<uint32_t> bandwidth_kbps;
    sc_in<double> packet_loss_rate;
    sc_in<sc_time> base_latency;
    sc_in<bool> congestion_control_enabled;
    
    // Network condition ports
    sc_out<sc_time> current_rtt;
    sc_out<double> current_throughput_mbps;
    sc_out<uint32_t> packets_lost;
    sc_out<uint32_t> packets_retransmitted;
    sc_out<double> congestion_window_size;
    
    /**
     * Network condition parameters
     */
    struct NetworkConditions {
        sc_time base_latency{50, SC_MS};
        sc_time jitter_max{10, SC_MS};
        uint32_t bandwidth_kbps{1000};
        double packet_loss_rate{0.001}; // 0.1%
        uint32_t mtu_size{1500};
        bool congestion_control{true};
    };
    
    /**
     * Congestion window management
     */
    struct CongestionWindow {
        double current_window{1.0};
        double max_window{64.0};
        double ssthresh{32.0};
        enum class State {
            SLOW_START,
            CONGESTION_AVOIDANCE,
            FAST_RECOVERY
        } state{State::SLOW_START};
    };

private:
    NetworkConditions conditions;
    CongestionWindow congestion_window;
    mutable std::mutex network_mutex;
    
    // Statistics
    uint64_t total_packets_sent{0};
    uint64_t total_packets_lost{0};
    uint64_t total_bytes_transmitted{0};
    sc_time total_transmission_time{0, SC_NS};

public:
    SC_CTOR(network_timing_model);
    
    // SystemC processes
    void network_simulation_process();
    void congestion_control_process();
    void packet_loss_simulation_process();
    
    // Network timing methods
    sc_time calculate_transmission_time(size_t packet_size) const;
    sc_time calculate_propagation_delay() const;
    sc_time calculate_total_delay(size_t packet_size) const;
    bool simulate_packet_loss() const;
    
    // Congestion control methods
    void update_congestion_window(bool packet_acked, bool packet_lost);
    double get_effective_bandwidth() const;
    sc_time get_retransmission_timeout() const;
    
    // Configuration methods
    void configure_network_conditions(const NetworkConditions& new_conditions);
    void set_congestion_control(bool enabled);
    
    // Statistics methods
    double get_packet_loss_rate() const;
    double get_average_throughput() const;
    sc_time get_average_rtt() const;

private:
    void initialize_network_conditions();
    sc_time generate_jitter() const;
    void update_congestion_state();
};

/**
 * Memory Timing Model
 * 
 * Models memory access patterns, cache behavior, and allocation timing.
 * Includes both DRAM and cache timing characteristics.
 */
SC_MODULE(memory_timing_model) {
public:
    // Configuration ports
    sc_in<uint64_t> cache_size_kb;
    sc_in<double> cache_hit_ratio;
    sc_in<bool> secure_memory_enabled;
    
    // Memory performance ports
    sc_out<sc_time> average_access_time;
    sc_out<uint64_t> cache_hits;
    sc_out<uint64_t> cache_misses;
    sc_out<double> memory_utilization_percent;
    sc_out<uint64_t> secure_allocations;
    
    /**
     * Cache hierarchy configuration
     */
    struct CacheLevel {
        uint64_t size_kb;
        sc_time access_time;
        double hit_ratio;
        uint32_t line_size_bytes;
        uint32_t associativity;
    };
    
    /**
     * Memory timing parameters
     */
    struct MemoryTiming {
        CacheLevel l1_cache{32, sc_time(1, SC_NS), 0.95, 64, 8};
        CacheLevel l2_cache{256, sc_time(5, SC_NS), 0.85, 64, 16};
        CacheLevel l3_cache{8192, sc_time(15, SC_NS), 0.75, 64, 16};
        
        sc_time dram_access_time{100, SC_NS};
        sc_time allocation_overhead{50, SC_NS};
        sc_time secure_zero_time{5, SC_NS};
        sc_time memory_copy_time{2, SC_NS}; // per byte
    };

private:
    MemoryTiming timing_config;
    std::map<void*, size_t> allocated_blocks;
    std::mutex memory_mutex;
    
    // Statistics
    uint64_t total_allocations{0};
    uint64_t total_deallocations{0};
    uint64_t total_cache_accesses{0};
    uint64_t total_cache_hits{0};
    uint64_t peak_memory_usage{0};
    uint64_t current_memory_usage{0};

public:
    SC_CTOR(memory_timing_model);
    
    // SystemC processes
    void memory_monitoring_process();
    void cache_simulation_process();
    void garbage_collection_process();
    
    // Memory timing methods
    sc_time calculate_allocation_time(size_t bytes, bool secure = false) const;
    sc_time calculate_deallocation_time(size_t bytes, bool secure = false) const;
    sc_time calculate_access_time(void* address, size_t bytes) const;
    sc_time calculate_copy_time(size_t bytes) const;
    
    // Cache simulation methods
    bool simulate_cache_hit(void* address, size_t bytes, int cache_level = 1) const;
    sc_time get_cache_access_time(int cache_level) const;
    void update_cache_statistics(bool hit, int cache_level);
    
    // Memory management methods
    void* allocate_memory(size_t bytes, bool secure = false);
    void deallocate_memory(void* ptr, bool secure = false);
    void secure_zero_memory(void* ptr, size_t bytes);
    
    // Configuration methods
    void configure_cache_hierarchy(const MemoryTiming& config);
    void set_cache_parameters(int level, const CacheLevel& cache_config);
    
    // Statistics methods
    double get_cache_hit_ratio() const;
    uint64_t get_memory_usage() const;
    double get_memory_utilization() const;

private:
    void initialize_memory_system();
    uint64_t calculate_cache_address(void* address, int cache_level) const;
    bool is_cache_line_present(uint64_t cache_address, int cache_level) const;
};

/**
 * Integrated Timing Manager
 * 
 * Coordinates all timing models and provides unified timing interface
 * for the DTLS protocol stack.
 */
SC_MODULE(dtls_timing_manager) {
public:
    // Component timing models
    std::unique_ptr<crypto_timing_model> crypto_timing;
    std::unique_ptr<network_timing_model> network_timing;
    std::unique_ptr<memory_timing_model> memory_timing;
    
    // Configuration ports
    sc_in<bool> enable_realistic_timing;
    sc_in<double> simulation_speedup_factor;
    
    // Global timing ports
    sc_out<sc_time> total_operation_time;
    sc_out<double> system_efficiency;
    sc_out<uint32_t> bottleneck_component; // 0=crypto, 1=network, 2=memory
    
public:
    SC_CTOR(dtls_timing_manager);
    
    // Unified timing interface
    sc_time calculate_total_operation_time(const std::string& operation,
                                         size_t data_size,
                                         bool use_network = true,
                                         bool use_memory = true) const;
    
    // Performance analysis
    void analyze_bottlenecks();
    double calculate_system_efficiency() const;
    
    // Configuration
    void configure_all_models(const dtls_timing_config& global_config);
    void set_simulation_parameters(bool realistic_timing, double speedup);

private:
    void initialize_timing_models();
    void connect_timing_models();
    
    // SystemC processes
    void timing_coordination_process();
    void bottleneck_analysis_process();
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_TIMING_MODELS_H