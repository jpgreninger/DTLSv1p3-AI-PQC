#include "dtls_timing_models.h"
#include <iostream>
#include <random>
#include <algorithm>
#include <cmath>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// Crypto Timing Model Implementation
SC_MODULE_EXPORT(crypto_timing_model);

crypto_timing_model::crypto_timing_model(sc_module_name name)
    : sc_module(name)
    , hardware_acceleration_enabled("hardware_acceleration_enabled")
    , cpu_load_factor("cpu_load_factor")
    , concurrent_operations("concurrent_operations")
    , current_aes_encrypt_time("current_aes_encrypt_time")
    , current_aes_decrypt_time("current_aes_decrypt_time")
    , current_ecdsa_sign_time("current_ecdsa_sign_time")
    , current_ecdsa_verify_time("current_ecdsa_verify_time")
    , current_hkdf_derive_time("current_hkdf_derive_time")
    , crypto_efficiency_factor("crypto_efficiency_factor")
{
    initialize_cipher_timings();
    
    // Register SystemC processes
    SC_THREAD(timing_update_process);
    SC_THREAD(load_monitoring_process);
    
    // Initialize output ports
    current_aes_encrypt_time.initialize(sc_time(50, SC_NS));
    current_aes_decrypt_time.initialize(sc_time(45, SC_NS));
    current_ecdsa_sign_time.initialize(sc_time(2000, SC_NS));
    current_ecdsa_verify_time.initialize(sc_time(3000, SC_NS));
    current_hkdf_derive_time.initialize(sc_time(100, SC_NS));
    crypto_efficiency_factor.initialize(1.0);
}

void crypto_timing_model::initialize_cipher_timings() {
    // AES-GCM timing
    cipher_timings["aes-gcm"] = {
        sc_time(40, SC_NS),  // base_time
        sc_time(2, SC_NS),   // per_byte_time
        sc_time(10, SC_NS),  // setup_time
        sc_time(5, SC_NS),   // teardown_time
        3.5,                 // hardware_speedup_factor
        4                    // parallel_operations_limit
    };
    
    // ChaCha20-Poly1305 timing
    cipher_timings["chacha20-poly1305"] = {
        sc_time(35, SC_NS),
        sc_time(1.5, SC_NS),
        sc_time(8, SC_NS),
        sc_time(4, SC_NS),
        2.8,
        2
    };
    
    // ECDSA P-256 timing
    cipher_timings["ecdsa-p256"] = {
        sc_time(1800, SC_NS), // signing
        sc_time(0.5, SC_NS),
        sc_time(100, SC_NS),
        sc_time(20, SC_NS),
        4.2,
        1
    };
    
    // ECDSA P-384 timing
    cipher_timings["ecdsa-p384"] = {
        sc_time(3200, SC_NS),
        sc_time(0.8, SC_NS),
        sc_time(150, SC_NS),
        sc_time(30, SC_NS),
        4.8,
        1
    };
    
    // RSA-PSS timing
    cipher_timings["rsa-pss-2048"] = {
        sc_time(5000, SC_NS),
        sc_time(1, SC_NS),
        sc_time(200, SC_NS),
        sc_time(50, SC_NS),
        8.0,
        1
    };
    
    // HKDF timing
    cipher_timings["hkdf-sha256"] = {
        sc_time(80, SC_NS),
        sc_time(3, SC_NS),
        sc_time(15, SC_NS),
        sc_time(5, SC_NS),
        2.5,
        8
    };
    
    // Random generation timing
    cipher_timings["random"] = {
        sc_time(20, SC_NS),
        sc_time(1, SC_NS),
        sc_time(5, SC_NS),
        sc_time(2, SC_NS),
        1.8,
        16
    };
}

void crypto_timing_model::timing_update_process() {
    while (true) {
        wait(sc_time(10, SC_MS)); // Update every 10ms
        
        // Calculate current timing based on load and hardware acceleration
        sc_time aes_encrypt = calculate_cipher_time("aes-gcm", 1024);
        sc_time aes_decrypt = calculate_cipher_time("aes-gcm", 1024);
        sc_time ecdsa_sign = calculate_signature_time("ecdsa-p256", 32);
        sc_time ecdsa_verify = calculate_signature_time("ecdsa-p256", 64);
        sc_time hkdf_derive = calculate_key_derivation_time("hkdf-sha256", 32);
        
        // Write to output ports
        current_aes_encrypt_time.write(aes_encrypt);
        current_aes_decrypt_time.write(aes_decrypt);
        current_ecdsa_sign_time.write(ecdsa_sign);
        current_ecdsa_verify_time.write(ecdsa_verify);
        current_hkdf_derive_time.write(hkdf_derive);
        
        // Calculate efficiency factor
        double efficiency = 1.0 / get_current_load_factor();
        crypto_efficiency_factor.write(efficiency);
    }
}

void crypto_timing_model::load_monitoring_process() {
    while (true) {
        wait(sc_time(100, SC_MS)); // Monitor every 100ms
        
        // Monitor concurrent operations and adjust load factor
        uint32_t concurrent_ops = concurrent_operations.read();
        double cpu_load = cpu_load_factor.read();
        
        update_load_factor(cpu_load);
        
        // Update performance statistics
        total_operations++;
        if (total_operations > 0) {
            average_efficiency = (average_efficiency * (total_operations - 1) + 
                                crypto_efficiency_factor.read()) / total_operations;
        }
    }
}

sc_time crypto_timing_model::calculate_cipher_time(const std::string& cipher, size_t data_size) const {
    std::lock_guard<std::mutex> lock(timing_mutex);
    
    auto it = cipher_timings.find(cipher);
    if (it == cipher_timings.end()) {
        return sc_time(100, SC_NS); // Default fallback
    }
    
    const CipherTiming& timing = it->second;
    
    sc_time base_time = timing.base_time + timing.setup_time + timing.teardown_time;
    sc_time data_time = sc_time(data_size, SC_NS) * timing.per_byte_time.to_double();
    sc_time total_time = base_time + data_time;
    
    // Apply load adjustment
    total_time = apply_load_adjustment(total_time);
    
    // Apply hardware acceleration if available
    total_time = apply_hardware_acceleration(total_time, cipher);
    
    return total_time;
}

sc_time crypto_timing_model::calculate_signature_time(const std::string& algorithm, size_t data_size) const {
    return calculate_cipher_time(algorithm, data_size);
}

sc_time crypto_timing_model::calculate_key_derivation_time(const std::string& algorithm, uint32_t key_length) const {
    return calculate_cipher_time(algorithm, key_length);
}

sc_time crypto_timing_model::calculate_random_generation_time(size_t bytes) const {
    return calculate_cipher_time("random", bytes);
}

sc_time crypto_timing_model::calculate_hash_time(const std::string& algorithm, size_t data_size) const {
    sc_time base_time = sc_time(25, SC_NS);
    sc_time data_time = sc_time(data_size * 0.5, SC_NS);
    return apply_load_adjustment(base_time + data_time);
}

double crypto_timing_model::get_current_load_factor() const {
    double cpu_load = cpu_load_factor.read();
    
    if (cpu_load < 0.25) {
        return load_adjustment.light_load_factor;
    } else if (cpu_load < 0.75) {
        return load_adjustment.medium_load_factor;
    } else if (cpu_load < 0.95) {
        return load_adjustment.heavy_load_factor;
    } else {
        return load_adjustment.overload_factor;
    }
}

void crypto_timing_model::update_load_factor(double cpu_utilization) {
    // Update load adjustment factors based on current CPU utilization
    if (cpu_utilization > 0.95) {
        load_adjustment.overload_factor = std::min(5.0, load_adjustment.overload_factor * 1.1);
    } else if (cpu_utilization < 0.25) {
        load_adjustment.light_load_factor = std::max(0.7, load_adjustment.light_load_factor * 0.95);
    }
}

bool crypto_timing_model::is_hardware_accelerated(const std::string& operation) const {
    return hardware_acceleration_enabled.read() && 
           (operation.find("aes") != std::string::npos || 
            operation.find("ecdsa") != std::string::npos ||
            operation.find("hkdf") != std::string::npos);
}

double crypto_timing_model::get_hardware_speedup(const std::string& operation) const {
    auto it = cipher_timings.find(operation);
    if (it != cipher_timings.end()) {
        return it->second.hardware_speedup_factor;
    }
    return 2.0; // Default speedup
}

sc_time crypto_timing_model::apply_load_adjustment(sc_time base_time) const {
    double load_factor = get_current_load_factor();
    return sc_time(base_time.to_double() * load_factor, SC_NS);
}

sc_time crypto_timing_model::apply_hardware_acceleration(sc_time base_time, const std::string& operation) const {
    if (is_hardware_accelerated(operation)) {
        double speedup = get_hardware_speedup(operation);
        return sc_time(base_time.to_double() / speedup, SC_NS);
    }
    return base_time;
}

// Network Timing Model Implementation
SC_MODULE_EXPORT(network_timing_model);

network_timing_model::network_timing_model(sc_module_name name)
    : sc_module(name)
    , bandwidth_kbps("bandwidth_kbps")
    , packet_loss_rate("packet_loss_rate")
    , base_latency("base_latency")
    , congestion_control_enabled("congestion_control_enabled")
    , current_rtt("current_rtt")
    , current_throughput_mbps("current_throughput_mbps")
    , packets_lost("packets_lost")
    , packets_retransmitted("packets_retransmitted")
    , congestion_window_size("congestion_window_size")
{
    initialize_network_conditions();
    
    // Register SystemC processes
    SC_THREAD(network_simulation_process);
    SC_THREAD(congestion_control_process);
    SC_THREAD(packet_loss_simulation_process);
    
    // Initialize output ports
    current_rtt.initialize(sc_time(100, SC_MS));
    current_throughput_mbps.initialize(1.0);
    packets_lost.initialize(0);
    packets_retransmitted.initialize(0);
    congestion_window_size.initialize(1.0);
}

void network_timing_model::initialize_network_conditions() {
    conditions.base_latency = sc_time(50, SC_MS);
    conditions.jitter_max = sc_time(10, SC_MS);
    conditions.bandwidth_kbps = 1000;
    conditions.packet_loss_rate = 0.001;
    conditions.mtu_size = 1500;
    conditions.congestion_control = true;
}

void network_timing_model::network_simulation_process() {
    while (true) {
        wait(sc_time(50, SC_MS)); // Network update cycle
        
        // Calculate current RTT with jitter
        sc_time rtt = conditions.base_latency * 2 + generate_jitter();
        current_rtt.write(rtt);
        
        // Calculate effective throughput
        double throughput = get_effective_bandwidth() / 1000.0; // Convert to Mbps
        current_throughput_mbps.write(throughput);
        
        // Update congestion window
        congestion_window_size.write(congestion_window.current_window);
    }
}

void network_timing_model::congestion_control_process() {
    while (true) {
        wait(sc_time(100, SC_MS)); // Congestion control update
        
        if (conditions.congestion_control) {
            update_congestion_state();
        }
    }
}

void network_timing_model::packet_loss_simulation_process() {
    while (true) {
        wait(sc_time(1, SC_MS)); // Packet loss simulation
        
        // Simulate packet loss events
        if (simulate_packet_loss()) {
            total_packets_lost++;
            packets_lost.write(total_packets_lost);
            
            // Trigger congestion control response
            update_congestion_window(false, true);
        }
    }
}

sc_time network_timing_model::calculate_transmission_time(size_t packet_size) const {
    std::lock_guard<std::mutex> lock(network_mutex);
    
    double bits = packet_size * 8.0;
    double bandwidth_bps = conditions.bandwidth_kbps * 1000.0;
    double transmission_seconds = bits / bandwidth_bps;
    
    return sc_time(transmission_seconds, SC_SEC);
}

sc_time network_timing_model::calculate_propagation_delay() const {
    return conditions.base_latency + generate_jitter();
}

sc_time network_timing_model::calculate_total_delay(size_t packet_size) const {
    sc_time transmission_time = calculate_transmission_time(packet_size);
    sc_time propagation_delay = calculate_propagation_delay();
    
    return transmission_time + propagation_delay;
}

bool network_timing_model::simulate_packet_loss() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(0.0, 1.0);
    
    return dis(gen) < conditions.packet_loss_rate;
}

void network_timing_model::update_congestion_window(bool packet_acked, bool packet_lost) {
    if (packet_lost) {
        // Packet loss detected - enter fast recovery
        congestion_window.ssthresh = congestion_window.current_window / 2.0;
        congestion_window.current_window = congestion_window.ssthresh;
        congestion_window.state = CongestionWindow::State::FAST_RECOVERY;
    } else if (packet_acked) {
        switch (congestion_window.state) {
            case CongestionWindow::State::SLOW_START:
                congestion_window.current_window += 1.0;
                if (congestion_window.current_window >= congestion_window.ssthresh) {
                    congestion_window.state = CongestionWindow::State::CONGESTION_AVOIDANCE;
                }
                break;
                
            case CongestionWindow::State::CONGESTION_AVOIDANCE:
                congestion_window.current_window += 1.0 / congestion_window.current_window;
                break;
                
            case CongestionWindow::State::FAST_RECOVERY:
                congestion_window.state = CongestionWindow::State::CONGESTION_AVOIDANCE;
                break;
        }
    }
    
    // Enforce window limits
    congestion_window.current_window = std::min(congestion_window.current_window, 
                                                congestion_window.max_window);
    congestion_window.current_window = std::max(congestion_window.current_window, 1.0);
}

double network_timing_model::get_effective_bandwidth() const {
    double base_bandwidth = conditions.bandwidth_kbps;
    double congestion_factor = congestion_window.current_window / congestion_window.max_window;
    
    return base_bandwidth * congestion_factor;
}

sc_time network_timing_model::get_retransmission_timeout() const {
    sc_time rtt = current_rtt.read();
    return rtt * 3.0; // RTO = 3 * RTT (simplified)
}

sc_time network_timing_model::generate_jitter() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(-1.0, 1.0);
    
    double jitter_factor = dis(gen);
    return conditions.jitter_max * jitter_factor;
}

void network_timing_model::update_congestion_state() {
    // Update congestion state based on network conditions
    double loss_rate = get_packet_loss_rate();
    
    if (loss_rate > 0.01) { // 1% loss rate
        congestion_window.ssthresh *= 0.9;
    } else if (loss_rate < 0.001) { // 0.1% loss rate
        congestion_window.ssthresh = std::min(congestion_window.max_window, 
                                             congestion_window.ssthresh * 1.05);
    }
}

double network_timing_model::get_packet_loss_rate() const {
    if (total_packets_sent > 0) {
        return static_cast<double>(total_packets_lost) / total_packets_sent;
    }
    return 0.0;
}

double network_timing_model::get_average_throughput() const {
    if (total_transmission_time > SC_ZERO_TIME) {
        double bytes_per_second = total_bytes_transmitted / total_transmission_time.to_seconds();
        return (bytes_per_second * 8.0) / (1024.0 * 1024.0); // Convert to Mbps
    }
    return 0.0;
}

sc_time network_timing_model::get_average_rtt() const {
    return current_rtt.read(); // Simplified - could maintain running average
}

// Memory Timing Model Implementation
SC_MODULE_EXPORT(memory_timing_model);

memory_timing_model::memory_timing_model(sc_module_name name)
    : sc_module(name)
    , cache_size_kb("cache_size_kb")
    , cache_hit_ratio("cache_hit_ratio")
    , secure_memory_enabled("secure_memory_enabled")
    , average_access_time("average_access_time")
    , cache_hits("cache_hits")
    , cache_misses("cache_misses")
    , memory_utilization_percent("memory_utilization_percent")
    , secure_allocations("secure_allocations")
{
    initialize_memory_system();
    
    // Register SystemC processes
    SC_THREAD(memory_monitoring_process);
    SC_THREAD(cache_simulation_process);
    SC_THREAD(garbage_collection_process);
    
    // Initialize output ports
    average_access_time.initialize(sc_time(10, SC_NS));
    cache_hits.initialize(0);
    cache_misses.initialize(0);
    memory_utilization_percent.initialize(0.0);
    secure_allocations.initialize(0);
}

void memory_timing_model::initialize_memory_system() {
    // Configure default cache hierarchy
    timing_config.l1_cache = {32, sc_time(1, SC_NS), 0.95, 64, 8};
    timing_config.l2_cache = {256, sc_time(5, SC_NS), 0.85, 64, 16}; 
    timing_config.l3_cache = {8192, sc_time(15, SC_NS), 0.75, 64, 16};
    
    timing_config.dram_access_time = sc_time(100, SC_NS);
    timing_config.allocation_overhead = sc_time(50, SC_NS);
    timing_config.secure_zero_time = sc_time(5, SC_NS);
    timing_config.memory_copy_time = sc_time(2, SC_NS);
}

void memory_timing_model::memory_monitoring_process() {
    while (true) {
        wait(sc_time(50, SC_MS)); // Memory monitoring cycle
        
        // Update memory utilization
        double utilization = get_memory_utilization();
        memory_utilization_percent.write(utilization);
        
        // Update peak usage tracking
        if (current_memory_usage > peak_memory_usage) {
            peak_memory_usage = current_memory_usage;
        }
    }
}

void memory_timing_model::cache_simulation_process() {
    while (true) {
        wait(sc_time(10, SC_MS)); // Cache simulation cycle
        
        // Update cache hit ratio and access times
        double hit_ratio = get_cache_hit_ratio();
        cache_hit_ratio.write(hit_ratio);
        
        // Calculate average access time based on cache performance
        sc_time avg_time = sc_time(1, SC_NS) * hit_ratio + 
                          timing_config.dram_access_time * (1.0 - hit_ratio);
        average_access_time.write(avg_time);
    }
}

void memory_timing_model::garbage_collection_process() {
    while (true) {
        wait(sc_time(1, SC_SEC)); // Garbage collection cycle
        
        // Simulate garbage collection overhead
        if (current_memory_usage > peak_memory_usage * 0.8) {
            // Trigger garbage collection
            sc_time gc_time = sc_time(current_memory_usage / 1024, SC_MS);
            wait(gc_time);
            
            // Simulate memory reclamation
            current_memory_usage = static_cast<uint64_t>(current_memory_usage * 0.85);
        }
    }
}

sc_time memory_timing_model::calculate_allocation_time(size_t bytes, bool secure) const {
    sc_time base_time = timing_config.allocation_overhead;
    
    if (secure) {
        base_time += timing_config.secure_zero_time * (bytes / 64); // per cache line
    }
    
    return base_time;
}

sc_time memory_timing_model::calculate_deallocation_time(size_t bytes, bool secure) const {
    sc_time base_time = timing_config.allocation_overhead * 0.8; // Deallocation is faster
    
    if (secure) {
        base_time += timing_config.secure_zero_time * (bytes / 64);
    }
    
    return base_time;
}

sc_time memory_timing_model::calculate_access_time(void* address, size_t bytes) const {
    // Simulate cache hierarchy access
    if (simulate_cache_hit(address, bytes, 1)) {
        return timing_config.l1_cache.access_time;
    } else if (simulate_cache_hit(address, bytes, 2)) {
        return timing_config.l2_cache.access_time;
    } else if (simulate_cache_hit(address, bytes, 3)) {
        return timing_config.l3_cache.access_time;
    } else {
        return timing_config.dram_access_time;
    }
}

sc_time memory_timing_model::calculate_copy_time(size_t bytes) const {
    return timing_config.memory_copy_time * bytes;
}

bool memory_timing_model::simulate_cache_hit(void* address, size_t bytes, int cache_level) const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<> dis(0.0, 1.0);
    
    double hit_ratio = 0.0;
    switch (cache_level) {
        case 1: hit_ratio = timing_config.l1_cache.hit_ratio; break;
        case 2: hit_ratio = timing_config.l2_cache.hit_ratio; break;
        case 3: hit_ratio = timing_config.l3_cache.hit_ratio; break;
        default: return false;
    }
    
    return dis(gen) < hit_ratio;
}

double memory_timing_model::get_cache_hit_ratio() const {
    if (total_cache_accesses > 0) {
        return static_cast<double>(total_cache_hits) / total_cache_accesses;
    }
    return 0.0;
}

uint64_t memory_timing_model::get_memory_usage() const {
    return current_memory_usage;
}

double memory_timing_model::get_memory_utilization() const {
    uint64_t total_system_memory = 1024ULL * 1024 * 1024 * 8; // 8GB assumed
    return (static_cast<double>(current_memory_usage) / total_system_memory) * 100.0;
}

// DTLS Timing Manager Implementation
SC_MODULE_EXPORT(dtls_timing_manager);

dtls_timing_manager::dtls_timing_manager(sc_module_name name)
    : sc_module(name)
    , enable_realistic_timing("enable_realistic_timing")
    , simulation_speedup_factor("simulation_speedup_factor")
    , total_operation_time("total_operation_time")
    , system_efficiency("system_efficiency")
    , bottleneck_component("bottleneck_component")
{
    initialize_timing_models();
    connect_timing_models();
    
    // Register SystemC processes
    SC_THREAD(timing_coordination_process);
    SC_THREAD(bottleneck_analysis_process);
    
    // Initialize output ports
    total_operation_time.initialize(SC_ZERO_TIME);
    system_efficiency.initialize(1.0);
    bottleneck_component.initialize(0);
}

void dtls_timing_manager::initialize_timing_models() {
    crypto_timing = std::make_unique<crypto_timing_model>("crypto_timing");
    network_timing = std::make_unique<network_timing_model>("network_timing");
    memory_timing = std::make_unique<memory_timing_model>("memory_timing");
}

void dtls_timing_manager::connect_timing_models() {
    // Connect timing models to global configuration
    // This would typically involve signal bindings in a real implementation
}

void dtls_timing_manager::timing_coordination_process() {
    while (true) {
        wait(sc_time(100, SC_MS)); // Coordination cycle
        
        // Calculate total system timing
        sc_time crypto_time = crypto_timing->current_aes_encrypt_time.read();
        sc_time network_time = network_timing->current_rtt.read();
        sc_time memory_time = memory_timing->average_access_time.read();
        
        sc_time total_time = crypto_time + network_time + memory_time;
        total_operation_time.write(total_time);
        
        // Calculate system efficiency
        double efficiency = calculate_system_efficiency();
        system_efficiency.write(efficiency);
    }
}

void dtls_timing_manager::bottleneck_analysis_process() {
    while (true) {
        wait(sc_time(500, SC_MS)); // Bottleneck analysis cycle
        
        analyze_bottlenecks();
    }
}

sc_time dtls_timing_manager::calculate_total_operation_time(const std::string& operation,
                                                          size_t data_size,
                                                          bool use_network,
                                                          bool use_memory) const {
    sc_time total_time = SC_ZERO_TIME;
    
    // Add crypto timing
    if (operation.find("encrypt") != std::string::npos ||
        operation.find("decrypt") != std::string::npos ||
        operation.find("sign") != std::string::npos) {
        total_time += crypto_timing->calculate_cipher_time(operation, data_size);
    }
    
    // Add network timing
    if (use_network) {
        total_time += network_timing->calculate_total_delay(data_size);
    }
    
    // Add memory timing
    if (use_memory) {
        total_time += memory_timing->calculate_access_time(nullptr, data_size);
    }
    
    // Apply simulation speedup
    double speedup = simulation_speedup_factor.read();
    if (speedup > 1.0) {
        total_time = sc_time(total_time.to_double() / speedup, SC_NS);
    }
    
    return total_time;
}

void dtls_timing_manager::analyze_bottlenecks() {
    sc_time crypto_time = crypto_timing->current_aes_encrypt_time.read();
    sc_time network_time = network_timing->current_rtt.read();
    sc_time memory_time = memory_timing->average_access_time.read();
    
    uint32_t bottleneck = 0; // crypto
    sc_time max_time = crypto_time;
    
    if (network_time > max_time) {
        bottleneck = 1; // network
        max_time = network_time;
    }
    
    if (memory_time > max_time) {
        bottleneck = 2; // memory
    }
    
    bottleneck_component.write(bottleneck);
}

double dtls_timing_manager::calculate_system_efficiency() const {
    double crypto_efficiency = crypto_timing->crypto_efficiency_factor.read();
    double network_efficiency = std::min(1.0, network_timing->current_throughput_mbps.read() / 100.0);
    double memory_efficiency = std::min(1.0, 1.0 - (memory_timing->memory_utilization_percent.read() / 100.0));
    
    return (crypto_efficiency + network_efficiency + memory_efficiency) / 3.0;
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls