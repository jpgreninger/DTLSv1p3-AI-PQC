#ifndef CRYPTO_PROVIDER_TLM_H
#define CRYPTO_PROVIDER_TLM_H

#include "dtls_systemc_types.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <mutex>
#include <atomic>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * SystemC TLM Model for DTLS Crypto Provider
 * 
 * This model simulates the behavior of a cryptographic provider
 * including timing, performance characteristics, and hardware acceleration.
 * Supports both blocking and non-blocking TLM transport interfaces.
 */
SC_MODULE(CryptoProviderTLM) {
public:
    // TLM target socket for receiving crypto operation requests
    tlm_utils::simple_target_socket<CryptoProviderTLM, 32, dtls_protocol_types> target_socket;
    
    // SystemC events for synchronization
    sc_event operation_completed;
    sc_event queue_not_full;
    sc_event queue_not_empty;
    
    /**
     * Statistics structure for crypto provider performance
     */
    struct CryptoStats {
        uint64_t total_operations{0};
        uint64_t successful_operations{0};
        uint64_t failed_operations{0};
        uint64_t encryption_operations{0};
        uint64_t signature_operations{0};
        uint64_t key_derivation_operations{0};
        uint64_t random_generation_operations{0};
        uint64_t hash_operations{0};
        
        size_t total_bytes_processed{0};
        
        sc_time total_processing_time{0, SC_NS};
        sc_time average_processing_time{0, SC_NS};
        sc_time min_processing_time{0, SC_NS};
        sc_time max_processing_time{0, SC_NS};
        
        double utilization_ratio{0.0};
        bool hardware_accelerated{false};
    };
    
    // Constructor
    CryptoProviderTLM(sc_module_name name, bool hardware_accelerated = false);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    bool get_direct_mem_ptr(tlm::tlm_generic_payload& trans, tlm::tlm_dmi& dmi_data);
    unsigned int transport_dbg(tlm::tlm_generic_payload& trans);
    
    // Configuration and monitoring methods
    void set_hardware_acceleration(bool enabled);
    bool is_busy() const;
    size_t get_queue_size() const;
    
    // Statistics methods
    CryptoStats get_statistics() const;
    void reset_statistics();

private:
    // Configuration
    bool hardware_accelerated_;
    
    // Processing infrastructure
    sc_fifo<crypto_transaction> processing_queue_;
    std::atomic<bool> busy_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    CryptoStats stats_;
    
    // SystemC processes
    void crypto_processing_thread();
    
    // Crypto operation implementations
    void perform_crypto_operation(crypto_transaction& trans);
    void perform_encryption(crypto_transaction& trans);
    void perform_decryption(crypto_transaction& trans);
    void perform_signing(crypto_transaction& trans);
    void perform_verification(crypto_transaction& trans);
    void perform_key_derivation(crypto_transaction& trans);
    void perform_random_generation(crypto_transaction& trans);
    void perform_hash_computation(crypto_transaction& trans);
    
    // Statistics updates
    void update_statistics(const crypto_transaction& trans);
    
    SC_HAS_PROCESS(CryptoProviderTLM);
};

/**
 * Hardware-Accelerated Crypto Provider TLM Model
 * 
 * Specialized version with hardware acceleration characteristics
 * including lower latency and higher throughput.
 */
SC_MODULE(HardwareAcceleratedCryptoTLM) {
public:
    // Composition with base crypto provider
    CryptoProviderTLM crypto_provider;
    
    // Hardware-specific ports
    sc_in<bool> hw_accel_enable;
    sc_out<bool> hw_accel_ready;
    sc_out<bool> hw_error;
    
    // Performance counters
    sc_signal<uint32_t> aes_operations_per_sec;
    sc_signal<uint32_t> ecc_operations_per_sec;
    sc_signal<double> power_consumption_mw;
    
    // Constructor
    HardwareAcceleratedCryptoTLM(sc_module_name name);
    
    // Hardware control methods
    void enable_hardware_acceleration();
    void disable_hardware_acceleration();
    bool is_hardware_ready() const;
    
    // Power management
    void set_power_mode(int mode); // 0=low, 1=normal, 2=high performance
    double get_power_consumption() const;

private:
    // Hardware state
    bool hw_ready_;
    int power_mode_;
    
    // SystemC processes
    void hardware_monitor_process();
    void power_management_process();
    
    SC_HAS_PROCESS(HardwareAcceleratedCryptoTLM);
};

/**
 * Multi-Provider Crypto Manager TLM Model
 * 
 * Manages multiple crypto providers and routes operations
 * based on availability, performance, and requirements.
 */
SC_MODULE(CryptoManagerTLM) {
public:
    // TLM initiator socket for making requests to providers
    tlm_utils::simple_initiator_socket<CryptoManagerTLM, 32, dtls_protocol_types> initiator_socket;
    
    // TLM target socket for receiving requests
    tlm_utils::simple_target_socket<CryptoManagerTLM, 32, dtls_protocol_types> target_socket;
    
    // Constructor
    CryptoManagerTLM(sc_module_name name, size_t num_providers = 2);
    
    // Provider management
    void add_crypto_provider(CryptoProviderTLM* provider);
    void remove_crypto_provider(size_t provider_id);
    void set_provider_priority(size_t provider_id, int priority);
    
    // Load balancing
    void set_load_balancing_algorithm(const std::string& algorithm); // "round_robin", "least_loaded", "fastest"
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);

private:
    struct ProviderInfo {
        CryptoProviderTLM* provider;
        int priority;
        uint64_t operation_count;
        sc_time total_processing_time;
        bool available;
    };
    
    std::vector<ProviderInfo> providers_;
    std::string load_balancing_algorithm_;
    std::atomic<size_t> round_robin_counter_;
    
    // Provider selection logic
    size_t select_provider(const crypto_transaction& trans);
    size_t select_round_robin();
    size_t select_least_loaded();
    size_t select_fastest();
    
    SC_HAS_PROCESS(CryptoManagerTLM);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // CRYPTO_PROVIDER_TLM_H