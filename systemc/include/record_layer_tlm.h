#ifndef RECORD_LAYER_TLM_H
#define RECORD_LAYER_TLM_H

#include "dtls_systemc_types.h"
#include "crypto_provider_tlm.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <mutex>
#include <unordered_map>
#include <bitset>

// Forward declarations for DTLS protocol types
namespace dtls::v13::protocol {
    class PlaintextRecord;
    class CiphertextRecord;
    struct RecordHeader;
}

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * SystemC TLM Model for Anti-Replay Window
 * 
 * Implements sliding window algorithm for detecting replay attacks
 * with configurable window size and timing characteristics.
 */
SC_MODULE(AntiReplayWindowTLM) {
public:
    // TLM target socket for replay check requests
    tlm_utils::simple_target_socket<AntiReplayWindowTLM> target_socket;
    
    // Configuration ports
    sc_in<uint32_t> window_size_config;
    sc_in<bool> reset_window;
    
    // Status ports
    sc_out<uint64_t> highest_sequence_number;
    sc_out<uint32_t> replay_count;
    sc_out<double> window_utilization;
    
    /**
     * Anti-replay statistics
     */
    struct AntiReplayStats {
        uint64_t total_checks{0};
        uint64_t valid_packets{0};
        uint64_t replay_detections{0};
        uint64_t out_of_window_packets{0};
        
        uint64_t current_highest_seq{0};
        uint32_t current_window_size{64};
        double utilization_ratio{0.0};
        
        sc_time total_check_time{0, SC_NS};
        sc_time average_check_time{0, SC_NS};
    };
    
    // Constructor
    AntiReplayWindowTLM(sc_module_name name, uint32_t window_size = 64);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    
    // Configuration methods
    void set_window_size(uint32_t size);
    void reset();
    
    // Statistics and monitoring
    AntiReplayStats get_statistics() const;
    void reset_statistics();
    bool is_sequence_valid(uint64_t sequence_number) const;

private:
    // Window state
    uint32_t window_size_;
    uint64_t highest_sequence_number_;
    std::vector<bool> window_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    AntiReplayStats stats_;
    
    // SystemC processes
    void window_monitor_process();
    void configuration_process();
    
    // Internal methods
    bool check_and_update_window(uint64_t sequence_number);
    void slide_window(uint64_t new_highest);
    void update_statistics(bool replay_detected, sc_time check_time);
    
    SC_HAS_PROCESS(AntiReplayWindowTLM);
};

/**
 * SystemC TLM Model for Sequence Number Manager
 * 
 * Manages sequence number generation with overflow protection
 * and epoch synchronization.
 */
SC_MODULE(SequenceNumberManagerTLM) {
public:
    // TLM target socket
    tlm_utils::simple_target_socket<SequenceNumberManagerTLM> target_socket;
    
    // Control ports
    sc_in<bool> reset_sequence;
    sc_in<uint16_t> current_epoch;
    
    // Status ports
    sc_out<uint64_t> current_sequence_number;
    sc_out<bool> overflow_warning;
    sc_out<uint64_t> remaining_sequence_numbers;
    
    /**
     * Sequence number statistics
     */
    struct SequenceStats {
        uint64_t numbers_generated{0};
        uint64_t current_sequence{0};
        uint16_t current_epoch{0};
        uint64_t max_sequence_number{(1ULL << 48) - 1};
        uint64_t remaining_numbers{(1ULL << 48) - 1};
        bool overflow_imminent{false};
        
        sc_time total_generation_time{0, SC_NS};
        sc_time average_generation_time{0, SC_NS};
    };
    
    // Constructor
    SequenceNumberManagerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Sequence number operations
    uint64_t get_next_sequence_number();
    uint64_t get_current_sequence_number() const;
    bool would_overflow() const;
    void reset();
    
    // Statistics and monitoring
    SequenceStats get_statistics() const;
    void reset_statistics();

private:
    // State
    std::atomic<uint64_t> current_sequence_number_;
    uint16_t current_epoch_;
    
    // Constants
    static constexpr uint64_t MAX_SEQUENCE_NUMBER = (1ULL << 48) - 1;
    static constexpr uint64_t OVERFLOW_WARNING_THRESHOLD = MAX_SEQUENCE_NUMBER - 1000000;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    SequenceStats stats_;
    
    // SystemC processes
    void overflow_monitor_process();
    void epoch_sync_process();
    
    // Internal methods
    void update_statistics(sc_time generation_time);
    void check_overflow_warning();
    
    SC_HAS_PROCESS(SequenceNumberManagerTLM);
};

/**
 * SystemC TLM Model for Epoch Manager
 * 
 * Manages DTLS epochs with cryptographic key storage
 * and secure epoch transitions.
 */
SC_MODULE(EpochManagerTLM) {
public:
    // TLM target socket
    tlm_utils::simple_target_socket<EpochManagerTLM> target_socket;
    
    // Control ports
    sc_in<bool> advance_epoch_trigger;
    sc_in<bool> key_update_ready;
    
    // Status ports
    sc_out<uint16_t> current_epoch;
    sc_out<bool> epoch_transition_in_progress;
    sc_out<uint32_t> active_epochs_count;
    
    /**
     * Epoch management statistics
     */
    struct EpochStats {
        uint16_t current_epoch{0};
        uint32_t total_epoch_advances{0};
        uint32_t active_epochs{1};
        uint32_t max_concurrent_epochs{3};
        
        sc_time total_transition_time{0, SC_NS};
        sc_time average_transition_time{0, SC_NS};
        sc_time last_transition_time{0, SC_NS};
        
        uint64_t key_derivations{0};
        uint64_t key_storage_bytes{0};
    };
    
    // Constructor
    EpochManagerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Epoch operations
    uint16_t get_current_epoch() const;
    uint16_t advance_epoch();
    bool is_valid_epoch(uint16_t epoch) const;
    
    // Key management
    bool set_epoch_keys(uint16_t epoch, 
                       const std::vector<uint8_t>& read_key,
                       const std::vector<uint8_t>& write_key,
                       const std::vector<uint8_t>& read_iv,
                       const std::vector<uint8_t>& write_iv);
    
    // Statistics and monitoring
    EpochStats get_statistics() const;
    void reset_statistics();

private:
    // Epoch state
    std::atomic<uint16_t> current_epoch_;
    std::atomic<bool> transition_in_progress_;
    
    // Key storage (simplified for SystemC model)
    struct EpochKeys {
        std::vector<uint8_t> read_key;
        std::vector<uint8_t> write_key;
        std::vector<uint8_t> read_iv;
        std::vector<uint8_t> write_iv;
        CipherSuite cipher_suite;
        sc_time creation_time;
    };
    
    std::unordered_map<uint16_t, EpochKeys> epoch_keys_;
    mutable std::mutex keys_mutex_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    EpochStats stats_;
    
    // SystemC processes
    void epoch_transition_process();
    void key_management_process();
    void cleanup_old_epochs_process();
    
    // Internal methods
    void perform_epoch_transition();
    void cleanup_old_epochs();
    void update_statistics(sc_time transition_time);
    
    SC_HAS_PROCESS(EpochManagerTLM);
};

/**
 * SystemC TLM Model for Record Layer
 * 
 * Main record layer component that orchestrates record protection,
 * anti-replay checking, and epoch management.
 */
SC_MODULE(RecordLayerTLM) {
public:
    // TLM interfaces
    tlm_utils::simple_target_socket<RecordLayerTLM> target_socket;
    tlm_utils::simple_initiator_socket<RecordLayerTLM> crypto_initiator_socket;
    
    // Component interfaces
    tlm_utils::simple_initiator_socket<RecordLayerTLM> antireplay_socket;
    tlm_utils::simple_initiator_socket<RecordLayerTLM> sequence_socket;
    tlm_utils::simple_initiator_socket<RecordLayerTLM> epoch_socket;
    
    // Control ports
    sc_in<bool> connection_id_enabled;
    sc_in<uint32_t> current_cipher_suite;
    
    // Status ports
    sc_out<uint64_t> records_protected;
    sc_out<uint64_t> records_unprotected;
    sc_out<uint32_t> replay_attacks_blocked;
    sc_out<double> protection_throughput_mbps;
    
    /**
     * Record layer performance statistics
     */
    struct RecordLayerStats {
        uint64_t total_protect_operations{0};
        uint64_t total_unprotect_operations{0};
        uint64_t successful_protections{0};
        uint64_t successful_unprotections{0};
        uint64_t failed_protections{0};
        uint64_t failed_unprotections{0};
        uint64_t replay_attacks_detected{0};
        
        size_t total_bytes_protected{0};
        size_t total_bytes_unprotected{0};
        
        sc_time total_protection_time{0, SC_NS};
        sc_time total_unprotection_time{0, SC_NS};
        sc_time average_protection_time{0, SC_NS};
        sc_time average_unprotection_time{0, SC_NS};
        
        double protection_throughput_mbps{0.0};
        double unprotection_throughput_mbps{0.0};
    };
    
    // Constructor
    RecordLayerTLM(sc_module_name name);
    
    // TLM interface methods
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    tlm::tlm_sync_enum nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                      tlm::tlm_phase& phase, 
                                      sc_time& delay);
    
    // Record operations
    bool protect_record(const protocol::PlaintextRecord& plaintext, 
                       protocol::CiphertextRecord& ciphertext);
    bool unprotect_record(const protocol::CiphertextRecord& ciphertext, 
                         protocol::PlaintextRecord& plaintext);
    
    // Configuration
    void set_cipher_suite(CipherSuite suite);
    void enable_connection_id(const ConnectionID& local_cid, const ConnectionID& peer_cid);
    
    // Statistics and monitoring
    RecordLayerStats get_statistics() const;
    void reset_statistics();

private:
    // Configuration
    CipherSuite current_cipher_suite_;
    bool connection_id_enabled_;
    ConnectionID local_connection_id_;
    ConnectionID peer_connection_id_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    RecordLayerStats stats_;
    
    // SystemC processes
    void record_processing_thread();
    void performance_monitor_process();
    void throughput_calculation_process();
    
    // Internal methods
    bool perform_record_protection(tlm::tlm_generic_payload& trans);
    bool perform_record_unprotection(tlm::tlm_generic_payload& trans);
    bool check_anti_replay(uint64_t sequence_number, uint16_t epoch);
    uint64_t get_next_sequence_number();
    
    std::vector<uint8_t> construct_aead_nonce(uint16_t epoch, 
                                             uint64_t sequence_number,
                                             const std::vector<uint8_t>& base_iv);
    std::vector<uint8_t> construct_additional_data(const protocol::RecordHeader& header,
                                                  const ConnectionID& cid);
    
    void update_protection_statistics(size_t bytes_processed, sc_time processing_time, bool success);
    void update_unprotection_statistics(size_t bytes_processed, sc_time processing_time, bool success);
    void calculate_throughput();
    
    SC_HAS_PROCESS(RecordLayerTLM);
};

/**
 * SystemC TLM Model for integrated Record Layer Security System
 * 
 * Top-level module that integrates all record layer security components
 * with proper interconnection and system-level monitoring.
 */
SC_MODULE(RecordLayerSecuritySystemTLM) {
public:
    // External TLM interface
    tlm_utils::simple_target_socket<RecordLayerSecuritySystemTLM> external_socket;
    
    // Component instances
    RecordLayerTLM record_layer;
    AntiReplayWindowTLM anti_replay_window;
    SequenceNumberManagerTLM sequence_manager;
    EpochManagerTLM epoch_manager;
    CryptoProviderTLM crypto_provider;
    
    // Internal TLM connections would be implemented as sc_signals or channels
    // For simplicity, showing the component composition
    
    // System control ports
    sc_in<bool> system_reset;
    sc_in<bool> security_mode_enable;
    
    // System status ports
    sc_out<bool> system_ready;
    sc_out<uint32_t> security_level;
    sc_out<double> overall_throughput_mbps;
    
    /**
     * System-level security statistics
     */
    struct SecuritySystemStats {
        uint64_t total_records_processed{0};
        uint64_t security_violations_detected{0};
        uint64_t system_resets{0};
        
        double overall_throughput_mbps{0.0};
        double security_effectiveness_ratio{0.0};
        
        sc_time system_uptime{0, SC_NS};
        sc_time total_processing_time{0, SC_NS};
        
        // Component-specific stats accessible through getters
    };
    
    // Constructor
    RecordLayerSecuritySystemTLM(sc_module_name name);
    
    // TLM interface
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // System control
    void initialize_system();
    void reset_system();
    void enable_security_mode(bool enable);
    
    // System monitoring
    SecuritySystemStats get_system_statistics() const;
    bool is_system_ready() const;
    uint32_t get_security_level() const;

private:
    // System state
    bool system_ready_;
    bool security_mode_enabled_;
    uint32_t security_level_;
    
    // Statistics
    mutable std::mutex system_stats_mutex_;
    SecuritySystemStats system_stats_;
    
    // SystemC processes
    void system_monitor_process();
    void system_control_process();
    void statistics_aggregation_process();
    
    // Internal methods
    void update_system_statistics();
    void handle_security_violation();
    void calculate_security_effectiveness();
    
    SC_HAS_PROCESS(RecordLayerSecuritySystemTLM);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // RECORD_LAYER_TLM_H