#ifndef DTLS_PROTOCOL_MODULES_H
#define DTLS_PROTOCOL_MODULES_H

#include "dtls_systemc_types.h"
#include "dtls_timing_models.h"
#include "dtls_tlm_extensions.h"
#include "record_layer_tlm.h"
#include "message_layer_tlm.h"
#include "crypto_provider_tlm.h"
#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_target_socket.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <memory>
#include <queue>
#include <map>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

/**
 * Enhanced Record Layer Module
 * 
 * Advanced SystemC module for DTLS record layer processing with
 * comprehensive encryption/decryption modeling, performance analysis,
 * and security metrics.
 */
SC_MODULE(record_layer_module) {
public:
    // TLM interfaces
    tlm_utils::simple_target_socket<record_layer_module> target_socket;
    tlm_utils::simple_initiator_socket<record_layer_module> crypto_socket;
    tlm_utils::simple_initiator_socket<record_layer_module> network_socket;
    
    // Configuration ports
    sc_in<bool> enable_protection;
    sc_in<uint16_t> cipher_suite;
    sc_in<uint32_t> max_record_size;
    sc_in<bool> hardware_acceleration;
    
    // Performance monitoring ports
    sc_out<uint64_t> records_protected;
    sc_out<uint64_t> records_unprotected;
    sc_out<sc_time> average_protection_time;
    sc_out<double> throughput_mbps;
    sc_out<uint32_t> encryption_queue_depth;
    sc_out<double> security_overhead_percent;
    
    // Security monitoring ports
    sc_out<uint64_t> replay_attacks_detected;
    sc_out<uint64_t> authentication_failures;
    sc_out<uint32_t> active_epochs;
    sc_out<bool> security_alert;
    
    // SystemC events
    sc_event record_processed;
    sc_event security_event;
    sc_event performance_threshold_exceeded;
    sc_event epoch_changed;

    /**
     * Record processing statistics
     */
    struct RecordLayerStats {
        // Processing statistics
        uint64_t total_records_processed{0};
        uint64_t records_protected{0};
        uint64_t records_unprotected{0};
        uint64_t bytes_processed{0};
        
        // Performance metrics
        sc_time total_processing_time{0, SC_NS};
        sc_time average_processing_time{0, SC_NS};
        sc_time min_processing_time{SC_ZERO_TIME};
        sc_time max_processing_time{SC_ZERO_TIME};
        
        // Security metrics
        uint64_t replay_attacks_blocked{0};
        uint64_t authentication_failures{0};
        uint64_t sequence_number_violations{0};
        uint64_t epoch_violations{0};
        
        // Resource utilization
        uint32_t peak_queue_depth{0};
        uint32_t current_queue_depth{0};
        double peak_throughput_mbps{0.0};
        double current_throughput_mbps{0.0};
        
        void reset() {
            total_records_processed = 0;
            records_protected = 0;
            records_unprotected = 0;
            bytes_processed = 0;
            total_processing_time = SC_ZERO_TIME;
            replay_attacks_blocked = 0;
            authentication_failures = 0;
            sequence_number_violations = 0;
            epoch_violations = 0;
            peak_queue_depth = 0;
            current_queue_depth = 0;
            peak_throughput_mbps = 0.0;
            current_throughput_mbps = 0.0;
        }
    };

private:
    // Internal components
    std::unique_ptr<RecordLayerTLM> record_processor;
    std::unique_ptr<AntiReplayWindowTLM> anti_replay;
    std::unique_ptr<SequenceNumberManagerTLM> seq_manager;
    std::unique_ptr<EpochManagerTLM> epoch_manager;
    
    // Performance monitoring
    std::unique_ptr<crypto_timing_model> crypto_timing;
    std::unique_ptr<memory_timing_model> memory_timing;
    
    // Processing queues
    std::queue<std::unique_ptr<dtls_transaction>> protection_queue;
    std::queue<std::unique_ptr<dtls_transaction>> unprotection_queue;
    
    // Statistics and state
    RecordLayerStats stats;
    std::mutex stats_mutex;
    std::map<uint32_t, uint16_t> connection_epochs;
    
    // Configuration
    bool protection_enabled{true};
    uint16_t current_cipher_suite{0};
    uint32_t max_record_size_bytes{16384};
    bool hw_accel_available{false};

public:
    SC_CTOR(record_layer_module);
    
    // SystemC processes
    void record_processing_thread();
    void performance_monitoring_thread();
    void security_monitoring_thread();
    void queue_management_thread();
    
    // TLM transport interface
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Record layer operations
    bool protect_record(dtls_transaction& trans);
    bool unprotect_record(dtls_transaction& trans);
    bool validate_record_security(const dtls_transaction& trans);
    
    // Performance analysis
    void update_performance_metrics();
    double calculate_throughput();
    sc_time calculate_processing_latency();
    
    // Security analysis
    bool detect_replay_attack(const dtls_transaction& trans);
    bool validate_epoch_sequence(const dtls_transaction& trans);
    void update_security_metrics();
    
    // Configuration methods
    void configure_cipher_suite(uint16_t suite);
    void set_hardware_acceleration(bool enabled);
    void set_max_record_size(uint32_t size);
    
    // Statistics methods
    RecordLayerStats get_statistics() const;
    void reset_statistics();

private:
    void initialize_components();
    void connect_internal_interfaces();
    void process_protection_queue();
    void process_unprotection_queue();
    void handle_security_event(const std::string& event_type, uint32_t connection_id);
    void log_performance_metrics();
};

/**
 * Handshake Engine Module
 * 
 * Advanced SystemC module for DTLS handshake processing with
 * state machine modeling, message processing logic, and
 * comprehensive handshake performance analysis.
 */
SC_MODULE(handshake_engine_module) {
public:
    // TLM interfaces
    tlm_utils::simple_target_socket<handshake_engine_module> target_socket;
    tlm_utils::simple_initiator_socket<handshake_engine_module> message_socket;
    tlm_utils::simple_initiator_socket<handshake_engine_module> crypto_socket;
    tlm_utils::simple_initiator_socket<handshake_engine_module> record_socket;
    
    // Configuration ports
    sc_in<bool> enable_handshake_processing;
    sc_in<uint32_t> handshake_timeout_ms;
    sc_in<bool> enable_early_data;
    sc_in<uint16_t> max_fragment_size;
    
    // Status ports
    sc_out<uint32_t> active_handshakes;
    sc_out<uint32_t> completed_handshakes;
    sc_out<uint32_t> failed_handshakes;
    sc_out<sc_time> average_handshake_time;
    sc_out<double> handshake_success_rate;
    
    // Performance monitoring ports
    sc_out<uint32_t> message_processing_queue_depth;
    sc_out<sc_time> certificate_verification_time;
    sc_out<sc_time> key_exchange_time;
    sc_out<double> cpu_utilization_percent;
    
    // Security monitoring ports
    sc_out<uint32_t> invalid_signatures_detected;
    sc_out<uint32_t> certificate_validation_failures;
    sc_out<uint32_t> protocol_violations;
    sc_out<bool> handshake_security_alert;
    
    // SystemC events
    sc_event handshake_completed;
    sc_event handshake_failed;
    sc_event certificate_validated;
    sc_event key_exchange_completed;
    sc_event early_data_processed;

    /**
     * Handshake state machine states
     */
    enum class HandshakeState {
        IDLE,
        CLIENT_HELLO_RECEIVED,
        SERVER_HELLO_SENT,
        CERTIFICATE_EXCHANGE,
        KEY_EXCHANGE,
        CERTIFICATE_VERIFY,
        FINISHED_EXCHANGE,
        HANDSHAKE_COMPLETE,
        HANDSHAKE_FAILED
    };
    
    /**
     * Handshake context for each connection
     */
    struct HandshakeContext {
        uint32_t connection_id;
        HandshakeState state{HandshakeState::IDLE};
        sc_time start_time{SC_ZERO_TIME};
        sc_time last_activity{SC_ZERO_TIME};
        
        // Message tracking
        std::map<uint8_t, bool> messages_received;
        std::map<uint8_t, bool> messages_sent;
        uint16_t next_message_sequence{0};
        
        // Security context
        std::vector<uint8_t> client_random;
        std::vector<uint8_t> server_random;
        uint16_t selected_cipher_suite{0};
        uint16_t signature_scheme{0};
        uint16_t named_group{0};
        
        // Performance tracking
        sc_time crypto_processing_time{SC_ZERO_TIME};
        sc_time network_processing_time{SC_ZERO_TIME};
        sc_time certificate_processing_time{SC_ZERO_TIME};
        
        // Fragmentation support
        std::map<uint16_t, std::vector<uint8_t>> fragment_buffers;
        std::map<uint16_t, uint16_t> expected_fragment_lengths;
        
        bool is_complete() const {
            return state == HandshakeState::HANDSHAKE_COMPLETE;
        }
        
        bool has_failed() const {
            return state == HandshakeState::HANDSHAKE_FAILED;
        }
        
        sc_time get_total_time() const {
            return sc_time_stamp() - start_time;
        }
    };
    
    /**
     * Handshake engine statistics
     */
    struct HandshakeEngineStats {
        // Handshake statistics
        uint32_t total_handshakes_initiated{0};
        uint32_t successful_handshakes{0};
        uint32_t failed_handshakes{0};
        uint32_t timeout_handshakes{0};
        
        // Timing statistics
        sc_time total_handshake_time{SC_ZERO_TIME};
        sc_time average_handshake_time{SC_ZERO_TIME};
        sc_time min_handshake_time{SC_ZERO_TIME};
        sc_time max_handshake_time{SC_ZERO_TIME};
        
        // Message processing statistics
        uint64_t messages_processed{0};
        uint64_t fragments_reassembled{0};
        uint64_t retransmissions_sent{0};
        uint64_t duplicate_messages_received{0};
        
        // Security statistics
        uint32_t signature_verification_failures{0};
        uint32_t certificate_validation_failures{0};
        uint32_t protocol_violations{0};
        uint32_t invalid_message_formats{0};
        
        // Performance statistics
        uint32_t peak_active_handshakes{0};
        uint32_t peak_queue_depth{0};
        sc_time peak_processing_time{SC_ZERO_TIME};
        double peak_cpu_utilization{0.0};
        
        void reset() {
            total_handshakes_initiated = 0;
            successful_handshakes = 0;
            failed_handshakes = 0;
            timeout_handshakes = 0;
            total_handshake_time = SC_ZERO_TIME;
            messages_processed = 0;
            fragments_reassembled = 0;
            retransmissions_sent = 0;
            duplicate_messages_received = 0;
            signature_verification_failures = 0;
            certificate_validation_failures = 0;
            protocol_violations = 0;
            invalid_message_formats = 0;
            peak_active_handshakes = 0;
            peak_queue_depth = 0;
            peak_processing_time = SC_ZERO_TIME;
            peak_cpu_utilization = 0.0;
        }
    };

private:
    // Handshake contexts
    std::map<uint32_t, std::unique_ptr<HandshakeContext>> active_handshakes;
    std::mutex handshake_mutex;
    
    // Message processing
    std::unique_ptr<MessageLayerTLM> message_processor;
    std::unique_ptr<MessageReassemblerTLM> reassembler;
    std::unique_ptr<MessageFragmenterTLM> fragmenter;
    std::unique_ptr<FlightManagerTLM> flight_manager;
    
    // Statistics and monitoring
    HandshakeEngineStats stats;
    std::mutex stats_mutex;
    
    // Configuration
    bool processing_enabled{true};
    uint32_t timeout_ms{30000};
    bool early_data_enabled{false};
    uint16_t max_fragment_size_bytes{1024};

public:
    SC_CTOR(handshake_engine_module);
    
    // SystemC processes
    void handshake_processing_thread();
    void timeout_monitoring_thread();
    void performance_analysis_thread();
    void security_validation_thread();
    
    // TLM transport interface
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Handshake processing methods
    bool process_handshake_message(dtls_transaction& trans);
    bool advance_handshake_state(uint32_t connection_id, const dtls_transaction& trans);
    void handle_handshake_timeout(uint32_t connection_id);
    
    // Message processing methods
    bool validate_message_format(const dtls_transaction& trans);
    bool process_client_hello(HandshakeContext& context, const dtls_transaction& trans);
    bool process_server_hello(HandshakeContext& context, const dtls_transaction& trans);
    bool process_certificate(HandshakeContext& context, const dtls_transaction& trans);
    bool process_certificate_verify(HandshakeContext& context, const dtls_transaction& trans);
    bool process_finished(HandshakeContext& context, const dtls_transaction& trans);
    
    // State machine methods
    HandshakeState get_next_state(HandshakeState current, uint8_t message_type);
    bool validate_state_transition(HandshakeState from, HandshakeState to);
    void update_handshake_state(uint32_t connection_id, HandshakeState new_state);
    
    // Performance monitoring methods
    void update_performance_metrics();
    double calculate_success_rate();
    sc_time calculate_average_handshake_time();
    double calculate_cpu_utilization();
    
    // Configuration methods
    void set_handshake_timeout(uint32_t timeout_ms);
    void enable_early_data(bool enabled);
    void set_max_fragment_size(uint16_t size);
    
    // Statistics methods
    HandshakeEngineStats get_statistics() const;
    void reset_statistics();

private:
    void initialize_message_components();
    void cleanup_completed_handshakes();
    void handle_handshake_failure(uint32_t connection_id, const std::string& reason);
    void log_handshake_event(uint32_t connection_id, const std::string& event);
};

/**
 * Key Manager Module
 * 
 * Advanced SystemC module for DTLS key management with
 * key derivation modeling, key schedule simulation, and
 * comprehensive cryptographic key lifecycle management.
 */
SC_MODULE(key_manager_module) {
public:
    // TLM interfaces
    tlm_utils::simple_target_socket<key_manager_module> target_socket;
    tlm_utils::simple_initiator_socket<key_manager_module> crypto_socket;
    
    // Configuration ports
    sc_in<bool> enable_key_updates;
    sc_in<uint32_t> key_update_threshold;
    sc_in<bool> hardware_key_storage;
    sc_in<uint16_t> cipher_suite;
    
    // Status ports
    sc_out<uint32_t> active_key_contexts;
    sc_out<uint64_t> keys_derived;
    sc_out<uint32_t> key_updates_performed;
    sc_out<sc_time> average_key_derivation_time;
    sc_out<bool> key_storage_secure;
    
    // Performance monitoring ports
    sc_out<sc_time> hkdf_processing_time;
    sc_out<sc_time> traffic_key_generation_time;
    sc_out<uint32_t> key_derivation_queue_depth;
    sc_out<double> key_generation_throughput;
    
    // Security monitoring ports
    sc_out<uint32_t> key_compromise_events;
    sc_out<uint32_t> key_validation_failures;
    sc_out<bool> key_security_alert;
    
    // SystemC events
    sc_event key_derived;
    sc_event key_updated;
    sc_event key_expired;
    sc_event key_compromise_detected;

    /**
     * Key derivation context
     */
    struct KeyContext {
        uint32_t connection_id;
        uint16_t epoch;
        
        // Key schedule state
        std::vector<uint8_t> early_secret;
        std::vector<uint8_t> handshake_secret;
        std::vector<uint8_t> master_secret;
        
        // Traffic keys
        std::vector<uint8_t> client_write_key;
        std::vector<uint8_t> server_write_key;
        std::vector<uint8_t> client_write_iv;
        std::vector<uint8_t> server_write_iv;
        
        // Key metadata
        sc_time creation_time{SC_ZERO_TIME};
        sc_time last_update{SC_ZERO_TIME};
        uint64_t usage_count{0};
        uint64_t bytes_protected{0};
        
        // Security parameters
        uint16_t cipher_suite{0};
        uint32_t key_length{0};
        uint32_t iv_length{0};
        bool hardware_stored{false};
        bool compromised{false};
        
        sc_time get_age() const {
            return sc_time_stamp() - creation_time;
        }
        
        bool needs_update(uint64_t threshold) const {
            return usage_count >= threshold || bytes_protected >= (1ULL << 32);
        }
    };
    
    /**
     * Key manager statistics
     */
    struct KeyManagerStats {
        // Key operation statistics
        uint64_t total_key_derivations{0};
        uint64_t successful_derivations{0};
        uint64_t failed_derivations{0};
        uint64_t key_updates{0};
        uint64_t key_rotations{0};
        uint64_t key_expirations{0};
        
        // Performance statistics
        sc_time total_derivation_time{SC_ZERO_TIME};
        sc_time average_derivation_time{SC_ZERO_TIME};
        sc_time min_derivation_time{SC_ZERO_TIME};
        sc_time max_derivation_time{SC_ZERO_TIME};
        
        // Security statistics
        uint32_t key_compromise_events{0};
        uint32_t key_validation_failures{0};
        uint32_t unauthorized_access_attempts{0};
        uint32_t key_export_requests{0};
        
        // Resource statistics
        uint32_t peak_active_contexts{0};
        uint32_t peak_queue_depth{0};
        uint64_t peak_memory_usage{0};
        uint64_t total_bytes_protected{0};
        
        void reset() {
            total_key_derivations = 0;
            successful_derivations = 0;
            failed_derivations = 0;
            key_updates = 0;
            key_rotations = 0;
            key_expirations = 0;
            total_derivation_time = SC_ZERO_TIME;
            key_compromise_events = 0;
            key_validation_failures = 0;
            unauthorized_access_attempts = 0;
            key_export_requests = 0;
            peak_active_contexts = 0;
            peak_queue_depth = 0;
            peak_memory_usage = 0;
            total_bytes_protected = 0;
        }
    };

private:
    // Key contexts
    std::map<uint32_t, std::unique_ptr<KeyContext>> key_contexts;
    std::mutex key_mutex;
    
    // Crypto integration
    std::unique_ptr<CryptoManagerTLM> crypto_manager;
    std::unique_ptr<crypto_timing_model> crypto_timing;
    
    // Statistics and monitoring
    KeyManagerStats stats;
    std::mutex stats_mutex;
    
    // Configuration
    bool key_updates_enabled{true};
    uint64_t update_threshold{1000000}; // 1M operations
    bool hw_key_storage{false};
    uint16_t current_cipher_suite{0};

public:
    SC_CTOR(key_manager_module);
    
    // SystemC processes
    void key_management_thread();
    void key_rotation_thread();
    void security_monitoring_thread();
    void performance_monitoring_thread();
    
    // TLM transport interface
    void b_transport(tlm::tlm_generic_payload& trans, sc_time& delay);
    
    // Key derivation methods
    bool derive_handshake_keys(uint32_t connection_id, const std::vector<uint8_t>& shared_secret);
    bool derive_traffic_keys(uint32_t connection_id, const std::vector<uint8_t>& master_secret);
    bool update_traffic_keys(uint32_t connection_id);
    
    // Key management methods
    bool create_key_context(uint32_t connection_id, uint16_t cipher_suite);
    bool destroy_key_context(uint32_t connection_id);
    KeyContext* get_key_context(uint32_t connection_id);
    
    // Security methods
    bool validate_key_usage(uint32_t connection_id, uint64_t bytes_to_protect);
    void handle_key_compromise(uint32_t connection_id);
    bool secure_key_storage(const std::vector<uint8_t>& key_material);
    
    // Performance monitoring methods
    void update_performance_metrics();
    sc_time calculate_average_derivation_time();
    double calculate_key_generation_throughput();
    
    // Configuration methods
    void set_update_threshold(uint64_t threshold);
    void enable_hardware_storage(bool enabled);
    void configure_cipher_suite(uint16_t suite);
    
    // Statistics methods
    KeyManagerStats get_statistics() const;
    void reset_statistics();

private:
    void initialize_crypto_components();
    void perform_key_rotation();
    void cleanup_expired_contexts();
    void log_key_event(uint32_t connection_id, const std::string& event);
    std::vector<uint8_t> derive_key_material(const std::vector<uint8_t>& secret,
                                           const std::string& label,
                                           uint32_t length);
};

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_MODULES_H