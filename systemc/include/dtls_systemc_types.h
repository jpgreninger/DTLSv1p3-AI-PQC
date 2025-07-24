#ifndef DTLS_SYSTEMC_TYPES_H
#define DTLS_SYSTEMC_TYPES_H

#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <tlm_utils/simple_target_socket.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/protocol/handshake.h>
#include <dtls/protocol/record.h>
#include <dtls/crypto/provider.h>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

using namespace ::sc_core;
using namespace ::sc_dt;
using namespace ::tlm;

/**
 * SystemC Transaction types for DTLS TLM modeling
 */

// Base transaction for all DTLS operations
struct dtls_transaction_base {
    sc_time timestamp;
    uint64_t transaction_id;
    bool response_status{false};
    std::string error_message;
    
    dtls_transaction_base() : timestamp(sc_time_stamp()), transaction_id(0) {}
    virtual ~dtls_transaction_base() = default;
};

// Crypto operation transaction
struct crypto_transaction : public dtls_transaction_base {
    enum operation_type {
        ENCRYPT,
        DECRYPT, 
        SIGN,
        VERIFY,
        KEY_DERIVE,
        RANDOM_GENERATE,
        HASH_COMPUTE
    } operation;
    
    // Input data
    std::vector<uint8_t> input_data;
    std::vector<uint8_t> key_material;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> additional_data;
    
    // Output data
    std::vector<uint8_t> output_data;
    std::vector<uint8_t> auth_tag;
    
    // Crypto parameters
    CipherSuite cipher_suite{CipherSuite::TLS_AES_128_GCM_SHA256};
    SignatureScheme signature_scheme{SignatureScheme::ECDSA_SECP256R1_SHA256};
    NamedGroup named_group{NamedGroup::SECP256R1};
    HashAlgorithm hash_algorithm{HashAlgorithm::SHA256};
    
    // Performance metrics
    sc_time processing_time;
    size_t operations_count{1};
    
    crypto_transaction() = default;
    crypto_transaction(operation_type op) : operation(op) {}
};

// Record layer transaction
struct record_transaction : public dtls_transaction_base {
    enum operation_type {
        PROTECT_RECORD,
        UNPROTECT_RECORD,
        ANTI_REPLAY_CHECK,
        SEQUENCE_NUMBER_GEN,
        EPOCH_ADVANCE
    } operation;
    
    // Record data
    protocol::PlaintextRecord plaintext_record;
    protocol::CiphertextRecord ciphertext_record;
    
    // Security parameters
    uint16_t epoch{0};
    uint64_t sequence_number{0};
    ConnectionID connection_id;
    
    // Anti-replay data
    bool replay_detected{false};
    uint64_t window_position{0};
    
    // Performance metrics
    sc_time processing_time;
    size_t bytes_processed{0};
    
    record_transaction() = default;
    record_transaction(operation_type op) : operation(op) {}
};

// Message layer transaction
struct message_transaction : public dtls_transaction_base {
    enum operation_type {
        FRAGMENT_MESSAGE,
        REASSEMBLE_MESSAGE,
        SEND_FLIGHT,
        RECEIVE_FRAGMENT,
        RETRANSMIT_FLIGHT
    } operation;
    
    // Message data
    protocol::HandshakeMessage handshake_message;
    std::vector<protocol::MessageFragment> fragments;
    
    // Flight data
    protocol::FlightType flight_type{protocol::FlightType::CLIENT_HELLO_FLIGHT};
    uint16_t message_sequence{0};
    
    // Fragmentation parameters
    size_t max_fragment_size{1200};
    size_t fragment_count{0};
    
    // Reassembly state
    bool message_complete{false};
    size_t reassembly_progress{0};
    
    // Performance metrics  
    sc_time processing_time;
    size_t retransmission_count{0};
    
    message_transaction() = default;
    message_transaction(operation_type op) : operation(op) {}
};

// Transport layer transaction
struct transport_transaction : public dtls_transaction_base {
    enum operation_type {
        SEND_PACKET,
        RECEIVE_PACKET,
        NETWORK_ERROR,
        CONNECTION_SETUP,
        CONNECTION_TEARDOWN
    } operation;
    
    // Network data
    std::vector<uint8_t> packet_data;
    std::string source_address;
    std::string destination_address;
    uint16_t source_port{0};
    uint16_t destination_port{0};
    
    // Transport parameters
    size_t mtu_size{1500};
    bool fragmentation_needed{false};
    
    // Network conditions
    sc_time network_delay;
    double packet_loss_probability{0.0};
    double bit_error_rate{0.0};
    
    // Performance metrics
    sc_time transmission_time;
    size_t bytes_transmitted{0};
    
    transport_transaction() = default;
    transport_transaction(operation_type op) : operation(op) {}
};

/**
 * SystemC TLM Protocol types for DTLS communication
 */
struct dtls_protocol_types {
    typedef crypto_transaction crypto_payload_type;
    typedef record_transaction record_payload_type;
    typedef message_transaction message_payload_type;
    typedef transport_transaction transport_payload_type;
    typedef tlm_base_protocol_types::tlm_phase_type tlm_phase_type;
    typedef tlm_base_protocol_types::tlm_sync_enum tlm_sync_enum;
};

// SystemC TLM socket types
typedef tlm_utils::simple_initiator_socket<SC_CURRENT_USER_MODULE, 32, dtls_protocol_types> dtls_initiator_socket;
typedef tlm_utils::simple_target_socket<SC_CURRENT_USER_MODULE, 32, dtls_protocol_types> dtls_target_socket;

/**
 * Common timing parameters for DTLS SystemC models
 */
struct dtls_timing_config {
    // Crypto operation timings
    sc_time aes_encryption_time{10, SC_NS};
    sc_time aes_decryption_time{10, SC_NS};
    sc_time ecdsa_sign_time{1, SC_US};
    sc_time ecdsa_verify_time{2, SC_US};
    sc_time hkdf_derive_time{500, SC_NS};
    sc_time random_generation_time{100, SC_NS};
    sc_time hash_computation_time{50, SC_NS};
    
    // Record layer operation timings
    sc_time record_protection_time{50, SC_NS};
    sc_time record_unprotection_time{75, SC_NS};
    sc_time anti_replay_check_time{5, SC_NS};
    sc_time sequence_number_gen_time{1, SC_NS};
    sc_time epoch_advance_time{100, SC_NS};
    
    // Message layer operation timings
    sc_time message_fragmentation_time{25, SC_NS};
    sc_time fragment_reassembly_time{30, SC_NS};
    sc_time flight_creation_time{10, SC_NS};
    sc_time retransmission_check_time{5, SC_NS};
    
    // Transport layer timings
    sc_time packet_transmission_time{1, SC_MS};
    sc_time network_latency{50, SC_MS};
    sc_time mtu_discovery_time{10, SC_MS};
    
    // Memory operation timings
    sc_time buffer_allocation_time{5, SC_NS};
    sc_time memory_copy_time{1, SC_NS}; // per byte
    sc_time secure_zero_time{2, SC_NS}; // per byte
    
    dtls_timing_config() = default;
};

// Global timing configuration instance
extern dtls_timing_config g_dtls_timing;

/**
 * Utility functions for SystemC DTLS modeling
 */
namespace utils {

// Calculate timing based on data size
inline sc_time calculate_processing_time(size_t data_size, sc_time base_time, sc_time per_byte_time = sc_time(0, SC_NS)) {
    return base_time + sc_time(data_size * per_byte_time.to_double(), per_byte_time.get_time_unit());
}

// Generate unique transaction ID
uint64_t generate_transaction_id();

// Convert DTLS result to SystemC transaction status
template<typename T>
void convert_result_to_transaction(const Result<T>& result, dtls_transaction_base& transaction) {
    transaction.response_status = result.is_success();
    if (result.is_error()) {
        // Convert DTLSError to string - simplified for now
        transaction.error_message = "DTLS Error occurred";
    }
}

// Create timing delays based on hardware acceleration availability
sc_time get_crypto_timing(crypto_transaction::operation_type op, bool hardware_accelerated = false);

} // namespace utils

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_SYSTEMC_TYPES_H