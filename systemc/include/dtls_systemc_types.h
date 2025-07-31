#ifndef DTLS_SYSTEMC_TYPES_H
#define DTLS_SYSTEMC_TYPES_H

#include <systemc>
#include <tlm.h>
#include <tlm_utils/simple_initiator_socket.h>
#include <tlm_utils/simple_target_socket.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include "dtls_tlm_extensions.h"
// Note: Minimal includes to avoid compilation issues with operator==
// Full DTLS headers can be included in implementation files as needed

namespace dtls {
namespace v13 {
namespace systemc_tlm {

using namespace ::sc_core;
using namespace ::sc_dt;
using namespace ::tlm;

/**
 * DTLS TLM Extensions for specialized transactions
 */

// Crypto operation extension
class crypto_extension : public tlm_extension<crypto_extension> {
public:
    enum operation_type {
        ENCRYPT,
        DECRYPT, 
        SIGN,
        VERIFY,
        KEY_DERIVE,
        RANDOM_GENERATE,
        HASH_COMPUTE
    };
    
    operation_type operation{ENCRYPT};
    
    // Crypto parameters
    CipherSuite cipher_suite{CipherSuite::TLS_AES_128_GCM_SHA256};
    SignatureScheme signature_scheme{SignatureScheme::ECDSA_SECP256R1_SHA256};
    NamedGroup named_group{NamedGroup::SECP256R1};
    HashAlgorithm hash_algorithm{HashAlgorithm::SHA256};
    
    // Input/output data pointers (actual data stored in generic payload)
    size_t key_material_offset{0};
    size_t key_material_length{0};
    size_t nonce_offset{0};
    size_t nonce_length{0};
    size_t additional_data_offset{0};
    size_t additional_data_length{0};
    size_t auth_tag_offset{0};
    size_t auth_tag_length{0};
    
    // Performance metrics
    sc_time processing_time;
    size_t operations_count{1};
    
    crypto_extension() = default;
    crypto_extension(operation_type op) : operation(op) {}
    
    virtual tlm_extension_base* clone() const override {
        crypto_extension* ext = new crypto_extension();
        ext->operation = operation;
        ext->cipher_suite = cipher_suite;
        ext->signature_scheme = signature_scheme;
        ext->named_group = named_group;
        ext->hash_algorithm = hash_algorithm;
        ext->key_material_offset = key_material_offset;
        ext->key_material_length = key_material_length;
        ext->nonce_offset = nonce_offset;
        ext->nonce_length = nonce_length;
        ext->additional_data_offset = additional_data_offset;
        ext->additional_data_length = additional_data_length;
        ext->auth_tag_offset = auth_tag_offset;
        ext->auth_tag_length = auth_tag_length;
        ext->processing_time = processing_time;
        ext->operations_count = operations_count;
        return ext;
    }
    
    virtual void copy_from(tlm_extension_base const& ext) override {
        const crypto_extension& other = static_cast<const crypto_extension&>(ext);
        operation = other.operation;
        cipher_suite = other.cipher_suite;
        signature_scheme = other.signature_scheme;
        named_group = other.named_group;
        hash_algorithm = other.hash_algorithm;
        key_material_offset = other.key_material_offset;
        key_material_length = other.key_material_length;
        nonce_offset = other.nonce_offset;
        nonce_length = other.nonce_length;
        additional_data_offset = other.additional_data_offset;
        additional_data_length = other.additional_data_length;
        auth_tag_offset = other.auth_tag_offset;
        auth_tag_length = other.auth_tag_length;
        processing_time = other.processing_time;
        operations_count = other.operations_count;
    }
};

// Record layer extension
class record_extension : public tlm_extension<record_extension> {
public:
    enum operation_type {
        PROTECT_RECORD,
        UNPROTECT_RECORD,
        ANTI_REPLAY_CHECK,
        SEQUENCE_NUMBER_GEN,
        EPOCH_ADVANCE
    };
    
    operation_type operation{PROTECT_RECORD};
    
    // Security parameters
    uint16_t epoch{0};
    uint64_t sequence_number{0};
    std::array<uint8_t, 16> connection_id{};
    
    // Anti-replay data
    bool replay_detected{false};
    uint64_t window_position{0};
    
    // Performance metrics
    sc_time processing_time;
    size_t bytes_processed{0};
    
    record_extension() = default;
    record_extension(operation_type op) : operation(op) {}
    
    virtual tlm_extension_base* clone() const override {
        record_extension* ext = new record_extension();
        ext->operation = operation;
        ext->epoch = epoch;
        ext->sequence_number = sequence_number;
        ext->connection_id = connection_id;
        ext->replay_detected = replay_detected;
        ext->window_position = window_position;
        ext->processing_time = processing_time;
        ext->bytes_processed = bytes_processed;
        return ext;
    }
    
    virtual void copy_from(tlm_extension_base const& ext) override {
        const record_extension& other = static_cast<const record_extension&>(ext);
        operation = other.operation;
        epoch = other.epoch;
        sequence_number = other.sequence_number;
        connection_id = other.connection_id;
        replay_detected = other.replay_detected;
        window_position = other.window_position;
        processing_time = other.processing_time;
        bytes_processed = other.bytes_processed;
    }
};

// Message layer extension
class message_extension : public tlm_extension<message_extension> {
public:
    enum operation_type {
        FRAGMENT_MESSAGE,
        REASSEMBLE_MESSAGE,
        SEND_FLIGHT,
        RECEIVE_FRAGMENT,
        RETRANSMIT_FLIGHT
    };
    
    operation_type operation{FRAGMENT_MESSAGE};
    
    // Flight data (use simple types only)
    uint32_t flight_type_value{1}; // Store FlightType as uint32_t
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
    
    message_extension() = default;
    message_extension(operation_type op) : operation(op) {}
    
    virtual tlm_extension_base* clone() const override {
        message_extension* ext = new message_extension();
        ext->operation = operation;
        ext->flight_type_value = flight_type_value;
        ext->message_sequence = message_sequence;
        ext->max_fragment_size = max_fragment_size;
        ext->fragment_count = fragment_count;
        ext->message_complete = message_complete;
        ext->reassembly_progress = reassembly_progress;
        ext->processing_time = processing_time;
        ext->retransmission_count = retransmission_count;
        return ext;
    }
    
    virtual void copy_from(tlm_extension_base const& ext) override {
        const message_extension& other = static_cast<const message_extension&>(ext);
        operation = other.operation;
        flight_type_value = other.flight_type_value;
        message_sequence = other.message_sequence;
        max_fragment_size = other.max_fragment_size;
        fragment_count = other.fragment_count;
        message_complete = other.message_complete;
        reassembly_progress = other.reassembly_progress;
        processing_time = other.processing_time;
        retransmission_count = other.retransmission_count;
    }
};

// Transport layer extension
class transport_extension : public tlm_extension<transport_extension> {
public:
    enum operation_type {
        SEND_PACKET,
        RECEIVE_PACKET,
        NETWORK_ERROR,
        CONNECTION_SETUP,
        CONNECTION_TEARDOWN
    };
    
    operation_type operation{SEND_PACKET};
    
    // Network data
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
    
    transport_extension() = default;
    transport_extension(operation_type op) : operation(op) {}
    
    virtual tlm_extension_base* clone() const override {
        transport_extension* ext = new transport_extension();
        ext->operation = operation;
        ext->source_address = source_address;
        ext->destination_address = destination_address;
        ext->source_port = source_port;
        ext->destination_port = destination_port;
        ext->mtu_size = mtu_size;
        ext->fragmentation_needed = fragmentation_needed;
        ext->network_delay = network_delay;
        ext->packet_loss_probability = packet_loss_probability;
        ext->bit_error_rate = bit_error_rate;
        ext->transmission_time = transmission_time;
        ext->bytes_transmitted = bytes_transmitted;
        return ext;
    }
    
    virtual void copy_from(tlm_extension_base const& ext) override {
        const transport_extension& other = static_cast<const transport_extension&>(ext);
        operation = other.operation;
        source_address = other.source_address;
        destination_address = other.destination_address;
        source_port = other.source_port;
        destination_port = other.destination_port;
        mtu_size = other.mtu_size;
        fragmentation_needed = other.fragmentation_needed;
        network_delay = other.network_delay;
        packet_loss_probability = other.packet_loss_probability;
        bit_error_rate = other.bit_error_rate;
        transmission_time = other.transmission_time;
        bytes_transmitted = other.bytes_transmitted;
    }
};

/**
 * Transaction type definitions for DTLS SystemC TLM communication
 * Each transaction type combines a TLM generic payload with the corresponding extension
 */

// Forward declaration of dtls_transaction from dtls_tlm_extensions.h
class dtls_transaction;

// Specialized transaction types using dtls_transaction as base
using crypto_transaction = dtls_transaction;
using record_transaction = dtls_transaction;
using message_transaction = dtls_transaction;
using transport_transaction = dtls_transaction;

/**
 * Base class for DTLS SystemC modules
 */
class dtls_module_base : public sc_module {
public:
    SC_HAS_PROCESS(dtls_module_base);
    dtls_module_base(sc_module_name name) : sc_module(name) {}
    virtual ~dtls_module_base() = default;
};

/**
 * SystemC TLM socket types for DTLS communication
 * Note: Forward declarations for template instantiation in derived classes
 */

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
    if (per_byte_time == sc_time(0, SC_NS)) {
        return base_time;
    }
    return base_time + sc_time(data_size * per_byte_time.to_double(), SC_NS);
}

// Generate unique transaction ID
uint64_t generate_transaction_id();

// Convert DTLS result to TLM response status
template<typename T>
void convert_result_to_tlm_response(const Result<T>& result, tlm_generic_payload& trans) {
    if (result.is_ok()) {
        trans.set_response_status(TLM_OK_RESPONSE);
    } else {
        trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
    }
}

// Create timing delays based on hardware acceleration availability
sc_time get_crypto_timing(crypto_extension::operation_type op, bool hardware_accelerated = false);

// Helper functions for setting up TLM transactions
void setup_crypto_transaction(tlm_generic_payload& trans, crypto_extension::operation_type op);
void setup_record_transaction(tlm_generic_payload& trans, record_extension::operation_type op);
void setup_message_transaction(tlm_generic_payload& trans, message_extension::operation_type op);
void setup_transport_transaction(tlm_generic_payload& trans, transport_extension::operation_type op);

} // namespace utils

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls

#endif // DTLS_SYSTEMC_TYPES_H