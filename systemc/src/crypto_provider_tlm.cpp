#include "crypto_provider_tlm.h"
#include <dtls/crypto/crypto_utils.h>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// Initialize global timing configuration
dtls_timing_config g_dtls_timing;

namespace utils {

static std::atomic<uint64_t> transaction_counter{1};

uint64_t generate_transaction_id() {
    return transaction_counter.fetch_add(1);
}

sc_time get_crypto_timing(crypto_transaction::operation_type op, bool hardware_accelerated) {
    sc_time base_time;
    double acceleration_factor = hardware_accelerated ? 0.1 : 1.0;
    
    switch (op) {
        case crypto_transaction::ENCRYPT:
        case crypto_transaction::DECRYPT:
            base_time = g_dtls_timing.aes_encryption_time;
            break;
        case crypto_transaction::SIGN:
            base_time = g_dtls_timing.ecdsa_sign_time;
            break;
        case crypto_transaction::VERIFY:
            base_time = g_dtls_timing.ecdsa_verify_time;
            break;
        case crypto_transaction::KEY_DERIVE:
            base_time = g_dtls_timing.hkdf_derive_time;
            break;
        case crypto_transaction::RANDOM_GENERATE:
            base_time = g_dtls_timing.random_generation_time;
            break;
        case crypto_transaction::HASH_COMPUTE:
            base_time = g_dtls_timing.hash_computation_time;
            break;
        default:
            base_time = sc_time(100, SC_NS);
            break;
    }
    
    return sc_time(base_time.to_double() * acceleration_factor, base_time.get_time_unit());
}

} // namespace utils

/**
 * SystemC TLM Model for Crypto Provider
 */
CryptoProviderTLM::CryptoProviderTLM(sc_module_name name, bool hardware_accelerated)
    : sc_module(name)
    , target_socket("target_socket")
    , hardware_accelerated_(hardware_accelerated)
    , processing_queue_("processing_queue", 16) // Buffer size 16
    , busy_(false)
{
    target_socket.register_b_transport(this, &CryptoProviderTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &CryptoProviderTLM::nb_transport_fw);
    target_socket.register_get_direct_mem_ptr(this, &CryptoProviderTLM::get_direct_mem_ptr);
    target_socket.register_transport_dbg(this, &CryptoProviderTLM::transport_dbg);
    
    SC_THREAD(crypto_processing_thread);
    
    // Initialize statistics
    reset_statistics();
}

void CryptoProviderTLM::b_transport(tlm_generic_payload& trans, sc_time& delay) {
    crypto_transaction* crypto_trans = reinterpret_cast<crypto_transaction*>(trans.get_data_ptr());
    
    if (!crypto_trans) {
        trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Calculate processing time based on operation type and data size
    sc_time processing_time = utils::get_crypto_timing(crypto_trans->operation, hardware_accelerated_);
    
    // Add data-dependent timing
    if (!crypto_trans->input_data.empty()) {
        processing_time += utils::calculate_processing_time(
            crypto_trans->input_data.size(),
            sc_time(0, SC_NS),
            sc_time(1, SC_NS) // 1ns per byte
        );
    }
    
    // Perform the crypto operation
    perform_crypto_operation(*crypto_trans);
    
    // Update timing and statistics
    crypto_trans->processing_time = processing_time;
    delay += processing_time;
    
    update_statistics(*crypto_trans);
    trans.set_response_status(crypto_trans->response_status ? TLM_OK_RESPONSE : TLM_GENERIC_ERROR_RESPONSE);
}

tlm_sync_enum CryptoProviderTLM::nb_transport_fw(tlm_generic_payload& trans, 
                                                tlm_phase& phase, 
                                                sc_time& delay) {
    crypto_transaction* crypto_trans = reinterpret_cast<crypto_transaction*>(trans.get_data_ptr());
    
    if (phase == BEGIN_REQ) {
        // Check if we can accept the transaction
        if (processing_queue_.num_free() == 0) {
            trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
            phase = END_REQ;
            return TLM_COMPLETED;
        }
        
        // Queue the transaction for processing
        crypto_trans->transaction_id = utils::generate_transaction_id();
        processing_queue_.write(*crypto_trans);
        
        phase = END_REQ;
        return TLM_ACCEPTED;
    }
    
    return TLM_ACCEPTED;
}

bool CryptoProviderTLM::get_direct_mem_ptr(tlm_generic_payload& trans, tlm_dmi& dmi_data) {
    // Direct memory access not supported for crypto operations
    return false;
}

unsigned int CryptoProviderTLM::transport_dbg(tlm_generic_payload& trans) {
    // Debug transport for inspection only
    crypto_transaction* crypto_trans = reinterpret_cast<crypto_transaction*>(trans.get_data_ptr());
    if (crypto_trans) {
        return crypto_trans->input_data.size();
    }
    return 0;
}

void CryptoProviderTLM::crypto_processing_thread() {
    while (true) {
        crypto_transaction trans = processing_queue_.read();
        
        busy_ = true;
        
        // Calculate processing time
        sc_time processing_time = utils::get_crypto_timing(trans.operation, hardware_accelerated_);
        
        // Wait for processing time
        wait(processing_time);
        
        // Perform the operation
        perform_crypto_operation(trans);
        
        // Update statistics
        update_statistics(trans);
        
        busy_ = false;
        
        // Trigger completion event
        operation_completed.notify();
    }
}

void CryptoProviderTLM::perform_crypto_operation(crypto_transaction& trans) {
    switch (trans.operation) {
        case crypto_transaction::ENCRYPT:
            perform_encryption(trans);
            break;
        case crypto_transaction::DECRYPT:
            perform_decryption(trans);
            break;
        case crypto_transaction::SIGN:
            perform_signing(trans);
            break;
        case crypto_transaction::VERIFY:
            perform_verification(trans);
            break;
        case crypto_transaction::KEY_DERIVE:
            perform_key_derivation(trans);
            break;
        case crypto_transaction::RANDOM_GENERATE:
            perform_random_generation(trans);
            break;
        case crypto_transaction::HASH_COMPUTE:
            perform_hash_computation(trans);
            break;
        default:
            trans.response_status = false;
            trans.error_message = "Unsupported crypto operation";
            return;
    }
}

void CryptoProviderTLM::perform_encryption(crypto_transaction& trans) {
    // Simulate AEAD encryption (AES-GCM)
    if (trans.input_data.empty() || trans.key_material.empty()) {
        trans.response_status = false;
        trans.error_message = "Missing input data or key material";
        return;
    }
    
    // Calculate output size (input + auth tag)
    size_t auth_tag_size = 16; // GCM tag size
    trans.output_data.resize(trans.input_data.size());
    trans.auth_tag.resize(auth_tag_size);
    
    // For simulation, just copy input to output and generate mock tag
    std::copy(trans.input_data.begin(), trans.input_data.end(), trans.output_data.begin());
    std::fill(trans.auth_tag.begin(), trans.auth_tag.end(), 0xAA);
    
    trans.response_status = true;
}

void CryptoProviderTLM::perform_decryption(crypto_transaction& trans) {
    // Simulate AEAD decryption (AES-GCM)
    if (trans.input_data.empty() || trans.key_material.empty() || trans.auth_tag.empty()) {
        trans.response_status = false;
        trans.error_message = "Missing input data, key material, or auth tag";
        return;
    }
    
    // For simulation, verify mock tag and copy input to output
    bool auth_valid = std::all_of(trans.auth_tag.begin(), trans.auth_tag.end(), 
                                 [](uint8_t b) { return b == 0xAA; });
    
    if (!auth_valid) {
        trans.response_status = false;
        trans.error_message = "Authentication tag verification failed";
        return;
    }
    
    trans.output_data.resize(trans.input_data.size());
    std::copy(trans.input_data.begin(), trans.input_data.end(), trans.output_data.begin());
    
    trans.response_status = true;
}

void CryptoProviderTLM::perform_signing(crypto_transaction& trans) {
    // Simulate ECDSA signing
    if (trans.input_data.empty() || trans.key_material.empty()) {
        trans.response_status = false;
        trans.error_message = "Missing input data or private key";
        return;
    }
    
    // Generate mock signature (typically 64 bytes for ECDSA P-256)
    trans.output_data.resize(64);
    std::fill(trans.output_data.begin(), trans.output_data.end(), 0xBB);
    
    trans.response_status = true;
}

void CryptoProviderTLM::perform_verification(crypto_transaction& trans) {
    // Simulate ECDSA signature verification
    if (trans.input_data.empty() || trans.key_material.empty() || trans.output_data.empty()) {
        trans.response_status = false;
        trans.error_message = "Missing input data, public key, or signature";
        return;
    }
    
    // For simulation, verify mock signature
    bool sig_valid = std::all_of(trans.output_data.begin(), trans.output_data.end(),
                                [](uint8_t b) { return b == 0xBB; });
    
    trans.response_status = sig_valid;
    if (!sig_valid) {
        trans.error_message = "Signature verification failed";
    }
}

void CryptoProviderTLM::perform_key_derivation(crypto_transaction& trans) {
    // Simulate HKDF key derivation
    if (trans.key_material.empty()) {
        trans.response_status = false;
        trans.error_message = "Missing key material for derivation";
        return;
    }
    
    // Generate derived key (typically 32 bytes for AES-256)
    size_t key_length = 32;
    trans.output_data.resize(key_length);
    
    // Simple mock derivation - XOR with a pattern
    for (size_t i = 0; i < key_length; ++i) {
        trans.output_data[i] = trans.key_material[i % trans.key_material.size()] ^ 0xCC;
    }
    
    trans.response_status = true;
}

void CryptoProviderTLM::perform_random_generation(crypto_transaction& trans) {
    // Simulate cryptographically secure random generation
    size_t random_length = trans.input_data.size() > 0 ? trans.input_data[0] : 32;
    
    trans.output_data.resize(random_length);
    
    // For simulation, generate pseudo-random data
    static uint32_t seed = 0x12345678;
    for (size_t i = 0; i < random_length; ++i) {
        seed = seed * 1103515245 + 12345; // Linear congruential generator
        trans.output_data[i] = static_cast<uint8_t>(seed >> 16);
    }
    
    trans.response_status = true;
}

void CryptoProviderTLM::perform_hash_computation(crypto_transaction& trans) {
    // Simulate SHA-256 hash computation
    if (trans.input_data.empty()) {
        trans.response_status = false;
        trans.error_message = "No input data for hashing";
        return;
    }
    
    // Generate mock hash (32 bytes for SHA-256)
    trans.output_data.resize(32);
    
    // Simple mock hash - sum bytes and spread across output
    uint32_t sum = 0;
    for (uint8_t byte : trans.input_data) {
        sum += byte;
    }
    
    for (size_t i = 0; i < 32; ++i) {
        trans.output_data[i] = static_cast<uint8_t>((sum + i) & 0xFF);
    }
    
    trans.response_status = true;
}

void CryptoProviderTLM::update_statistics(const crypto_transaction& trans) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_operations++;
    stats_.total_processing_time += trans.processing_time;
    
    if (trans.response_status) {
        stats_.successful_operations++;
    } else {
        stats_.failed_operations++;
    }
    
    stats_.total_bytes_processed += trans.input_data.size();
    
    // Update operation-specific statistics
    switch (trans.operation) {
        case crypto_transaction::ENCRYPT:
        case crypto_transaction::DECRYPT:
            stats_.encryption_operations++;
            break;
        case crypto_transaction::SIGN:
        case crypto_transaction::VERIFY:
            stats_.signature_operations++;
            break;
        case crypto_transaction::KEY_DERIVE:
            stats_.key_derivation_operations++;
            break;
        case crypto_transaction::RANDOM_GENERATE:
            stats_.random_generation_operations++;
            break;
        case crypto_transaction::HASH_COMPUTE:
            stats_.hash_operations++;
            break;
    }
    
    // Update performance metrics
    if (trans.processing_time > stats_.max_processing_time) {
        stats_.max_processing_time = trans.processing_time;
    }
    
    if (stats_.min_processing_time == sc_time(0, SC_NS) || 
        trans.processing_time < stats_.min_processing_time) {
        stats_.min_processing_time = trans.processing_time;
    }
}

CryptoProviderTLM::CryptoStats CryptoProviderTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    CryptoStats stats = stats_;
    
    // Calculate average processing time
    if (stats.total_operations > 0) {
        stats.average_processing_time = sc_time(
            stats.total_processing_time.to_double() / stats.total_operations,
            stats.total_processing_time.get_time_unit()
        );
    }
    
    return stats;
}

void CryptoProviderTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = CryptoStats{};
}

bool CryptoProviderTLM::is_busy() const {
    return busy_;
}

size_t CryptoProviderTLM::get_queue_size() const {
    return processing_queue_.num_available();
}

void CryptoProviderTLM::set_hardware_acceleration(bool enabled) {
    hardware_accelerated_ = enabled;
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls