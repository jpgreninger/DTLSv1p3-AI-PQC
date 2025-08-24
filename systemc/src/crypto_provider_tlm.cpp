#include "crypto_provider_tlm.h"
#include <dtls/crypto/crypto_utils.h>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// CryptoProviderTLM Implementation
CryptoProviderTLM::CryptoProviderTLM(sc_module_name name, bool hardware_accelerated)
    : dtls_module_base(name)
    , target_socket("target_socket")
    , hardware_accelerated_(hardware_accelerated)
    , busy_(false)
{
    // Register TLM transport interface
    target_socket.register_b_transport(this, &CryptoProviderTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &CryptoProviderTLM::nb_transport_fw);
    target_socket.register_get_direct_mem_ptr(this, &CryptoProviderTLM::get_direct_mem_ptr);
    target_socket.register_transport_dbg(this, &CryptoProviderTLM::transport_dbg);
    
    // Start processing thread
    SC_THREAD(crypto_processing_thread);
}

void CryptoProviderTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    // Extract crypto extension
    crypto_extension* ext = trans.get_extension<crypto_extension>();
    if (!ext) {
        trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Set busy state
    busy_.store(true);
    
    // Perform the crypto operation
    perform_crypto_operation(trans, *ext);
    
    // Calculate processing time
    sc_time processing_time = utils::get_crypto_timing(ext->operation, hardware_accelerated_);
    delay += processing_time;
    ext->processing_time = processing_time;
    
    // Update statistics
    update_statistics(*ext);
    
    // Clear busy state
    busy_.store(false);
    
    // Set successful response
    trans.set_response_status(TLM_OK_RESPONSE);
}

tlm::tlm_sync_enum CryptoProviderTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                     tlm::tlm_phase& phase, 
                                                     sc_time& delay) {
    // Simple implementation - convert to blocking
    b_transport(trans, delay);
    return tlm::TLM_COMPLETED;
}

bool CryptoProviderTLM::get_direct_mem_ptr(tlm::tlm_generic_payload& trans, tlm::tlm_dmi& dmi_data) {
    // DMI not supported for crypto operations
    return false;
}

unsigned int CryptoProviderTLM::transport_dbg(tlm::tlm_generic_payload& trans) {
    // Debug transport not implemented
    return 0;
}

void CryptoProviderTLM::crypto_processing_thread() {
    while (true) {
        wait(operation_completed);
        // Processing logic can be extended here for queued operations
    }
}

void CryptoProviderTLM::perform_crypto_operation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    switch (ext.operation) {
        case crypto_extension::ENCRYPT:
            perform_encryption(trans, ext);
            break;
        case crypto_extension::DECRYPT:
            perform_decryption(trans, ext);
            break;
        case crypto_extension::SIGN:
            perform_signing(trans, ext);
            break;
        case crypto_extension::VERIFY:
            perform_verification(trans, ext);
            break;
        case crypto_extension::KEY_DERIVE:
            perform_key_derivation(trans, ext);
            break;
        case crypto_extension::RANDOM_GENERATE:
            perform_random_generation(trans, ext);
            break;
        case crypto_extension::HASH_COMPUTE:
            perform_hash_computation(trans, ext);
            break;
        case crypto_extension::PQC_SIGN:
            perform_pqc_signing(trans, ext);
            break;
        case crypto_extension::PQC_VERIFY:
            perform_pqc_verification(trans, ext);
            break;
        case crypto_extension::PQC_KEYGEN:
            perform_pqc_key_generation(trans, ext);
            break;
        case crypto_extension::HYBRID_PQC_SIGN:
            perform_hybrid_pqc_signing(trans, ext);
            break;
        case crypto_extension::HYBRID_PQC_VERIFY:
            perform_hybrid_pqc_verification(trans, ext);
            break;
        case crypto_extension::HYBRID_PQC_KEYGEN:
            perform_hybrid_pqc_key_generation(trans, ext);
            break;
        default:
            // Unknown operation
            break;
    }
}

void CryptoProviderTLM::perform_encryption(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate encryption operation
    // In a real implementation, this would call actual crypto libraries
    size_t data_length = trans.get_data_length();
    ext.operations_count = 1;
    
    // Simulate processing time based on data size
    ext.processing_time = utils::calculate_processing_time(
        data_length, 
        g_dtls_timing.aes_encryption_time,
        g_dtls_timing.memory_copy_time
    );
}

void CryptoProviderTLM::perform_decryption(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate decryption operation
    size_t data_length = trans.get_data_length();
    ext.operations_count = 1;
    
    ext.processing_time = utils::calculate_processing_time(
        data_length, 
        g_dtls_timing.aes_decryption_time,
        g_dtls_timing.memory_copy_time
    );
}

void CryptoProviderTLM::perform_signing(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate signing operation
    ext.operations_count = 1;
    ext.processing_time = g_dtls_timing.ecdsa_sign_time;
}

void CryptoProviderTLM::perform_verification(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate verification operation
    ext.operations_count = 1;
    ext.processing_time = g_dtls_timing.ecdsa_verify_time;
}

void CryptoProviderTLM::perform_key_derivation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate key derivation operation
    ext.operations_count = 1;
    ext.processing_time = g_dtls_timing.hkdf_derive_time;
}

void CryptoProviderTLM::perform_random_generation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate random number generation
    size_t data_length = trans.get_data_length();
    ext.operations_count = 1;
    
    ext.processing_time = utils::calculate_processing_time(
        data_length, 
        g_dtls_timing.random_generation_time,
        sc_time(1, SC_NS)
    );
}

void CryptoProviderTLM::perform_hash_computation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate hash computation
    size_t data_length = trans.get_data_length();
    ext.operations_count = 1;
    
    ext.processing_time = utils::calculate_processing_time(
        data_length, 
        g_dtls_timing.hash_computation_time,
        sc_time(1, SC_NS)
    );
}

// Post-Quantum Cryptographic operations
void CryptoProviderTLM::perform_pqc_signing(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate PQC signature generation with algorithm-specific timing
    size_t message_length = trans.get_data_length();
    ext.operations_count = 1;
    
    // PQC signing typically takes longer than classical algorithms
    // ML-DSA (Dilithium) has faster signing than SLH-DSA (SPHINCS+)
    sc_time base_time = sc_time(10, SC_US);  // Base 10µs for PQC signing
    
    // Adjust timing based on signature scheme
    double multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::ML_DSA_87) {
        // ML-DSA has faster signing
        multiplier = 0.8;
    } else if (ext.signature_scheme >= SignatureScheme::SLH_DSA_SHA2_128S &&
               ext.signature_scheme <= SignatureScheme::SLH_DSA_SHAKE_256F) {
        // SLH-DSA has slower signing but faster verification
        multiplier = 2.5;
    }
    
    ext.processing_time = utils::calculate_processing_time(
        message_length,
        base_time * multiplier,
        sc_time(100, SC_NS)
    );
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.6; // 40% speedup with hardware acceleration
    }
}

void CryptoProviderTLM::perform_pqc_verification(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate PQC signature verification
    size_t message_length = trans.get_data_length();
    ext.operations_count = 1;
    
    // PQC verification timing varies by algorithm
    sc_time base_time = sc_time(5, SC_US);  // Base 5µs for PQC verification
    
    double multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::ML_DSA_87) {
        // ML-DSA has moderate verification time
        multiplier = 1.2;
    } else if (ext.signature_scheme >= SignatureScheme::SLH_DSA_SHA2_128S &&
               ext.signature_scheme <= SignatureScheme::SLH_DSA_SHAKE_256F) {
        // SLH-DSA has fast verification
        multiplier = 0.3;
    }
    
    ext.processing_time = utils::calculate_processing_time(
        message_length,
        base_time * multiplier,
        sc_time(50, SC_NS)
    );
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.5; // 50% speedup with hardware acceleration
    }
}

void CryptoProviderTLM::perform_pqc_key_generation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate PQC key generation
    ext.operations_count = 1;
    
    // PQC key generation typically takes significantly longer than classical
    sc_time base_time = sc_time(50, SC_US);  // Base 50µs for PQC keygen
    
    double multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::ML_DSA_87) {
        // ML-DSA key generation timing based on parameter set
        switch (ext.signature_scheme) {
            case SignatureScheme::ML_DSA_44:
                multiplier = 0.8; // Fastest
                break;
            case SignatureScheme::ML_DSA_65:
                multiplier = 1.2; // Medium
                break;
            case SignatureScheme::ML_DSA_87:
                multiplier = 1.8; // Slowest
                break;
            default:
                break;
        }
    } else if (ext.signature_scheme >= SignatureScheme::SLH_DSA_SHA2_128S &&
               ext.signature_scheme <= SignatureScheme::SLH_DSA_SHAKE_256F) {
        // SLH-DSA key generation is typically faster
        multiplier = 0.4;
    }
    
    ext.processing_time = base_time * multiplier;
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.7; // 30% speedup with hardware RNG
    }
}

// Hybrid Post-Quantum + Classical operations
void CryptoProviderTLM::perform_hybrid_pqc_signing(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate hybrid signature generation (both classical and PQC components)
    size_t message_length = trans.get_data_length();
    ext.operations_count = 2; // Both classical and PQC signatures
    
    // Hybrid operations require both classical and PQC computations
    sc_time classical_time = sc_time(2, SC_US);  // Classical signature time
    sc_time pqc_time = sc_time(15, SC_US);       // PQC signature time
    
    // Adjust PQC time based on scheme
    double pqc_multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::RSA3072_ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::P521_ML_DSA_87) {
        // Hybrid with ML-DSA
        pqc_multiplier = 0.8;
    }
    
    ext.processing_time = classical_time + (pqc_time * pqc_multiplier) + 
                         utils::calculate_processing_time(message_length, sc_time(1, SC_US), sc_time(10, SC_NS));
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.65; // Combined acceleration benefits
    }
}

void CryptoProviderTLM::perform_hybrid_pqc_verification(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate hybrid signature verification (both components must verify)
    size_t message_length = trans.get_data_length();
    ext.operations_count = 2;
    
    sc_time classical_time = sc_time(1, SC_US);  // Classical verification
    sc_time pqc_time = sc_time(8, SC_US);        // PQC verification
    
    double pqc_multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::RSA3072_ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::P521_ML_DSA_87) {
        // Hybrid with ML-DSA
        pqc_multiplier = 1.2;
    }
    
    ext.processing_time = classical_time + (pqc_time * pqc_multiplier) + 
                         utils::calculate_processing_time(message_length, sc_time(500, SC_NS), sc_time(5, SC_NS));
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.55; // Better acceleration due to parallel processing
    }
}

void CryptoProviderTLM::perform_hybrid_pqc_key_generation(tlm::tlm_generic_payload& trans, crypto_extension& ext) {
    // Simulate hybrid key generation (generate both key pairs)
    ext.operations_count = 2;
    
    sc_time classical_time = sc_time(5, SC_US);   // Classical key generation
    sc_time pqc_time = sc_time(60, SC_US);        // PQC key generation
    
    double pqc_multiplier = 1.0;
    if (ext.signature_scheme >= SignatureScheme::RSA3072_ML_DSA_44 && 
        ext.signature_scheme <= SignatureScheme::P521_ML_DSA_87) {
        // Hybrid with ML-DSA - adjust based on parameter set
        if (ext.signature_scheme <= SignatureScheme::P521_ML_DSA_44) {
            pqc_multiplier = 0.8;
        } else if (ext.signature_scheme <= SignatureScheme::P521_ML_DSA_65) {
            pqc_multiplier = 1.2;
        } else {
            pqc_multiplier = 1.8;
        }
    }
    
    ext.processing_time = classical_time + (pqc_time * pqc_multiplier);
    
    if (hardware_accelerated_) {
        ext.processing_time *= 0.6; // Hardware acceleration for both components
    }
}

void CryptoProviderTLM::set_hardware_acceleration(bool enabled) {
    hardware_accelerated_ = enabled;
    stats_.hardware_accelerated = enabled;
}

bool CryptoProviderTLM::is_busy() const {
    return busy_.load();
}

size_t CryptoProviderTLM::get_queue_size() const {
    return 0; // No queue in this simple implementation
}

CryptoProviderTLM::CryptoStats CryptoProviderTLM::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void CryptoProviderTLM::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = CryptoStats{};
    stats_.hardware_accelerated = hardware_accelerated_;
}

void CryptoProviderTLM::update_statistics(const crypto_extension& ext) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_operations++;
    stats_.successful_operations++;
    
    switch (ext.operation) {
        case crypto_extension::ENCRYPT:
        case crypto_extension::DECRYPT:
            stats_.encryption_operations++;
            break;
        case crypto_extension::SIGN:
        case crypto_extension::VERIFY:
        case crypto_extension::PQC_SIGN:
        case crypto_extension::PQC_VERIFY:
        case crypto_extension::HYBRID_PQC_SIGN:
        case crypto_extension::HYBRID_PQC_VERIFY:
            stats_.signature_operations++;
            break;
        case crypto_extension::KEY_DERIVE:
        case crypto_extension::PQC_KEYGEN:
        case crypto_extension::HYBRID_PQC_KEYGEN:
            stats_.key_derivation_operations++;
            break;
        case crypto_extension::RANDOM_GENERATE:
            stats_.random_generation_operations++;
            break;
        case crypto_extension::HASH_COMPUTE:
            stats_.hash_operations++;
            break;
    }
    
    stats_.total_processing_time += ext.processing_time;
    
    if (stats_.total_operations > 0) {
        stats_.average_processing_time = sc_time(
            stats_.total_processing_time.to_double() / stats_.total_operations, 
            SC_NS
        );
    }
    
    if (stats_.min_processing_time == sc_time(0, SC_NS) || 
        ext.processing_time < stats_.min_processing_time) {
        stats_.min_processing_time = ext.processing_time;
    }
    
    if (ext.processing_time > stats_.max_processing_time) {
        stats_.max_processing_time = ext.processing_time;
    }
}

// HardwareAcceleratedCryptoTLM Implementation
HardwareAcceleratedCryptoTLM::HardwareAcceleratedCryptoTLM(sc_module_name name)
    : dtls_module_base(name)
    , crypto_provider("crypto_provider", true)
    , hw_accel_enable("hw_accel_enable")
    , hw_accel_ready("hw_accel_ready")
    , hw_error("hw_error")
    , aes_operations_per_sec("aes_operations_per_sec")
    , ecc_operations_per_sec("ecc_operations_per_sec")
    , power_consumption_mw("power_consumption_mw")
    , hw_ready_(true)
    , power_mode_(1)
{
    SC_THREAD(hardware_monitor_process);
    SC_THREAD(power_management_process);
    
    // Initialize hardware status
    hw_accel_ready.write(true);
    hw_error.write(false);
}

void HardwareAcceleratedCryptoTLM::hardware_monitor_process() {
    while (true) {
        wait(1, SC_MS); // Monitor every millisecond
        
        // Update hardware status
        hw_accel_ready.write(hw_ready_);
        
        // Update performance counters (simplified)
        aes_operations_per_sec.write(10000); // 10K AES ops/sec
        ecc_operations_per_sec.write(1000);  // 1K ECC ops/sec
    }
}

void HardwareAcceleratedCryptoTLM::power_management_process() {
    while (true) {
        wait(10, SC_MS); // Update power every 10ms
        
        double power = 100.0; // Base power in mW
        switch (power_mode_) {
            case 0: power *= 0.5; break; // Low power
            case 1: power *= 1.0; break; // Normal
            case 2: power *= 2.0; break; // High performance
        }
        
        power_consumption_mw.write(power);
    }
}

void HardwareAcceleratedCryptoTLM::enable_hardware_acceleration() {
    hw_ready_ = true;
    crypto_provider.set_hardware_acceleration(true);
}

void HardwareAcceleratedCryptoTLM::disable_hardware_acceleration() {
    hw_ready_ = false;
    crypto_provider.set_hardware_acceleration(false);
}

bool HardwareAcceleratedCryptoTLM::is_hardware_ready() const {
    return hw_ready_;
}

void HardwareAcceleratedCryptoTLM::set_power_mode(int mode) {
    if (mode >= 0 && mode <= 2) {
        power_mode_ = mode;
    }
}

double HardwareAcceleratedCryptoTLM::get_power_consumption() const {
    return power_consumption_mw.read();
}

// CryptoManagerTLM Implementation
CryptoManagerTLM::CryptoManagerTLM(sc_module_name name, size_t num_providers)
    : dtls_module_base(name)
    , initiator_socket("initiator_socket")
    , target_socket("target_socket")
    , load_balancing_algorithm_("round_robin")
    , round_robin_counter_(0)
{
    target_socket.register_b_transport(this, &CryptoManagerTLM::b_transport);
    target_socket.register_nb_transport_fw(this, &CryptoManagerTLM::nb_transport_fw);
    
    // Reserve space for providers
    providers_.reserve(num_providers);
}

void CryptoManagerTLM::b_transport(tlm::tlm_generic_payload& trans, sc_time& delay) {
    crypto_extension* ext = trans.get_extension<crypto_extension>();
    if (!ext) {
        trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Select appropriate provider
    size_t provider_id = select_provider(*ext);
    if (provider_id >= providers_.size() || !providers_[provider_id].available) {
        trans.set_response_status(TLM_GENERIC_ERROR_RESPONSE);
        return;
    }
    
    // Forward to selected provider
    initiator_socket->b_transport(trans, delay);
    
    // Update provider statistics
    providers_[provider_id].operation_count++;
    providers_[provider_id].total_processing_time += delay;
}

tlm::tlm_sync_enum CryptoManagerTLM::nb_transport_fw(tlm::tlm_generic_payload& trans, 
                                                    tlm::tlm_phase& phase, 
                                                    sc_time& delay) {
    // Convert to blocking for simplicity
    b_transport(trans, delay);
    return tlm::TLM_COMPLETED;
}

void CryptoManagerTLM::add_crypto_provider(CryptoProviderTLM* provider) {
    ProviderInfo info;
    info.provider = provider;
    info.priority = 0;
    info.operation_count = 0;
    info.total_processing_time = sc_time(0, SC_NS);
    info.available = true;
    
    providers_.push_back(info);
}

void CryptoManagerTLM::remove_crypto_provider(size_t provider_id) {
    if (provider_id < providers_.size()) {
        providers_[provider_id].available = false;
    }
}

void CryptoManagerTLM::set_provider_priority(size_t provider_id, int priority) {
    if (provider_id < providers_.size()) {
        providers_[provider_id].priority = priority;
    }
}

void CryptoManagerTLM::set_load_balancing_algorithm(const std::string& algorithm) {
    load_balancing_algorithm_ = algorithm;
}

size_t CryptoManagerTLM::select_provider(const crypto_extension& ext) {
    if (load_balancing_algorithm_ == "round_robin") {
        return select_round_robin();
    } else if (load_balancing_algorithm_ == "least_loaded") {
        return select_least_loaded();
    } else if (load_balancing_algorithm_ == "fastest") {
        return select_fastest();
    }
    return 0; // Default to first provider
}

size_t CryptoManagerTLM::select_round_robin() {
    size_t available_count = 0;
    for (const auto& provider : providers_) {
        if (provider.available) available_count++;
    }
    
    if (available_count == 0) return 0;
    
    size_t counter = round_robin_counter_.fetch_add(1) % available_count;
    size_t current = 0;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        if (providers_[i].available) {
            if (current == counter) {
                return i;
            }
            current++;
        }
    }
    
    return 0;
}

size_t CryptoManagerTLM::select_least_loaded() {
    size_t best_provider = 0;
    uint64_t min_operations = UINT64_MAX;
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        if (providers_[i].available && providers_[i].operation_count < min_operations) {
            min_operations = providers_[i].operation_count;
            best_provider = i;
        }
    }
    
    return best_provider;
}

size_t CryptoManagerTLM::select_fastest() {
    size_t best_provider = 0;
    double best_avg_time = 1e9; // Very large initial value
    
    for (size_t i = 0; i < providers_.size(); ++i) {
        if (providers_[i].available && providers_[i].operation_count > 0) {
            double avg_time = providers_[i].total_processing_time.to_double() / providers_[i].operation_count;
            if (avg_time < best_avg_time) {
                best_avg_time = avg_time;
                best_provider = i;
            }
        }
    }
    
    return best_provider;
}

} // namespace systemc_tlm
} // namespace v13
} // namespace dtls