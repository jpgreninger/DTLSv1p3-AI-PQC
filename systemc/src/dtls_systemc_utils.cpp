#include <dtls_systemc_types.h>
#include <atomic>

namespace dtls {
namespace v13 {
namespace systemc_tlm {

// Global timing configuration instance
dtls_timing_config g_dtls_timing;

namespace utils {

// Generate unique transaction ID
uint64_t generate_transaction_id() {
    static std::atomic<uint64_t> counter{0};
    return ++counter;
}

// Create timing delays based on hardware acceleration availability
sc_time get_crypto_timing(crypto_extension::operation_type op, bool hardware_accelerated) {
    sc_time base_time;
    double acceleration_factor = hardware_accelerated ? 0.1 : 1.0;
    
    switch (op) {
        case crypto_extension::ENCRYPT:
        case crypto_extension::DECRYPT:
            base_time = g_dtls_timing.aes_encryption_time;
            break;
        case crypto_extension::SIGN:
            base_time = g_dtls_timing.ecdsa_sign_time;
            break;
        case crypto_extension::VERIFY:
            base_time = g_dtls_timing.ecdsa_verify_time;
            break;
        case crypto_extension::KEY_DERIVE:
            base_time = g_dtls_timing.hkdf_derive_time;
            break;
        case crypto_extension::RANDOM_GENERATE:
            base_time = g_dtls_timing.random_generation_time;
            break;
        case crypto_extension::HASH_COMPUTE:
            base_time = g_dtls_timing.hash_computation_time;
            break;
        case crypto_extension::PQC_SIGN:
            base_time = sc_time(10, SC_US);  // PQC signing typically takes microseconds
            break;
        case crypto_extension::PQC_VERIFY:
            base_time = sc_time(5, SC_US);   // PQC verification timing
            break;
        case crypto_extension::PQC_KEYGEN:
            base_time = sc_time(50, SC_US);  // PQC key generation is slower
            break;
        case crypto_extension::HYBRID_PQC_SIGN:
            base_time = sc_time(17, SC_US);  // Classical + PQC signing time
            break;
        case crypto_extension::HYBRID_PQC_VERIFY:
            base_time = sc_time(9, SC_US);   // Classical + PQC verification time
            break;
        case crypto_extension::HYBRID_PQC_KEYGEN:
            base_time = sc_time(65, SC_US);  // Classical + PQC key generation time
            break;
        default:
            base_time = sc_time(100, SC_NS);
            break;
    }
    
    return sc_time(base_time.to_double() * acceleration_factor, SC_NS);
}

// Helper functions for setting up TLM transactions
void setup_crypto_transaction(tlm_generic_payload& trans, crypto_extension::operation_type op) {
    crypto_extension* ext = new crypto_extension(op);
    trans.set_extension(ext);
    trans.set_command(TLM_WRITE_COMMAND);
    trans.set_response_status(TLM_INCOMPLETE_RESPONSE);
}

void setup_record_transaction(tlm_generic_payload& trans, record_extension::operation_type op) {
    record_extension* ext = new record_extension(op);
    trans.set_extension(ext);
    trans.set_command(TLM_WRITE_COMMAND);
    trans.set_response_status(TLM_INCOMPLETE_RESPONSE);
}

void setup_message_transaction(tlm_generic_payload& trans, message_extension::operation_type op) {
    message_extension* ext = new message_extension(op);
    trans.set_extension(ext);
    trans.set_command(TLM_WRITE_COMMAND);
    trans.set_response_status(TLM_INCOMPLETE_RESPONSE);
}

void setup_transport_transaction(tlm_generic_payload& trans, transport_extension::operation_type op) {
    transport_extension* ext = new transport_extension(op);
    trans.set_extension(ext);
    trans.set_command(TLM_WRITE_COMMAND);
    trans.set_response_status(TLM_INCOMPLETE_RESPONSE);
}

} // namespace utils
} // namespace systemc_tlm
} // namespace v13
} // namespace dtls