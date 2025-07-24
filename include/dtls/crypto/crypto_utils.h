#ifndef DTLS_CRYPTO_UTILS_H
#define DTLS_CRYPTO_UTILS_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/crypto/provider.h>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * Cryptographic utility functions for DTLS v1.3
 * 
 * High-level functions that work with any crypto provider
 * to perform common cryptographic operations.
 */
namespace utils {

// Key derivation utilities
DTLS_API Result<std::vector<uint8_t>> hkdf_extract(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& input_key_material);

DTLS_API Result<std::vector<uint8_t>> hkdf_expand(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& pseudo_random_key,
    const std::vector<uint8_t>& info,
    size_t output_length);

DTLS_API Result<std::vector<uint8_t>> hkdf_expand_label(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length);

// Traffic key derivation
DTLS_API Result<KeySchedule> derive_handshake_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const std::vector<uint8_t>& handshake_secret,
    const std::vector<uint8_t>& client_random,
    const std::vector<uint8_t>& server_random);

DTLS_API Result<KeySchedule> derive_application_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const std::vector<uint8_t>& master_secret,
    const std::vector<uint8_t>& handshake_hash);

DTLS_API Result<KeySchedule> update_traffic_keys(
    CryptoProvider& provider,
    const CipherSpec& cipher_spec,
    const KeySchedule& current_keys);

// Transcript hash utilities
class DTLS_API TranscriptHash {
public:
    explicit TranscriptHash(HashAlgorithm algorithm);
    ~TranscriptHash();
    
    Result<void> update(const std::vector<uint8_t>& data);
    Result<std::vector<uint8_t>> finalize(CryptoProvider& provider);
    Result<std::vector<uint8_t>> current_hash(CryptoProvider& provider) const;
    
    void reset();
    size_t length() const { return data_.size(); }
    HashAlgorithm algorithm() const { return algorithm_; }

private:
    HashAlgorithm algorithm_;
    std::vector<uint8_t> data_;
};

// Record protection utilities
DTLS_API Result<std::vector<uint8_t>> protect_record(
    CryptoProvider& provider,
    const AEADParams& params,
    ContentType content_type,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& additional_data);

DTLS_API Result<std::pair<ContentType, std::vector<uint8_t>>> unprotect_record(
    CryptoProvider& provider,
    const AEADParams& params,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& additional_data);

// Nonce generation for AEAD
DTLS_API std::vector<uint8_t> construct_aead_nonce(
    const std::vector<uint8_t>& write_iv,
    SequenceNumber sequence_number);

DTLS_API std::vector<uint8_t> construct_aead_additional_data(
    const ConnectionID& connection_id,
    Epoch epoch,
    SequenceNumber sequence_number,
    ContentType content_type,
    ProtocolVersion version,
    uint16_t length);

// Key exchange utilities
DTLS_API Result<std::vector<uint8_t>> compute_ecdh_shared_secret(
    CryptoProvider& provider,
    const PrivateKey& private_key,
    const std::vector<uint8_t>& peer_public_key,
    NamedGroup group);

DTLS_API Result<std::vector<uint8_t>> compute_dh_shared_secret(
    CryptoProvider& provider,
    const PrivateKey& private_key,
    const std::vector<uint8_t>& peer_public_key,
    NamedGroup group);

// Signature utilities
DTLS_API Result<std::vector<uint8_t>> create_certificate_verify_data(
    const TranscriptHash& transcript,
    bool is_server);

DTLS_API Result<std::vector<uint8_t>> create_finished_verify_data(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& base_key,
    const std::vector<uint8_t>& transcript_hash);

// PSK utilities
DTLS_API Result<std::vector<uint8_t>> compute_psk_binder(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& psk,
    const std::vector<uint8_t>& transcript_hash);

DTLS_API Result<bool> verify_psk_binder(
    CryptoProvider& provider,
    HashAlgorithm hash,
    const std::vector<uint8_t>& psk,
    const std::vector<uint8_t>& transcript_hash,
    const std::vector<uint8_t>& binder);

// Random utilities
DTLS_API Result<Random> generate_random(CryptoProvider& provider);
DTLS_API Result<std::vector<uint8_t>> generate_session_id(CryptoProvider& provider);
DTLS_API Result<ConnectionID> generate_connection_id(
    CryptoProvider& provider, 
    size_t length = 8);

// Timing-safe comparison
DTLS_API bool constant_time_compare(
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b);

// Secure memory utilities
DTLS_API void secure_zero(std::vector<uint8_t>& data);
DTLS_API void secure_zero(uint8_t* data, size_t length);

// Cipher suite utilities
DTLS_API bool is_aead_cipher_suite(CipherSuite suite);
DTLS_API bool is_psk_cipher_suite(CipherSuite suite);
DTLS_API size_t get_cipher_suite_key_length(CipherSuite suite);
DTLS_API size_t get_cipher_suite_iv_length(CipherSuite suite);
DTLS_API size_t get_cipher_suite_tag_length(CipherSuite suite);
DTLS_API HashAlgorithm get_cipher_suite_hash(CipherSuite suite);

// Named group utilities
DTLS_API bool is_ecdh_group(NamedGroup group);
DTLS_API bool is_ffdh_group(NamedGroup group);
DTLS_API size_t get_named_group_key_length(NamedGroup group);
DTLS_API size_t get_named_group_public_key_length(NamedGroup group);

// Hash algorithm utilities
DTLS_API size_t get_hash_output_length(HashAlgorithm hash);
DTLS_API std::string get_hash_name(HashAlgorithm hash);

// Signature scheme utilities
DTLS_API bool is_rsa_signature(SignatureScheme scheme);
DTLS_API bool is_ecdsa_signature(SignatureScheme scheme);
DTLS_API bool is_eddsa_signature(SignatureScheme scheme);
DTLS_API bool is_pss_signature(SignatureScheme scheme);
DTLS_API HashAlgorithm get_signature_hash_algorithm(SignatureScheme scheme);

// Certificate utilities
DTLS_API Result<std::vector<uint8_t>> extract_certificate_public_key_bytes(
    const std::vector<uint8_t>& certificate_der);

DTLS_API Result<SignatureScheme> detect_certificate_signature_scheme(
    const std::vector<uint8_t>& certificate_der);

// Error handling utilities
DTLS_API std::string crypto_error_to_string(DTLSError error);
DTLS_API bool is_crypto_error(DTLSError error);
DTLS_API AlertDescription crypto_error_to_alert(DTLSError error);

// Performance monitoring
struct CryptoOperationStats {
    std::string operation_name;
    size_t call_count{0};
    std::chrono::nanoseconds total_time{0};
    std::chrono::nanoseconds min_time{std::chrono::nanoseconds::max()};
    std::chrono::nanoseconds max_time{0};
    std::chrono::nanoseconds average_time() const {
        return call_count > 0 ? std::chrono::duration_cast<std::chrono::nanoseconds>(total_time / call_count) : std::chrono::nanoseconds{0};
    }
};

class DTLS_API CryptoStatsCollector {
public:
    static CryptoStatsCollector& instance();
    
    void record_operation(
        const std::string& operation,
        std::chrono::nanoseconds duration);
    
    CryptoOperationStats get_stats(const std::string& operation) const;
    std::vector<CryptoOperationStats> get_all_stats() const;
    void reset_stats();
    void reset_operation_stats(const std::string& operation);
    
    // Configuration
    void enable_collection(bool enabled) { collection_enabled_ = enabled; }
    bool is_collection_enabled() const { return collection_enabled_; }

private:
    CryptoStatsCollector() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CryptoOperationStats> stats_;
    bool collection_enabled_{false};
};

// RAII timer for crypto operations
class DTLS_API CryptoOperationTimer {
public:
    explicit CryptoOperationTimer(const std::string& operation_name);
    ~CryptoOperationTimer();
    
    CryptoOperationTimer(const CryptoOperationTimer&) = delete;
    CryptoOperationTimer& operator=(const CryptoOperationTimer&) = delete;

private:
    std::string operation_name_;
    std::chrono::steady_clock::time_point start_time_;
};

// Convenience macro for timing crypto operations
#define DTLS_CRYPTO_TIMER(op_name) \
    dtls::v13::crypto::utils::CryptoOperationTimer _timer(op_name)

} // namespace utils

// Key derivation constants
namespace constants {

// HKDF labels
constexpr const char* HKDF_LABEL_DERIVED = "derived";
constexpr const char* HKDF_LABEL_EXTERNAL_PSK_BINDER = "ext binder";
constexpr const char* HKDF_LABEL_RESUMPTION_PSK_BINDER = "res binder";
constexpr const char* HKDF_LABEL_CLIENT_EARLY_TRAFFIC = "c e traffic";
constexpr const char* HKDF_LABEL_EARLY_EXPORTER_MASTER = "e exp master";
constexpr const char* HKDF_LABEL_CLIENT_HANDSHAKE_TRAFFIC = "c hs traffic";
constexpr const char* HKDF_LABEL_SERVER_HANDSHAKE_TRAFFIC = "s hs traffic";
constexpr const char* HKDF_LABEL_CLIENT_APPLICATION_TRAFFIC = "c ap traffic";
constexpr const char* HKDF_LABEL_SERVER_APPLICATION_TRAFFIC = "s ap traffic";
constexpr const char* HKDF_LABEL_EXPORTER_MASTER = "exp master";
constexpr const char* HKDF_LABEL_RESUMPTION_MASTER = "res master";

// Key and IV labels
constexpr const char* HKDF_LABEL_KEY = "key";
constexpr const char* HKDF_LABEL_IV = "iv";
constexpr const char* HKDF_LABEL_SN = "sn";

// Finished labels
constexpr const char* HKDF_LABEL_CLIENT_FINISHED = "client finished";
constexpr const char* HKDF_LABEL_SERVER_FINISHED = "server finished";

// Certificate verify context
constexpr const char* CERT_VERIFY_CONTEXT_CLIENT = 
    "TLS 1.3, client CertificateVerify";
constexpr const char* CERT_VERIFY_CONTEXT_SERVER = 
    "TLS 1.3, server CertificateVerify";

// Standard hash empty values
extern DTLS_API const std::vector<uint8_t> SHA256_EMPTY_HASH;
extern DTLS_API const std::vector<uint8_t> SHA384_EMPTY_HASH;
extern DTLS_API const std::vector<uint8_t> SHA512_EMPTY_HASH;

} // namespace constants
} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_UTILS_H