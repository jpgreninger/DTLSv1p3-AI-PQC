#ifndef DTLS_CRYPTO_PROVIDER_H
#define DTLS_CRYPTO_PROVIDER_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <memory>
#include <vector>
#include <string>
#include <functional>

namespace dtls {
namespace v13 {
namespace crypto {

// Forward declarations
struct CipherSpec;
struct KeySchedule;
struct CertificateChain;
struct PrivateKey;
struct PublicKey;

// Crypto provider capabilities
struct ProviderCapabilities {
    std::vector<CipherSuite> supported_cipher_suites;
    std::vector<NamedGroup> supported_groups;
    std::vector<SignatureScheme> supported_signatures;
    std::vector<HashAlgorithm> supported_hashes;
    bool hardware_acceleration{false};
    bool fips_mode{false};
    std::string provider_name;
    std::string provider_version;
};

// Key derivation parameters
struct KeyDerivationParams {
    std::vector<uint8_t> secret;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> info;
    size_t output_length{0};
    HashAlgorithm hash_algorithm{HashAlgorithm::SHA256};
};

// AEAD encryption/decryption parameters
struct AEADParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> additional_data;
    AEADCipher cipher{AEADCipher::AES_128_GCM};
};

// AEAD encryption parameters for new interface
struct AEADEncryptionParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> additional_data;
    std::vector<uint8_t> plaintext;
    AEADCipher cipher{AEADCipher::AES_128_GCM};
};

// AEAD decryption parameters for new interface
struct AEADDecryptionParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> additional_data;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    AEADCipher cipher{AEADCipher::AES_128_GCM};
};

// AEAD encryption output
struct AEADEncryptionOutput {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

// Digital signature parameters
struct SignatureParams {
    std::vector<uint8_t> data;
    SignatureScheme scheme{SignatureScheme::RSA_PKCS1_SHA256};
    const PrivateKey* private_key{nullptr};
    const PublicKey* public_key{nullptr};
};

// Key exchange parameters
struct KeyExchangeParams {
    NamedGroup group{NamedGroup::SECP256R1};
    std::vector<uint8_t> peer_public_key;
    const PrivateKey* private_key{nullptr};
};

// Random number generation parameters
struct RandomParams {
    size_t length{0};
    bool cryptographically_secure{true};
    std::vector<uint8_t> additional_entropy;
};

// Certificate validation parameters
struct CertValidationParams {
    const CertificateChain* chain{nullptr};
    std::vector<uint8_t> root_ca_store;
    std::string hostname;
    bool check_revocation{true};
    std::chrono::system_clock::time_point validation_time;
};

// Hash computation parameters
struct HashParams {
    std::vector<uint8_t> data;
    HashAlgorithm algorithm{HashAlgorithm::SHA256};
};

// HMAC computation parameters
struct HMACParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> data;
    HashAlgorithm algorithm{HashAlgorithm::SHA256};
};

// MAC validation parameters for timing-attack resistant verification
struct MACValidationParams {
    std::vector<uint8_t> key;                    // HMAC key
    std::vector<uint8_t> data;                   // Data to authenticate
    std::vector<uint8_t> expected_mac;           // Expected MAC value
    HashAlgorithm algorithm{HashAlgorithm::SHA256}; // Hash algorithm
    bool constant_time_required{true};          // Require constant-time operation
    size_t max_data_length{0};                  // Maximum expected data length (0 = no limit)
    
    // DTLS v1.3 specific validation context
    struct DTLSContext {
        ContentType content_type{ContentType::APPLICATION_DATA};
        ProtocolVersion protocol_version{DTLS_V13};
        Epoch epoch{0};
        SequenceNumber sequence_number{0};
        bool is_inner_plaintext{false};         // For DTLSInnerPlaintext validation
    } dtls_context;
};

// Record MAC validation parameters for DTLS v1.3
struct RecordMACParams {
    std::vector<uint8_t> mac_key;               // Record MAC key
    std::vector<uint8_t> sequence_number_key;   // Sequence number encryption key
    std::vector<uint8_t> record_header;         // DTLS record header
    std::vector<uint8_t> plaintext;             // Record plaintext
    std::vector<uint8_t> expected_mac;          // Expected MAC from record
    HashAlgorithm mac_algorithm{HashAlgorithm::SHA256};
    ContentType content_type{ContentType::APPLICATION_DATA};
    Epoch epoch{0};
    SequenceNumber sequence_number{0};
};

// DTLS v1.3 Certificate Verify parameters (RFC 9147 Section 4.2.3)
struct DTLSCertificateVerifyParams {
    std::vector<uint8_t> transcript_hash;        // The handshake transcript hash
    SignatureScheme scheme{SignatureScheme::RSA_PKCS1_SHA256};
    const PublicKey* public_key{nullptr};
    bool is_server_context{true};                // true for server cert, false for client cert
    
    // Optional certificate information for enhanced validation
    std::vector<uint8_t> certificate_der;       // DER-encoded certificate for compatibility checking
};

/**
 * Abstract base class for cryptographic providers
 * 
 * This interface defines all cryptographic operations required for DTLS v1.3.
 * Implementations provide backend-specific crypto functionality (OpenSSL, Botan, etc.)
 */
class DTLS_API CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    // Provider information
    virtual std::string name() const = 0;
    virtual std::string version() const = 0;
    virtual ProviderCapabilities capabilities() const = 0;
    virtual bool is_available() const = 0;
    virtual Result<void> initialize() = 0;
    virtual void cleanup() = 0;

    // Random number generation
    virtual Result<std::vector<uint8_t>> generate_random(const RandomParams& params) = 0;
    
    // Key derivation
    virtual Result<std::vector<uint8_t>> derive_key_hkdf(const KeyDerivationParams& params) = 0;
    virtual Result<std::vector<uint8_t>> derive_key_pbkdf2(const KeyDerivationParams& params) = 0;
    
    // AEAD operations
    virtual Result<std::vector<uint8_t>> aead_encrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& plaintext) = 0;
    
    virtual Result<std::vector<uint8_t>> aead_decrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& ciphertext) = 0;
    
    // New AEAD interface with separate ciphertext and tag
    virtual Result<AEADEncryptionOutput> encrypt_aead(const AEADEncryptionParams& params) = 0;
    virtual Result<std::vector<uint8_t>> decrypt_aead(const AEADDecryptionParams& params) = 0;
    
    // Hash functions
    virtual Result<std::vector<uint8_t>> compute_hash(const HashParams& params) = 0;
    virtual Result<std::vector<uint8_t>> compute_hmac(const HMACParams& params) = 0;
    
    // MAC validation with timing-attack resistance (RFC 9147 Section 5.2)
    virtual Result<bool> verify_hmac(const MACValidationParams& params) = 0;
    
    // DTLS v1.3 record MAC validation (RFC 9147 Section 4.2.1)
    virtual Result<bool> validate_record_mac(const RecordMACParams& params) = 0;
    
    // Legacy MAC verification for backward compatibility
    virtual Result<bool> verify_hmac_legacy(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) = 0;
    
    // Digital signatures
    virtual Result<std::vector<uint8_t>> sign_data(const SignatureParams& params) = 0;
    virtual Result<bool> verify_signature(
        const SignatureParams& params,
        const std::vector<uint8_t>& signature) = 0;
    
    // DTLS v1.3 Certificate Verify (RFC 9147 Section 4.2.3)
    virtual Result<bool> verify_dtls_certificate_signature(
        const DTLSCertificateVerifyParams& params,
        const std::vector<uint8_t>& signature) = 0;
    
    // Key exchange
    virtual Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_key_pair(NamedGroup group) = 0;
    
    virtual Result<std::vector<uint8_t>> perform_key_exchange(const KeyExchangeParams& params) = 0;
    
    // Certificate operations
    virtual Result<bool> validate_certificate_chain(const CertValidationParams& params) = 0;
    virtual Result<std::unique_ptr<PublicKey>> extract_public_key(
        const std::vector<uint8_t>& certificate) = 0;
    
    // Key import/export
    virtual Result<std::unique_ptr<PrivateKey>> import_private_key(
        const std::vector<uint8_t>& key_data,
        const std::string& format = "PEM") = 0;
    
    virtual Result<std::unique_ptr<PublicKey>> import_public_key(
        const std::vector<uint8_t>& key_data,
        const std::string& format = "PEM") = 0;
    
    virtual Result<std::vector<uint8_t>> export_private_key(
        const PrivateKey& key,
        const std::string& format = "PEM") = 0;
    
    virtual Result<std::vector<uint8_t>> export_public_key(
        const PublicKey& key,
        const std::string& format = "PEM") = 0;

    // Utility functions
    virtual bool supports_cipher_suite(CipherSuite suite) const = 0;
    virtual bool supports_named_group(NamedGroup group) const = 0;
    virtual bool supports_signature_scheme(SignatureScheme scheme) const = 0;
    virtual bool supports_hash_algorithm(HashAlgorithm hash) const = 0;
    
    // Performance and security features
    virtual bool has_hardware_acceleration() const = 0;
    virtual bool is_fips_compliant() const = 0;
    virtual SecurityLevel security_level() const = 0;
    virtual Result<void> set_security_level(SecurityLevel level) = 0;

protected:
    CryptoProvider() = default;
};

// Key interface for cryptographic keys
class DTLS_API CryptoKey {
public:
    virtual ~CryptoKey() = default;
    virtual std::string algorithm() const = 0;
    virtual size_t key_size() const = 0;
    virtual NamedGroup group() const = 0;
    virtual std::vector<uint8_t> fingerprint() const = 0;
    virtual bool is_private() const = 0;
    
protected:
    CryptoKey() = default;
};

// Private key interface
class DTLS_API PrivateKey : public CryptoKey {
public:
    ~PrivateKey() override = default;
    bool is_private() const override { return true; }
    virtual Result<std::unique_ptr<PublicKey>> derive_public_key() const = 0;
    
protected:
    PrivateKey() = default;
};

// Public key interface
class DTLS_API PublicKey : public CryptoKey {
public:
    ~PublicKey() override = default;
    bool is_private() const override { return false; }
    virtual bool equals(const PublicKey& other) const = 0;
    
protected:
    PublicKey() = default;
};

// Certificate chain representation
class DTLS_API CertificateChain {
public:
    virtual ~CertificateChain() = default;
    virtual size_t certificate_count() const = 0;
    virtual std::vector<uint8_t> certificate_at(size_t index) const = 0;
    virtual std::unique_ptr<PublicKey> leaf_public_key() const = 0;
    virtual std::string subject_name() const = 0;
    virtual std::string issuer_name() const = 0;
    virtual std::chrono::system_clock::time_point not_before() const = 0;
    virtual std::chrono::system_clock::time_point not_after() const = 0;
    virtual bool is_valid() const = 0;
    
protected:
    CertificateChain() = default;
};

// Cipher specification for a particular cipher suite
struct CipherSpec {
    CipherSuite suite{CipherSuite::TLS_AES_128_GCM_SHA256};
    AEADCipher aead_cipher{AEADCipher::AES_128_GCM};
    HashAlgorithm hash_algorithm{HashAlgorithm::SHA256};
    size_t key_length{16};
    size_t iv_length{12};
    size_t tag_length{16};
    size_t hash_length{32};
    
    static Result<CipherSpec> from_cipher_suite(CipherSuite suite);
};

// Key schedule for managing traffic keys
struct KeySchedule {
    std::vector<uint8_t> client_write_key;
    std::vector<uint8_t> server_write_key;
    std::vector<uint8_t> client_write_iv;
    std::vector<uint8_t> server_write_iv;
    std::vector<uint8_t> client_sequence_number_key;
    std::vector<uint8_t> server_sequence_number_key;
    Epoch epoch{0};
    
    void clear() {
        client_write_key.clear();
        server_write_key.clear();
        client_write_iv.clear();
        server_write_iv.clear();
        client_sequence_number_key.clear();
        server_sequence_number_key.clear();
        epoch = 0;
    }
};

// Provider selection criteria
struct ProviderSelection {
    std::string preferred_provider;
    bool require_hardware_acceleration{false};
    bool require_fips_compliance{false};
    SecurityLevel minimum_security_level{SecurityLevel::MEDIUM};
    std::vector<CipherSuite> required_cipher_suites;
    std::vector<NamedGroup> required_groups;
    std::vector<SignatureScheme> required_signatures;
};

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_PROVIDER_H