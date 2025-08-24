/**
 * @file provider.h
 * @brief DTLS v1.3 Cryptographic Provider Interface
 * 
 * This file defines the abstract cryptographic provider interface for DTLS v1.3,
 * enabling multiple cryptographic backend implementations (OpenSSL, Botan, etc.)
 * with a unified API. Supports advanced features including quantum-resistant
 * ML-KEM cryptography, hardware acceleration, and high-performance operations.
 * 
 * @author DTLS v1.3 Implementation Team
 * @version 1.0.0
 * @date 2025-08-15
 * 
 * @rfc9147 Implements cryptographic requirements from RFC 9147 Section 4.1
 * @security Provides quantum-resistant ML-KEM and traditional ECDHE key exchange
 * @performance Optimized for high-throughput with hardware acceleration support
 * @thread_safety All provider implementations must be thread-safe
 */

#ifndef DTLS_CRYPTO_PROVIDER_H
#define DTLS_CRYPTO_PROVIDER_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <future>
#include <unordered_map>

/**
 * @namespace dtls::v13::crypto
 * @brief Cryptographic subsystem for DTLS v1.3
 * 
 * Contains all cryptographic interfaces, implementations, and utilities
 * required for DTLS v1.3 protocol operation. Supports multiple crypto
 * providers and advanced security features.
 */
namespace dtls {
namespace v13 {
namespace crypto {

// Forward declarations
struct CipherSpec;
struct KeySchedule;
struct CertificateChain;
struct PrivateKey;
struct PublicKey;
enum class HardwareCapability;
struct HardwareAccelerationProfile;

/**
 * Crypto provider capabilities structure.
 * 
 * This structure defines the cryptographic capabilities supported by a provider
 * including cipher suites, elliptic curve groups, signature schemes, and 
 * hardware acceleration features.
 */
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

/**
 * Key derivation parameters for HKDF and PBKDF2 operations.
 * 
 * Contains all necessary parameters for key derivation functions
 * as specified in RFC 5869 (HKDF) and RFC 2898 (PBKDF2).
 */
struct KeyDerivationParams {
    std::vector<uint8_t> secret;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> info;
    size_t output_length{0};
    HashAlgorithm hash_algorithm{HashAlgorithm::SHA256};
};

/**
 * AEAD encryption/decryption parameters.
 * 
 * Parameters for Authenticated Encryption with Associated Data operations
 * as defined in RFC 5116. Used for both encryption and decryption operations.
 */
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

// ML-KEM parameter sets (FIPS 203)
enum class MLKEMParameterSet : uint8_t {
    MLKEM512 = 1,    ///< ML-KEM-512: k=2, eta1=3, eta2=2
    MLKEM768 = 2,    ///< ML-KEM-768: k=3, eta1=2, eta2=2  
    MLKEM1024 = 3    ///< ML-KEM-1024: k=4, eta1=2, eta2=2
};

// ML-KEM key generation parameters
struct MLKEMKeyGenParams {
    MLKEMParameterSet parameter_set{MLKEMParameterSet::MLKEM512};
    std::vector<uint8_t> additional_entropy; ///< Optional additional entropy
};

// ML-KEM encapsulation parameters
struct MLKEMEncapParams {
    MLKEMParameterSet parameter_set{MLKEMParameterSet::MLKEM512};
    std::vector<uint8_t> public_key;         ///< ML-KEM public key
    std::vector<uint8_t> randomness;         ///< Encapsulation randomness (optional)
};

// ML-KEM decapsulation parameters
struct MLKEMDecapParams {
    MLKEMParameterSet parameter_set{MLKEMParameterSet::MLKEM512};
    std::vector<uint8_t> private_key;        ///< ML-KEM private key
    std::vector<uint8_t> ciphertext;         ///< Encapsulated ciphertext
};

// ML-KEM encapsulation result
struct MLKEMEncapResult {
    std::vector<uint8_t> ciphertext;         ///< Encapsulated ciphertext
    std::vector<uint8_t> shared_secret;      ///< Shared secret (32 bytes)
};

// Pure ML-KEM key exchange parameters (draft-connolly-tls-mlkem-key-agreement-05)
struct PureMLKEMKeyExchangeParams {
    NamedGroup mlkem_group{NamedGroup::MLKEM512};
    bool is_encapsulation{true};                    ///< true=encap (client), false=decap (server)
    
    // Encapsulation parameters (client side)
    std::vector<uint8_t> peer_public_key;           ///< ML-KEM public key from peer (encap only)
    std::vector<uint8_t> encap_randomness;          ///< Optional randomness for encapsulation
    
    // Decapsulation parameters (server side)
    std::vector<uint8_t> private_key;               ///< Our ML-KEM private key (decap only)
    std::vector<uint8_t> ciphertext;                ///< ML-KEM ciphertext to decapsulate (decap only)
};

// Pure ML-KEM key exchange result
struct PureMLKEMKeyExchangeResult {
    std::vector<uint8_t> public_key;                ///< Generated ML-KEM public key (if applicable)
    std::vector<uint8_t> ciphertext;                ///< ML-KEM ciphertext (if encap)
    std::vector<uint8_t> shared_secret;             ///< ML-KEM shared secret (32 bytes)
};

// Hybrid key exchange parameters (combining classical + PQ)
struct HybridKeyExchangeParams {
    NamedGroup hybrid_group{NamedGroup::ECDHE_P256_MLKEM512};
    std::vector<uint8_t> classical_peer_public_key;  ///< ECDHE public key
    std::vector<uint8_t> pq_peer_public_key;         ///< ML-KEM public key or ciphertext
    const PrivateKey* classical_private_key{nullptr}; ///< ECDHE private key
    std::vector<uint8_t> pq_private_key;             ///< ML-KEM private key (for decap)
    bool is_encapsulation{true};                     ///< true=encap (client), false=decap (server)
};

// Hybrid key exchange result
struct HybridKeyExchangeResult {
    std::vector<uint8_t> classical_public_key;       ///< Generated ECDHE public key (if applicable)
    std::vector<uint8_t> pq_ciphertext;              ///< ML-KEM ciphertext (if encap)
    std::vector<uint8_t> classical_shared_secret;    ///< ECDHE shared secret
    std::vector<uint8_t> pq_shared_secret;           ///< ML-KEM shared secret
    std::vector<uint8_t> combined_shared_secret;     ///< HKDF-combined shared secret
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

// ML-DSA parameter sets (FIPS 204)
enum class MLDSAParameterSet : uint8_t {
    ML_DSA_44 = 1,    ///< ML-DSA-44: (2,4) lattice, ~1312 byte signatures, Security Level 2
    ML_DSA_65 = 2,    ///< ML-DSA-65: (3,5) lattice, ~2420 byte signatures, Security Level 3
    ML_DSA_87 = 3     ///< ML-DSA-87: (4,7) lattice, ~3309 byte signatures, Security Level 5
};

// SLH-DSA parameter sets (FIPS 205)
enum class SLHDSAParameterSet : uint8_t {
    SLH_DSA_SHA2_128S = 1,    ///< SHA2-128s: small signatures, slow signing
    SLH_DSA_SHA2_128F = 2,    ///< SHA2-128f: larger signatures, fast signing
    SLH_DSA_SHA2_192S = 3,    ///< SHA2-192s: small signatures, slow signing
    SLH_DSA_SHA2_192F = 4,    ///< SHA2-192f: larger signatures, fast signing
    SLH_DSA_SHA2_256S = 5,    ///< SHA2-256s: small signatures, slow signing
    SLH_DSA_SHA2_256F = 6,    ///< SHA2-256f: larger signatures, fast signing
    SLH_DSA_SHAKE_128S = 7,   ///< SHAKE-128s: small signatures, slow signing
    SLH_DSA_SHAKE_128F = 8,   ///< SHAKE-128f: larger signatures, fast signing
    SLH_DSA_SHAKE_192S = 9,   ///< SHAKE-192s: small signatures, slow signing
    SLH_DSA_SHAKE_192F = 10,  ///< SHAKE-192f: larger signatures, fast signing
    SLH_DSA_SHAKE_256S = 11,  ///< SHAKE-256s: small signatures, slow signing
    SLH_DSA_SHAKE_256F = 12   ///< SHAKE-256f: larger signatures, fast signing
};

// ML-DSA key generation parameters
struct MLDSAKeyGenParams {
    MLDSAParameterSet parameter_set{MLDSAParameterSet::ML_DSA_44};
    std::vector<uint8_t> seed;                   ///< Optional deterministic seed (32 bytes)
    std::vector<uint8_t> additional_entropy;     ///< Additional entropy source
};

// ML-DSA signature parameters
struct MLDSASignatureParams {
    MLDSAParameterSet parameter_set{MLDSAParameterSet::ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to sign
    std::vector<uint8_t> private_key;            ///< ML-DSA private key
    std::vector<uint8_t> context;                ///< Optional context string
    bool deterministic{false};                   ///< Use deterministic signing
};

// ML-DSA verification parameters
struct MLDSAVerificationParams {
    MLDSAParameterSet parameter_set{MLDSAParameterSet::ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to verify
    std::vector<uint8_t> signature;              ///< ML-DSA signature
    std::vector<uint8_t> public_key;             ///< ML-DSA public key
    std::vector<uint8_t> context;                ///< Optional context string
};

// SLH-DSA key generation parameters
struct SLHDSAKeyGenParams {
    SLHDSAParameterSet parameter_set{SLHDSAParameterSet::SLH_DSA_SHA2_128S};
    std::vector<uint8_t> seed;                   ///< Optional deterministic seed
    std::vector<uint8_t> additional_entropy;     ///< Additional entropy source
};

// SLH-DSA signature parameters
struct SLHDSASignatureParams {
    SLHDSAParameterSet parameter_set{SLHDSAParameterSet::SLH_DSA_SHA2_128S};
    std::vector<uint8_t> message;                ///< Message to sign
    std::vector<uint8_t> private_key;            ///< SLH-DSA private key
    std::vector<uint8_t> context;                ///< Optional context string
    bool use_prehash{false};                     ///< Use pre-hash variant
};

// SLH-DSA verification parameters
struct SLHDSAVerificationParams {
    SLHDSAParameterSet parameter_set{SLHDSAParameterSet::SLH_DSA_SHA2_128S};
    std::vector<uint8_t> message;                ///< Message to verify
    std::vector<uint8_t> signature;              ///< SLH-DSA signature
    std::vector<uint8_t> public_key;             ///< SLH-DSA public key
    std::vector<uint8_t> context;                ///< Optional context string
    bool use_prehash{false};                     ///< Use pre-hash variant
};

// Pure PQC signature parameters (unified interface)
struct PurePQCSignatureParams {
    SignatureScheme scheme{SignatureScheme::ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to sign
    std::vector<uint8_t> private_key;            ///< PQC private key
    std::vector<uint8_t> context;                ///< Optional context string
    std::vector<uint8_t> additional_entropy;     ///< Additional randomness
    bool deterministic{false};                   ///< Use deterministic signing (ML-DSA only)
    bool use_prehash{false};                     ///< Use pre-hash variant (SLH-DSA only)
};

// Pure PQC verification parameters (unified interface)
struct PurePQCVerificationParams {
    SignatureScheme scheme{SignatureScheme::ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to verify
    std::vector<uint8_t> signature;              ///< PQC signature
    std::vector<uint8_t> public_key;             ///< PQC public key
    std::vector<uint8_t> context;                ///< Optional context string
    bool use_prehash{false};                     ///< Use pre-hash variant (SLH-DSA only)
};

// Hybrid PQC signature parameters (classical + PQC)
struct HybridPQCSignatureParams {
    SignatureScheme hybrid_scheme{SignatureScheme::RSA3072_ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to sign
    const PrivateKey* classical_private_key{nullptr}; ///< Classical private key
    std::vector<uint8_t> pqc_private_key;        ///< PQC private key
    std::vector<uint8_t> context;                ///< Optional context string
    std::vector<uint8_t> additional_entropy;     ///< Additional randomness
};

// Hybrid PQC verification parameters
struct HybridPQCVerificationParams {
    SignatureScheme hybrid_scheme{SignatureScheme::RSA3072_ML_DSA_44};
    std::vector<uint8_t> message;                ///< Message to verify
    std::vector<uint8_t> hybrid_signature;       ///< Combined classical+PQC signature
    const PublicKey* classical_public_key{nullptr}; ///< Classical public key
    std::vector<uint8_t> pqc_public_key;         ///< PQC public key
    std::vector<uint8_t> context;                ///< Optional context string
};

// Hybrid signature result
struct HybridSignatureResult {
    std::vector<uint8_t> classical_signature;    ///< Classical signature component
    std::vector<uint8_t> pqc_signature;          ///< PQC signature component
    std::vector<uint8_t> combined_signature;     ///< Concatenated hybrid signature
};

// Provider health status
enum class ProviderHealth {
    HEALTHY = 0,
    DEGRADED = 1,
    FAILING = 2,
    UNAVAILABLE = 3
};

// Provider performance metrics
struct ProviderPerformanceMetrics {
    std::chrono::milliseconds average_init_time{0};
    std::chrono::milliseconds average_operation_time{0};
    double throughput_mbps{0.0};
    size_t memory_usage_bytes{0};
    size_t success_count{0};
    size_t failure_count{0};
    double success_rate{0.0};
    std::chrono::steady_clock::time_point last_updated;
};

// Enhanced provider capabilities with runtime information
struct EnhancedProviderCapabilities : public ProviderCapabilities {
    // Runtime capabilities
    bool supports_async_operations{false};
    bool supports_streaming{false};
    bool supports_batch_operations{false};
    bool is_thread_safe{true};
    
    // Performance characteristics
    ProviderPerformanceMetrics performance;
    
    // Health and availability
    ProviderHealth health_status{ProviderHealth::HEALTHY};
    std::chrono::steady_clock::time_point last_health_check;
    std::string health_message;
    
    // Resource usage
    size_t max_memory_usage{0};
    size_t current_memory_usage{0};
    size_t max_concurrent_operations{0};
    size_t current_operations{0};
    
    // Compatibility matrix
    std::unordered_map<std::string, bool> compatibility_flags;
};

/**
 * Abstract base class for cryptographic providers.
 * 
 * This interface defines all cryptographic operations required for DTLS v1.3.
 * Implementations provide backend-specific crypto functionality (OpenSSL, Botan, etc.)
 * 
 * @note This class is thread-safe when properly implemented by concrete providers.
 * @see OpenSSLProvider, BotanProvider for concrete implementations.
 */
class DTLS_API CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    /**
     * Returns the name of this crypto provider.
     * @return Provider name (e.g., "OpenSSL", "Botan")
     */
    virtual std::string name() const = 0;
    
    /**
     * Returns the version string of this crypto provider.
     * @return Provider version string
     */
    virtual std::string version() const = 0;
    
    /**
     * Returns the capabilities supported by this provider.
     * @return Provider capabilities structure
     */
    virtual ProviderCapabilities capabilities() const = 0;
    
    /**
     * Checks if this provider is available for use.
     * @return true if provider is available, false otherwise
     */
    virtual bool is_available() const = 0;
    
    /**
     * Initializes the crypto provider.
     * @return Success result or error details
     */
    virtual Result<void> initialize() = 0;
    
    /**
     * Cleans up provider resources.
     */
    virtual void cleanup() = 0;

    /**
     * Generates cryptographically secure random bytes.
     * @param params Random generation parameters
     * @return Generated random bytes or error details
     */
    virtual Result<std::vector<uint8_t>> generate_random(const RandomParams& params) = 0;
    
    /**
     * Derives key material using HKDF (RFC 5869).
     * @param params Key derivation parameters including secret, salt, and info
     * @return Derived key material or error details
     */
    virtual Result<std::vector<uint8_t>> derive_key_hkdf(const KeyDerivationParams& params) = 0;
    
    /**
     * Derives key material using PBKDF2 (RFC 2898).
     * @param params Key derivation parameters including password and salt
     * @return Derived key material or error details
     */
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
    
    // Pure Post-Quantum Signatures (FIPS 204 - ML-DSA)
    virtual Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
        ml_dsa_generate_keypair(const MLDSAKeyGenParams& params) = 0;
    
    virtual Result<std::vector<uint8_t>> 
        ml_dsa_sign(const MLDSASignatureParams& params) = 0;
    
    virtual Result<bool> 
        ml_dsa_verify(const MLDSAVerificationParams& params) = 0;
    
    // Pure Post-Quantum Signatures (FIPS 205 - SLH-DSA)
    virtual Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
        slh_dsa_generate_keypair(const SLHDSAKeyGenParams& params) = 0;
    
    virtual Result<std::vector<uint8_t>> 
        slh_dsa_sign(const SLHDSASignatureParams& params) = 0;
    
    virtual Result<bool> 
        slh_dsa_verify(const SLHDSAVerificationParams& params) = 0;
    
    // Unified Pure PQC Signature Interface
    virtual Result<std::vector<uint8_t>> 
        pure_pqc_sign(const PurePQCSignatureParams& params) = 0;
    
    virtual Result<bool> 
        pure_pqc_verify(const PurePQCVerificationParams& params) = 0;
    
    // Hybrid PQC Signature Interface (Classical + PQC)
    virtual Result<HybridSignatureResult> 
        hybrid_pqc_sign(const HybridPQCSignatureParams& params) = 0;
    
    virtual Result<bool> 
        hybrid_pqc_verify(const HybridPQCVerificationParams& params) = 0;
    
    // Key exchange
    virtual Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_key_pair(NamedGroup group) = 0;
    
    virtual Result<std::vector<uint8_t>> perform_key_exchange(const KeyExchangeParams& params) = 0;
    
    // ML-KEM Post-Quantum Key Encapsulation (FIPS 203)
    virtual Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
        mlkem_generate_keypair(const MLKEMKeyGenParams& params) = 0;
    
    virtual Result<MLKEMEncapResult> 
        mlkem_encapsulate(const MLKEMEncapParams& params) = 0;
    
    virtual Result<std::vector<uint8_t>> 
        mlkem_decapsulate(const MLKEMDecapParams& params) = 0;
    
    // Pure ML-KEM Key Exchange (draft-connolly-tls-mlkem-key-agreement-05)
    virtual Result<PureMLKEMKeyExchangeResult>
        perform_pure_mlkem_key_exchange(const PureMLKEMKeyExchangeParams& params) = 0;
    
    // Hybrid Post-Quantum + Classical Key Exchange (draft-kwiatkowski-tls-ecdhe-mlkem-03)
    virtual Result<HybridKeyExchangeResult> 
        perform_hybrid_key_exchange(const HybridKeyExchangeParams& params) = 0;
    
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
    
    // Pure ML-KEM utility functions
    virtual bool supports_pure_mlkem_group(NamedGroup group) const {
        return group == NamedGroup::MLKEM512 ||
               group == NamedGroup::MLKEM768 ||
               group == NamedGroup::MLKEM1024;
    }
    
    virtual bool is_pure_mlkem_group(NamedGroup group) const {
        return supports_pure_mlkem_group(group);
    }
    
    // Hybrid PQC utility functions
    virtual bool supports_hybrid_group(NamedGroup group) const {
        return group == NamedGroup::ECDHE_P256_MLKEM512 ||
               group == NamedGroup::ECDHE_P384_MLKEM768 ||
               group == NamedGroup::ECDHE_P521_MLKEM1024;
    }
    
    virtual bool is_hybrid_group(NamedGroup group) const {
        return supports_hybrid_group(group);
    }
    
    // Pure PQC signature utility functions
    virtual bool supports_pure_pqc_signature(SignatureScheme scheme) const {
        return is_ml_dsa_signature(scheme) || is_slh_dsa_signature(scheme);
    }
    
    virtual bool is_ml_dsa_signature(SignatureScheme scheme) const {
        return scheme == SignatureScheme::ML_DSA_44 ||
               scheme == SignatureScheme::ML_DSA_65 ||
               scheme == SignatureScheme::ML_DSA_87;
    }
    
    virtual bool is_slh_dsa_signature(SignatureScheme scheme) const {
        return scheme == SignatureScheme::SLH_DSA_SHA2_128S ||
               scheme == SignatureScheme::SLH_DSA_SHA2_128F ||
               scheme == SignatureScheme::SLH_DSA_SHA2_192S ||
               scheme == SignatureScheme::SLH_DSA_SHA2_192F ||
               scheme == SignatureScheme::SLH_DSA_SHA2_256S ||
               scheme == SignatureScheme::SLH_DSA_SHA2_256F ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_128S ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_128F ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_192S ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_192F ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_256S ||
               scheme == SignatureScheme::SLH_DSA_SHAKE_256F;
    }
    
    // Hybrid PQC signature utility functions
    virtual bool supports_hybrid_pqc_signature(SignatureScheme scheme) const {
        return is_hybrid_ml_dsa_signature(scheme) || is_hybrid_slh_dsa_signature(scheme);
    }
    
    virtual bool is_hybrid_ml_dsa_signature(SignatureScheme scheme) const {
        return scheme == SignatureScheme::RSA3072_ML_DSA_44 ||
               scheme == SignatureScheme::P256_ML_DSA_44 ||
               scheme == SignatureScheme::RSA3072_ML_DSA_65 ||
               scheme == SignatureScheme::P384_ML_DSA_65 ||
               scheme == SignatureScheme::P521_ML_DSA_87;
    }
    
    virtual bool is_hybrid_slh_dsa_signature(SignatureScheme scheme) const {
        return scheme == SignatureScheme::RSA3072_SLH_DSA_128S ||
               scheme == SignatureScheme::P256_SLH_DSA_128S ||
               scheme == SignatureScheme::RSA3072_SLH_DSA_192S ||
               scheme == SignatureScheme::P384_SLH_DSA_192S ||
               scheme == SignatureScheme::P521_SLH_DSA_256S;
    }
    
    virtual bool is_any_pqc_signature(SignatureScheme scheme) const {
        return supports_pure_pqc_signature(scheme) || supports_hybrid_pqc_signature(scheme);
    }
    
    // Performance and security features
    virtual bool has_hardware_acceleration() const = 0;
    virtual bool is_fips_compliant() const = 0;
    virtual SecurityLevel security_level() const = 0;
    virtual Result<void> set_security_level(SecurityLevel level) = 0;
    
    // Enhanced provider features for dependency reduction
    virtual EnhancedProviderCapabilities enhanced_capabilities() const = 0;
    virtual Result<void> perform_health_check() = 0;
    virtual ProviderHealth get_health_status() const = 0;
    virtual ProviderPerformanceMetrics get_performance_metrics() const = 0;
    virtual Result<void> reset_performance_metrics() = 0;
    
    // Resource management
    virtual size_t get_memory_usage() const = 0;
    virtual size_t get_current_operations() const = 0;
    virtual Result<void> set_memory_limit(size_t limit) = 0;
    virtual Result<void> set_operation_limit(size_t limit) = 0;
    
    // Async operation support (optional)
    virtual bool supports_async_operations() const { return false; }
    virtual Result<std::future<std::vector<uint8_t>>> async_derive_key_hkdf(
        const KeyDerivationParams& params) { 
        (void)params;
        return Result<std::future<std::vector<uint8_t>>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    virtual Result<std::future<AEADEncryptionOutput>> async_encrypt_aead(
        const AEADEncryptionParams& params) {
        (void)params;
        return Result<std::future<AEADEncryptionOutput>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    virtual Result<std::future<std::vector<uint8_t>>> async_decrypt_aead(
        const AEADDecryptionParams& params) {
        (void)params;
        return Result<std::future<std::vector<uint8_t>>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Hardware acceleration interface
    virtual Result<HardwareAccelerationProfile> get_hardware_profile() const = 0;
    virtual Result<void> enable_hardware_acceleration(HardwareCapability capability) = 0;
    virtual Result<void> disable_hardware_acceleration(HardwareCapability capability) = 0;
    virtual bool is_hardware_accelerated(const std::string& operation) const = 0;
    virtual Result<float> benchmark_hardware_operation(const std::string& operation) = 0;
    
    // Zero-copy hardware operations
    virtual Result<void> aead_encrypt_inplace(
        const AEADParams& params,
        std::vector<uint8_t>& data,
        size_t plaintext_len) { 
        (void)params; (void)data; (void)plaintext_len;
        return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    virtual Result<void> aead_decrypt_inplace(
        const AEADParams& params,
        std::vector<uint8_t>& data,
        size_t ciphertext_len) {
        (void)params; (void)data; (void)ciphertext_len;
        return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    // Vectorized operations for multiple connections
    virtual Result<std::vector<AEADEncryptionOutput>> batch_encrypt_aead(
        const std::vector<AEADEncryptionParams>& params_batch) {
        (void)params_batch;
        return Result<std::vector<AEADEncryptionOutput>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }
    
    virtual Result<std::vector<std::vector<uint8_t>>> batch_decrypt_aead(
        const std::vector<AEADDecryptionParams>& params_batch) {
        (void)params_batch;
        return Result<std::vector<std::vector<uint8_t>>>(DTLSError::OPERATION_NOT_SUPPORTED);
    }

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

// Enhanced provider selection criteria with advanced options
struct ProviderSelection {
    std::string preferred_provider;
    std::vector<std::string> fallback_providers;
    bool require_hardware_acceleration{false};
    bool require_fips_compliance{false};
    bool allow_software_fallback{true};
    SecurityLevel minimum_security_level{SecurityLevel::MEDIUM};
    std::vector<CipherSuite> required_cipher_suites;
    std::vector<NamedGroup> required_groups;
    std::vector<SignatureScheme> required_signatures;
    
    // Performance requirements
    std::chrono::milliseconds max_init_time{1000};
    size_t max_memory_usage{0}; // 0 = no limit
    double min_throughput_mbps{0.0}; // 0.0 = no requirement
    
    // Compatibility requirements
    bool require_thread_safety{true};
    bool require_async_operations{false};
    bool require_streaming_support{false};
    
    // Provider health requirements
    bool enable_health_monitoring{true};
    std::chrono::seconds health_check_interval{300};
    size_t max_consecutive_failures{3};
};

// Legacy namespace for hybrid PQC operations (for backward compatibility)
namespace hybrid_pqc {

/**
 * Get the classical ECDHE group for a hybrid named group.
 */
inline NamedGroup get_classical_group(NamedGroup hybrid_group) {
    switch (hybrid_group) {
        case NamedGroup::ECDHE_P256_MLKEM512: return NamedGroup::SECP256R1;
        case NamedGroup::ECDHE_P384_MLKEM768: return NamedGroup::SECP384R1;
        case NamedGroup::ECDHE_P521_MLKEM1024: return NamedGroup::SECP521R1;
        default: return NamedGroup::SECP256R1; // fallback
    }
}

/**
 * Get the ML-KEM parameter set for a hybrid named group.
 */
inline MLKEMParameterSet get_mlkem_parameter_set(NamedGroup hybrid_group) {
    switch (hybrid_group) {
        case NamedGroup::ECDHE_P256_MLKEM512: return MLKEMParameterSet::MLKEM512;
        case NamedGroup::ECDHE_P384_MLKEM768: return MLKEMParameterSet::MLKEM768;
        case NamedGroup::ECDHE_P521_MLKEM1024: return MLKEMParameterSet::MLKEM1024;
        default: return MLKEMParameterSet::MLKEM512; // fallback
    }
}

/**
 * Get ML-KEM key sizes (public key, private key, ciphertext) for a parameter set.
 */
struct MLKEMSizes {
    size_t public_key_bytes;
    size_t private_key_bytes; 
    size_t ciphertext_bytes;
    size_t shared_secret_bytes = 32; // Always 32 bytes for ML-KEM
};

inline MLKEMSizes get_mlkem_sizes(MLKEMParameterSet param_set) {
    switch (param_set) {
        case MLKEMParameterSet::MLKEM512:
            return {800, 1632, 768, 32};  // ML-KEM-512 sizes
        case MLKEMParameterSet::MLKEM768:
            return {1184, 2400, 1088, 32}; // ML-KEM-768 sizes
        case MLKEMParameterSet::MLKEM1024:
            return {1568, 3168, 1568, 32}; // ML-KEM-1024 sizes
        default:
            return {800, 1632, 768, 32};   // fallback to ML-KEM-512
    }
}

/**
 * Check if a named group is a hybrid PQC group.
 */
inline bool is_hybrid_pqc_group(NamedGroup group) {
    return group == NamedGroup::ECDHE_P256_MLKEM512 ||
           group == NamedGroup::ECDHE_P384_MLKEM768 ||
           group == NamedGroup::ECDHE_P521_MLKEM1024;
}

/**
 * Check if a named group is a pure ML-KEM group.
 */
inline bool is_pure_mlkem_group_internal(NamedGroup group) {
    return group == NamedGroup::MLKEM512 ||
           group == NamedGroup::MLKEM768 ||
           group == NamedGroup::MLKEM1024;
}

/**
 * Check if a named group is any kind of post-quantum group (pure ML-KEM or hybrid).
 */
inline bool is_pqc_group(NamedGroup group) {
    return is_pure_mlkem_group_internal(group) || is_hybrid_pqc_group(group);
}

/**
 * Get the expected hybrid key share size for client (public keys only).
 */
inline size_t get_hybrid_client_keyshare_size(NamedGroup hybrid_group) {
    auto mlkem_sizes = get_mlkem_sizes(get_mlkem_parameter_set(hybrid_group));
    size_t classical_size = 0;
    
    switch (get_classical_group(hybrid_group)) {
        case NamedGroup::SECP256R1: classical_size = 65; break; // uncompressed P-256
        case NamedGroup::SECP384R1: classical_size = 97; break; // uncompressed P-384
        case NamedGroup::SECP521R1: classical_size = 133; break; // uncompressed P-521
        default: classical_size = 65; break;
    }
    
    return classical_size + mlkem_sizes.public_key_bytes;
}

/**
 * Get the expected hybrid key share size for server (ECDHE pubkey + ML-KEM ciphertext).
 */
inline size_t get_hybrid_server_keyshare_size(NamedGroup hybrid_group) {
    auto mlkem_sizes = get_mlkem_sizes(get_mlkem_parameter_set(hybrid_group));
    size_t classical_size = 0;
    
    switch (get_classical_group(hybrid_group)) {
        case NamedGroup::SECP256R1: classical_size = 65; break; // uncompressed P-256
        case NamedGroup::SECP384R1: classical_size = 97; break; // uncompressed P-384
        case NamedGroup::SECP521R1: classical_size = 133; break; // uncompressed P-521
        default: classical_size = 65; break;
    }
    
    return classical_size + mlkem_sizes.ciphertext_bytes;
}

} // namespace hybrid_pqc

// Utility functions for pure ML-KEM operations
namespace pqc_utils {

/**
 * Check if a named group is a pure ML-KEM group.
 */
inline bool is_pure_mlkem_group(NamedGroup group) {
    return hybrid_pqc::is_pure_mlkem_group_internal(group);
}

/**
 * Get the ML-KEM parameter set for a pure ML-KEM named group.
 */
inline MLKEMParameterSet get_pure_mlkem_parameter_set(NamedGroup group) {
    switch (group) {
        case NamedGroup::MLKEM512: return MLKEMParameterSet::MLKEM512;
        case NamedGroup::MLKEM768: return MLKEMParameterSet::MLKEM768;
        case NamedGroup::MLKEM1024: return MLKEMParameterSet::MLKEM1024;
        default: return MLKEMParameterSet::MLKEM512; // fallback
    }
}

/**
 * Get the expected key share size for pure ML-KEM (public key for client, ciphertext for server).
 */
inline size_t get_pure_mlkem_client_keyshare_size(NamedGroup group) {
    if (!is_pure_mlkem_group(group)) return 0;
    auto mlkem_sizes = hybrid_pqc::get_mlkem_sizes(get_pure_mlkem_parameter_set(group));
    return mlkem_sizes.public_key_bytes;
}

inline size_t get_pure_mlkem_server_keyshare_size(NamedGroup group) {
    if (!is_pure_mlkem_group(group)) return 0;
    auto mlkem_sizes = hybrid_pqc::get_mlkem_sizes(get_pure_mlkem_parameter_set(group));
    return mlkem_sizes.ciphertext_bytes;
}

/**
 * Validate ML-KEM key sizes for pure ML-KEM groups.
 */
inline bool validate_pure_mlkem_public_key_size(NamedGroup group, size_t key_size) {
    return is_pure_mlkem_group(group) && 
           key_size == get_pure_mlkem_client_keyshare_size(group);
}

inline bool validate_pure_mlkem_ciphertext_size(NamedGroup group, size_t ciphertext_size) {
    return is_pure_mlkem_group(group) && 
           ciphertext_size == get_pure_mlkem_server_keyshare_size(group);
}

inline bool validate_pure_mlkem_shared_secret_size(size_t secret_size) {
    return secret_size == 32; // ML-KEM always produces 32-byte shared secrets
}

} // namespace pqc_utils


} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_PROVIDER_H