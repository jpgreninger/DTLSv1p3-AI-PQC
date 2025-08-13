#ifndef DTLS_CRYPTO_OPENSSL_PROVIDER_H
#define DTLS_CRYPTO_OPENSSL_PROVIDER_H

#include <dtls/config.h>
#include <dtls/crypto/provider.h>
#include <memory>
#include <mutex>

// Forward declarations for OpenSSL types
struct evp_pkey_st;
struct x509_st;
struct x509_store_st;
struct stack_st_X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
typedef struct stack_st_X509 STACK_OF_X509;

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * OpenSSL-based cryptographic provider implementation
 * 
 * Provides full DTLS v1.3 cryptographic functionality using OpenSSL
 * as the underlying crypto library.
 */
class DTLS_API OpenSSLProvider : public CryptoProvider {
public:
    OpenSSLProvider();
    ~OpenSSLProvider() override;
    
    // Non-copyable, movable
    OpenSSLProvider(const OpenSSLProvider&) = delete;
    OpenSSLProvider& operator=(const OpenSSLProvider&) = delete;
    OpenSSLProvider(OpenSSLProvider&&) noexcept;
    OpenSSLProvider& operator=(OpenSSLProvider&&) noexcept;

    // Provider information
    std::string name() const override;
    std::string version() const override;
    ProviderCapabilities capabilities() const override;
    bool is_available() const override;
    Result<void> initialize() override;
    void cleanup() override;

    // Random number generation
    Result<std::vector<uint8_t>> generate_random(const RandomParams& params) override;
    
    // Key derivation
    Result<std::vector<uint8_t>> derive_key_hkdf(const KeyDerivationParams& params) override;
    Result<std::vector<uint8_t>> derive_key_pbkdf2(const KeyDerivationParams& params) override;
    
    // AEAD operations
    Result<std::vector<uint8_t>> aead_encrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& plaintext) override;
    
    Result<std::vector<uint8_t>> aead_decrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& ciphertext) override;
    
    // New AEAD interface with separate ciphertext and tag
    Result<AEADEncryptionOutput> encrypt_aead(const AEADEncryptionParams& params) override;
    Result<std::vector<uint8_t>> decrypt_aead(const AEADDecryptionParams& params) override;
    
    // Hash functions  
    Result<std::vector<uint8_t>> compute_hash(const HashParams& params) override;
    Result<std::vector<uint8_t>> compute_hmac(const HMACParams& params) override;
    
    // MAC validation with timing-attack resistance (RFC 9147 Section 5.2)
    Result<bool> verify_hmac(const MACValidationParams& params) override;
    
    // DTLS v1.3 record MAC validation (RFC 9147 Section 4.2.1)
    Result<bool> validate_record_mac(const RecordMACParams& params) override;
    
    // Legacy MAC verification for backward compatibility
    Result<bool> verify_hmac_legacy(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    
    // Digital signatures
    Result<std::vector<uint8_t>> sign_data(const SignatureParams& params) override;
    Result<bool> verify_signature(
        const SignatureParams& params,
        const std::vector<uint8_t>& signature) override;
    
    // DTLS v1.3 Certificate Verify (RFC 9147 Section 4.2.3)
    Result<bool> verify_dtls_certificate_signature(
        const DTLSCertificateVerifyParams& params,
        const std::vector<uint8_t>& signature) override;
    
    // Additional signature helper methods for DTLS v1.3
    Result<size_t> get_signature_length(SignatureScheme scheme, const PrivateKey& key) const;
    Result<size_t> get_signature_length(SignatureScheme scheme, const PublicKey& key) const;
    Result<std::vector<uint8_t>> create_certificate_signature(
        const std::vector<uint8_t>& certificate_data,
        SignatureScheme scheme,
        const PrivateKey& private_key) const;
    Result<std::vector<uint8_t>> sign_handshake_transcript(
        const std::vector<uint8_t>& transcript_hash,
        SignatureScheme scheme,
        const PrivateKey& private_key,
        bool is_server = false) const;
    Result<std::vector<uint8_t>> generate_finished_signature(
        const std::vector<uint8_t>& finished_key,
        const std::vector<uint8_t>& transcript_hash,
        HashAlgorithm hash_algorithm) const;
    std::vector<SignatureScheme> get_supported_signature_algorithms() const;
    
    // Key exchange
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_key_pair(NamedGroup group) override;
    
    Result<std::vector<uint8_t>> perform_key_exchange(const KeyExchangeParams& params) override;
    
    // Additional key generation methods for specific algorithms
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_rsa_keypair(int key_size);
    
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_eddsa_keypair(int key_type);
    
    // Helper methods for supported curves and key sizes
    std::vector<NamedGroup> get_supported_curves() const;
    std::vector<int> get_supported_rsa_sizes() const;
    
    // Certificate operations
    Result<bool> validate_certificate_chain(const CertValidationParams& params) override;
    Result<std::unique_ptr<PublicKey>> extract_public_key(
        const std::vector<uint8_t>& certificate) override;
    
    // Key import/export
    Result<std::unique_ptr<PrivateKey>> import_private_key(
        const std::vector<uint8_t>& key_data,
        const std::string& format = "PEM") override;
    
    Result<std::unique_ptr<PublicKey>> import_public_key(
        const std::vector<uint8_t>& key_data,
        const std::string& format = "PEM") override;
    
    Result<std::vector<uint8_t>> export_private_key(
        const PrivateKey& key,
        const std::string& format = "PEM") override;
    
    Result<std::vector<uint8_t>> export_public_key(
        const PublicKey& key,
        const std::string& format = "PEM") override;

    // Utility functions
    bool supports_cipher_suite(CipherSuite suite) const override;
    bool supports_named_group(NamedGroup group) const override;
    bool supports_signature_scheme(SignatureScheme scheme) const override;
    bool supports_hash_algorithm(HashAlgorithm hash) const override;
    
    // Performance and security features
    bool has_hardware_acceleration() const override;
    bool is_fips_compliant() const override;
    SecurityLevel security_level() const override;
    Result<void> set_security_level(SecurityLevel level) override;
    
    // AEAD utility functions
    size_t get_aead_key_length(AEADCipher cipher) const;
    size_t get_aead_nonce_length(AEADCipher cipher) const;
    size_t get_aead_tag_length(AEADCipher cipher) const;
    
    // Enhanced provider features for dependency reduction
    EnhancedProviderCapabilities enhanced_capabilities() const override;
    Result<void> perform_health_check() override;
    ProviderHealth get_health_status() const override;
    ProviderPerformanceMetrics get_performance_metrics() const override;
    Result<void> reset_performance_metrics() override;
    
    // Resource management
    size_t get_memory_usage() const override;
    size_t get_current_operations() const override;
    Result<void> set_memory_limit(size_t limit) override;
    Result<void> set_operation_limit(size_t limit) override;
    
    // Hardware acceleration interface
    Result<HardwareAccelerationProfile> get_hardware_profile() const override;
    Result<void> enable_hardware_acceleration(HardwareCapability capability) override;
    Result<void> disable_hardware_acceleration(HardwareCapability capability) override;
    bool is_hardware_accelerated(const std::string& operation) const override;
    Result<float> benchmark_hardware_operation(const std::string& operation) override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    
    // Private helper methods
    Result<void> validate_aead_params(AEADCipher cipher, 
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& nonce) const;
    DTLSError map_openssl_error_detailed() const;
    void secure_cleanup(std::vector<uint8_t>& buffer) const;
    bool validate_key_scheme_compatibility(int key_type, SignatureScheme scheme) const;
    bool validate_random_entropy(const std::vector<uint8_t>& random_data) const;
};

/**
 * OpenSSL private key implementation
 */
class DTLS_API OpenSSLPrivateKey : public PrivateKey {
public:
    explicit OpenSSLPrivateKey(EVP_PKEY* key);
    ~OpenSSLPrivateKey() override;
    
    // Non-copyable, movable
    OpenSSLPrivateKey(const OpenSSLPrivateKey&) = delete;
    OpenSSLPrivateKey& operator=(const OpenSSLPrivateKey&) = delete;
    OpenSSLPrivateKey(OpenSSLPrivateKey&&) noexcept;
    OpenSSLPrivateKey& operator=(OpenSSLPrivateKey&&) noexcept;
    
    // CryptoKey interface
    std::string algorithm() const override;
    size_t key_size() const override;
    NamedGroup group() const override;
    std::vector<uint8_t> fingerprint() const override;
    
    // PrivateKey interface
    Result<std::unique_ptr<PublicKey>> derive_public_key() const override;
    
    // OpenSSL-specific access
    EVP_PKEY* native_key() const { return key_; }

private:
    EVP_PKEY* key_;
};

/**
 * OpenSSL public key implementation  
 */
class DTLS_API OpenSSLPublicKey : public PublicKey {
public:
    explicit OpenSSLPublicKey(EVP_PKEY* key);
    ~OpenSSLPublicKey() override;
    
    // Non-copyable, movable
    OpenSSLPublicKey(const OpenSSLPublicKey&) = delete;
    OpenSSLPublicKey& operator=(const OpenSSLPublicKey&) = delete;
    OpenSSLPublicKey(OpenSSLPublicKey&&) noexcept;
    OpenSSLPublicKey& operator=(OpenSSLPublicKey&&) noexcept;
    
    // CryptoKey interface
    std::string algorithm() const override;
    size_t key_size() const override;
    NamedGroup group() const override;
    std::vector<uint8_t> fingerprint() const override;
    
    // PublicKey interface
    bool equals(const PublicKey& other) const override;
    
    // OpenSSL-specific access
    EVP_PKEY* native_key() const { return key_; }

private:
    EVP_PKEY* key_;
};

/**
 * OpenSSL certificate chain implementation
 */
class DTLS_API OpenSSLCertificateChain : public CertificateChain {
public:
    explicit OpenSSLCertificateChain(STACK_OF_X509* chain);
    ~OpenSSLCertificateChain() override;
    
    // Non-copyable, movable
    OpenSSLCertificateChain(const OpenSSLCertificateChain&) = delete;
    OpenSSLCertificateChain& operator=(const OpenSSLCertificateChain&) = delete;
    OpenSSLCertificateChain(OpenSSLCertificateChain&&) noexcept;
    OpenSSLCertificateChain& operator=(OpenSSLCertificateChain&&) noexcept;
    
    // CertificateChain interface
    size_t certificate_count() const override;
    std::vector<uint8_t> certificate_at(size_t index) const override;
    std::unique_ptr<PublicKey> leaf_public_key() const override;
    std::string subject_name() const override;
    std::string issuer_name() const override;
    std::chrono::system_clock::time_point not_before() const override;
    std::chrono::system_clock::time_point not_after() const override;
    bool is_valid() const override;
    
    // OpenSSL-specific access
    STACK_OF_X509* native_chain() const { return chain_; }

private:
    STACK_OF_X509* chain_;
};

// OpenSSL utility functions
namespace openssl_utils {

/**
 * Initialize OpenSSL library
 */
DTLS_API Result<void> initialize_openssl();

/**
 * Cleanup OpenSSL library
 */
DTLS_API void cleanup_openssl();

/**
 * Check if OpenSSL is available and properly configured
 */
DTLS_API bool is_openssl_available();

/**
 * Get OpenSSL version information
 */
DTLS_API std::string get_openssl_version();

/**
 * Convert OpenSSL error to DTLSError
 */
DTLS_API DTLSError map_openssl_error(unsigned long openssl_error);

/**
 * Get last OpenSSL error as DTLS result
 */
template<typename T>
Result<T> openssl_error_result() {
    return Result<T>(map_openssl_error(0)); // Will get last error internally
}

/**
 * Convert cipher suite to OpenSSL cipher
 */
DTLS_API Result<const void*> cipher_suite_to_openssl(CipherSuite suite);

/**
 * Convert named group to OpenSSL NID
 */
DTLS_API Result<int> named_group_to_openssl(NamedGroup group);

/**
 * Convert signature scheme to OpenSSL parameters
 */
DTLS_API Result<std::pair<int, int>> signature_scheme_to_openssl(SignatureScheme scheme);

/**
 * Convert hash algorithm to OpenSSL EVP_MD
 */
DTLS_API Result<const void*> hash_algorithm_to_openssl(HashAlgorithm hash);

} // namespace openssl_utils
} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_OPENSSL_PROVIDER_H