#ifndef DTLS_CRYPTO_BOTAN_PROVIDER_H
#define DTLS_CRYPTO_BOTAN_PROVIDER_H

#include <dtls/config.h>
#include <dtls/crypto/provider.h>
#include <memory>
#include <mutex>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * Botan-based cryptographic provider implementation
 * 
 * Provides full DTLS v1.3 cryptographic functionality using Botan
 * as the underlying crypto library. This serves as an alternative
 * to the OpenSSL provider for environments where Botan is preferred.
 */
class DTLS_API BotanProvider : public CryptoProvider {
public:
    BotanProvider();
    ~BotanProvider() override;
    
    // Non-copyable, movable
    BotanProvider(const BotanProvider&) = delete;
    BotanProvider& operator=(const BotanProvider&) = delete;
    BotanProvider(BotanProvider&&) noexcept;
    BotanProvider& operator=(BotanProvider&&) noexcept;

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
    
    // Key exchange
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_key_pair(NamedGroup group) override;
    
    Result<std::vector<uint8_t>> perform_key_exchange(const KeyExchangeParams& params) override;
    
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

    // AEAD helper functions
    size_t get_aead_key_length(AEADCipher cipher) const;
    size_t get_aead_nonce_length(AEADCipher cipher) const;
    size_t get_aead_tag_length(AEADCipher cipher) const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    
    // Private helper functions
    Result<void> validate_aead_params(AEADCipher cipher, 
                                     const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& nonce) const;
    Result<std::string> aead_cipher_to_botan(AEADCipher cipher) const;
    
    // Signature operation helper functions
    bool validate_key_scheme_compatibility(const std::string& key_algorithm, SignatureScheme scheme) const;
    bool validate_signature_length(const std::vector<uint8_t>& signature, SignatureScheme scheme, const PublicKey& key) const;
    Result<std::vector<uint8_t>> construct_dtls_signature_context(
        const std::vector<uint8_t>& transcript_hash, bool is_server_context) const;
    
    // Enhanced validation functions for RFC 9147 compliance
    bool validate_enhanced_key_scheme_compatibility(const CryptoKey& key, SignatureScheme scheme) const;
    bool validate_ecdsa_curve_compatibility(NamedGroup key_curve, SignatureScheme scheme) const;
    Result<bool> validate_asn1_ecdsa_signature(const std::vector<uint8_t>& signature) const;
    
    // Security policy validation
    bool is_signature_scheme_allowed(SignatureScheme scheme) const;
    bool is_signature_scheme_deprecated(SignatureScheme scheme) const;
};

/**
 * Botan private key implementation
 */
class DTLS_API BotanPrivateKey : public PrivateKey {
public:
    // Accept unique_ptr with custom deleter to handle both simulation and real Botan keys
    template<typename Deleter>
    explicit BotanPrivateKey(std::unique_ptr<void, Deleter> key) 
        : key_(std::move(key)), group_(NamedGroup::SECP256R1) {}
    
    template<typename Deleter>
    BotanPrivateKey(std::unique_ptr<void, Deleter> key, NamedGroup group) 
        : key_(std::move(key)), group_(group) {}
    
    ~BotanPrivateKey() override;
    
    // Non-copyable, movable
    BotanPrivateKey(const BotanPrivateKey&) = delete;
    BotanPrivateKey& operator=(const BotanPrivateKey&) = delete;
    BotanPrivateKey(BotanPrivateKey&&) noexcept;
    BotanPrivateKey& operator=(BotanPrivateKey&&) noexcept;
    
    // CryptoKey interface
    std::string algorithm() const override;
    size_t key_size() const override;
    NamedGroup group() const override;
    std::vector<uint8_t> fingerprint() const override;
    
    // PrivateKey interface
    Result<std::unique_ptr<PublicKey>> derive_public_key() const override;
    
    // Botan-specific access
    void* native_key() const { return key_.get(); }

private:
    std::unique_ptr<void, std::function<void(void*)>> key_; // Use function deleter for flexibility
    NamedGroup group_; // Elliptic curve group
};

/**
 * Botan public key implementation  
 */
class DTLS_API BotanPublicKey : public PublicKey {
public:
    // Accept unique_ptr with custom deleter to handle both simulation and real Botan keys
    template<typename Deleter>
    explicit BotanPublicKey(std::unique_ptr<void, Deleter> key) 
        : key_(std::move(key)), group_(NamedGroup::SECP256R1) {}
    
    template<typename Deleter>
    BotanPublicKey(std::unique_ptr<void, Deleter> key, NamedGroup group) 
        : key_(std::move(key)), group_(group) {}
    
    ~BotanPublicKey() override;
    
    // Non-copyable, movable
    BotanPublicKey(const BotanPublicKey&) = delete;
    BotanPublicKey& operator=(const BotanPublicKey&) = delete;
    BotanPublicKey(BotanPublicKey&&) noexcept;
    BotanPublicKey& operator=(BotanPublicKey&&) noexcept;
    
    // CryptoKey interface
    std::string algorithm() const override;
    size_t key_size() const override;
    NamedGroup group() const override;
    std::vector<uint8_t> fingerprint() const override;
    
    // PublicKey interface
    bool equals(const PublicKey& other) const override;
    
    // Botan-specific access
    void* native_key() const { return key_.get(); }

private:
    std::unique_ptr<void, std::function<void(void*)>> key_; // Use function deleter for flexibility
    NamedGroup group_; // Elliptic curve group
};

/**
 * Botan certificate chain implementation
 */
class DTLS_API BotanCertificateChain : public CertificateChain {
public:
    explicit BotanCertificateChain(std::vector<std::vector<uint8_t>> certs);
    ~BotanCertificateChain() override;
    
    // Non-copyable, movable
    BotanCertificateChain(const BotanCertificateChain&) = delete;
    BotanCertificateChain& operator=(const BotanCertificateChain&) = delete;
    BotanCertificateChain(BotanCertificateChain&&) noexcept;
    BotanCertificateChain& operator=(BotanCertificateChain&&) noexcept;
    
    // CertificateChain interface
    size_t certificate_count() const override;
    std::vector<uint8_t> certificate_at(size_t index) const override;
    std::unique_ptr<PublicKey> leaf_public_key() const override;
    std::string subject_name() const override;
    std::string issuer_name() const override;
    std::chrono::system_clock::time_point not_before() const override;
    std::chrono::system_clock::time_point not_after() const override;
    bool is_valid() const override;

private:
    std::vector<std::vector<uint8_t>> certificates_;
};

// Botan utility functions
namespace botan_utils {

/**
 * Initialize Botan library
 */
DTLS_API Result<void> initialize_botan();

/**
 * Cleanup Botan library
 */
DTLS_API void cleanup_botan();

/**
 * Check if Botan is available and properly configured
 */
DTLS_API bool is_botan_available();

/**
 * Get Botan version information
 */
DTLS_API std::string get_botan_version();

/**
 * Convert cipher suite to Botan cipher name
 */
DTLS_API Result<std::string> cipher_suite_to_botan(CipherSuite suite);

/**
 * Convert named group to Botan group name
 */
DTLS_API Result<std::string> named_group_to_botan(NamedGroup group);

/**
 * Convert signature scheme to Botan signature parameters
 */
DTLS_API Result<std::pair<std::string, std::string>> signature_scheme_to_botan(SignatureScheme scheme);

/**
 * Convert hash algorithm to Botan hash name
 */
DTLS_API Result<std::string> hash_algorithm_to_botan(HashAlgorithm hash);

} // namespace botan_utils
} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_BOTAN_PROVIDER_H