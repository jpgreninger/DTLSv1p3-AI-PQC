#ifndef DTLS_CRYPTO_OPERATIONS_H
#define DTLS_CRYPTO_OPERATIONS_H

#include <dtls/config.h>
#include <dtls/types.h>
#include <dtls/result.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <memory>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * Abstract Crypto Operations Interface
 * 
 * This interface provides a high-level abstraction layer over cryptographic
 * operations, decoupling the protocol logic from specific crypto provider
 * implementations. It enables easier testing, provider switching, and 
 * modular crypto operation management.
 * 
 * All operations maintain RFC 9147 compliance and provide consistent
 * error handling across different crypto backends.
 */
class DTLS_API ICryptoOperations {
public:
    virtual ~ICryptoOperations() = default;
    
    // === Random Number Generation Operations ===
    
    /**
     * Generate cryptographically secure random bytes
     * 
     * @param length Number of random bytes to generate
     * @param additional_entropy Optional additional entropy source
     * @return Random bytes or error details
     */
    virtual Result<std::vector<uint8_t>> generate_random(
        size_t length,
        const std::vector<uint8_t>& additional_entropy = {}) = 0;
    
    /**
     * Generate DTLS random structure (32 bytes)
     * 
     * @return 32-byte random value suitable for DTLS handshake
     */
    virtual Result<Random> generate_dtls_random() = 0;
    
    /**
     * Generate session ID
     * 
     * @param length Session ID length (typically 32 bytes)
     * @return Session ID bytes or error details
     */
    virtual Result<std::vector<uint8_t>> generate_session_id(size_t length = 32) = 0;
    
    /**
     * Generate connection ID for DTLS v1.3
     * 
     * @param length Connection ID length (1-255 bytes)
     * @return Connection ID or error details
     */
    virtual Result<ConnectionID> generate_connection_id(size_t length = 8) = 0;
    
    // === Key Derivation Operations ===
    
    /**
     * Derive key using HKDF-Expand-Label (RFC 8446)
     * 
     * @param secret Input key material
     * @param label Key derivation label
     * @param context Key derivation context 
     * @param length Output key length
     * @param hash_algo Hash algorithm to use
     * @return Derived key or error details
     */
    virtual Result<std::vector<uint8_t>> hkdf_expand_label(
        const std::vector<uint8_t>& secret,
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t length,
        HashAlgorithm hash_algo = HashAlgorithm::SHA256) = 0;
    
    /**
     * Derive traffic keys for current epoch
     * 
     * @param master_secret Current master secret
     * @param cipher_suite Active cipher suite
     * @param context Handshake context
     * @return Key schedule or error details
     */
    virtual Result<KeySchedule> derive_traffic_keys(
        const std::vector<uint8_t>& master_secret,
        CipherSuite cipher_suite,
        const std::vector<uint8_t>& context) = 0;
    
    // === AEAD Encryption/Decryption Operations ===
    
    /**
     * AEAD encrypt with integrated authentication
     * 
     * @param plaintext Data to encrypt
     * @param key Encryption key
     * @param nonce Encryption nonce/IV
     * @param additional_data Additional authenticated data (AAD)
     * @param cipher AEAD cipher to use
     * @return Ciphertext with integrated authentication tag or error
     */
    virtual Result<AEADEncryptionOutput> aead_encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher) = 0;
    
    /**
     * AEAD decrypt with authentication verification
     * 
     * @param ciphertext Data to decrypt
     * @param tag Authentication tag
     * @param key Decryption key
     * @param nonce Decryption nonce/IV
     * @param additional_data Additional authenticated data (AAD)
     * @param cipher AEAD cipher to use
     * @return Decrypted plaintext or error details
     */
    virtual Result<std::vector<uint8_t>> aead_decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher) = 0;
    
    // === Hash and HMAC Operations ===
    
    /**
     * Compute cryptographic hash
     * 
     * @param data Data to hash
     * @param algorithm Hash algorithm to use
     * @return Hash digest or error details
     */
    virtual Result<std::vector<uint8_t>> compute_hash(
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) = 0;
    
    /**
     * Compute HMAC with timing-attack resistance
     * 
     * @param key HMAC key
     * @param data Data to authenticate
     * @param algorithm Hash algorithm for HMAC
     * @return HMAC tag or error details
     */
    virtual Result<std::vector<uint8_t>> compute_hmac(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) = 0;
    
    /**
     * Verify HMAC with constant-time comparison
     * 
     * @param key HMAC key
     * @param data Data to verify
     * @param expected_mac Expected HMAC value
     * @param algorithm Hash algorithm for HMAC
     * @return true if HMAC is valid, false otherwise
     */
    virtual Result<bool> verify_hmac(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) = 0;
    
    // === Digital Signature Operations ===
    
    /**
     * Generate digital signature
     * 
     * @param data Data to sign
     * @param private_key Private key for signing
     * @param scheme Signature scheme to use
     * @return Signature bytes or error details
     */
    virtual Result<std::vector<uint8_t>> sign_data(
        const std::vector<uint8_t>& data,
        const PrivateKey& private_key,
        SignatureScheme scheme) = 0;
    
    /**
     * Verify digital signature
     * 
     * @param data Original data that was signed
     * @param signature Signature to verify
     * @param public_key Public key for verification
     * @param scheme Signature scheme used
     * @return true if signature is valid, false otherwise
     */
    virtual Result<bool> verify_signature(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature,
        const PublicKey& public_key,
        SignatureScheme scheme) = 0;
    
    /**
     * Verify DTLS Certificate signature (RFC 9147 Section 4.2.3)
     * 
     * @param transcript_hash Handshake transcript hash
     * @param signature Certificate signature
     * @param public_key Certificate public key
     * @param scheme Signature scheme used
     * @param is_server_context true for server certificates
     * @return true if certificate signature is valid
     */
    virtual Result<bool> verify_certificate_signature(
        const std::vector<uint8_t>& transcript_hash,
        const std::vector<uint8_t>& signature,
        const PublicKey& public_key,
        SignatureScheme scheme,
        bool is_server_context = true) = 0;
    
    // === Key Exchange Operations ===
    
    /**
     * Generate key pair for key exchange
     * 
     * @param group Named group for key generation
     * @return Key pair (private, public) or error details
     */
    virtual Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
        generate_key_pair(NamedGroup group) = 0;
    
    /**
     * Perform Diffie-Hellman key exchange
     * 
     * @param private_key Local private key
     * @param peer_public_key Peer's public key
     * @param group Named group for key exchange
     * @return Shared secret or error details
     */
    virtual Result<std::vector<uint8_t>> key_exchange(
        const PrivateKey& private_key,
        const std::vector<uint8_t>& peer_public_key,
        NamedGroup group) = 0;
    
    // === Certificate Operations ===
    
    /**
     * Validate certificate chain
     * 
     * @param chain Certificate chain to validate
     * @param root_ca_store Trusted root CA certificates
     * @param hostname Expected hostname (for SNI validation)
     * @param check_revocation Whether to check certificate revocation
     * @return true if chain is valid, false otherwise
     */
    virtual Result<bool> validate_certificate_chain(
        const CertificateChain& chain,
        const std::vector<uint8_t>& root_ca_store,
        const std::string& hostname = "",
        bool check_revocation = true) = 0;
    
    /**
     * Extract public key from certificate
     * 
     * @param certificate_der DER-encoded certificate
     * @return Public key or error details
     */
    virtual Result<std::unique_ptr<PublicKey>> extract_public_key(
        const std::vector<uint8_t>& certificate_der) = 0;
    
    // === DTLS v1.3 Specific Operations ===
    
    /**
     * Encrypt sequence number (RFC 9147 Section 4.2.2)
     * 
     * @param sequence_number Plain sequence number
     * @param key Sequence number encryption key
     * @param sample Record sample for masking
     * @return Encrypted sequence number or error details
     */
    virtual Result<std::vector<uint8_t>> encrypt_sequence_number(
        uint64_t sequence_number,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& sample) = 0;
    
    /**
     * Decrypt sequence number (RFC 9147 Section 4.2.2)
     * 
     * @param encrypted_sequence_number Encrypted sequence number
     * @param key Sequence number encryption key  
     * @param sample Record sample for masking
     * @return Decrypted sequence number or error details
     */
    virtual Result<uint64_t> decrypt_sequence_number(
        const std::vector<uint8_t>& encrypted_sequence_number,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& sample) = 0;
    
    /**
     * Validate record MAC for DTLS v1.3 (RFC 9147 Section 4.2.1)
     * 
     * @param mac_key Record MAC key
     * @param sequence_number_key Sequence number encryption key
     * @param record_header DTLS record header
     * @param plaintext Record plaintext
     * @param expected_mac Expected MAC from record
     * @param content_type Record content type
     * @param epoch Current epoch
     * @param sequence_number Current sequence number
     * @return true if MAC is valid, false otherwise
     */
    virtual Result<bool> validate_record_mac(
        const std::vector<uint8_t>& mac_key,
        const std::vector<uint8_t>& sequence_number_key,
        const std::vector<uint8_t>& record_header,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& expected_mac,
        ContentType content_type,
        Epoch epoch,
        SequenceNumber sequence_number) = 0;
    
    // === Provider Information ===
    
    /**
     * Get provider name
     * 
     * @return Name of the underlying crypto provider
     */
    virtual std::string provider_name() const = 0;
    
    /**
     * Get provider capabilities
     * 
     * @return Capabilities of the underlying crypto provider
     */
    virtual ProviderCapabilities capabilities() const = 0;
    
    /**
     * Check if operation is supported
     * 
     * @param cipher_suite Cipher suite to check
     * @return true if cipher suite is supported
     */
    virtual bool supports_cipher_suite(CipherSuite cipher_suite) const = 0;
    
    /**
     * Check if named group is supported
     * 
     * @param group Named group to check
     * @return true if named group is supported
     */
    virtual bool supports_named_group(NamedGroup group) const = 0;
    
    /**
     * Check if signature scheme is supported
     * 
     * @param scheme Signature scheme to check
     * @return true if signature scheme is supported
     */
    virtual bool supports_signature_scheme(SignatureScheme scheme) const = 0;

protected:
    ICryptoOperations() = default;
};

/**
 * Crypto Operations Factory Interface
 * 
 * Factory for creating crypto operations instances with different
 * underlying providers and configurations.
 */
class DTLS_API ICryptoOperationsFactory {
public:
    virtual ~ICryptoOperationsFactory() = default;
    
    /**
     * Create crypto operations with specific provider
     * 
     * @param provider_name Name of crypto provider to use
     * @return Crypto operations instance or error details
     */
    virtual Result<std::unique_ptr<ICryptoOperations>> 
        create_operations(const std::string& provider_name = "") = 0;
    
    /**
     * Create crypto operations with selection criteria
     * 
     * @param criteria Provider selection criteria
     * @return Crypto operations instance or error details
     */
    virtual Result<std::unique_ptr<ICryptoOperations>>
        create_operations(const ProviderSelection& criteria) = 0;
    
    /**
     * Create mock crypto operations for testing
     * 
     * @return Mock crypto operations instance
     */
    virtual std::unique_ptr<ICryptoOperations> create_mock_operations() = 0;

protected:
    ICryptoOperationsFactory() = default;
};

/**
 * Enhanced RAII wrapper for crypto operations management
 * 
 * Provides automatic resource management, failover support, health monitoring,
 * and load balancing for crypto operations instances.
 */
class DTLS_API CryptoOperationsManager {
public:
    explicit CryptoOperationsManager(const ProviderSelection& criteria = {});
    explicit CryptoOperationsManager(const std::string& provider_name);
    explicit CryptoOperationsManager(const ProviderPoolConfig& pool_config);
    ~CryptoOperationsManager();
    
    // Non-copyable, movable
    CryptoOperationsManager(const CryptoOperationsManager&) = delete;
    CryptoOperationsManager& operator=(const CryptoOperationsManager&) = delete;
    CryptoOperationsManager(CryptoOperationsManager&&) noexcept;
    CryptoOperationsManager& operator=(CryptoOperationsManager&&) noexcept;
    
    // Operations access with automatic failover
    bool is_initialized() const { return current_operations_ != nullptr; }
    ICryptoOperations* get() const;
    ICryptoOperations* operator->() const;
    ICryptoOperations& operator*() const;
    
    // Provider information
    std::string current_provider_name() const;
    ProviderCapabilities current_capabilities() const;
    EnhancedProviderCapabilities current_enhanced_capabilities() const;
    
    // Enhanced failover and load balancing
    Result<void> switch_to_provider(const std::string& name);
    Result<void> switch_to_fallback();
    Result<void> switch_to_best_provider();
    bool has_fallback() const { return !fallback_providers_.empty(); }
    
    // Health monitoring and automatic recovery
    Result<void> perform_health_check();
    bool is_provider_healthy() const;
    Result<void> enable_auto_recovery(bool enable = true);
    
    // Load balancing and provider pool management
    Result<void> add_provider_to_pool(const std::string& provider_name);
    Result<void> remove_provider_from_pool(const std::string& provider_name);
    std::vector<std::string> get_provider_pool() const;
    Result<void> rebalance_provider_pool();
    
    // Statistics and monitoring
    struct OperationsStats {
        size_t total_operations{0};
        size_t successful_operations{0};
        size_t failed_operations{0};
        size_t provider_switches{0};
        size_t auto_recoveries{0};
        std::chrono::milliseconds average_operation_time{0};
        std::chrono::steady_clock::time_point last_operation;
        std::chrono::steady_clock::time_point last_failure;
        std::chrono::steady_clock::time_point last_recovery;
    };
    
    OperationsStats get_stats() const { return stats_; }
    void reset_stats();
    
    // Configuration
    void set_pool_config(const ProviderPoolConfig& config);
    ProviderPoolConfig get_pool_config() const { return pool_config_; }

private:
    // Provider management
    void initialize_operations(const std::string& name);
    void initialize_best_operations(const ProviderSelection& criteria);
    void cleanup_current_operations();
    Result<void> try_provider_recovery();
    
    // Health monitoring
    void start_health_monitoring();
    void stop_health_monitoring();
    void health_monitoring_loop();
    
    // Load balancing
    std::string select_next_provider();
    void update_provider_metrics(const std::string& provider_name, bool success, std::chrono::milliseconds duration);
    
    // Core operations state
    std::unique_ptr<ICryptoOperations> current_operations_;
    std::string current_provider_name_;
    
    // Failover and pool management
    std::vector<std::string> fallback_providers_;
    std::vector<std::string> provider_pool_;
    ProviderSelection selection_criteria_;
    ProviderPoolConfig pool_config_;
    
    // Health monitoring
    std::atomic<bool> auto_recovery_enabled_{true};
    std::atomic<bool> health_monitoring_enabled_{false};
    std::thread health_monitoring_thread_;
    std::atomic<bool> shutdown_requested_{false};
    
    // Statistics
    mutable OperationsStats stats_;
    std::unordered_map<std::string, ProviderPerformanceMetrics> provider_metrics_;
    
    // Thread safety
    mutable std::mutex operations_mutex_;
    mutable std::mutex stats_mutex_;
    
    std::chrono::steady_clock::time_point creation_time_;
};

// === Utility Functions ===

/**
 * Create default crypto operations instance
 * 
 * @return Default crypto operations or error details
 */
DTLS_API Result<std::unique_ptr<ICryptoOperations>> create_crypto_operations(
    const std::string& provider_name = "");

/**
 * Create crypto operations with selection criteria
 * 
 * @param criteria Provider selection criteria
 * @return Crypto operations or error details
 */
DTLS_API Result<std::unique_ptr<ICryptoOperations>> create_best_crypto_operations(
    const ProviderSelection& criteria = {});

/**
 * Create mock crypto operations for testing
 * 
 * @return Mock crypto operations instance
 */
DTLS_API std::unique_ptr<ICryptoOperations> create_mock_crypto_operations();

/**
 * Get global crypto operations factory
 * 
 * @return Reference to global factory instance
 */
DTLS_API ICryptoOperationsFactory& get_crypto_operations_factory();

/**
 * Create crypto operations manager with pool support
 * 
 * @param pool_config Provider pool configuration
 * @return Crypto operations manager with pool support
 */
DTLS_API std::unique_ptr<CryptoOperationsManager> create_crypto_operations_manager(
    const ProviderPoolConfig& pool_config = {});

/**
 * Create crypto operations with automatic provider selection and failover
 * 
 * @param criteria Provider selection criteria
 * @param enable_failover Enable automatic failover
 * @return Crypto operations with enhanced capabilities
 */
DTLS_API Result<std::unique_ptr<ICryptoOperations>> create_resilient_crypto_operations(
    const ProviderSelection& criteria = {},
    bool enable_failover = true);

/**
 * Create crypto operations with load balancing
 * 
 * @param pool_config Provider pool configuration
 * @return Load-balanced crypto operations
 */
DTLS_API Result<std::unique_ptr<ICryptoOperations>> create_load_balanced_crypto_operations(
    const ProviderPoolConfig& pool_config = {});

/**
 * Validate crypto provider compatibility with requirements
 * 
 * @param provider_name Provider to check
 * @param criteria Requirements to validate against
 * @return Compatibility result with score and recommendations
 */
DTLS_API Result<ProviderCompatibilityResult> validate_crypto_provider_compatibility(
    const std::string& provider_name,
    const ProviderSelection& criteria);

/**
 * Perform comprehensive crypto provider health check
 * 
 * @param provider_name Provider to check (empty for all)
 * @return Health check results
 */
DTLS_API Result<std::unordered_map<std::string, ProviderHealth>> perform_crypto_provider_health_check(
    const std::string& provider_name = "");

/**
 * Provider-agnostic crypto operation wrapper
 * 
 * This class provides a completely provider-agnostic interface that can
 * automatically select the best provider for each operation, reducing
 * coupling to specific crypto implementations.
 */
class DTLS_API AgnosticCryptoOperations : public ICryptoOperations {
public:
    /**
     * Create agnostic crypto operations with automatic provider selection
     * 
     * @param default_criteria Default provider selection criteria
     * @param enable_per_operation_selection Enable per-operation provider selection
     */
    explicit AgnosticCryptoOperations(
        const ProviderSelection& default_criteria = {},
        bool enable_per_operation_selection = false);
    
    ~AgnosticCryptoOperations() override;
    
    // Configure per-operation provider preferences
    void set_operation_provider_preference(
        const std::string& operation_category,
        const ProviderSelection& criteria);
    
    // ICryptoOperations implementation with automatic provider selection
    Result<std::vector<uint8_t>> generate_random(
        size_t length,
        const std::vector<uint8_t>& additional_entropy = {}) override;
    
    Result<Random> generate_dtls_random() override;
    Result<std::vector<uint8_t>> generate_session_id(size_t length = 32) override;
    Result<ConnectionID> generate_connection_id(size_t length = 8) override;
    
    Result<std::vector<uint8_t>> hkdf_expand_label(
        const std::vector<uint8_t>& secret,
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t length,
        HashAlgorithm hash_algo = HashAlgorithm::SHA256) override;
    
    Result<KeySchedule> derive_traffic_keys(
        const std::vector<uint8_t>& master_secret,
        CipherSuite cipher_suite,
        const std::vector<uint8_t>& context) override;
    
    Result<AEADEncryptionOutput> aead_encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher) override;
    
    Result<std::vector<uint8_t>> aead_decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher) override;
    
    Result<std::vector<uint8_t>> compute_hash(
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    
    Result<std::vector<uint8_t>> compute_hmac(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    
    Result<bool> verify_hmac(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac,
        HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    
    Result<std::vector<uint8_t>> sign_data(
        const std::vector<uint8_t>& data,
        const PrivateKey& private_key,
        SignatureScheme scheme) override;
    
    Result<bool> verify_signature(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature,
        const PublicKey& public_key,
        SignatureScheme scheme) override;
    
    Result<bool> verify_certificate_signature(
        const std::vector<uint8_t>& transcript_hash,
        const std::vector<uint8_t>& signature,
        const PublicKey& public_key,
        SignatureScheme scheme,
        bool is_server_context = true) override;
    
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
        generate_key_pair(NamedGroup group) override;
    
    Result<std::vector<uint8_t>> key_exchange(
        const PrivateKey& private_key,
        const std::vector<uint8_t>& peer_public_key,
        NamedGroup group) override;
    
    Result<bool> validate_certificate_chain(
        const CertificateChain& chain,
        const std::vector<uint8_t>& root_ca_store,
        const std::string& hostname = "",
        bool check_revocation = true) override;
    
    Result<std::unique_ptr<PublicKey>> extract_public_key(
        const std::vector<uint8_t>& certificate_der) override;
    
    Result<std::vector<uint8_t>> encrypt_sequence_number(
        uint64_t sequence_number,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& sample) override;
    
    Result<uint64_t> decrypt_sequence_number(
        const std::vector<uint8_t>& encrypted_sequence_number,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& sample) override;
    
    Result<bool> validate_record_mac(
        const std::vector<uint8_t>& mac_key,
        const std::vector<uint8_t>& sequence_number_key,
        const std::vector<uint8_t>& record_header,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& expected_mac,
        ContentType content_type,
        Epoch epoch,
        SequenceNumber sequence_number) override;
    
    // Provider information (aggregated from all providers)
    std::string provider_name() const override;
    ProviderCapabilities capabilities() const override;
    bool supports_cipher_suite(CipherSuite cipher_suite) const override;
    bool supports_named_group(NamedGroup group) const override;
    bool supports_signature_scheme(SignatureScheme scheme) const override;
    
    // Enhanced provider management
    std::vector<std::string> get_active_providers() const;
    Result<void> refresh_provider_capabilities();
    void enable_provider_switching(bool enable) { provider_switching_enabled_ = enable; }
    bool is_provider_switching_enabled() const { return provider_switching_enabled_; }

private:
    // Operation category definitions
    static constexpr const char* OP_CATEGORY_RANDOM = "random";
    static constexpr const char* OP_CATEGORY_HASH = "hash";
    static constexpr const char* OP_CATEGORY_AEAD = "aead";
    static constexpr const char* OP_CATEGORY_SIGNATURE = "signature";
    static constexpr const char* OP_CATEGORY_KEY_EXCHANGE = "key_exchange";
    static constexpr const char* OP_CATEGORY_CERTIFICATE = "certificate";
    static constexpr const char* OP_CATEGORY_DTLS_SPECIFIC = "dtls_specific";
    
    // Get best provider for specific operation
    Result<ICryptoOperations*> get_best_provider_for_operation(
        const std::string& operation_category,
        const std::function<bool(const ProviderCapabilities&)>& capability_checker = nullptr);
    
    // Provider caching and management
    void refresh_provider_cache();
    void cleanup_unused_providers();
    
    // Configuration
    ProviderSelection default_criteria_;
    std::unordered_map<std::string, ProviderSelection> operation_criteria_;
    bool enable_per_operation_selection_;
    bool provider_switching_enabled_{true};
    
    // Provider cache
    std::unordered_map<std::string, std::unique_ptr<ICryptoOperations>> provider_cache_;
    std::unordered_map<std::string, ProviderCapabilities> capability_cache_;
    std::chrono::steady_clock::time_point last_cache_refresh_;
    
    // Thread safety
    mutable std::shared_mutex cache_mutex_;
    
    // Statistics
    std::unordered_map<std::string, size_t> provider_usage_count_;
    std::unordered_map<std::string, std::chrono::milliseconds> provider_avg_time_;
};

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_OPERATIONS_H