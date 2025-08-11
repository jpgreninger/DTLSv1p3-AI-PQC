#ifndef DTLS_CRYPTO_OPERATIONS_IMPL_H
#define DTLS_CRYPTO_OPERATIONS_IMPL_H

#include <dtls/crypto/operations.h>
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>
#include <memory>
#include <shared_mutex>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * Default implementation of ICryptoOperations
 * 
 * This implementation wraps a CryptoProvider instance and provides
 * the high-level crypto operations interface while maintaining
 * RFC 9147 compliance and performance characteristics.
 */
class DTLS_API CryptoOperationsImpl : public ICryptoOperations {
public:
    /**
     * Constructor with existing provider
     * 
     * @param provider Initialized crypto provider
     */
    explicit CryptoOperationsImpl(std::unique_ptr<CryptoProvider> provider);
    
    /**
     * Constructor with provider name
     * 
     * @param provider_name Name of provider to create
     */
    explicit CryptoOperationsImpl(const std::string& provider_name = "");
    
    /**
     * Constructor with selection criteria
     * 
     * @param criteria Provider selection criteria
     */
    explicit CryptoOperationsImpl(const ProviderSelection& criteria);
    
    ~CryptoOperationsImpl() override;
    
    // Non-copyable, movable
    CryptoOperationsImpl(const CryptoOperationsImpl&) = delete;
    CryptoOperationsImpl& operator=(const CryptoOperationsImpl&) = delete;
    CryptoOperationsImpl(CryptoOperationsImpl&&) noexcept;
    CryptoOperationsImpl& operator=(CryptoOperationsImpl&&) noexcept;
    
    // === Random Number Generation Operations ===
    Result<std::vector<uint8_t>> generate_random(
        size_t length,
        const std::vector<uint8_t>& additional_entropy = {}) override;
    
    Result<Random> generate_dtls_random() override;
    Result<std::vector<uint8_t>> generate_session_id(size_t length = 32) override;
    Result<ConnectionID> generate_connection_id(size_t length = 8) override;
    
    // === Key Derivation Operations ===
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
    
    // === AEAD Encryption/Decryption Operations ===
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
    
    // === Hash and HMAC Operations ===
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
    
    // === Digital Signature Operations ===
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
    
    // === Key Exchange Operations ===
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>>
        generate_key_pair(NamedGroup group) override;
    
    Result<std::vector<uint8_t>> key_exchange(
        const PrivateKey& private_key,
        const std::vector<uint8_t>& peer_public_key,
        NamedGroup group) override;
    
    // === Certificate Operations ===
    Result<bool> validate_certificate_chain(
        const CertificateChain& chain,
        const std::vector<uint8_t>& root_ca_store,
        const std::string& hostname = "",
        bool check_revocation = true) override;
    
    Result<std::unique_ptr<PublicKey>> extract_public_key(
        const std::vector<uint8_t>& certificate_der) override;
    
    // === DTLS v1.3 Specific Operations ===
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
    
    // === Provider Information ===
    std::string provider_name() const override;
    ProviderCapabilities capabilities() const override;
    bool supports_cipher_suite(CipherSuite cipher_suite) const override;
    bool supports_named_group(NamedGroup group) const override;
    bool supports_signature_scheme(SignatureScheme scheme) const override;

private:
    // Initialize provider
    Result<void> initialize_provider();
    
    // Helper methods for parameter conversion
    RandomParams create_random_params(size_t length, const std::vector<uint8_t>& entropy = {});
    KeyDerivationParams create_key_derivation_params(
        const std::vector<uint8_t>& secret,
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t length,
        HashAlgorithm hash_algo);
    AEADEncryptionParams create_aead_encryption_params(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher);
    AEADDecryptionParams create_aead_decryption_params(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data,
        AEADCipher cipher);
    HashParams create_hash_params(const std::vector<uint8_t>& data, HashAlgorithm algorithm);
    HMACParams create_hmac_params(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        HashAlgorithm algorithm);
    MACValidationParams create_mac_validation_params(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac,
        HashAlgorithm algorithm);
    SignatureParams create_signature_params(
        const std::vector<uint8_t>& data,
        SignatureScheme scheme,
        const PrivateKey* private_key = nullptr,
        const PublicKey* public_key = nullptr);
    KeyExchangeParams create_key_exchange_params(
        NamedGroup group,
        const std::vector<uint8_t>& peer_public_key,
        const PrivateKey* private_key);
    DTLSCertificateVerifyParams create_certificate_verify_params(
        const std::vector<uint8_t>& transcript_hash,
        SignatureScheme scheme,
        const PublicKey* public_key,
        bool is_server_context);
    RecordMACParams create_record_mac_params(
        const std::vector<uint8_t>& mac_key,
        const std::vector<uint8_t>& sequence_number_key,
        const std::vector<uint8_t>& record_header,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& expected_mac,
        ContentType content_type,
        Epoch epoch,
        SequenceNumber sequence_number);
    
    // Member variables
    std::unique_ptr<CryptoProvider> provider_;
    std::string provider_name_;
    bool initialized_{false};
};

/**
 * Mock crypto operations for testing
 * 
 * Provides deterministic crypto operations for unit testing
 * without requiring actual crypto computations.
 */
class DTLS_API MockCryptoOperations : public ICryptoOperations {
public:
    MockCryptoOperations();
    ~MockCryptoOperations() override = default;
    
    // Configuration methods for testing
    void set_random_bytes(const std::vector<uint8_t>& bytes);
    void set_hash_result(const std::vector<uint8_t>& hash);
    void set_hmac_result(const std::vector<uint8_t>& hmac);
    void set_signature_result(const std::vector<uint8_t>& signature);
    void set_key_exchange_result(const std::vector<uint8_t>& shared_secret);
    void set_verification_result(bool result);
    void set_aead_encryption_result(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag);
    void set_aead_decryption_result(const std::vector<uint8_t>& plaintext);
    
    // Call tracking for verification
    size_t random_call_count() const { return random_call_count_; }
    size_t hash_call_count() const { return hash_call_count_; }
    size_t hmac_call_count() const { return hmac_call_count_; }
    size_t signature_call_count() const { return signature_call_count_; }
    size_t verification_call_count() const { return verification_call_count_; }
    size_t aead_encrypt_call_count() const { return aead_encrypt_call_count_; }
    size_t aead_decrypt_call_count() const { return aead_decrypt_call_count_; }
    
    void reset_call_counts();
    
    // ICryptoOperations implementation (returns mocked results)
    Result<std::vector<uint8_t>> generate_random(size_t length, const std::vector<uint8_t>& additional_entropy = {}) override;
    Result<Random> generate_dtls_random() override;
    Result<std::vector<uint8_t>> generate_session_id(size_t length = 32) override;
    Result<ConnectionID> generate_connection_id(size_t length = 8) override;
    
    Result<std::vector<uint8_t>> hkdf_expand_label(
        const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& context,
        size_t length, HashAlgorithm hash_algo = HashAlgorithm::SHA256) override;
    Result<KeySchedule> derive_traffic_keys(
        const std::vector<uint8_t>& master_secret, CipherSuite cipher_suite, const std::vector<uint8_t>& context) override;
    
    Result<AEADEncryptionOutput> aead_encrypt(
        const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& additional_data, AEADCipher cipher) override;
    Result<std::vector<uint8_t>> aead_decrypt(
        const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag, const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& additional_data, AEADCipher cipher) override;
    
    Result<std::vector<uint8_t>> compute_hash(const std::vector<uint8_t>& data, HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    Result<std::vector<uint8_t>> compute_hmac(
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    Result<bool> verify_hmac(
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& expected_mac, HashAlgorithm algorithm = HashAlgorithm::SHA256) override;
    
    Result<std::vector<uint8_t>> sign_data(
        const std::vector<uint8_t>& data, const PrivateKey& private_key, SignatureScheme scheme) override;
    Result<bool> verify_signature(
        const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature,
        const PublicKey& public_key, SignatureScheme scheme) override;
    Result<bool> verify_certificate_signature(
        const std::vector<uint8_t>& transcript_hash, const std::vector<uint8_t>& signature,
        const PublicKey& public_key, SignatureScheme scheme, bool is_server_context = true) override;
    
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> generate_key_pair(NamedGroup group) override;
    Result<std::vector<uint8_t>> key_exchange(
        const PrivateKey& private_key, const std::vector<uint8_t>& peer_public_key, NamedGroup group) override;
    
    Result<bool> validate_certificate_chain(
        const CertificateChain& chain, const std::vector<uint8_t>& root_ca_store,
        const std::string& hostname = "", bool check_revocation = true) override;
    Result<std::unique_ptr<PublicKey>> extract_public_key(const std::vector<uint8_t>& certificate_der) override;
    
    Result<std::vector<uint8_t>> encrypt_sequence_number(
        uint64_t sequence_number, const std::vector<uint8_t>& key, const std::vector<uint8_t>& sample) override;
    Result<uint64_t> decrypt_sequence_number(
        const std::vector<uint8_t>& encrypted_sequence_number, const std::vector<uint8_t>& key, const std::vector<uint8_t>& sample) override;
    Result<bool> validate_record_mac(
        const std::vector<uint8_t>& mac_key, const std::vector<uint8_t>& sequence_number_key,
        const std::vector<uint8_t>& record_header, const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& expected_mac, ContentType content_type, Epoch epoch, SequenceNumber sequence_number) override;
    
    std::string provider_name() const override { return "Mock"; }
    ProviderCapabilities capabilities() const override;
    bool supports_cipher_suite(CipherSuite cipher_suite) const override { (void)cipher_suite; return true; }
    bool supports_named_group(NamedGroup group) const override { (void)group; return true; }
    bool supports_signature_scheme(SignatureScheme scheme) const override { (void)scheme; return true; }

private:
    // Mock result storage
    std::vector<uint8_t> mock_random_bytes_;
    std::vector<uint8_t> mock_hash_result_;
    std::vector<uint8_t> mock_hmac_result_;
    std::vector<uint8_t> mock_signature_result_;
    std::vector<uint8_t> mock_key_exchange_result_;
    std::vector<uint8_t> mock_aead_ciphertext_;
    std::vector<uint8_t> mock_aead_tag_;
    std::vector<uint8_t> mock_aead_plaintext_;
    bool mock_verification_result_{true};
    
    // Call counters
    mutable size_t random_call_count_{0};
    mutable size_t hash_call_count_{0};
    mutable size_t hmac_call_count_{0};
    mutable size_t signature_call_count_{0};
    mutable size_t verification_call_count_{0};
    mutable size_t aead_encrypt_call_count_{0};
    mutable size_t aead_decrypt_call_count_{0};
};

/**
 * Enhanced crypto operations factory with dependency reduction features
 */
class DTLS_API CryptoOperationsFactory : public ICryptoOperationsFactory {
public:
    static CryptoOperationsFactory& instance();
    
    Result<std::unique_ptr<ICryptoOperations>> 
        create_operations(const std::string& provider_name = "") override;
    
    Result<std::unique_ptr<ICryptoOperations>>
        create_operations(const ProviderSelection& criteria) override;
    
    std::unique_ptr<ICryptoOperations> create_mock_operations() override;
    
    // Enhanced factory methods for dependency reduction
    Result<std::unique_ptr<ICryptoOperations>>
        create_cached_operations(const std::string& provider_name);
    
    Result<std::unique_ptr<ICryptoOperations>>
        create_pooled_operations(const ProviderPoolConfig& pool_config);
    
    std::unique_ptr<AgnosticCryptoOperations>
        create_agnostic_operations(
            const ProviderSelection& default_criteria = {},
            bool enable_per_operation_selection = false);
    
    Result<std::unique_ptr<ICryptoOperations>>
        create_resilient_operations(
            const ProviderSelection& criteria,
            const std::vector<std::string>& fallback_providers);
    
    // Caching and optimization
    void enable_operation_caching(bool enable) { caching_enabled_ = enable; }
    void set_cache_size_limit(size_t limit) { cache_size_limit_ = limit; }
    void clear_operation_cache();
    size_t get_cache_hit_count() const { return cache_hit_count_; }
    size_t get_cache_miss_count() const { return cache_miss_count_; }
    double get_cache_hit_rate() const;
    
    // Factory statistics
    struct FactoryStats {
        size_t total_created{0};
        size_t cached_created{0};
        size_t pooled_created{0};
        size_t agnostic_created{0};
        size_t resilient_created{0};
        size_t mock_created{0};
        std::chrono::steady_clock::time_point creation_start_time;
    };
    
    FactoryStats get_factory_stats() const { return factory_stats_; }
    void reset_factory_stats();

private:
    CryptoOperationsFactory();
    ~CryptoOperationsFactory();
    CryptoOperationsFactory(const CryptoOperationsFactory&) = delete;
    CryptoOperationsFactory& operator=(const CryptoOperationsFactory&) = delete;
    
    // Cache management
    struct CachedOperations {
        std::unique_ptr<ICryptoOperations> operations;
        std::chrono::steady_clock::time_point created_time;
        std::chrono::steady_clock::time_point last_used;
        size_t use_count{0};
    };
    
    std::string generate_cache_key(const std::string& provider_name, const ProviderSelection& criteria) const;
    void cleanup_expired_cache_entries();
    
    // Member variables
    mutable std::shared_mutex factory_mutex_;
    std::unordered_map<std::string, CachedOperations> operation_cache_;
    
    // Configuration
    bool caching_enabled_{true};
    size_t cache_size_limit_{50};
    std::chrono::minutes cache_expiry_time_{30};
    
    // Statistics
    mutable FactoryStats factory_stats_;
    mutable std::atomic<size_t> cache_hit_count_{0};
    mutable std::atomic<size_t> cache_miss_count_{0};
    
    // Cleanup thread
    std::thread cache_cleanup_thread_;
    std::atomic<bool> cleanup_shutdown_requested_{false};
    std::condition_variable cleanup_cv_;
    std::mutex cleanup_mutex_;
};

/**
 * Provider capability matcher for intelligent provider selection
 */
class DTLS_API ProviderCapabilityMatcher {
public:
    /**
     * Find the best provider for specific requirements
     * 
     * @param criteria Selection criteria
     * @return Best matching provider name or error
     */
    static Result<std::string> find_best_provider(const ProviderSelection& criteria);
    
    /**
     * Check if provider meets requirements
     * 
     * @param provider_name Provider to check
     * @param criteria Requirements to validate
     * @return Compatibility result with score
     */
    static Result<ProviderCompatibilityResult> check_compatibility(
        const std::string& provider_name,
        const ProviderSelection& criteria);
    
    /**
     * Rank all providers by compatibility score
     * 
     * @param criteria Selection criteria
     * @return Providers ranked by compatibility (best first)
     */
    static std::vector<std::pair<std::string, double>> rank_providers(
        const ProviderSelection& criteria);
    
    /**
     * Find providers with specific capability
     * 
     * @param capability_checker Function to check specific capability
     * @return List of compatible providers
     */
    static std::vector<std::string> find_providers_with_capability(
        const std::function<bool(const ProviderCapabilities&)>& capability_checker);
    
    /**
     * Create compatibility matrix for all providers
     * 
     * @param criteria_list List of criteria to test
     * @return Compatibility matrix [provider][criteria] -> score
     */
    static std::unordered_map<std::string, std::unordered_map<size_t, double>>
        create_compatibility_matrix(const std::vector<ProviderSelection>& criteria_list);

private:
    static double calculate_compatibility_score(
        const ProviderCapabilities& capabilities,
        const ProviderSelection& criteria);
    
    static bool meets_basic_requirements(
        const ProviderCapabilities& capabilities,
        const ProviderSelection& criteria);
    
    static double calculate_feature_score(
        const ProviderCapabilities& capabilities,
        const ProviderSelection& criteria);
    
    static double calculate_performance_score(
        const ProviderCapabilities& capabilities,
        const ProviderSelection& criteria);
};

/**
 * Crypto operations with automatic provider failover
 * 
 * This class provides crypto operations with automatic failover to backup
 * providers when the primary provider fails, reducing dependency on any
 * single crypto implementation.
 */
class DTLS_API ResilientCryptoOperations : public ICryptoOperations {
public:
    /**
     * Create resilient crypto operations with fallback providers
     * 
     * @param primary_criteria Primary provider selection criteria
     * @param fallback_providers List of fallback provider names
     * @param auto_recovery Enable automatic recovery to primary provider
     */
    ResilientCryptoOperations(
        const ProviderSelection& primary_criteria,
        const std::vector<std::string>& fallback_providers,
        bool auto_recovery = true);
    
    ~ResilientCryptoOperations() override;
    
    // Failover configuration
    void set_failover_threshold(size_t consecutive_failures) { failover_threshold_ = consecutive_failures; }
    void set_recovery_check_interval(std::chrono::seconds interval) { recovery_check_interval_ = interval; }
    void enable_auto_recovery(bool enable) { auto_recovery_enabled_ = enable; }
    
    // Status monitoring
    bool is_using_primary_provider() const { return current_provider_index_ == 0; }
    std::string get_current_provider_name() const;
    size_t get_current_failure_count() const { return consecutive_failures_; }
    std::chrono::steady_clock::time_point get_last_failover_time() const { return last_failover_time_; }
    
    // Manual provider management
    Result<void> force_failover_to_next();
    Result<void> attempt_recovery_to_primary();
    std::vector<std::string> get_available_providers() const;
    
    // ICryptoOperations implementation with automatic failover
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
    
    // Provider information (from current active provider)
    std::string provider_name() const override;
    ProviderCapabilities capabilities() const override;
    bool supports_cipher_suite(CipherSuite cipher_suite) const override;
    bool supports_named_group(NamedGroup group) const override;
    bool supports_signature_scheme(SignatureScheme scheme) const override;
    
    // Resilient operation statistics
    struct ResilienceStats {
        size_t total_operations{0};
        size_t successful_operations{0};
        size_t failed_operations{0};
        size_t failovers_performed{0};
        size_t recoveries_attempted{0};
        size_t successful_recoveries{0};
        std::chrono::steady_clock::time_point last_operation;
        std::chrono::steady_clock::time_point last_failover;
        std::chrono::steady_clock::time_point last_recovery;
        std::vector<std::string> recent_errors;
    };
    
    ResilienceStats get_resilience_stats() const { return resilience_stats_; }
    void reset_resilience_stats();

private:
    // Failover management
    template<typename Operation, typename... Args>
    auto execute_with_failover(Operation op, Args&&... args) -> decltype(op(std::forward<Args>(args)...));
    
    Result<void> attempt_failover();
    void start_recovery_monitoring();
    void stop_recovery_monitoring();
    void recovery_monitoring_loop();
    
    // Provider management
    Result<std::unique_ptr<ICryptoOperations>> create_provider_operations(const std::string& provider_name);
    void update_failure_statistics(bool success);
    
    // Configuration
    ProviderSelection primary_criteria_;
    std::vector<std::string> fallback_providers_;
    size_t failover_threshold_{3};
    bool auto_recovery_enabled_{true};
    std::chrono::seconds recovery_check_interval_{60};
    
    // Current state
    std::vector<std::unique_ptr<ICryptoOperations>> provider_operations_;
    size_t current_provider_index_{0};
    size_t consecutive_failures_{0};
    std::chrono::steady_clock::time_point last_failover_time_;
    
    // Recovery monitoring
    std::thread recovery_thread_;
    std::atomic<bool> recovery_shutdown_requested_{false};
    
    // Statistics
    mutable ResilienceStats resilience_stats_;
    mutable std::mutex stats_mutex_;
    mutable std::mutex provider_mutex_;
};

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_OPERATIONS_IMPL_H