#ifndef DTLS_CRYPTO_HARDWARE_ACCELERATED_PROVIDER_H
#define DTLS_CRYPTO_HARDWARE_ACCELERATED_PROVIDER_H

#include "dtls/crypto/provider.h"
#include "dtls/crypto/hardware_acceleration.h"
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <thread>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * @brief Hardware-accelerated crypto provider wrapper
 * 
 * This class wraps an existing crypto provider and adds hardware acceleration
 * capabilities, performance monitoring, and adaptive optimization.
 */
class DTLS_API HardwareAcceleratedProvider : public CryptoProvider {
public:
    /**
     * @brief Construct with base provider and hardware profile
     */
    explicit HardwareAcceleratedProvider(
        std::unique_ptr<CryptoProvider> base_provider,
        const HardwareAccelerationProfile& hw_profile);
    
    virtual ~HardwareAcceleratedProvider() = default;

    // Base provider interface
    std::string name() const override;
    std::string version() const override;
    ProviderCapabilities capabilities() const override;
    bool is_available() const override;
    Result<void> initialize() override;
    void cleanup() override;

    // Cryptographic operations - enhanced with hardware acceleration
    Result<std::vector<uint8_t>> generate_random(const RandomParams& params) override;
    Result<std::vector<uint8_t>> derive_key_hkdf(const KeyDerivationParams& params) override;
    Result<std::vector<uint8_t>> derive_key_pbkdf2(const KeyDerivationParams& params) override;
    
    // AEAD operations with hardware optimization
    Result<std::vector<uint8_t>> aead_encrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& plaintext) override;
    
    Result<std::vector<uint8_t>> aead_decrypt(
        const AEADParams& params,
        const std::vector<uint8_t>& ciphertext) override;
    
    Result<AEADEncryptionOutput> encrypt_aead(const AEADEncryptionParams& params) override;
    Result<std::vector<uint8_t>> decrypt_aead(const AEADDecryptionParams& params) override;
    
    // Hash operations
    Result<std::vector<uint8_t>> compute_hash(const HashParams& params) override;
    Result<std::vector<uint8_t>> compute_hmac(const HMACParams& params) override;
    Result<bool> verify_hmac(const MACValidationParams& params) override;
    Result<bool> validate_record_mac(const RecordMACParams& params) override;
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
    
    Result<bool> verify_dtls_certificate_signature(
        const DTLSCertificateVerifyParams& params,
        const std::vector<uint8_t>& signature) override;
    
    // Key exchange
    Result<std::pair<std::unique_ptr<PrivateKey>, std::unique_ptr<PublicKey>>> 
        generate_key_pair(NamedGroup group) override;
    
    Result<std::vector<uint8_t>> perform_key_exchange(const KeyExchangeParams& params) override;
    
    // ML-KEM Post-Quantum Key Encapsulation (FIPS 203)
    Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> 
        mlkem_generate_keypair(const MLKEMKeyGenParams& params) override;
    
    Result<MLKEMEncapResult> 
        mlkem_encapsulate(const MLKEMEncapParams& params) override;
    
    Result<std::vector<uint8_t>> 
        mlkem_decapsulate(const MLKEMDecapParams& params) override;
    
    // Pure ML-KEM Key Exchange (draft-connolly-tls-mlkem-key-agreement-05)
    Result<PureMLKEMKeyExchangeResult>
        perform_pure_mlkem_key_exchange(const PureMLKEMKeyExchangeParams& params) override;
    
    // Hybrid Post-Quantum + Classical Key Exchange
    Result<HybridKeyExchangeResult> 
        perform_hybrid_key_exchange(const HybridKeyExchangeParams& params) override;
    
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
    
    // Enhanced provider features
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
    
    // Async operations
    bool supports_async_operations() const override;
    Result<std::future<std::vector<uint8_t>>> async_derive_key_hkdf(
        const KeyDerivationParams& params) override;
    Result<std::future<AEADEncryptionOutput>> async_encrypt_aead(
        const AEADEncryptionParams& params) override;
    Result<std::future<std::vector<uint8_t>>> async_decrypt_aead(
        const AEADDecryptionParams& params) override;
    
    // Hardware acceleration interface
    Result<HardwareAccelerationProfile> get_hardware_profile() const override;
    Result<void> enable_hardware_acceleration(HardwareCapability capability) override;
    Result<void> disable_hardware_acceleration(HardwareCapability capability) override;
    bool is_hardware_accelerated(const std::string& operation) const override;
    Result<float> benchmark_hardware_operation(const std::string& operation) override;
    
    // Zero-copy hardware operations
    Result<void> aead_encrypt_inplace(
        const AEADParams& params,
        std::vector<uint8_t>& data,
        size_t plaintext_len) override;
    
    Result<void> aead_decrypt_inplace(
        const AEADParams& params,
        std::vector<uint8_t>& data,
        size_t ciphertext_len) override;
    
    // Vectorized operations for multiple connections
    Result<std::vector<AEADEncryptionOutput>> batch_encrypt_aead(
        const std::vector<AEADEncryptionParams>& params_batch) override;
    
    Result<std::vector<std::vector<uint8_t>>> batch_decrypt_aead(
        const std::vector<AEADDecryptionParams>& params_batch) override;

private:
    std::unique_ptr<CryptoProvider> base_provider_;
    HardwareAccelerationProfile hw_profile_;
    mutable std::mutex hw_mutex_;
    
    // Performance tracking
    mutable std::atomic<uint64_t> operations_count_{0};
    mutable std::atomic<uint64_t> hw_accelerated_ops_{0};
    mutable std::atomic<uint64_t> sw_fallback_ops_{0};
    mutable std::chrono::steady_clock::time_point last_benchmark_time_;
    
    // Hardware acceleration state
    std::unordered_map<HardwareCapability, bool> enabled_capabilities_;
    std::unordered_map<std::string, float> operation_speedups_;
    std::atomic<bool> adaptive_selection_enabled_{true};
    
    // Helper methods
    bool should_use_hardware_for_operation(const std::string& operation) const;
    void update_performance_metrics(const std::string& operation, 
                                   std::chrono::microseconds duration,
                                   bool used_hardware) const;
    float get_hardware_speedup(const std::string& operation) const;
    std::string classify_operation(const AEADParams& params) const;
    std::string classify_operation(const HashParams& params) const;
    std::string classify_operation(const SignatureParams& params) const;
    
    // Batch operation helpers
    Result<std::vector<AEADEncryptionOutput>> batch_encrypt_simd(
        const std::vector<AEADEncryptionParams>& params_batch);
    
    Result<std::vector<std::vector<uint8_t>>> batch_decrypt_simd(
        const std::vector<AEADDecryptionParams>& params_batch);
};

/**
 * @brief Factory for creating hardware-accelerated providers
 */
class DTLS_API HardwareAcceleratedProviderFactory {
public:
    /**
     * @brief Create hardware-accelerated provider wrapping a base provider
     */
    static Result<std::unique_ptr<HardwareAcceleratedProvider>> create(
        std::unique_ptr<CryptoProvider> base_provider);
    
    /**
     * @brief Create optimized provider based on hardware profile
     */
    static Result<std::unique_ptr<HardwareAcceleratedProvider>> create_optimized(
        const std::string& base_provider_name = "");
    
    /**
     * @brief Get best provider for current hardware
     */
    static Result<std::string> get_optimal_base_provider();

private:
    static Result<HardwareAccelerationProfile> detect_and_cache_hardware();
    static HardwareAccelerationProfile cached_hw_profile_;
    static std::atomic<bool> hw_profile_detected_;
    static std::mutex detection_mutex_;
};

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_HARDWARE_ACCELERATED_PROVIDER_H