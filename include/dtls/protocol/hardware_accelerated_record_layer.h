#ifndef DTLS_PROTOCOL_HARDWARE_ACCELERATED_RECORD_LAYER_H
#define DTLS_PROTOCOL_HARDWARE_ACCELERATED_RECORD_LAYER_H

#include "dtls/protocol/record_layer_interface.h"
#include "dtls/crypto/hardware_zero_copy.h"
#include "dtls/crypto/hardware_accelerated_provider.h"
#include <memory>
#include <atomic>
#include <mutex>
#include <queue>

namespace dtls {
namespace v13 {
namespace protocol {

/**
 * @brief Hardware-accelerated DTLS record layer
 * 
 * Provides hardware-accelerated record processing with zero-copy operations,
 * SIMD batch processing, and performance optimization for high-throughput scenarios.
 */
class DTLS_API HardwareAcceleratedRecordLayer : public RecordLayerInterface {
public:
    /**
     * @brief Configuration for hardware-accelerated record processing
     */
    struct HardwareConfig {
        bool enable_batch_processing{true};
        bool enable_zero_copy{true};
        bool enable_simd_operations{true};
        size_t batch_size{16};
        size_t max_concurrent_operations{64};
        bool prefer_hardware_alignment{true};
        size_t buffer_pool_size{128};
        std::chrono::milliseconds batch_timeout{1}; // Max time to wait for full batch
    };
    
    /**
     * @brief Create with hardware crypto provider
     */
    explicit HardwareAcceleratedRecordLayer(
        std::shared_ptr<crypto::HardwareAcceleratedProvider> crypto_provider,
        const HardwareConfig& config = {});
    
    ~HardwareAcceleratedRecordLayer() override;
    
    // RecordLayerInterface implementation with hardware acceleration
    Result<void> initialize(const ConnectionParams& params) override;
    void cleanup() override;
    
    Result<ProtectedRecord> protect_record(
        const PlaintextRecord& plaintext,
        const ProtectionParams& params) override;
    
    Result<PlaintextRecord> unprotect_record(
        const ProtectedRecord& protected_record,
        const ProtectionParams& params) override;
    
    Result<void> update_keys(
        const KeyUpdateParams& params) override;
    
    // Batch operations for high throughput
    Result<std::vector<ProtectedRecord>> protect_records_batch(
        const std::vector<PlaintextRecord>& plaintexts,
        const std::vector<ProtectionParams>& params);
    
    Result<std::vector<PlaintextRecord>> unprotect_records_batch(
        const std::vector<ProtectedRecord>& protected_records,
        const std::vector<ProtectionParams>& params);
    
    // Zero-copy operations
    Result<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>> protect_record_zero_copy(
        const PlaintextRecord& plaintext,
        const ProtectionParams& params);
    
    Result<std::pair<std::vector<uint8_t>, ContentType>> unprotect_record_zero_copy(
        crypto::HardwareAcceleratedCryptoBuffer& ciphertext_buffer,
        const ProtectionParams& params);
    
    // Stream processing for large data
    Result<void> protect_stream(
        const uint8_t* input,
        uint8_t* output,
        size_t length,
        const ProtectionParams& params,
        size_t chunk_size = 65536);
    
    Result<void> unprotect_stream(
        const uint8_t* input,
        uint8_t* output,
        size_t length,
        const ProtectionParams& params,
        size_t chunk_size = 65536);
    
    // Performance monitoring
    struct HardwareMetrics {
        uint64_t records_protected{0};
        uint64_t records_unprotected{0};
        uint64_t batch_operations{0};
        uint64_t zero_copy_operations{0};
        uint64_t hardware_accelerated_ops{0};
        uint64_t software_fallback_ops{0};
        float average_protection_time_us{0.0f};
        float average_batch_speedup{1.0f};
        float hardware_utilization_ratio{0.0f};
        std::chrono::milliseconds total_processing_time{0};
    };
    
    HardwareMetrics get_hardware_metrics() const;
    void reset_hardware_metrics();
    
    // Configuration management
    void update_hardware_config(const HardwareConfig& config);
    HardwareConfig get_hardware_config() const;
    
    // Hardware status
    bool is_hardware_acceleration_active() const;
    Result<crypto::HardwareAccelerationProfile> get_hardware_profile() const;

private:
    std::shared_ptr<crypto::HardwareAcceleratedProvider> crypto_provider_;
    std::unique_ptr<crypto::HardwareZeroCopyCrypto> zero_copy_crypto_;
    std::unique_ptr<crypto::DTLSHardwareRecordProcessor> record_processor_;
    
    HardwareConfig hardware_config_;
    mutable HardwareMetrics hardware_metrics_;
    mutable std::mutex metrics_mutex_;
    
    // Connection state
    ConnectionParams connection_params_;
    std::atomic<bool> initialized_{false};
    
    // Buffer management
    std::queue<std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer>> buffer_pool_;
    std::mutex buffer_pool_mutex_;
    std::atomic<size_t> active_operations_{0};
    
    // Batch processing
    struct BatchContext {
        std::vector<PlaintextRecord> pending_plaintexts;
        std::vector<ProtectionParams> pending_params;
        std::chrono::steady_clock::time_point batch_start_time;
        std::mutex batch_mutex;
    };
    std::unique_ptr<BatchContext> protection_batch_;
    std::unique_ptr<BatchContext> unprotection_batch_;
    
    // Helper methods
    std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer> get_buffer_from_pool(size_t min_size);
    void return_buffer_to_pool(std::unique_ptr<crypto::HardwareAcceleratedCryptoBuffer> buffer);
    
    Result<crypto::AEADParams> build_aead_params(
        const ProtectionParams& params,
        const std::vector<uint8_t>& additional_data) const;
    
    std::vector<uint8_t> build_additional_data(
        const PlaintextRecord& plaintext,
        const ProtectionParams& params) const;
    
    void update_metrics(const std::string& operation,
                       std::chrono::microseconds duration,
                       bool used_hardware,
                       bool used_batch) const;
    
    bool should_use_batch_processing() const;
    Result<void> flush_pending_batches();
    
    // Hardware-specific optimizations
    Result<ProtectedRecord> protect_record_aes_gcm_hw(
        const PlaintextRecord& plaintext,
        const ProtectionParams& params);
    
    Result<PlaintextRecord> unprotect_record_aes_gcm_hw(
        const ProtectedRecord& protected_record,
        const ProtectionParams& params);
    
    Result<std::vector<ProtectedRecord>> protect_batch_simd(
        const std::vector<PlaintextRecord>& plaintexts,
        const std::vector<ProtectionParams>& params);
};

/**
 * @brief Factory for creating hardware-accelerated record layers
 */
class DTLS_API HardwareAcceleratedRecordLayerFactory {
public:
    /**
     * @brief Create optimal hardware-accelerated record layer
     */
    static Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> create_optimal();
    
    /**
     * @brief Create with specific crypto provider
     */
    static Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> create_with_provider(
        const std::string& provider_name,
        const HardwareAcceleratedRecordLayer::HardwareConfig& config = {});
    
    /**
     * @brief Create with custom provider
     */
    static Result<std::unique_ptr<HardwareAcceleratedRecordLayer>> create_with_custom_provider(
        std::shared_ptr<crypto::HardwareAcceleratedProvider> provider,
        const HardwareAcceleratedRecordLayer::HardwareConfig& config = {});
    
    /**
     * @brief Get optimal configuration for current hardware
     */
    static Result<HardwareAcceleratedRecordLayer::HardwareConfig> get_optimal_config();
    
    /**
     * @brief Benchmark different configurations
     */
    static Result<std::vector<std::pair<HardwareAcceleratedRecordLayer::HardwareConfig, float>>> 
    benchmark_configurations();

private:
    static std::shared_ptr<crypto::HardwareAcceleratedProvider> cached_provider_;
    static std::mutex factory_mutex_;
};

/**
 * @brief Hardware-accelerated handshake processor
 * 
 * Provides hardware acceleration for handshake operations including
 * signature generation/verification, key exchange, and key derivation.
 */
class DTLS_API HardwareAcceleratedHandshakeProcessor {
public:
    explicit HardwareAcceleratedHandshakeProcessor(
        std::shared_ptr<crypto::HardwareAcceleratedProvider> crypto_provider);
    
    ~HardwareAcceleratedHandshakeProcessor() = default;
    
    // Handshake message processing with hardware acceleration
    Result<std::vector<uint8_t>> process_client_hello(
        const std::vector<uint8_t>& client_hello_data);
    
    Result<std::vector<uint8_t>> process_server_hello(
        const std::vector<uint8_t>& server_hello_data);
    
    Result<std::vector<uint8_t>> process_certificate(
        const std::vector<uint8_t>& certificate_data);
    
    Result<std::vector<uint8_t>> process_certificate_verify(
        const std::vector<uint8_t>& cert_verify_data);
    
    Result<std::vector<uint8_t>> process_finished(
        const std::vector<uint8_t>& finished_data);
    
    // Key derivation with hardware acceleration
    Result<std::vector<uint8_t>> derive_handshake_keys(
        const std::vector<uint8_t>& shared_secret,
        const std::vector<uint8_t>& handshake_context);
    
    Result<std::vector<uint8_t>> derive_application_keys(
        const std::vector<uint8_t>& master_secret,
        const std::vector<uint8_t>& handshake_context);
    
    // Signature operations with hardware acceleration
    Result<std::vector<uint8_t>> generate_certificate_verify_signature(
        const std::vector<uint8_t>& transcript_hash,
        const crypto::PrivateKey& private_key,
        SignatureScheme signature_scheme);
    
    Result<bool> verify_certificate_verify_signature(
        const std::vector<uint8_t>& transcript_hash,
        const std::vector<uint8_t>& signature,
        const crypto::PublicKey& public_key,
        SignatureScheme signature_scheme);
    
    // Key exchange with hardware acceleration
    Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> generate_key_exchange(
        NamedGroup group);
    
    Result<std::vector<uint8_t>> perform_key_exchange(
        const std::vector<uint8_t>& peer_public_key,
        const crypto::PrivateKey& private_key,
        NamedGroup group);
    
    // Batch handshake processing for multiple connections
    Result<std::vector<std::vector<uint8_t>>> batch_process_client_hellos(
        const std::vector<std::vector<uint8_t>>& client_hello_batch);
    
    Result<std::vector<std::vector<uint8_t>>> batch_derive_keys(
        const std::vector<std::vector<uint8_t>>& shared_secrets,
        const std::vector<std::vector<uint8_t>>& handshake_contexts);
    
    // Performance metrics
    struct HandshakeMetrics {
        uint64_t handshake_messages_processed{0};
        uint64_t key_derivations_performed{0};
        uint64_t signatures_generated{0};
        uint64_t signatures_verified{0};
        uint64_t key_exchanges_performed{0};
        uint64_t batch_operations{0};
        uint64_t hardware_accelerated_ops{0};
        float average_handshake_time_ms{0.0f};
        float average_key_derivation_time_us{0.0f};
        float hardware_speedup_ratio{1.0f};
    };
    
    HandshakeMetrics get_handshake_metrics() const;
    void reset_handshake_metrics();

private:
    std::shared_ptr<crypto::HardwareAcceleratedProvider> crypto_provider_;
    mutable HandshakeMetrics handshake_metrics_;
    mutable std::mutex handshake_metrics_mutex_;
    
    void update_handshake_metrics(const std::string& operation,
                                 std::chrono::microseconds duration,
                                 bool used_hardware) const;
    
    Result<crypto::HMACParams> build_hmac_params(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        crypto::HashAlgorithm algorithm) const;
};

} // namespace protocol
} // namespace v13
} // namespace dtls

#endif // DTLS_PROTOCOL_HARDWARE_ACCELERATED_RECORD_LAYER_H