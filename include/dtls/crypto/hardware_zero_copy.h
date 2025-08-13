#ifndef DTLS_CRYPTO_HARDWARE_ZERO_COPY_H
#define DTLS_CRYPTO_HARDWARE_ZERO_COPY_H

#include "dtls/memory/zero_copy_crypto.h"
#include "dtls/crypto/hardware_acceleration.h"
#include "dtls/crypto/hardware_accelerated_provider.h"
#include <memory>
#include <atomic>
#include <mutex>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * @brief Hardware-accelerated zero-copy crypto buffer
 * 
 * Extends CryptoBuffer with hardware acceleration support, including
 * memory alignment for SIMD operations and hardware-specific optimizations.
 */
class DTLS_API HardwareAcceleratedCryptoBuffer : public memory::CryptoBuffer {
public:
    /**
     * @brief Create hardware-aligned buffer
     */
    static std::unique_ptr<HardwareAcceleratedCryptoBuffer> create_aligned(
        size_t size, size_t alignment = 64);
    
    /**
     * @brief Create from existing buffer with hardware optimization
     */
    static std::unique_ptr<HardwareAcceleratedCryptoBuffer> wrap(
        std::vector<uint8_t>&& data);
    
    /**
     * @brief Get hardware alignment requirements
     */
    size_t get_hardware_alignment() const { return hardware_alignment_; }
    
    /**
     * @brief Check if buffer is hardware-aligned
     */
    bool is_hardware_aligned() const;
    
    /**
     * @brief Ensure buffer is hardware-aligned (may reallocate)
     */
    Result<void> ensure_hardware_aligned();
    
    /**
     * @brief Get pointer for hardware operations (aligned)
     */
    uint8_t* get_hardware_pointer();
    const uint8_t* get_hardware_pointer() const;
    
    /**
     * @brief Reserve space for in-place encryption with tag
     */
    Result<void> reserve_for_encryption(size_t plaintext_size, size_t tag_size);

private:
    explicit HardwareAcceleratedCryptoBuffer(size_t size, size_t alignment);
    explicit HardwareAcceleratedCryptoBuffer(std::vector<uint8_t>&& data);
    
    size_t hardware_alignment_{64}; // Default to cache line alignment
    bool is_aligned_{false};
};

/**
 * @brief Hardware-accelerated zero-copy crypto operations
 * 
 * Provides zero-copy cryptographic operations optimized for hardware
 * acceleration, including in-place encryption/decryption and SIMD batch operations.
 */
class DTLS_API HardwareZeroCopyCrypto {
public:
    /**
     * @brief Configuration for hardware operations
     */
    struct HardwareConfig {
        bool enable_simd_batch_ops{true};
        bool enable_in_place_ops{true};
        bool prefer_hardware_alignment{true};
        size_t simd_batch_size{8};
        size_t preferred_alignment{64};
        HardwareCapability required_capabilities{HardwareCapability::AES_NI};
    };
    
    explicit HardwareZeroCopyCrypto(
        std::shared_ptr<HardwareAcceleratedProvider> provider,
        const HardwareConfig& config = {});
    
    ~HardwareZeroCopyCrypto() = default;
    
    /**
     * @brief In-place AEAD encryption with hardware acceleration
     */
    Result<size_t> encrypt_in_place(
        const AEADParams& params,
        HardwareAcceleratedCryptoBuffer& buffer,
        size_t plaintext_len);
    
    /**
     * @brief In-place AEAD decryption with hardware acceleration
     */
    Result<size_t> decrypt_in_place(
        const AEADParams& params,
        HardwareAcceleratedCryptoBuffer& buffer,
        size_t ciphertext_len);
    
    /**
     * @brief Batch encryption with SIMD optimization
     */
    Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>> 
    batch_encrypt_simd(
        const std::vector<AEADEncryptionParams>& params_batch,
        const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& plaintext_buffers);
    
    /**
     * @brief Batch decryption with SIMD optimization
     */
    Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>> 
    batch_decrypt_simd(
        const std::vector<AEADDecryptionParams>& params_batch,
        const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& ciphertext_buffers);
    
    /**
     * @brief Vectorized hash computation
     */
    Result<std::vector<std::vector<uint8_t>>> compute_hash_batch(
        const std::vector<HashParams>& params_batch,
        const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& data_buffers);
    
    /**
     * @brief Stream cipher operations for large data
     */
    Result<void> stream_encrypt(
        const AEADParams& params,
        const uint8_t* input,
        uint8_t* output,
        size_t length,
        size_t chunk_size = 65536);
    
    Result<void> stream_decrypt(
        const AEADParams& params,
        const uint8_t* input,
        uint8_t* output,
        size_t length,
        size_t chunk_size = 65536);
    
    /**
     * @brief Get hardware performance metrics
     */
    struct HardwareMetrics {
        uint64_t simd_operations{0};
        uint64_t in_place_operations{0};
        uint64_t hardware_accelerated_ops{0};
        uint64_t software_fallback_ops{0};
        float average_simd_speedup{1.0f};
        float average_hw_speedup{1.0f};
        std::chrono::microseconds total_hw_time{0};
        std::chrono::microseconds total_sw_time{0};
    };
    
    HardwareMetrics get_metrics() const;
    void reset_metrics();
    
    /**
     * @brief Update hardware configuration
     */
    void update_config(const HardwareConfig& config);
    
    /**
     * @brief Check if hardware acceleration is active
     */
    bool is_hardware_active() const;

private:
    std::shared_ptr<HardwareAcceleratedProvider> provider_;
    HardwareConfig config_;
    mutable HardwareMetrics metrics_;
    mutable std::mutex metrics_mutex_;
    
    // Hardware-specific operation implementations
    Result<size_t> encrypt_in_place_aes_gcm(
        const AEADParams& params,
        HardwareAcceleratedCryptoBuffer& buffer,
        size_t plaintext_len);
    
    Result<size_t> decrypt_in_place_aes_gcm(
        const AEADParams& params,
        HardwareAcceleratedCryptoBuffer& buffer,
        size_t ciphertext_len);
    
    Result<void> batch_process_aes_gcm_simd(
        const std::vector<AEADEncryptionParams>& params_batch,
        const std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& input_buffers,
        std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>& output_buffers,
        bool encrypt);
    
    bool can_use_simd_batch(const std::vector<AEADEncryptionParams>& params_batch) const;
    void update_metrics(const std::string& operation, 
                       std::chrono::microseconds duration,
                       bool used_hardware, 
                       bool used_simd) const;
};

/**
 * @brief Factory for hardware zero-copy crypto operations
 */
class DTLS_API HardwareZeroCryptoFactory {
public:
    static HardwareZeroCryptoFactory& instance();
    
    /**
     * @brief Create hardware zero-copy crypto with optimal provider
     */
    Result<std::unique_ptr<HardwareZeroCopyCrypto>> create_optimal();
    
    /**
     * @brief Create with specific provider
     */
    Result<std::unique_ptr<HardwareZeroCopyCrypto>> create_with_provider(
        const std::string& provider_name,
        const HardwareZeroCopyCrypto::HardwareConfig& config = {});
    
    /**
     * @brief Get recommended configuration for current hardware
     */
    Result<HardwareZeroCopyCrypto::HardwareConfig> get_optimal_config();
    
    /**
     * @brief Benchmark different configurations
     */
    Result<std::vector<std::pair<HardwareZeroCopyCrypto::HardwareConfig, float>>> 
    benchmark_configurations();

private:
    HardwareZeroCryptoFactory() = default;
    ~HardwareZeroCryptoFactory() = default;
    
    mutable std::mutex factory_mutex_;
    std::shared_ptr<HardwareAcceleratedProvider> cached_provider_;
};

/**
 * @brief DTLS-specific hardware-accelerated record operations
 */
class DTLS_API DTLSHardwareRecordProcessor {
public:
    explicit DTLSHardwareRecordProcessor(
        std::shared_ptr<HardwareZeroCopyCrypto> crypto);
    
    /**
     * @brief Process DTLS record encryption with hardware acceleration
     */
    Result<std::unique_ptr<HardwareAcceleratedCryptoBuffer>> protect_record(
        const DTLSContext& context,
        const std::vector<uint8_t>& plaintext,
        ContentType content_type);
    
    /**
     * @brief Process DTLS record decryption with hardware acceleration
     */
    Result<std::pair<std::vector<uint8_t>, ContentType>> unprotect_record(
        const DTLSContext& context,
        const std::vector<uint8_t>& ciphertext);
    
    /**
     * @brief Batch process multiple records
     */
    Result<std::vector<std::unique_ptr<HardwareAcceleratedCryptoBuffer>>> 
    batch_protect_records(
        const std::vector<DTLSContext>& contexts,
        const std::vector<std::vector<uint8_t>>& plaintexts,
        const std::vector<ContentType>& content_types);
    
    /**
     * @brief Get record processing performance metrics
     */
    struct RecordMetrics {
        uint64_t records_protected{0};
        uint64_t records_unprotected{0};
        uint64_t batch_operations{0};
        float average_record_time_us{0.0f};
        float hardware_speedup_ratio{1.0f};
    };
    
    RecordMetrics get_record_metrics() const;
    void reset_record_metrics();

private:
    std::shared_ptr<HardwareZeroCopyCrypto> crypto_;
    mutable RecordMetrics record_metrics_;
    mutable std::mutex record_metrics_mutex_;
    
    Result<AEADParams> build_aead_params(
        const DTLSContext& context,
        const std::vector<uint8_t>& additional_data);
};

// Utility functions for hardware memory management
namespace hardware_memory {

/**
 * @brief Allocate hardware-aligned memory
 */
DTLS_API std::unique_ptr<uint8_t[]> allocate_aligned(size_t size, size_t alignment = 64);

/**
 * @brief Check if pointer is hardware-aligned
 */
DTLS_API bool is_aligned(const void* ptr, size_t alignment = 64);

/**
 * @brief Get optimal alignment for current hardware
 */
DTLS_API size_t get_optimal_alignment();

/**
 * @brief Copy data with hardware acceleration if available
 */
DTLS_API void copy_optimized(const void* src, void* dest, size_t size);

/**
 * @brief Secure zero memory with hardware acceleration
 */
DTLS_API void secure_zero(void* ptr, size_t size);

} // namespace hardware_memory

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_HARDWARE_ZERO_COPY_H