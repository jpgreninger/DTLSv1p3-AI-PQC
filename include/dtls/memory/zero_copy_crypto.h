#ifndef DTLS_MEMORY_ZERO_COPY_CRYPTO_H
#define DTLS_MEMORY_ZERO_COPY_CRYPTO_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/crypto/provider.h>
#include <memory>
#include <vector>
#include <functional>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Zero-copy cryptographic operations for DTLS v1.3
 * 
 * This system provides cryptographic operations that work directly
 * with buffer references without unnecessary copying, optimizing
 * performance for high-throughput DTLS scenarios.
 */

// Forward declarations
namespace crypto = dtls::v13::crypto;

// Zero-copy buffer interface for crypto operations
class DTLS_API CryptoBuffer {
public:
    // Create from ZeroCopyBuffer
    explicit CryptoBuffer(const ZeroCopyBuffer& buffer);
    CryptoBuffer(std::shared_ptr<BufferSharedState> shared_state, size_t offset, size_t size);
    
    // Create mutable crypto buffer
    static CryptoBuffer create_mutable(ZeroCopyBuffer&& buffer);
    static CryptoBuffer create_shared(const ZeroCopyBuffer& buffer);
    
    // Data access (const operations are zero-copy)
    const std::byte* data() const noexcept;
    std::byte* mutable_data(); // May trigger copy-on-write
    size_t size() const noexcept;
    bool empty() const noexcept;
    
    // Zero-copy slicing
    CryptoBuffer slice(size_t offset, size_t length) const;
    CryptoBuffer slice(size_t offset) const;
    
    // Buffer operations
    bool is_mutable() const noexcept;
    bool is_shared() const noexcept;
    size_t reference_count() const noexcept;
    
    // Ensure exclusive access (copy-on-write)
    Result<void> make_unique();
    
    // Convert back to ZeroCopyBuffer
    ZeroCopyBuffer to_buffer() const;
    Result<ZeroCopyBuffer> to_mutable_buffer();
    
    // Security operations
    void secure_zero();
    
private:
    std::shared_ptr<BufferSharedState> shared_state_;
    size_t offset_{0};
    size_t size_{0};
    bool is_mutable_{false};
};

// Zero-copy crypto operation context
class DTLS_API ZeroCopyCryptoContext {
public:
    virtual ~ZeroCopyCryptoContext() = default;
    
    // Crypto operations with zero-copy buffers
    virtual Result<CryptoBuffer> encrypt(const CryptoBuffer& plaintext, 
                                        const CryptoBuffer& key,
                                        const CryptoBuffer& nonce) = 0;
    
    virtual Result<CryptoBuffer> decrypt(const CryptoBuffer& ciphertext,
                                        const CryptoBuffer& key, 
                                        const CryptoBuffer& nonce) = 0;
    
    virtual Result<CryptoBuffer> sign(const CryptoBuffer& data,
                                     const CryptoBuffer& private_key) = 0;
    
    virtual Result<bool> verify(const CryptoBuffer& data,
                               const CryptoBuffer& signature,
                               const CryptoBuffer& public_key) = 0;
    
    virtual Result<CryptoBuffer> hash(const CryptoBuffer& data) = 0;
    
    virtual Result<CryptoBuffer> hmac(const CryptoBuffer& data,
                                     const CryptoBuffer& key) = 0;
    
    // Batch operations for multiple buffers
    virtual Result<std::vector<CryptoBuffer>> encrypt_batch(
        const std::vector<CryptoBuffer>& plaintexts,
        const CryptoBuffer& key,
        const CryptoBuffer& base_nonce) = 0;
    
    // In-place operations (when possible)
    virtual Result<void> encrypt_in_place(CryptoBuffer& buffer,
                                         const CryptoBuffer& key,
                                         const CryptoBuffer& nonce) = 0;
    
    virtual Result<void> decrypt_in_place(CryptoBuffer& buffer,
                                         const CryptoBuffer& key,
                                         const CryptoBuffer& nonce) = 0;
    
    // Stream operations for large data
    virtual Result<void> encrypt_stream(const CryptoBuffer& input,
                                       CryptoBuffer& output,
                                       const CryptoBuffer& key,
                                       const CryptoBuffer& nonce) = 0;
    
    // Performance optimizations
    virtual void prefetch_keys(const std::vector<CryptoBuffer>& keys) = 0;
    virtual void warmup_context() = 0;
};

// AEAD operations with zero-copy
class DTLS_API ZeroCopyAEAD {
public:
    ZeroCopyAEAD(std::unique_ptr<ZeroCopyCryptoContext> context);
    
    // AEAD encrypt with associated data
    Result<CryptoBuffer> aead_encrypt(const CryptoBuffer& plaintext,
                                     const CryptoBuffer& associated_data,
                                     const CryptoBuffer& key,
                                     const CryptoBuffer& nonce);
    
    // AEAD decrypt with associated data
    Result<CryptoBuffer> aead_decrypt(const CryptoBuffer& ciphertext,
                                     const CryptoBuffer& associated_data, 
                                     const CryptoBuffer& key,
                                     const CryptoBuffer& nonce);
    
    // In-place AEAD operations
    Result<void> aead_encrypt_in_place(CryptoBuffer& buffer,
                                      const CryptoBuffer& associated_data,
                                      const CryptoBuffer& key,
                                      const CryptoBuffer& nonce);
    
    Result<void> aead_decrypt_in_place(CryptoBuffer& buffer,
                                      const CryptoBuffer& associated_data,
                                      const CryptoBuffer& key,
                                      const CryptoBuffer& nonce);
    
    // Batch AEAD operations
    Result<std::vector<CryptoBuffer>> aead_encrypt_batch(
        const std::vector<CryptoBuffer>& plaintexts,
        const std::vector<CryptoBuffer>& associated_data,
        const CryptoBuffer& key,
        const CryptoBuffer& base_nonce);
    
    // Configuration
    void set_tag_size(size_t tag_size) { tag_size_ = tag_size; }
    size_t get_tag_size() const { return tag_size_; }

private:
    std::unique_ptr<ZeroCopyCryptoContext> context_;
    size_t tag_size_{16}; // Default 128-bit tag
};

// Key derivation with zero-copy
class DTLS_API ZeroCopyKeyDerivation {
public:
    explicit ZeroCopyKeyDerivation(std::unique_ptr<ZeroCopyCryptoContext> context);
    
    // HKDF operations
    Result<CryptoBuffer> hkdf_extract(const CryptoBuffer& salt,
                                     const CryptoBuffer& input_key_material);
    
    Result<CryptoBuffer> hkdf_expand(const CryptoBuffer& pseudo_random_key,
                                    const CryptoBuffer& info,
                                    size_t output_length);
    
    Result<CryptoBuffer> hkdf_expand_label(const CryptoBuffer& secret,
                                          const std::string& label,
                                          const CryptoBuffer& context,
                                          size_t length);
    
    // Derive multiple keys at once
    Result<std::vector<CryptoBuffer>> derive_keys(const CryptoBuffer& master_secret,
                                                 const std::vector<std::string>& labels,
                                                 const CryptoBuffer& context,
                                                 const std::vector<size_t>& lengths);
    
    // Key schedule operations
    Result<CryptoBuffer> derive_secret(const CryptoBuffer& secret,
                                      const std::string& label,
                                      const CryptoBuffer& messages);
    
private:
    std::unique_ptr<ZeroCopyCryptoContext> context_;
};

// Crypto buffer pool for reusing crypto buffers
class DTLS_API CryptoBufferPool {
public:
    static CryptoBufferPool& instance();
    
    // Get crypto buffer from pool
    CryptoBuffer acquire_buffer(size_t size, bool mutable_required = false);
    void release_buffer(CryptoBuffer&& buffer);
    
    // Pre-allocate buffers for crypto operations
    void preallocate_crypto_buffers(size_t count, size_t size);
    
    // Statistics
    struct PoolStats {
        size_t total_crypto_buffers{0};
        size_t available_crypto_buffers{0};
        size_t crypto_buffer_hits{0};
        size_t crypto_buffer_misses{0};
        double crypto_hit_rate{0.0};
    };
    
    PoolStats get_statistics() const;
    void reset_statistics();
    
private:
    CryptoBufferPool() = default;
    ~CryptoBufferPool() = default;
    
    mutable std::mutex pool_mutex_;
    std::unordered_map<size_t, std::vector<CryptoBuffer>> available_buffers_;
    PoolStats stats_;
};

// Zero-copy crypto factory
class DTLS_API ZeroCopyCryptoFactory {
public:
    static ZeroCopyCryptoFactory& instance();
    
    // Create crypto contexts
    std::unique_ptr<ZeroCopyCryptoContext> create_context(const std::string& algorithm);
    std::unique_ptr<ZeroCopyAEAD> create_aead(const std::string& algorithm);
    std::unique_ptr<ZeroCopyKeyDerivation> create_key_derivation(const std::string& algorithm);
    
    // Register custom crypto providers
    using CryptoContextFactory = std::function<std::unique_ptr<ZeroCopyCryptoContext>()>;
    void register_context_factory(const std::string& algorithm, CryptoContextFactory factory);
    
    // Crypto buffer utilities
    CryptoBuffer create_crypto_buffer(size_t size, bool secure = true);
    CryptoBuffer wrap_buffer(const ZeroCopyBuffer& buffer);
    CryptoBuffer wrap_data(const std::byte* data, size_t size);
    CryptoBuffer clone_buffer(const CryptoBuffer& buffer);
    
    // Performance optimizations
    void enable_hardware_acceleration(bool enabled);
    void enable_crypto_buffer_pooling(bool enabled);
    void set_preferred_crypto_provider(const std::string& provider);

private:
    ZeroCopyCryptoFactory() = default;
    ~ZeroCopyCryptoFactory() = default;
    
    std::unordered_map<std::string, CryptoContextFactory> context_factories_;
    mutable std::mutex factories_mutex_;
    
    std::atomic<bool> hardware_acceleration_enabled_{true};
    std::atomic<bool> crypto_pooling_enabled_{true};
    std::string preferred_provider_{"openssl"};
};

// DTLS-specific zero-copy crypto operations
namespace dtls_crypto {

// Record layer crypto operations
class DTLS_API DTLSRecordCrypto {
public:
    DTLSRecordCrypto(std::unique_ptr<ZeroCopyAEAD> aead,
                    std::unique_ptr<ZeroCopyKeyDerivation> key_derivation);
    
    // Encrypt DTLS record
    Result<CryptoBuffer> encrypt_record(const CryptoBuffer& plaintext_record,
                                       const CryptoBuffer& sequence_number,
                                       const CryptoBuffer& write_key,
                                       const CryptoBuffer& write_iv);
    
    // Decrypt DTLS record  
    Result<CryptoBuffer> decrypt_record(const CryptoBuffer& ciphertext_record,
                                       const CryptoBuffer& sequence_number,
                                       const CryptoBuffer& read_key,
                                       const CryptoBuffer& read_iv);
    
    // Sequence number encryption/decryption
    Result<CryptoBuffer> encrypt_sequence_number(const CryptoBuffer& sequence_number,
                                                const CryptoBuffer& sn_key);
    
    Result<CryptoBuffer> decrypt_sequence_number(const CryptoBuffer& encrypted_sequence_number,
                                                const CryptoBuffer& sn_key);
    
    // Batch record operations
    Result<std::vector<CryptoBuffer>> encrypt_records_batch(
        const std::vector<CryptoBuffer>& plaintext_records,
        const std::vector<CryptoBuffer>& sequence_numbers,
        const CryptoBuffer& write_key,
        const CryptoBuffer& write_iv);

private:
    std::unique_ptr<ZeroCopyAEAD> aead_;
    std::unique_ptr<ZeroCopyKeyDerivation> key_derivation_;
};

// Handshake crypto operations
class DTLS_API DTLSHandshakeCrypto {
public:
    DTLSHandshakeCrypto(std::unique_ptr<ZeroCopyCryptoContext> context,
                       std::unique_ptr<ZeroCopyKeyDerivation> key_derivation);
    
    // Certificate verification
    Result<bool> verify_certificate_chain(const std::vector<CryptoBuffer>& certificates,
                                         const CryptoBuffer& trusted_root);
    
    // Signature operations
    Result<CryptoBuffer> sign_handshake_message(const CryptoBuffer& message,
                                               const CryptoBuffer& private_key);
    
    Result<bool> verify_handshake_signature(const CryptoBuffer& message,
                                           const CryptoBuffer& signature,
                                           const CryptoBuffer& public_key);
    
    // Key exchange
    Result<CryptoBuffer> generate_key_share(const std::string& group);
    Result<CryptoBuffer> compute_shared_secret(const CryptoBuffer& private_key,
                                              const CryptoBuffer& peer_public_key,
                                              const std::string& group);
    
    // Transcript hash
    Result<CryptoBuffer> compute_transcript_hash(const std::vector<CryptoBuffer>& messages);
    
private:
    std::unique_ptr<ZeroCopyCryptoContext> context_;
    std::unique_ptr<ZeroCopyKeyDerivation> key_derivation_;
};

} // namespace dtls_crypto

// Integration with existing crypto providers
class DTLS_API CryptoProviderBridge {
public:
    // Convert between crypto systems
    static Result<CryptoBuffer> from_crypto_provider(const crypto::CryptoProvider& provider,
                                                    const std::vector<uint8_t>& data);
    
    static Result<std::vector<uint8_t>> to_crypto_provider(const CryptoBuffer& crypto_buffer);
    
    // Wrap existing crypto provider with zero-copy interface
    static std::unique_ptr<ZeroCopyCryptoContext> wrap_provider(
        std::unique_ptr<crypto::CryptoProvider> provider);
};

// Utility functions
DTLS_API CryptoBuffer make_crypto_buffer(size_t size, bool secure = true);
DTLS_API CryptoBuffer wrap_crypto_buffer(const ZeroCopyBuffer& buffer);
DTLS_API Result<ZeroCopyBuffer> crypto_buffer_to_zero_copy(const CryptoBuffer& crypto_buffer);

// Performance monitoring for crypto operations
DTLS_API void enable_crypto_performance_monitoring(bool enabled);
DTLS_API struct CryptoPerformanceStats {
    std::chrono::nanoseconds average_encrypt_time{0};
    std::chrono::nanoseconds average_decrypt_time{0};
    std::chrono::nanoseconds average_sign_time{0};
    std::chrono::nanoseconds average_verify_time{0};
    size_t zero_copy_operations{0};
    size_t copy_operations{0};
    double zero_copy_ratio{0.0};
} get_crypto_performance_stats();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_ZERO_COPY_CRYPTO_H