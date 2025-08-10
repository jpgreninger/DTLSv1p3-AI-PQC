#include <dtls/memory/zero_copy_crypto.h>
#include <dtls/error.h>
#include <algorithm>
#include <cstring>
#include <iostream>

namespace dtls {
namespace v13 {
namespace memory {

// CryptoBuffer implementation
CryptoBuffer::CryptoBuffer(const ZeroCopyBuffer& buffer) 
    : shared_state_(buffer.is_shared() ? buffer.shared_state_ : nullptr)
    , offset_(buffer.is_shared() ? buffer.offset_ : 0)
    , size_(buffer.size())
    , is_mutable_(false) {
    
    if (!buffer.is_shared()) {
        // Convert to shared buffer for crypto operations
        if (buffer.data() && buffer.size() > 0) {
            auto new_shared = std::make_shared<BufferSharedState>(
                std::make_unique<std::byte[]>(buffer.capacity()), buffer.capacity());
            std::memcpy(new_shared->mutable_data(), buffer.data(), buffer.size());
            shared_state_ = new_shared;
            offset_ = 0;
        }
    }
}

CryptoBuffer::CryptoBuffer(std::shared_ptr<BufferSharedState> shared_state, size_t offset, size_t size)
    : shared_state_(std::move(shared_state))
    , offset_(offset)
    , size_(size)
    , is_mutable_(false) {
    
    if (shared_state_) {
        // Ensure offset and size are within bounds
        size_t max_size = shared_state_->capacity();
        if (offset_ > max_size) {
            offset_ = max_size;
            size_ = 0;
        } else if (offset_ + size_ > max_size) {
            size_ = max_size - offset_;
        }
    }
}

CryptoBuffer CryptoBuffer::create_mutable(ZeroCopyBuffer&& buffer) {
    CryptoBuffer crypto_buffer(buffer);
    crypto_buffer.is_mutable_ = true;
    return crypto_buffer;
}

CryptoBuffer CryptoBuffer::create_shared(const ZeroCopyBuffer& buffer) {
    return CryptoBuffer(buffer);
}

const std::byte* CryptoBuffer::data() const noexcept {
    if (!shared_state_) {
        return nullptr;
    }
    return shared_state_->data() + offset_;
}

std::byte* CryptoBuffer::mutable_data() {
    if (!shared_state_ || !is_mutable_) {
        return nullptr;
    }
    
    // Check if we need copy-on-write
    if (shared_state_->ref_count.load() > 1) {
        auto copy_result = make_unique();
        if (!copy_result) {
            return nullptr;
        }
    }
    
    return shared_state_->mutable_data() + offset_;
}

size_t CryptoBuffer::size() const noexcept {
    return size_;
}

bool CryptoBuffer::empty() const noexcept {
    return size_ == 0;
}

CryptoBuffer CryptoBuffer::slice(size_t offset, size_t length) const {
    if (offset >= size_) {
        return CryptoBuffer(shared_state_, offset_ + size_, 0); // Empty slice
    }
    
    size_t actual_length = std::min(length, size_ - offset);
    return CryptoBuffer(shared_state_, offset_ + offset, actual_length);
}

CryptoBuffer CryptoBuffer::slice(size_t offset) const {
    if (offset >= size_) {
        return CryptoBuffer(shared_state_, offset_ + size_, 0); // Empty slice
    }
    
    return CryptoBuffer(shared_state_, offset_ + offset, size_ - offset);
}

bool CryptoBuffer::is_mutable() const noexcept {
    return is_mutable_;
}

bool CryptoBuffer::is_shared() const noexcept {
    return shared_state_ != nullptr;
}

size_t CryptoBuffer::reference_count() const noexcept {
    if (!shared_state_) {
        return 0;
    }
    return shared_state_->ref_count.load();
}

Result<void> CryptoBuffer::make_unique() {
    if (!shared_state_) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    if (shared_state_->ref_count.load() == 1) {
        return Result<void>(); // Already unique
    }
    
    // Create unique copy
    auto new_data = std::make_unique<std::byte[]>(size_);
    if (!new_data) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
    
    std::memcpy(new_data.get(), data(), size_);
    
    // Create new shared state
    auto new_shared = std::make_shared<BufferSharedState>(std::move(new_data), size_);
    
    shared_state_ = new_shared;
    offset_ = 0;
    
    return Result<void>();
}

ZeroCopyBuffer CryptoBuffer::to_buffer() const {
    if (!shared_state_) {
        return ZeroCopyBuffer();
    }
    
    return ZeroCopyBuffer(shared_state_, offset_, size_);
}

Result<ZeroCopyBuffer> CryptoBuffer::to_mutable_buffer() {
    if (!is_mutable_) {
        return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
    }
    
    auto copy_result = make_unique();
    if (!copy_result) {
        return Result<ZeroCopyBuffer>(copy_result.error());
    }
    
    return Result<ZeroCopyBuffer>(ZeroCopyBuffer(shared_state_, offset_, size_));
}

void CryptoBuffer::secure_zero() {
    if (shared_state_ && is_mutable_) {
        // Make unique first if shared
        if (shared_state_->ref_count.load() > 1) {
            make_unique();
        }
        
        std::byte* mutable_ptr = shared_state_->mutable_data() + offset_;
        secure_zero_memory(mutable_ptr, size_);
    }
}

// ZeroCopyAEAD implementation
ZeroCopyAEAD::ZeroCopyAEAD(std::unique_ptr<ZeroCopyCryptoContext> context)
    : context_(std::move(context)) {
}

Result<CryptoBuffer> ZeroCopyAEAD::aead_encrypt(const CryptoBuffer& plaintext,
                                               const CryptoBuffer& associated_data,
                                               const CryptoBuffer& key,
                                               const CryptoBuffer& nonce) {
    if (!context_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // For AEAD, we need to handle associated data properly
    // This is a simplified implementation - real implementation would
    // properly handle AEAD algorithm specifics
    
    auto encrypt_result = context_->encrypt(plaintext, key, nonce);
    if (!encrypt_result) {
        return encrypt_result;
    }
    
    // In a real implementation, the AEAD algorithm would incorporate
    // the associated data into the authentication tag
    
    return encrypt_result;
}

Result<CryptoBuffer> ZeroCopyAEAD::aead_decrypt(const CryptoBuffer& ciphertext,
                                               const CryptoBuffer& associated_data,
                                               const CryptoBuffer& key,
                                               const CryptoBuffer& nonce) {
    if (!context_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // Verify authentication tag with associated data
    // This is a simplified implementation
    
    auto decrypt_result = context_->decrypt(ciphertext, key, nonce);
    if (!decrypt_result) {
        return decrypt_result;
    }
    
    return decrypt_result;
}

Result<void> ZeroCopyAEAD::aead_encrypt_in_place(CryptoBuffer& buffer,
                                                const CryptoBuffer& associated_data,
                                                const CryptoBuffer& key,
                                                const CryptoBuffer& nonce) {
    if (!context_) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    if (!buffer.is_mutable()) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    // In-place encryption - modify the buffer directly
    auto encrypt_result = context_->encrypt_in_place(buffer, key, nonce);
    return encrypt_result;
}

Result<void> ZeroCopyAEAD::aead_decrypt_in_place(CryptoBuffer& buffer,
                                                const CryptoBuffer& associated_data,
                                                const CryptoBuffer& key,
                                                const CryptoBuffer& nonce) {
    if (!context_) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    if (!buffer.is_mutable()) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    // Verify authentication tag first, then decrypt in-place
    auto decrypt_result = context_->decrypt_in_place(buffer, key, nonce);
    return decrypt_result;
}

Result<std::vector<CryptoBuffer>> ZeroCopyAEAD::aead_encrypt_batch(
    const std::vector<CryptoBuffer>& plaintexts,
    const std::vector<CryptoBuffer>& associated_data,
    const CryptoBuffer& key,
    const CryptoBuffer& base_nonce) {
    
    if (!context_) {
        return Result<std::vector<CryptoBuffer>>(DTLSError::NOT_INITIALIZED);
    }
    
    if (plaintexts.size() != associated_data.size()) {
        return Result<std::vector<CryptoBuffer>>(DTLSError::INVALID_PARAMETER);
    }
    
    // Batch encryption with AEAD
    auto batch_result = context_->encrypt_batch(plaintexts, key, base_nonce);
    if (!batch_result) {
        return Result<std::vector<CryptoBuffer>>(batch_result.error());
    }
    
    return batch_result;
}

// ZeroCopyKeyDerivation implementation
ZeroCopyKeyDerivation::ZeroCopyKeyDerivation(std::unique_ptr<ZeroCopyCryptoContext> context)
    : context_(std::move(context)) {
}

Result<CryptoBuffer> ZeroCopyKeyDerivation::hkdf_extract(const CryptoBuffer& salt,
                                                        const CryptoBuffer& input_key_material) {
    if (!context_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    auto prk_result = context_->hmac(input_key_material, salt);
    return prk_result;
}

Result<CryptoBuffer> ZeroCopyKeyDerivation::hkdf_expand(const CryptoBuffer& pseudo_random_key,
                                                       const CryptoBuffer& info,
                                                       size_t output_length) {
    if (!context_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // Simplified HKDF-Expand implementation
    // Real implementation would follow RFC 5869 exactly
    
    // Create output buffer
    auto output_buffer = CryptoBufferPool::instance().acquire_buffer(output_length, true);
    
    // Perform HKDF-Expand (simplified)
    size_t hash_len = 32; // Assuming SHA-256
    size_t n = (output_length + hash_len - 1) / hash_len;
    
    auto current_output = output_buffer.mutable_data();
    size_t bytes_written = 0;
    
    for (size_t i = 1; i <= n && bytes_written < output_length; ++i) {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        // For i=1, T(0) is empty
        
        // This is a simplified implementation
        auto hmac_result = context_->hmac(info, pseudo_random_key);
        if (!hmac_result) {
            return Result<CryptoBuffer>(hmac_result.error());
        }
        
        size_t to_copy = std::min(hash_len, output_length - bytes_written);
        std::memcpy(current_output, hmac_result->data(), to_copy);
        
        current_output += to_copy;
        bytes_written += to_copy;
    }
    
    return Result<CryptoBuffer>(std::move(output_buffer));
}

Result<CryptoBuffer> ZeroCopyKeyDerivation::hkdf_expand_label(const CryptoBuffer& secret,
                                                             const std::string& label,
                                                             const CryptoBuffer& context,
                                                             size_t length) {
    // RFC 8446 Section 7.1: HKDF-Expand-Label
    
    if (length > 255) {
        return Result<CryptoBuffer>(DTLSError::INVALID_PARAMETER);
    }
    
    // HkdfLabel struct:
    // uint16 length;
    // opaque label<7..255>;
    // opaque context<0..255>;
    
    std::string tls_label = "tls13 " + label;
    
    size_t hkdf_label_size = 2 + 1 + tls_label.length() + 1 + context.size();
    auto info_buffer = CryptoBufferPool::instance().acquire_buffer(hkdf_label_size, true);
    
    std::byte* info_data = info_buffer.mutable_data();
    size_t offset = 0;
    
    // Write length (big-endian uint16)
    info_data[offset++] = static_cast<std::byte>((length >> 8) & 0xFF);
    info_data[offset++] = static_cast<std::byte>(length & 0xFF);
    
    // Write label length and data
    info_data[offset++] = static_cast<std::byte>(tls_label.length());
    std::memcpy(info_data + offset, tls_label.data(), tls_label.length());
    offset += tls_label.length();
    
    // Write context length and data
    info_data[offset++] = static_cast<std::byte>(context.size());
    if (!context.empty()) {
        std::memcpy(info_data + offset, context.data(), context.size());
        offset += context.size();
    }
    
    // Perform HKDF-Expand
    return hkdf_expand(secret, info_buffer, length);
}

Result<std::vector<CryptoBuffer>> ZeroCopyKeyDerivation::derive_keys(
    const CryptoBuffer& master_secret,
    const std::vector<std::string>& labels,
    const CryptoBuffer& context,
    const std::vector<size_t>& lengths) {
    
    if (labels.size() != lengths.size()) {
        return Result<std::vector<CryptoBuffer>>(DTLSError::INVALID_PARAMETER);
    }
    
    std::vector<CryptoBuffer> derived_keys;
    derived_keys.reserve(labels.size());
    
    for (size_t i = 0; i < labels.size(); ++i) {
        auto key_result = hkdf_expand_label(master_secret, labels[i], context, lengths[i]);
        if (!key_result) {
            return Result<std::vector<CryptoBuffer>>(key_result.error());
        }
        
        derived_keys.push_back(std::move(*key_result));
    }
    
    return Result<std::vector<CryptoBuffer>>(std::move(derived_keys));
}

Result<CryptoBuffer> ZeroCopyKeyDerivation::derive_secret(const CryptoBuffer& secret,
                                                         const std::string& label,
                                                         const CryptoBuffer& messages) {
    // Compute transcript hash of messages
    auto transcript_result = context_->hash(messages);
    if (!transcript_result) {
        return Result<CryptoBuffer>(transcript_result.error());
    }
    
    // Derive secret using HKDF-Expand-Label
    return hkdf_expand_label(secret, label, *transcript_result, 32); // Assuming 256-bit output
}

// CryptoBufferPool implementation
CryptoBufferPool& CryptoBufferPool::instance() {
    static CryptoBufferPool instance;
    return instance;
}

CryptoBuffer CryptoBufferPool::acquire_buffer(size_t size, bool mutable_required) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto it = available_buffers_.find(size);
    if (it != available_buffers_.end() && !it->second.empty()) {
        auto buffer = std::move(it->second.back());
        it->second.pop_back();
        
        stats_.crypto_buffer_hits++;
        stats_.available_crypto_buffers--;
        
        // Ensure mutability if required
        if (mutable_required && !buffer.is_mutable()) {
            // Convert to mutable buffer
            auto zero_copy_result = buffer.to_mutable_buffer();
            if (zero_copy_result) {
                return CryptoBuffer::create_mutable(std::move(*zero_copy_result));
            }
        }
        
        return buffer;
    }
    
    // Create new buffer
    stats_.crypto_buffer_misses++;
    
    auto zero_copy_buffer = ZeroCopyBuffer(size);
    if (mutable_required) {
        return CryptoBuffer::create_mutable(std::move(zero_copy_buffer));
    } else {
        return CryptoBuffer::create_shared(zero_copy_buffer);
    }
}

void CryptoBufferPool::release_buffer(CryptoBuffer&& buffer) {
    if (buffer.empty()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    size_t size = buffer.size();
    
    // Secure zero the buffer before returning to pool
    if (buffer.is_mutable()) {
        buffer.secure_zero();
    }
    
    // Add to available buffers
    available_buffers_[size].push_back(std::move(buffer));
    stats_.available_crypto_buffers++;
    stats_.total_crypto_buffers = std::max(stats_.total_crypto_buffers, stats_.available_crypto_buffers);
}

void CryptoBufferPool::preallocate_crypto_buffers(size_t count, size_t size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    auto& buffers = available_buffers_[size];
    buffers.reserve(buffers.size() + count);
    
    for (size_t i = 0; i < count; ++i) {
        auto zero_copy_buffer = ZeroCopyBuffer(size);
        buffers.emplace_back(CryptoBuffer::create_shared(zero_copy_buffer));
    }
    
    stats_.available_crypto_buffers += count;
    stats_.total_crypto_buffers += count;
}

CryptoBufferPool::PoolStats CryptoBufferPool::get_statistics() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    PoolStats stats = stats_;
    
    size_t total_requests = stats.crypto_buffer_hits + stats.crypto_buffer_misses;
    if (total_requests > 0) {
        stats.crypto_hit_rate = static_cast<double>(stats.crypto_buffer_hits) / total_requests;
    }
    
    return stats;
}

void CryptoBufferPool::reset_statistics() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    stats_.crypto_buffer_hits = 0;
    stats_.crypto_buffer_misses = 0;
    stats_.crypto_hit_rate = 0.0;
}

// ZeroCopyCryptoFactory implementation
ZeroCopyCryptoFactory& ZeroCopyCryptoFactory::instance() {
    static ZeroCopyCryptoFactory instance;
    return instance;
}

std::unique_ptr<ZeroCopyCryptoContext> ZeroCopyCryptoFactory::create_context(const std::string& algorithm) {
    std::lock_guard<std::mutex> lock(factories_mutex_);
    
    auto it = context_factories_.find(algorithm);
    if (it != context_factories_.end()) {
        return it->second();
    }
    
    // Default implementation would create algorithm-specific context
    return nullptr;
}

std::unique_ptr<ZeroCopyAEAD> ZeroCopyCryptoFactory::create_aead(const std::string& algorithm) {
    auto context = create_context(algorithm);
    if (!context) {
        return nullptr;
    }
    
    return std::make_unique<ZeroCopyAEAD>(std::move(context));
}

std::unique_ptr<ZeroCopyKeyDerivation> ZeroCopyCryptoFactory::create_key_derivation(const std::string& algorithm) {
    auto context = create_context(algorithm);
    if (!context) {
        return nullptr;
    }
    
    return std::make_unique<ZeroCopyKeyDerivation>(std::move(context));
}

void ZeroCopyCryptoFactory::register_context_factory(const std::string& algorithm, CryptoContextFactory factory) {
    std::lock_guard<std::mutex> lock(factories_mutex_);
    context_factories_[algorithm] = factory;
}

CryptoBuffer ZeroCopyCryptoFactory::create_crypto_buffer(size_t size, bool secure) {
    if (crypto_pooling_enabled_.load()) {
        return CryptoBufferPool::instance().acquire_buffer(size, secure);
    } else {
        auto zero_copy_buffer = ZeroCopyBuffer(size);
        if (secure) {
            zero_copy_buffer.secure_zero();
            return CryptoBuffer::create_mutable(std::move(zero_copy_buffer));
        } else {
            return CryptoBuffer::create_shared(zero_copy_buffer);
        }
    }
}

CryptoBuffer ZeroCopyCryptoFactory::wrap_buffer(const ZeroCopyBuffer& buffer) {
    return CryptoBuffer::create_shared(buffer);
}

CryptoBuffer ZeroCopyCryptoFactory::wrap_data(const std::byte* data, size_t size) {
    auto zero_copy_buffer = ZeroCopyBuffer(data, size);
    return CryptoBuffer::create_shared(zero_copy_buffer);
}

CryptoBuffer ZeroCopyCryptoFactory::clone_buffer(const CryptoBuffer& buffer) {
    if (buffer.empty()) {
        return CryptoBuffer::create_shared(ZeroCopyBuffer());
    }
    
    auto new_buffer = create_crypto_buffer(buffer.size(), true);
    std::memcpy(new_buffer.mutable_data(), buffer.data(), buffer.size());
    
    return new_buffer;
}

void ZeroCopyCryptoFactory::enable_hardware_acceleration(bool enabled) {
    hardware_acceleration_enabled_ = enabled;
}

void ZeroCopyCryptoFactory::enable_crypto_buffer_pooling(bool enabled) {
    crypto_pooling_enabled_ = enabled;
}

void ZeroCopyCryptoFactory::set_preferred_crypto_provider(const std::string& provider) {
    preferred_provider_ = provider;
}

// DTLS-specific crypto operations
namespace dtls_crypto {

DTLSRecordCrypto::DTLSRecordCrypto(std::unique_ptr<ZeroCopyAEAD> aead,
                                  std::unique_ptr<ZeroCopyKeyDerivation> key_derivation)
    : aead_(std::move(aead))
    , key_derivation_(std::move(key_derivation)) {
}

Result<CryptoBuffer> DTLSRecordCrypto::encrypt_record(const CryptoBuffer& plaintext_record,
                                                     const CryptoBuffer& sequence_number,
                                                     const CryptoBuffer& write_key,
                                                     const CryptoBuffer& write_iv) {
    if (!aead_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // Construct nonce for DTLS record encryption
    // Typically: write_iv XOR sequence_number (padded)
    auto nonce_buffer = ZeroCopyCryptoFactory::instance().create_crypto_buffer(12, true); // 96-bit nonce
    
    // Copy write_iv to nonce buffer
    if (write_iv.size() >= 4) {
        std::memcpy(nonce_buffer.mutable_data(), write_iv.data(), 4);
    }
    
    // XOR with sequence number
    if (sequence_number.size() >= 8) {
        const std::byte* seq_data = sequence_number.data() + (sequence_number.size() - 8);
        std::byte* nonce_data = nonce_buffer.mutable_data() + 4;
        
        for (size_t i = 0; i < 8; ++i) {
            nonce_data[i] = nonce_data[i] ^ seq_data[i];
        }
    }
    
    // DTLS record encryption includes the DTLS header as associated data
    // For simplicity, we'll use an empty associated data here
    CryptoBuffer empty_ad = ZeroCopyCryptoFactory::instance().create_crypto_buffer(0);
    
    return aead_->aead_encrypt(plaintext_record, empty_ad, write_key, nonce_buffer);
}

Result<CryptoBuffer> DTLSRecordCrypto::decrypt_record(const CryptoBuffer& ciphertext_record,
                                                     const CryptoBuffer& sequence_number,
                                                     const CryptoBuffer& read_key,
                                                     const CryptoBuffer& read_iv) {
    if (!aead_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // Construct nonce (same as encryption)
    auto nonce_buffer = ZeroCopyCryptoFactory::instance().create_crypto_buffer(12, true);
    
    if (read_iv.size() >= 4) {
        std::memcpy(nonce_buffer.mutable_data(), read_iv.data(), 4);
    }
    
    if (sequence_number.size() >= 8) {
        const std::byte* seq_data = sequence_number.data() + (sequence_number.size() - 8);
        std::byte* nonce_data = nonce_buffer.mutable_data() + 4;
        
        for (size_t i = 0; i < 8; ++i) {
            nonce_data[i] = nonce_data[i] ^ seq_data[i];
        }
    }
    
    CryptoBuffer empty_ad = ZeroCopyCryptoFactory::instance().create_crypto_buffer(0);
    
    return aead_->aead_decrypt(ciphertext_record, empty_ad, read_key, nonce_buffer);
}

Result<CryptoBuffer> DTLSRecordCrypto::encrypt_sequence_number(const CryptoBuffer& sequence_number,
                                                              const CryptoBuffer& sn_key) {
    if (!aead_) {
        return Result<CryptoBuffer>(DTLSError::NOT_INITIALIZED);
    }
    
    // DTLS 1.3 sequence number encryption
    // Use a simple encryption (in practice, this would use AES or similar)
    auto encrypted = ZeroCopyCryptoFactory::instance().create_crypto_buffer(sequence_number.size(), true);
    
    // Simple XOR encryption for demonstration (not secure!)
    const std::byte* seq_data = sequence_number.data();
    const std::byte* key_data = sn_key.data();
    std::byte* enc_data = encrypted.mutable_data();
    
    for (size_t i = 0; i < sequence_number.size(); ++i) {
        enc_data[i] = seq_data[i] ^ key_data[i % sn_key.size()];
    }
    
    return Result<CryptoBuffer>(std::move(encrypted));
}

Result<CryptoBuffer> DTLSRecordCrypto::decrypt_sequence_number(const CryptoBuffer& encrypted_sequence_number,
                                                              const CryptoBuffer& sn_key) {
    // Decryption is the same as encryption for XOR
    return encrypt_sequence_number(encrypted_sequence_number, sn_key);
}

Result<std::vector<CryptoBuffer>> DTLSRecordCrypto::encrypt_records_batch(
    const std::vector<CryptoBuffer>& plaintext_records,
    const std::vector<CryptoBuffer>& sequence_numbers,
    const CryptoBuffer& write_key,
    const CryptoBuffer& write_iv) {
    
    if (plaintext_records.size() != sequence_numbers.size()) {
        return Result<std::vector<CryptoBuffer>>(DTLSError::INVALID_PARAMETER);
    }
    
    std::vector<CryptoBuffer> encrypted_records;
    encrypted_records.reserve(plaintext_records.size());
    
    for (size_t i = 0; i < plaintext_records.size(); ++i) {
        auto encrypt_result = encrypt_record(plaintext_records[i], sequence_numbers[i], write_key, write_iv);
        if (!encrypt_result) {
            return Result<std::vector<CryptoBuffer>>(encrypt_result.error());
        }
        encrypted_records.push_back(std::move(*encrypt_result));
    }
    
    return Result<std::vector<CryptoBuffer>>(std::move(encrypted_records));
}

} // namespace dtls_crypto

// Utility functions implementation
CryptoBuffer make_crypto_buffer(size_t size, bool secure) {
    return ZeroCopyCryptoFactory::instance().create_crypto_buffer(size, secure);
}

CryptoBuffer wrap_crypto_buffer(const ZeroCopyBuffer& buffer) {
    return ZeroCopyCryptoFactory::instance().wrap_buffer(buffer);
}

Result<ZeroCopyBuffer> crypto_buffer_to_zero_copy(const CryptoBuffer& crypto_buffer) {
    return Result<ZeroCopyBuffer>(crypto_buffer.to_buffer());
}

// Performance monitoring stubs
static std::atomic<bool> g_crypto_perf_monitoring{false};
static CryptoPerformanceStats g_crypto_perf_stats;

void enable_crypto_performance_monitoring(bool enabled) {
    g_crypto_perf_monitoring = enabled;
}

CryptoPerformanceStats get_crypto_performance_stats() {
    return g_crypto_perf_stats;
}

} // namespace memory
} // namespace v13
} // namespace dtls