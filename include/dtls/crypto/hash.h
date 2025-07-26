#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include <cstdint>
#include <array>

namespace dtls::v13::crypto {

/**
 * Hash Algorithm Types
 */
enum class HashAlgorithm : uint8_t {
    SHA256 = 0,
    SHA384 = 1,
    SHA512 = 2,
    SHA1 = 3    // Deprecated, for legacy support only
};

/**
 * Hash digest sizes
 */
constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA384_DIGEST_SIZE = 48;
constexpr size_t SHA512_DIGEST_SIZE = 64;
constexpr size_t SHA1_DIGEST_SIZE = 20;

/**
 * Get digest size for hash algorithm
 */
constexpr size_t get_digest_size(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::SHA256: return SHA256_DIGEST_SIZE;
        case HashAlgorithm::SHA384: return SHA384_DIGEST_SIZE;
        case HashAlgorithm::SHA512: return SHA512_DIGEST_SIZE;
        case HashAlgorithm::SHA1: return SHA1_DIGEST_SIZE;
        default: return 0;
    }
}

/**
 * Hash Context Interface
 */
class DTLS_API HashContext {
public:
    virtual ~HashContext() = default;
    
    /**
     * Update hash with data
     */
    virtual Result<void> update(const void* data, size_t length) = 0;
    virtual Result<void> update(const memory::Buffer& buffer) = 0;
    
    /**
     * Finalize hash and get digest
     */
    virtual Result<memory::Buffer> finalize() = 0;
    
    /**
     * Reset context for reuse
     */
    virtual Result<void> reset() = 0;
    
    /**
     * Get hash algorithm
     */
    virtual HashAlgorithm algorithm() const = 0;
    
    /**
     * Get expected digest size
     */
    virtual size_t digest_size() const = 0;
};

/**
 * Hash utility functions
 */

/**
 * Create hash context for algorithm
 */
DTLS_API Result<std::unique_ptr<HashContext>> create_hash_context(HashAlgorithm algorithm);

/**
 * One-shot hash computation
 */
DTLS_API Result<memory::Buffer> compute_hash(HashAlgorithm algorithm, 
                                           const void* data, size_t length);
DTLS_API Result<memory::Buffer> compute_hash(HashAlgorithm algorithm, 
                                           const memory::Buffer& buffer);

/**
 * Specific hash functions
 */
DTLS_API Result<std::array<uint8_t, SHA256_DIGEST_SIZE>> sha256(const void* data, size_t length);
DTLS_API Result<std::array<uint8_t, SHA256_DIGEST_SIZE>> sha256(const memory::Buffer& buffer);

DTLS_API Result<std::array<uint8_t, SHA384_DIGEST_SIZE>> sha384(const void* data, size_t length);
DTLS_API Result<std::array<uint8_t, SHA384_DIGEST_SIZE>> sha384(const memory::Buffer& buffer);

DTLS_API Result<std::array<uint8_t, SHA512_DIGEST_SIZE>> sha512(const void* data, size_t length);
DTLS_API Result<std::array<uint8_t, SHA512_DIGEST_SIZE>> sha512(const memory::Buffer& buffer);

/**
 * Hash verification
 */
DTLS_API bool verify_hash(HashAlgorithm algorithm,
                         const void* data, size_t length,
                         const void* expected_digest, size_t digest_length);
DTLS_API bool verify_hash(HashAlgorithm algorithm,
                         const memory::Buffer& buffer,
                         const memory::Buffer& expected_digest);

} // namespace dtls::v13::crypto