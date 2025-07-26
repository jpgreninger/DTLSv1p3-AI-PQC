#pragma once

#include "dtls/types.h"
#include "dtls/result.h"
#include "dtls/memory.h"
#include "dtls/crypto/hash.h"
#include <cstdint>
#include <array>

namespace dtls::v13::crypto {

/**
 * HMAC Context Interface
 */
class DTLS_API HMACContext {
public:
    virtual ~HMACContext() = default;
    
    /**
     * Initialize HMAC with key
     */
    virtual Result<void> init(const void* key, size_t key_length) = 0;
    virtual Result<void> init(const memory::Buffer& key) = 0;
    
    /**
     * Update HMAC with data
     */
    virtual Result<void> update(const void* data, size_t length) = 0;
    virtual Result<void> update(const memory::Buffer& buffer) = 0;
    
    /**
     * Finalize HMAC and get digest
     */
    virtual Result<memory::Buffer> finalize() = 0;
    
    /**
     * Reset context for reuse (key remains set)
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
 * HMAC utility functions
 */

/**
 * Create HMAC context for algorithm
 */
DTLS_API Result<std::unique_ptr<HMACContext>> create_hmac_context(HashAlgorithm algorithm);

/**
 * One-shot HMAC computation
 */
DTLS_API Result<memory::Buffer> compute_hmac(HashAlgorithm algorithm,
                                           const void* key, size_t key_length,
                                           const void* data, size_t data_length);
DTLS_API Result<memory::Buffer> compute_hmac(HashAlgorithm algorithm,
                                           const memory::Buffer& key,
                                           const memory::Buffer& data);

/**
 * Specific HMAC functions
 */
DTLS_API Result<std::array<uint8_t, SHA256_DIGEST_SIZE>> 
hmac_sha256(const void* key, size_t key_length,
            const void* data, size_t data_length);
DTLS_API Result<std::array<uint8_t, SHA256_DIGEST_SIZE>> 
hmac_sha256(const memory::Buffer& key, const memory::Buffer& data);

DTLS_API Result<std::array<uint8_t, SHA384_DIGEST_SIZE>> 
hmac_sha384(const void* key, size_t key_length,
            const void* data, size_t data_length);
DTLS_API Result<std::array<uint8_t, SHA384_DIGEST_SIZE>> 
hmac_sha384(const memory::Buffer& key, const memory::Buffer& data);

DTLS_API Result<std::array<uint8_t, SHA512_DIGEST_SIZE>> 
hmac_sha512(const void* key, size_t key_length,
            const void* data, size_t data_length);
DTLS_API Result<std::array<uint8_t, SHA512_DIGEST_SIZE>> 
hmac_sha512(const memory::Buffer& key, const memory::Buffer& data);

/**
 * HMAC verification
 */
DTLS_API bool verify_hmac(HashAlgorithm algorithm,
                         const void* key, size_t key_length,
                         const void* data, size_t data_length,
                         const void* expected_hmac, size_t hmac_length);
DTLS_API bool verify_hmac(HashAlgorithm algorithm,
                         const memory::Buffer& key,
                         const memory::Buffer& data,
                         const memory::Buffer& expected_hmac);

/**
 * HMAC-based Key Derivation Function (HKDF) - RFC 5869
 */

/**
 * HKDF Extract step
 */
DTLS_API Result<memory::Buffer> hkdf_extract(HashAlgorithm algorithm,
                                            const memory::Buffer& salt,
                                            const memory::Buffer& input_key_material);

/**
 * HKDF Expand step
 */
DTLS_API Result<memory::Buffer> hkdf_expand(HashAlgorithm algorithm,
                                           const memory::Buffer& pseudo_random_key,
                                           const memory::Buffer& info,
                                           size_t output_length);

/**
 * HKDF full operation (Extract + Expand)
 */
DTLS_API Result<memory::Buffer> hkdf(HashAlgorithm algorithm,
                                    const memory::Buffer& salt,
                                    const memory::Buffer& input_key_material,
                                    const memory::Buffer& info,
                                    size_t output_length);

} // namespace dtls::v13::crypto