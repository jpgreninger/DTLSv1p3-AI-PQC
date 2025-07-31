#pragma once

/**
 * @file advanced_cipher_suites.h
 * @brief Advanced cipher suite support for DTLS v1.3
 * 
 * Extends the base DTLS v1.3 implementation with additional cipher suites
 * including ChaCha20-Poly1305, AES-CCM variants, and hardware-optimized ciphers.
 */

#include "dtls/types.h"
#include "dtls/error.h"
#include "dtls/result.h"
#include "dtls/crypto/provider.h"

namespace dtls {
namespace v13 {
namespace crypto {
namespace advanced {

/**
 * @brief Extended cipher suites beyond base DTLS v1.3
 */
enum class ExtendedCipherSuite : uint16_t {
    // ChaCha20-Poly1305 variants
    TLS_CHACHA20_POLY1305_SHA256_EXTENDED = 0x1305,
    TLS_XCHACHA20_POLY1305_SHA256 = 0x1306,
    
    // AES-CCM variants
    TLS_AES_128_CCM_SHA256_EXTENDED = 0x1307,
    TLS_AES_128_CCM_8_SHA256_EXTENDED = 0x1308,
    TLS_AES_256_CCM_SHA384 = 0x1309,
    TLS_AES_256_CCM_8_SHA384 = 0x130A,
    
    // Hardware-optimized variants
    TLS_AES_128_GCM_SHA256_HW = 0x130B,
    TLS_AES_256_GCM_SHA384_HW = 0x130C,
    
    // Post-quantum crypto preparation
    TLS_AES_256_GCM_SHA512 = 0x130D,
    TLS_CHACHA20_POLY1305_SHA512 = 0x130E,
    
    // ARIA cipher support
    TLS_ARIA_128_GCM_SHA256 = 0x130F,
    TLS_ARIA_256_GCM_SHA384 = 0x1310,
    
    // Camellia cipher support  
    TLS_CAMELLIA_128_GCM_SHA256 = 0x1311,
    TLS_CAMELLIA_256_GCM_SHA384 = 0x1312,
    
    // High-performance streaming ciphers
    TLS_CHACHA20_BLAKE2B_256 = 0x1313,
    TLS_SALSA20_POLY1305_SHA256 = 0x1314,
};

/**
 * @brief Extended AEAD cipher algorithms
 */
enum class ExtendedAEADCipher : uint8_t {
    // Base ciphers (compatibility)
    AES_128_GCM = 1,
    AES_256_GCM = 2, 
    CHACHA20_POLY1305 = 3,
    AES_128_CCM = 4,
    AES_128_CCM_8 = 5,
    
    // Extended ciphers
    XCHACHA20_POLY1305 = 6,
    AES_256_CCM = 7,
    AES_256_CCM_8 = 8,
    ARIA_128_GCM = 9,
    ARIA_256_GCM = 10,
    CAMELLIA_128_GCM = 11,
    CAMELLIA_256_GCM = 12,
    CHACHA20_BLAKE2B = 13,
    SALSA20_POLY1305 = 14,
    
    // Hardware accelerated variants (same algorithm, different implementation)
    AES_128_GCM_HW = 15,
    AES_256_GCM_HW = 16,
};

/**
 * @brief Extended hash algorithms
 */
enum class ExtendedHashAlgorithm : uint8_t {
    // Base algorithms (compatibility)
    SHA256 = 1,
    SHA384 = 2,
    SHA512 = 3,
    
    // Extended algorithms
    BLAKE2B_256 = 4,
    BLAKE2B_384 = 5,
    BLAKE2B_512 = 6,
    BLAKE2S_256 = 7,
    SHA3_256 = 8,
    SHA3_384 = 9,
    SHA3_512 = 10,
    KECCAK_256 = 11,
    
    // High-performance variants
    BLAKE3_256 = 12,
    BLAKE3_384 = 13,
    BLAKE3_512 = 14,
};

/**
 * @brief Cipher suite properties for extended algorithms
 */
struct ExtendedCipherSuiteProperties {
    ExtendedCipherSuite suite;
    ExtendedAEADCipher aead_cipher;
    ExtendedHashAlgorithm hash_algorithm;
    uint16_t key_length;
    uint16_t iv_length;
    uint16_t tag_length;
    uint16_t hash_length;
    bool requires_hardware_acceleration;
    bool provides_quantum_resistance;
    uint8_t security_level; // 1-5 scale
    uint32_t performance_rating; // Relative performance score
    
    static const ExtendedCipherSuiteProperties& get_properties(ExtendedCipherSuite suite);
};

/**
 * @brief Advanced crypto provider interface
 */
class DTLS_API AdvancedCryptoProvider : public CryptoProvider {
public:
    virtual ~AdvancedCryptoProvider() = default;

    /**
     * @brief Check if extended cipher suite is supported
     */
    virtual bool supports_extended_cipher_suite(ExtendedCipherSuite suite) const = 0;

    /**
     * @brief AEAD encryption with extended algorithms
     */
    virtual Result<std::vector<uint8_t>> extended_aead_encrypt(
        const ExtendedAEADParams& params,
        const std::vector<uint8_t>& plaintext
    ) = 0;

    /**
     * @brief AEAD decryption with extended algorithms
     */
    virtual Result<std::vector<uint8_t>> extended_aead_decrypt(
        const ExtendedAEADParams& params,
        const std::vector<uint8_t>& ciphertext
    ) = 0;

    /**
     * @brief Hash computation with extended algorithms
     */
    virtual Result<std::vector<uint8_t>> extended_hash(
        const ExtendedHashParams& params,
        const std::vector<uint8_t>& data
    ) = 0;

    /**
     * @brief HMAC computation with extended algorithms
     */
    virtual Result<std::vector<uint8_t>> extended_hmac(
        const ExtendedHMACParams& params,
        const std::vector<uint8_t>& data
    ) = 0;

    /**
     * @brief Key derivation with extended algorithms
     */
    virtual Result<std::vector<uint8_t>> extended_key_derivation(
        const ExtendedKeyDerivationParams& params
    ) = 0;

    /**
     * @brief Get performance characteristics
     */
    virtual ProviderPerformanceProfile get_performance_profile() const = 0;

    /**
     * @brief Get supported extended cipher suites
     */
    virtual std::vector<ExtendedCipherSuite> get_supported_extended_cipher_suites() const = 0;
};

/**
 * @brief Extended AEAD parameters
 */
struct ExtendedAEADParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> additional_data;
    ExtendedAEADCipher cipher;
    bool use_hardware_acceleration = true;
    
    // Algorithm-specific parameters
    struct ChaCha20Params {
        uint32_t counter = 1;
        bool use_xchacha_variant = false;
    } chacha20_params;
    
    struct AESParams {
        bool use_hardware_acceleration = true;
        bool constant_time_operation = true;
    } aes_params;
    
    struct ARIAParams {
        uint8_t rounds = 12; // Default rounds for ARIA
    } aria_params;
};

/**
 * @brief Extended hash parameters
 */
struct ExtendedHashParams {
    ExtendedHashAlgorithm algorithm;
    bool use_hardware_acceleration = true;
    
    // Algorithm-specific parameters
    struct BLAKE2Params {
        std::vector<uint8_t> key; // Optional key for keyed hashing
        std::vector<uint8_t> salt; // Optional salt
        std::vector<uint8_t> personalization; // Optional personalization
        uint8_t digest_length = 32; // Output length for BLAKE2b
    } blake2_params;
    
    struct SHA3Params {
        uint16_t capacity = 512; // Capacity for SHA-3
    } sha3_params;
};

/**
 * @brief Extended HMAC parameters
 */
struct ExtendedHMACParams {
    std::vector<uint8_t> key;
    ExtendedHashAlgorithm algorithm;
    bool use_hardware_acceleration = true;
};

/**
 * @brief Extended key derivation parameters
 */
struct ExtendedKeyDerivationParams : public KeyDerivationParams {
    ExtendedHashAlgorithm hash_algorithm;
    bool use_quantum_resistant_expansion = false;
    uint32_t iteration_count = 1; // For PBKDF2-like schemes
    std::vector<uint8_t> personalization; // For algorithm-specific customization
};

/**
 * @brief Provider performance profile
 */
struct ProviderPerformanceProfile {
    std::unordered_map<ExtendedAEADCipher, uint32_t> aead_performance_scores;
    std::unordered_map<ExtendedHashAlgorithm, uint32_t> hash_performance_scores;
    bool hardware_acceleration_available;
    std::vector<HardwareCapability> available_capabilities;
    uint32_t overall_performance_score;
    std::string platform_optimization_level; // "generic", "optimized", "highly_optimized"
};

/**
 * @brief Advanced cipher suite manager
 */
class DTLS_API AdvancedCipherSuiteManager {
public:
    /**
     * @brief Create advanced cipher suite manager
     */
    static std::unique_ptr<AdvancedCipherSuiteManager> create();

    virtual ~AdvancedCipherSuiteManager() = default;

    /**
     * @brief Register advanced crypto provider
     */
    virtual Result<void> register_provider(
        const std::shared_ptr<AdvancedCryptoProvider>& provider
    ) = 0;

    /**
     * @brief Get optimal cipher suite for connection
     */
    virtual Result<ExtendedCipherSuite> select_optimal_cipher_suite(
        const std::vector<ExtendedCipherSuite>& client_suites,
        const PerformanceRequirements& requirements
    ) = 0;

    /**
     * @brief Get cipher suite security assessment
     */
    virtual SecurityAssessment assess_cipher_suite_security(
        ExtendedCipherSuite suite
    ) = 0;

    /**
     * @brief Get performance benchmark for cipher suite
     */
    virtual Result<PerformanceBenchmark> benchmark_cipher_suite(
        ExtendedCipherSuite suite,
        size_t data_size = 1024
    ) = 0;

    /**
     * @brief Check quantum resistance of cipher suite
     */
    virtual bool is_quantum_resistant(ExtendedCipherSuite suite) = 0;

    /**
     * @brief Get recommended cipher suites for security level
     */
    virtual std::vector<ExtendedCipherSuite> get_recommended_cipher_suites(
        SecurityLevel security_level,
        bool require_quantum_resistance = false
    ) = 0;
};

/**
 * @brief Performance requirements for cipher suite selection
 */
struct PerformanceRequirements {
    uint32_t min_throughput_mbps = 0; // Minimum throughput requirement
    uint32_t max_latency_us = 1000000; // Maximum latency tolerance (microseconds)
    bool prefer_hardware_acceleration = true;
    bool require_constant_time = true;
    uint8_t min_security_level = 3; // 1-5 scale
    bool require_perfect_forward_secrecy = true;
    size_t typical_message_size = 1024; // For optimization
};

/**
 * @brief Security assessment result
 */
struct SecurityAssessment {
    uint8_t overall_security_level; // 1-5 scale
    bool provides_confidentiality;
    bool provides_integrity;
    bool provides_authentication;
    bool provides_perfect_forward_secrecy;
    bool quantum_resistant;
    uint16_t effective_key_strength; // Bits of security
    std::vector<std::string> security_notes;
    std::vector<std::string> recommendations;
};

/**
 * @brief Performance benchmark result
 */
struct PerformanceBenchmark {
    uint32_t throughput_mbps;
    uint32_t latency_encrypt_us;
    uint32_t latency_decrypt_us;
    uint32_t cpu_cycles_per_byte;
    uint32_t memory_usage_kb;
    bool uses_hardware_acceleration;
    std::string platform_info;
    std::chrono::steady_clock::time_point benchmark_time;
};

/**
 * @brief Utility functions for advanced cipher suites
 */
namespace utils {

/**
 * @brief Convert base cipher suite to extended
 */
ExtendedCipherSuite convert_base_to_extended(CipherSuite base_suite);

/**
 * @brief Convert extended cipher suite to base (if possible)
 */
Result<CipherSuite> convert_extended_to_base(ExtendedCipherSuite extended_suite);

/**
 * @brief Check cipher suite compatibility
 */
bool are_cipher_suites_compatible(ExtendedCipherSuite suite1, ExtendedCipherSuite suite2);

/**
 * @brief Get cipher suite name
 */
std::string get_cipher_suite_name(ExtendedCipherSuite suite);

/**
 * @brief Parse cipher suite from string
 */
Result<ExtendedCipherSuite> parse_cipher_suite(const std::string& name);

/**
 * @brief Get minimum TLS/DTLS version for cipher suite
 */
ProtocolVersion get_minimum_version(ExtendedCipherSuite suite);

/**
 * @brief Check if cipher suite is approved by standards
 */
bool is_standards_approved(ExtendedCipherSuite suite);

/**
 * @brief Get cipher suite standardization status
 */
std::string get_standardization_status(ExtendedCipherSuite suite);

} // namespace utils

} // namespace advanced
} // namespace crypto
} // namespace v13
} // namespace dtls