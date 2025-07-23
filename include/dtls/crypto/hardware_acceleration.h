#ifndef DTLS_CRYPTO_HARDWARE_ACCELERATION_H
#define DTLS_CRYPTO_HARDWARE_ACCELERATION_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <vector>
#include <string>

namespace dtls {
namespace v13 {
namespace crypto {

/**
 * Hardware acceleration capabilities and detection
 */
enum class HardwareCapability {
    // CPU instruction sets
    AES_NI,          // Intel AES-NI instructions
    AVX,             // Advanced Vector Extensions
    AVX2,            // Advanced Vector Extensions 2
    SSE2,            // Streaming SIMD Extensions 2
    SSE3,            // Streaming SIMD Extensions 3
    SSE4_1,          // Streaming SIMD Extensions 4.1
    SSE4_2,          // Streaming SIMD Extensions 4.2
    PCLMULQDQ,       // Carry-less multiplication
    
    // ARM instruction sets
    ARM_NEON,        // ARM NEON SIMD
    ARM_AES,         // ARM AES instructions
    ARM_SHA1,        // ARM SHA1 instructions
    ARM_SHA2,        // ARM SHA2 instructions
    ARM_SHA3,        // ARM SHA3 instructions
    
    // Hardware security modules
    TPM_2_0,         // Trusted Platform Module 2.0
    HSM,             // Hardware Security Module
    SECURE_ENCLAVE,  // ARM TrustZone / Intel SGX
    
    // Cryptographic accelerators
    CRYPTO_ENGINE,   // Dedicated crypto engine
    RNG_HARDWARE,    // Hardware random number generator
    
    // Platform-specific
    INTEL_QAT,       // Intel QuickAssist Technology
    ARM_CRYPTO_EXT,  // ARM Cryptography Extension
    POWER_CRYPTO,    // IBM POWER crypto instructions
    
    // Virtualization
    VIRTUAL_HSM,     // Virtualized HSM
    CLOUD_KMS        // Cloud Key Management Service
};

/**
 * Hardware acceleration status for a specific capability
 */
struct HardwareCapabilityStatus {
    HardwareCapability capability;
    bool available;
    bool enabled;
    std::string description;
    std::string version_info;
    float performance_multiplier; // Speed improvement factor (1.0 = no improvement)
};

/**
 * Complete hardware acceleration profile
 */
struct HardwareAccelerationProfile {
    std::string platform_name;
    std::string cpu_model;
    std::string os_version;
    std::vector<HardwareCapabilityStatus> capabilities;
    bool has_any_acceleration;
    float overall_performance_score; // Relative performance score
    std::string recommendations;
};

/**
 * Hardware acceleration detection and management
 */
class DTLS_API HardwareAccelerationDetector {
public:
    /**
     * Detect all available hardware acceleration capabilities
     */
    static Result<HardwareAccelerationProfile> detect_capabilities();
    
    /**
     * Check if a specific capability is available
     */
    static bool is_capability_available(HardwareCapability capability);
    
    /**
     * Get the best available crypto provider based on hardware
     */
    static Result<std::string> get_recommended_provider();
    
    /**
     * Enable hardware acceleration for a specific capability
     */
    static Result<void> enable_capability(HardwareCapability capability);
    
    /**
     * Disable hardware acceleration for a specific capability
     */
    static Result<void> disable_capability(HardwareCapability capability);
    
    /**
     * Get performance benchmark for a capability
     */
    static Result<float> benchmark_capability(HardwareCapability capability);
    
    /**
     * Get optimization recommendations
     */
    static Result<std::vector<std::string>> get_optimization_recommendations();

private:
    static bool detect_aes_ni();
    static bool detect_avx();
    static bool detect_arm_crypto();
    static bool detect_tpm();
    static bool detect_hardware_rng();
    static std::string get_cpu_model();
    static std::string get_platform_info();
};

/**
 * Hardware-accelerated crypto provider selector
 */
class DTLS_API HardwareAcceleratedProviderSelector {
public:
    /**
     * Select the best provider based on hardware capabilities
     */
    static Result<std::string> select_best_provider(
        const std::vector<std::string>& available_providers,
        const HardwareAccelerationProfile& hw_profile);
    
    /**
     * Get provider-specific acceleration settings
     */
    static Result<std::vector<std::pair<std::string, std::string>>> 
        get_provider_acceleration_settings(const std::string& provider_name);
    
    /**
     * Optimize provider configuration for hardware
     */
    static Result<void> optimize_provider_for_hardware(
        const std::string& provider_name,
        const HardwareAccelerationProfile& hw_profile);

private:
    static float score_provider_for_hardware(
        const std::string& provider_name,
        const HardwareAccelerationProfile& hw_profile);
};

// Utility functions
namespace hardware_utils {

/**
 * Get hardware acceleration status summary
 */
DTLS_API std::string get_acceleration_summary();

/**
 * Test hardware acceleration performance
 */
DTLS_API Result<std::vector<std::pair<HardwareCapability, float>>> 
    benchmark_all_capabilities();

/**
 * Generate hardware optimization report
 */
DTLS_API Result<std::string> generate_optimization_report();

/**
 * Check if system supports secure boot
 */
DTLS_API bool supports_secure_boot();

/**
 * Check if system has hardware entropy source
 */
DTLS_API bool has_hardware_entropy();

/**
 * Get recommended cipher suites for hardware
 */
DTLS_API std::vector<CipherSuite> get_hardware_optimized_cipher_suites();

} // namespace hardware_utils
} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_HARDWARE_ACCELERATION_H