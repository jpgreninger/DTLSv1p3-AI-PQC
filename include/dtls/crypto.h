#ifndef DTLS_CRYPTO_H
#define DTLS_CRYPTO_H

/**
 * DTLS v1.3 Cryptographic Provider System
 * 
 * This header provides access to the complete cryptographic subsystem
 * for DTLS v1.3, including:
 * 
 * - Abstract crypto provider interface
 * - Provider factory and management
 * - OpenSSL provider implementation
 * - Cryptographic utilities and helpers
 * - Key derivation and management
 * - AEAD encryption/decryption
 * - Digital signatures and verification
 * - Certificate handling
 * - Random number generation
 * 
 * Usage:
 *   #include <dtls/crypto.h>
 * 
 * Basic usage example:
 * 
 *   using namespace dtls::v13::crypto;
 *   
 *   // Create a crypto provider
 *   auto provider_result = create_best_crypto_provider();
 *   if (!provider_result) {
 *       // Handle error
 *       return provider_result.error();
 *   }
 *   auto provider = std::move(*provider_result);
 *   
 *   // Initialize the provider
 *   auto init_result = provider->initialize();
 *   if (!init_result) {
 *       // Handle initialization error
 *       return init_result.error();
 *   }
 *   
 *   // Use the provider for crypto operations
 *   RandomParams params{.length = 32, .cryptographically_secure = true};
 *   auto random_result = provider->generate_random(params);
 *   if (random_result) {
 *       auto random_bytes = std::move(*random_result);
 *       // Use random bytes...
 *   }
 */

// Core crypto interfaces
#include <dtls/crypto/provider.h>
#include <dtls/crypto/provider_factory.h>

// Provider implementations
#include <dtls/crypto/openssl_provider.h>

// Utility functions and helpers
#include <dtls/crypto/crypto_utils.h>

// Crypto operations abstraction layer
#include <dtls/crypto/operations.h>
#include <dtls/crypto/operations_impl.h>

// Advanced cipher suites (optional - commented out due to compilation issues)
// #include <dtls/crypto/advanced_cipher_suites.h>

namespace dtls {
namespace v13 {

/**
 * Crypto namespace contains all cryptographic functionality
 * for DTLS v1.3 implementation.
 */
namespace crypto {

/**
 * Initialize the cryptographic subsystem
 * 
 * This function should be called once at application startup
 * to initialize the crypto provider system and register all
 * available providers.
 * 
 * @return Success or error result
 */
DTLS_API Result<void> initialize_crypto_system();

/**
 * Cleanup the cryptographic subsystem
 * 
 * This function should be called once at application shutdown
 * to cleanup the crypto provider system and free resources.
 */
DTLS_API void cleanup_crypto_system();

/**
 * Check if the crypto system is initialized
 * 
 * @return true if initialized, false otherwise
 */
DTLS_API bool is_crypto_system_initialized();

/**
 * Get system-wide crypto configuration
 */
struct CryptoSystemConfig {
    // Default security settings
    SecurityLevel default_security_level{SecurityLevel::HIGH};
    
    // Provider preferences
    std::string preferred_provider;
    bool require_hardware_acceleration{false};
    bool require_fips_compliance{false};
    
    // Performance settings
    bool enable_crypto_stats{false};
    size_t provider_cache_size{16};
    
    // Security settings
    bool allow_weak_ciphers{false};
    bool allow_legacy_signatures{false};
    std::vector<CipherSuite> disabled_cipher_suites;
    std::vector<NamedGroup> disabled_groups;
    std::vector<SignatureScheme> disabled_signatures;
    
    // Debugging and diagnostics
    bool enable_crypto_logging{false};
    std::string log_level{"INFO"};
};

/**
 * Set system-wide crypto configuration
 * 
 * @param config The configuration to apply
 * @return Success or error result
 */
DTLS_API Result<void> set_crypto_system_config(const CryptoSystemConfig& config);

/**
 * Get current system-wide crypto configuration
 * 
 * @return Current configuration
 */
DTLS_API CryptoSystemConfig get_crypto_system_config();

/**
 * Reset crypto configuration to defaults
 */
DTLS_API void reset_crypto_system_config();

/**
 * Validate system crypto configuration
 * 
 * Checks if the current configuration is valid and secure.
 * 
 * @return Validation result with any issues found
 */
struct ConfigValidationIssue {
    enum class Severity { INFO, WARNING, ERROR, CRITICAL };
    
    Severity severity;
    std::string component;
    std::string message;
    std::string recommendation;
};

DTLS_API Result<std::vector<ConfigValidationIssue>> validate_crypto_config();

/**
 * System-wide crypto status information
 */
struct CryptoSystemStatus {
    bool is_initialized{false};
    std::string default_provider;
    size_t available_providers{0};
    size_t active_providers{0};
    bool hardware_acceleration_available{false};
    bool fips_mode_available{false};
    std::string openssl_version;
    std::chrono::steady_clock::time_point initialization_time;
    std::chrono::milliseconds uptime{0};
};

/**
 * Get current crypto system status
 * 
 * @return Current system status
 */
DTLS_API CryptoSystemStatus get_crypto_system_status();

/**
 * Crypto system health check
 * 
 * Performs comprehensive health check of the crypto system
 * including provider availability, performance tests, and
 * security validation.
 * 
 * @return Health check results
 */
struct CryptoHealthCheckResult {
    bool overall_healthy{false};
    std::vector<std::string> available_providers;
    std::vector<std::string> failed_providers;
    std::vector<ConfigValidationIssue> issues;
    std::chrono::milliseconds check_duration{0};
    std::chrono::steady_clock::time_point check_time;
};

DTLS_API Result<CryptoHealthCheckResult> perform_crypto_health_check();

/**
 * Run crypto system self-tests
 * 
 * Executes comprehensive self-tests to validate that all
 * cryptographic operations are working correctly.
 * 
 * @return Self-test results
 */
struct CryptoSelfTestResult {
    bool all_tests_passed{false};
    size_t tests_run{0};
    size_t tests_passed{0};
    size_t tests_failed{0};
    std::vector<std::string> failed_test_names;
    std::chrono::milliseconds total_test_time{0};
};

DTLS_API Result<CryptoSelfTestResult> run_crypto_self_tests();

// Convenience aliases for commonly used types
using Provider = CryptoProvider;
using ProviderPtr = std::unique_ptr<CryptoProvider>;
using ProviderManager = crypto::ProviderManager;
using PrivateKeyPtr = std::unique_ptr<PrivateKey>;
using PublicKeyPtr = std::unique_ptr<PublicKey>;
using CertChainPtr = std::unique_ptr<CertificateChain>;

// Crypto operations abstraction aliases
using CryptoOps = ICryptoOperations;
using CryptoOpsPtr = std::unique_ptr<ICryptoOperations>;
using CryptoOpsManager = CryptoOperationsManager;

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_H