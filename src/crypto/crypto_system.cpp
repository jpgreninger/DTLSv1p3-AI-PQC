#include <dtls/crypto.h>
#include <dtls/crypto/provider_factory.h>
#include <dtls/crypto/openssl_provider.h>
#include <mutex>
#include <atomic>

namespace dtls {
namespace v13 {
namespace crypto {

// Global state management
namespace {
    std::atomic<bool> g_crypto_initialized{false};
    std::mutex g_crypto_mutex;
    CryptoSystemConfig g_crypto_config;
    std::chrono::steady_clock::time_point g_initialization_time;
}

// System initialization
Result<void> initialize_crypto_system() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    
    if (g_crypto_initialized.load()) {
        return Result<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    try {
        // Initialize OpenSSL library first
        auto openssl_init = openssl_utils::initialize_openssl();
        if (!openssl_init) {
            return openssl_init;
        }
        
        // Register all built-in providers
        auto register_result = builtin::register_all_providers();
        if (!register_result) {
            return register_result;
        }
        
        // Refresh provider availability
        auto& factory = ProviderFactory::instance();
        auto refresh_result = factory.refresh_availability();
        if (!refresh_result) {
            return refresh_result;
        }
        
        // Set default configuration
        g_crypto_config = CryptoSystemConfig{};
        g_initialization_time = std::chrono::steady_clock::now();
        
        // Try to set a default provider
        auto available_providers = factory.available_providers();
        if (!available_providers.empty()) {
            factory.set_default_provider(available_providers[0]);
            g_crypto_config.preferred_provider = available_providers[0];
        }
        
        g_crypto_initialized.store(true);
        return Result<void>();
        
    } catch (const DTLSException& e) {
        return Result<void>(e.dtls_error());
    } catch (...) {
        return Result<void>(DTLSError::INTERNAL_ERROR);
    }
}

void cleanup_crypto_system() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    
    if (!g_crypto_initialized.load()) {
        return;
    }
    
    try {
        // Reset crypto stats
        utils::CryptoStatsCollector::instance().reset_stats();
        
        // Cleanup OpenSSL
        openssl_utils::cleanup_openssl();
        
        g_crypto_initialized.store(false);
        
    } catch (...) {
        // Ignore cleanup errors
    }
}

bool is_crypto_system_initialized() {
    return g_crypto_initialized.load();
}

// Configuration management
Result<void> set_crypto_system_config(const CryptoSystemConfig& config) {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    
    if (!g_crypto_initialized.load()) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    try {
        g_crypto_config = config;
        
        // Apply configuration changes
        auto& factory = ProviderFactory::instance();
        
        if (!config.preferred_provider.empty()) {
            factory.set_default_provider(config.preferred_provider);
        }
        
        // Enable/disable crypto stats collection
        utils::CryptoStatsCollector::instance().enable_collection(config.enable_crypto_stats);
        
        return Result<void>();
        
    } catch (const DTLSException& e) {
        return Result<void>(e.dtls_error());
    } catch (...) {
        return Result<void>(DTLSError::INTERNAL_ERROR);
    }
}

CryptoSystemConfig get_crypto_system_config() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    return g_crypto_config;
}

void reset_crypto_system_config() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    g_crypto_config = CryptoSystemConfig{};
}

// Configuration validation
Result<std::vector<ConfigValidationIssue>> validate_crypto_config() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    
    std::vector<ConfigValidationIssue> issues;
    
    if (!g_crypto_initialized.load()) {
        issues.push_back({
            ConfigValidationIssue::Severity::CRITICAL,
            "system",
            "Crypto system not initialized",
            "Call initialize_crypto_system() before validation"
        });
        return Result<std::vector<ConfigValidationIssue>>(std::move(issues));
    }
    
    auto& factory = ProviderFactory::instance();
    
    // Check if preferred provider is available
    if (!g_crypto_config.preferred_provider.empty()) {
        if (!factory.is_provider_available(g_crypto_config.preferred_provider)) {
            issues.push_back({
                ConfigValidationIssue::Severity::WARNING,
                "provider",
                "Preferred provider '" + g_crypto_config.preferred_provider + "' not available",
                "Check provider installation or choose different provider"
            });
        }
    }
    
    // Check hardware acceleration requirements
    if (g_crypto_config.require_hardware_acceleration) {
        auto hw_providers = factory.get_hardware_accelerated_providers();
        if (hw_providers.empty()) {
            issues.push_back({
                ConfigValidationIssue::Severity::ERROR,
                "hardware",
                "Hardware acceleration required but no providers support it",
                "Install hardware-accelerated crypto provider or disable requirement"
            });
        }
    }
    
    // Check FIPS compliance requirements
    if (g_crypto_config.require_fips_compliance) {
        auto fips_providers = factory.get_fips_compliant_providers();
        if (fips_providers.empty()) {
            issues.push_back({
                ConfigValidationIssue::Severity::ERROR,
                "fips",
                "FIPS compliance required but no providers support it",
                "Install FIPS-compliant crypto provider or disable requirement"
            });
        }
    }
    
    // Check disabled cipher suites
    auto available_providers = factory.available_providers();
    for (const auto& provider_name : available_providers) {
        auto caps_result = factory.get_capabilities(provider_name);
        if (caps_result) {
            const auto& caps = *caps_result;
            
            // Check if all cipher suites are disabled
            bool all_disabled = true;
            for (const auto& suite : caps.supported_cipher_suites) {
                if (std::find(g_crypto_config.disabled_cipher_suites.begin(),
                             g_crypto_config.disabled_cipher_suites.end(),
                             suite) == g_crypto_config.disabled_cipher_suites.end()) {
                    all_disabled = false;
                    break;
                }
            }
            
            if (all_disabled && !caps.supported_cipher_suites.empty()) {
                issues.push_back({
                    ConfigValidationIssue::Severity::WARNING,
                    "cipher_suites",
                    "All cipher suites disabled for provider '" + provider_name + "'",
                    "Enable at least one cipher suite for proper operation"
                });
            }
        }
    }
    
    // Check security level
    if (g_crypto_config.default_security_level == SecurityLevel::NONE) {
        issues.push_back({
            ConfigValidationIssue::Severity::WARNING,
            "security",
            "Security level set to NONE",
            "Consider using higher security level for production"
        });
    }
    
    return Result<std::vector<ConfigValidationIssue>>(std::move(issues));
}

// System status
CryptoSystemStatus get_crypto_system_status() {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    
    CryptoSystemStatus status;
    status.is_initialized = g_crypto_initialized.load();
    
    if (!status.is_initialized) {
        return status;
    }
    
    auto& factory = ProviderFactory::instance();
    
    status.default_provider = factory.get_default_provider();
    
    auto available = factory.available_providers();
    status.available_providers = available.size();
    status.active_providers = available.size(); // All available are considered active
    
    // Check for hardware acceleration
    auto hw_providers = factory.get_hardware_accelerated_providers();
    status.hardware_acceleration_available = !hw_providers.empty();
    
    // Check for FIPS mode
    auto fips_providers = factory.get_fips_compliant_providers();
    status.fips_mode_available = !fips_providers.empty();
    
    // Get OpenSSL version
    if (openssl_utils::is_openssl_available()) {
        status.openssl_version = openssl_utils::get_openssl_version();
    }
    
    status.initialization_time = g_initialization_time;
    auto now = std::chrono::steady_clock::now();
    status.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - g_initialization_time);
    
    return status;
}

// Health check
Result<CryptoHealthCheckResult> perform_crypto_health_check() {
    auto start_time = std::chrono::steady_clock::now();
    
    CryptoHealthCheckResult result;
    result.check_time = start_time;
    
    if (!g_crypto_initialized.load()) {
        result.overall_healthy = false;
        result.issues.push_back({
            ConfigValidationIssue::Severity::CRITICAL,
            "system",
            "Crypto system not initialized",
            "Call initialize_crypto_system()"
        });
        
        auto end_time = std::chrono::steady_clock::now();
        result.check_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        return Result<CryptoHealthCheckResult>(std::move(result));
    }
    
    auto& factory = ProviderFactory::instance();
    
    // Test all available providers
    auto available_providers = factory.available_providers();
    for (const auto& provider_name : available_providers) {
        try {
            auto provider_result = factory.create_provider(provider_name);
            if (provider_result) {
                auto provider = std::move(*provider_result);
                auto init_result = provider->initialize();
                if (init_result) {
                    result.available_providers.push_back(provider_name);
                    provider->cleanup();
                } else {
                    result.failed_providers.push_back(provider_name);
                    result.issues.push_back({
                        ConfigValidationIssue::Severity::WARNING,
                        "provider",
                        "Provider '" + provider_name + "' failed to initialize",
                        "Check provider configuration and dependencies"
                    });
                }
            } else {
                result.failed_providers.push_back(provider_name);
                result.issues.push_back({
                    ConfigValidationIssue::Severity::WARNING,
                    "provider",
                    "Provider '" + provider_name + "' failed to create",
                    "Check provider availability and dependencies"
                });
            }
        } catch (...) {
            result.failed_providers.push_back(provider_name);
            result.issues.push_back({
                ConfigValidationIssue::Severity::ERROR,
                "provider",
                "Provider '" + provider_name + "' threw exception during test",
                "Check provider implementation and system state"
            });
        }
    }
    
    // Validate configuration
    auto validation_result = validate_crypto_config();
    if (validation_result) {
        auto validation_issues = *validation_result;
        result.issues.insert(result.issues.end(), 
                            validation_issues.begin(), validation_issues.end());
    }
    
    // Determine overall health
    bool has_critical_issues = false;
    bool has_error_issues = false;
    
    for (const auto& issue : result.issues) {
        if (issue.severity == ConfigValidationIssue::Severity::CRITICAL) {
            has_critical_issues = true;
        } else if (issue.severity == ConfigValidationIssue::Severity::ERROR) {
            has_error_issues = true;
        }
    }
    
    result.overall_healthy = !has_critical_issues && !has_error_issues && 
                            !result.available_providers.empty();
    
    auto end_time = std::chrono::steady_clock::now();
    result.check_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return Result<CryptoHealthCheckResult>(std::move(result));
}

// Self-tests
Result<CryptoSelfTestResult> run_crypto_self_tests() {
    auto start_time = std::chrono::steady_clock::now();
    
    CryptoSelfTestResult result;
    
    if (!g_crypto_initialized.load()) {
        result.all_tests_passed = false;
        result.failed_test_names.push_back("system_initialization");
        result.tests_run = 1;
        result.tests_failed = 1;
        
        auto end_time = std::chrono::steady_clock::now();
        result.total_test_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        return Result<CryptoSelfTestResult>(std::move(result));
    }
    
    auto& factory = ProviderFactory::instance();
    auto available_providers = factory.available_providers();
    
    for (const auto& provider_name : available_providers) {
        try {
            auto provider_result = factory.create_provider(provider_name);
            if (!provider_result) {
                result.failed_test_names.push_back("create_" + provider_name);
                result.tests_failed++;
                continue;
            }
            
            auto provider = std::move(*provider_result);
            auto init_result = provider->initialize();
            if (!init_result) {
                result.failed_test_names.push_back("init_" + provider_name);
                result.tests_failed++;
                continue;
            }
            
            result.tests_passed++;
            
            // Test basic random generation
            RandomParams random_params;
            random_params.length = 32;
            random_params.cryptographically_secure = true;
            
            auto random_result = provider->generate_random(random_params);
            if (random_result && random_result->size() == 32) {
                result.tests_passed++;
            } else {
                result.failed_test_names.push_back("random_" + provider_name);
                result.tests_failed++;
            }
            
            // Test hash computation
            HashParams hash_params;
            hash_params.data = {'t', 'e', 's', 't'};
            hash_params.algorithm = HashAlgorithm::SHA256;
            
            auto hash_result = provider->compute_hash(hash_params);
            if (hash_result && hash_result->size() == 32) {
                result.tests_passed++;
            } else {
                result.failed_test_names.push_back("hash_" + provider_name);
                result.tests_failed++;
            }
            
            provider->cleanup();
            
        } catch (...) {
            result.failed_test_names.push_back("exception_" + provider_name);
            result.tests_failed++;
        }
    }
    
    result.tests_run = result.tests_passed + result.tests_failed;
    result.all_tests_passed = (result.tests_failed == 0);
    
    auto end_time = std::chrono::steady_clock::now();
    result.total_test_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return Result<CryptoSelfTestResult>(std::move(result));
}

} // namespace crypto
} // namespace v13
} // namespace dtls