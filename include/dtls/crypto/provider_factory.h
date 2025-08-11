#ifndef DTLS_CRYPTO_PROVIDER_FACTORY_H
#define DTLS_CRYPTO_PROVIDER_FACTORY_H

#include <dtls/config.h>
#include <dtls/crypto/provider.h>
#include <dtls/result.h>
#include <memory>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace dtls {
namespace v13 {
namespace crypto {

// Provider factory function type
using ProviderFactoryFunction = std::function<std::unique_ptr<CryptoProvider>()>;

// Provider plugin information for dynamic loading
struct ProviderPluginInfo {
    std::string plugin_path;
    std::string plugin_name;
    std::string plugin_version;
    std::vector<std::string> dependencies;
    std::unordered_map<std::string, std::string> metadata;
};

// Enhanced provider registration information
struct ProviderRegistration {
    std::string name;
    std::string description;
    ProviderFactoryFunction factory;
    int priority{0}; // Higher priority providers are preferred
    bool is_available{true};
    ProviderCapabilities capabilities;
    
    // Enhanced registration info
    std::string provider_version;
    std::vector<std::string> supported_standards;
    std::unordered_map<std::string, bool> feature_flags;
    ProviderPluginInfo plugin_info;
    
    // Health and monitoring
    ProviderHealth health_status{ProviderHealth::HEALTHY};
    std::chrono::steady_clock::time_point last_health_check;
    size_t consecutive_failures{0};
    
    // Performance tracking
    ProviderPerformanceMetrics performance_metrics;
};

// Provider compatibility result
struct ProviderCompatibilityResult {
    bool is_compatible{false};
    double compatibility_score{0.0};
    std::vector<std::string> missing_features;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
};

// Provider load balancing strategy
enum class LoadBalancingStrategy {
    ROUND_ROBIN,
    LEAST_LOADED,
    PERFORMANCE_BASED,
    HEALTH_BASED,
    CUSTOM
};

// Provider pool configuration
struct ProviderPoolConfig {
    LoadBalancingStrategy strategy{LoadBalancingStrategy::HEALTH_BASED};
    size_t min_pool_size{1};
    size_t max_pool_size{5};
    bool enable_health_monitoring{true};
    std::chrono::seconds health_check_interval{300};
    bool auto_failover_enabled{true};
    size_t max_retries{3};
};

/**
 * Factory class for creating and managing crypto providers
 * 
 * Handles provider registration, discovery, and instantiation based on
 * selection criteria and availability.
 */
class DTLS_API ProviderFactory {
public:
    // Singleton access
    static ProviderFactory& instance();
    
    // Provider registration
    Result<void> register_provider(
        const std::string& name,
        const std::string& description,
        ProviderFactoryFunction factory,
        int priority = 0);
    
    void unregister_provider(const std::string& name);
    
    // Provider discovery
    std::vector<std::string> available_providers() const;
    std::vector<std::string> available_providers_unlocked() const;
    std::vector<ProviderRegistration> get_all_registrations() const;
    Result<ProviderRegistration> get_registration(const std::string& name) const;
    
    // Provider creation
    Result<std::unique_ptr<CryptoProvider>> create_provider(
        const std::string& name) const;
    
    Result<std::unique_ptr<CryptoProvider>> create_best_provider(
        const ProviderSelection& criteria = {}) const;
    
    Result<std::unique_ptr<CryptoProvider>> create_default_provider() const;
    
    // Provider capabilities query
    Result<ProviderCapabilities> get_capabilities(const std::string& name) const;
    Result<EnhancedProviderCapabilities> get_enhanced_capabilities(const std::string& name) const;
    bool supports_cipher_suite(const std::string& provider_name, CipherSuite suite) const;
    bool supports_named_group(const std::string& provider_name, NamedGroup group) const;
    bool supports_signature_scheme(const std::string& provider_name, SignatureScheme scheme) const;
    
    // Enhanced compatibility checking
    Result<ProviderCompatibilityResult> check_compatibility(
        const std::string& provider_name, const ProviderSelection& criteria) const;
    std::vector<std::string> find_compatible_providers(
        const ProviderSelection& criteria) const;
    Result<std::string> select_best_compatible_provider(
        const ProviderSelection& criteria) const;
    
    // Provider availability
    bool is_provider_available(const std::string& name) const;
    Result<void> refresh_availability();
    
    // Configuration
    void set_default_provider(const std::string& name);
    std::string get_default_provider() const;
    
    void set_provider_preference_order(const std::vector<std::string>& order);
    std::vector<std::string> get_provider_preference_order() const;
    
    // Security and compliance
    std::vector<std::string> get_fips_compliant_providers() const;
    std::vector<std::string> get_hardware_accelerated_providers() const;
    
    // Provider selection algorithms
    Result<std::string> select_provider_for_cipher_suite(CipherSuite suite) const;
    Result<std::string> select_provider_for_key_exchange(NamedGroup group) const;
    Result<std::string> select_provider_for_signature(SignatureScheme scheme) const;
    
    // Advanced provider selection
    Result<std::vector<std::string>> rank_providers_by_performance() const;
    Result<std::vector<std::string>> rank_providers_by_compatibility(
        const ProviderSelection& criteria) const;
    Result<std::string> select_provider_with_load_balancing(
        const ProviderSelection& criteria,
        LoadBalancingStrategy strategy = LoadBalancingStrategy::HEALTH_BASED) const;
    
    // Provider health monitoring
    Result<void> perform_health_checks();
    Result<void> perform_health_check(const std::string& provider_name);
    std::vector<std::string> get_healthy_providers() const;
    std::vector<std::string> get_unhealthy_providers() const;
    
    // Provider plugin management
    Result<void> load_provider_plugin(const std::string& plugin_path);
    Result<void> unload_provider_plugin(const std::string& plugin_name);
    std::vector<ProviderPluginInfo> list_loaded_plugins() const;
    Result<void> reload_provider_plugins();
    
    // Enhanced statistics and monitoring
    struct ProviderStats {
        size_t creation_count{0};
        size_t success_count{0};
        size_t failure_count{0};
        std::chrono::steady_clock::time_point last_used;
        std::chrono::milliseconds average_init_time{0};
        
        // Enhanced stats
        size_t operations_count{0};
        std::chrono::milliseconds average_operation_time{0};
        size_t memory_usage_peak{0};
        size_t memory_usage_current{0};
        double success_rate{0.0};
        std::chrono::steady_clock::time_point last_failure;
        std::vector<std::string> recent_errors;
    };
    
    ProviderStats get_provider_stats(const std::string& name) const;
    void reset_provider_stats(const std::string& name);
    void reset_all_stats();

private:
    ProviderFactory() = default;
    ~ProviderFactory() = default;
    ProviderFactory(const ProviderFactory&) = delete;
    ProviderFactory& operator=(const ProviderFactory&) = delete;
    
    // Internal methods
    bool meets_selection_criteria(
        const ProviderRegistration& registration,
        const ProviderSelection& criteria) const;
    
    int calculate_provider_score(
        const ProviderRegistration& registration,
        const ProviderSelection& criteria) const;
    
    void update_provider_stats(
        const std::string& name,
        bool success,
        std::chrono::milliseconds init_time) const;
    
    // Enhanced internal methods
    double calculate_compatibility_score(
        const ProviderRegistration& registration,
        const ProviderSelection& criteria) const;
    
    Result<void> validate_provider_health(
        const std::string& name, 
        ProviderRegistration& registration) const;
    
    void update_provider_health_status(
        const std::string& name,
        ProviderHealth status,
        const std::string& message = "") const;
    
    std::string select_provider_with_strategy(
        const std::vector<std::string>& candidates,
        LoadBalancingStrategy strategy) const;
    
    Result<void> load_provider_from_plugin(
        const ProviderPluginInfo& plugin_info);
    
    // Member variables
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ProviderRegistration> providers_;
    mutable std::unordered_map<std::string, ProviderStats> stats_;
    std::string default_provider_;
    std::vector<std::string> preference_order_;
    
    // Enhanced factory state
    std::unordered_map<std::string, ProviderPluginInfo> loaded_plugins_;
    ProviderPoolConfig pool_config_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_health_checks_;
    mutable std::atomic<size_t> round_robin_counter_{0};
    
    // Monitoring and health tracking
    std::chrono::steady_clock::time_point last_global_health_check_;
    bool auto_health_monitoring_enabled_{true};
    std::thread health_monitoring_thread_;
    std::atomic<bool> shutdown_requested_{false};
};

/**
 * RAII wrapper for crypto provider management
 * 
 * Automatically handles provider initialization and cleanup,
 * with support for fallback providers on failure.
 */
class DTLS_API ProviderManager {
public:
    explicit ProviderManager(const ProviderSelection& criteria = {});
    explicit ProviderManager(const std::string& provider_name);
    ~ProviderManager();
    
    // Non-copyable, movable
    ProviderManager(const ProviderManager&) = delete;
    ProviderManager& operator=(const ProviderManager&) = delete;
    ProviderManager(ProviderManager&&) noexcept;
    ProviderManager& operator=(ProviderManager&&) noexcept;
    
    // Provider access
    bool is_initialized() const { return provider_ != nullptr; }
    CryptoProvider* get() const { return provider_.get(); }
    CryptoProvider* operator->() const { return provider_.get(); }
    CryptoProvider& operator*() const { return *provider_; }
    
    // Provider information
    std::string current_provider_name() const { return provider_name_; }
    ProviderCapabilities current_capabilities() const;
    
    // Failover support
    Result<void> switch_to_provider(const std::string& name);
    Result<void> switch_to_fallback();
    bool has_fallback() const { return !fallback_providers_.empty(); }
    
    // Statistics
    std::chrono::steady_clock::time_point creation_time() const { return creation_time_; }
    std::chrono::milliseconds uptime() const;

private:
    void initialize_provider(const std::string& name);
    void initialize_best_provider(const ProviderSelection& criteria);
    void cleanup_current_provider();
    
    std::unique_ptr<CryptoProvider> provider_;
    std::string provider_name_;
    std::vector<std::string> fallback_providers_;
    ProviderSelection selection_criteria_;
    std::chrono::steady_clock::time_point creation_time_;
};

// Built-in provider registration functions
namespace builtin {

/**
 * Register all built-in crypto providers
 * 
 * This function registers all available built-in providers
 * (OpenSSL, Botan, etc.) with the factory.
 */
DTLS_API Result<void> register_all_providers();

/**
 * Register OpenSSL provider
 */
DTLS_API Result<void> register_openssl_provider();

/**
 * Register Botan provider (if compiled with Botan support)
 */
DTLS_API Result<void> register_botan_provider();

/**
 * Register null/mock provider for testing
 */
DTLS_API Result<void> register_null_provider();

} // namespace builtin

// Convenience functions
DTLS_API Result<std::unique_ptr<CryptoProvider>> create_crypto_provider(
    const std::string& name = "");

DTLS_API Result<std::unique_ptr<CryptoProvider>> create_best_crypto_provider(
    const ProviderSelection& criteria = {});

// Provider utility functions
DTLS_API std::vector<std::string> list_available_providers();
DTLS_API bool is_provider_available(const std::string& name);
DTLS_API std::string get_default_provider_name();

// Auto-initialization support
class DTLS_API ProviderAutoInit {
public:
    ProviderAutoInit();
    ~ProviderAutoInit() = default;
    
private:
    static bool initialized_;
};

// Global instance to ensure providers are registered
static ProviderAutoInit g_provider_auto_init;

} // namespace crypto
} // namespace v13
} // namespace dtls

#endif // DTLS_CRYPTO_PROVIDER_FACTORY_H