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

// Provider registration information
struct ProviderRegistration {
    std::string name;
    std::string description;
    ProviderFactoryFunction factory;
    int priority{0}; // Higher priority providers are preferred
    bool is_available{true};
    ProviderCapabilities capabilities;
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
    bool supports_cipher_suite(const std::string& provider_name, CipherSuite suite) const;
    bool supports_named_group(const std::string& provider_name, NamedGroup group) const;
    bool supports_signature_scheme(const std::string& provider_name, SignatureScheme scheme) const;
    
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
    
    // Statistics and monitoring
    struct ProviderStats {
        size_t creation_count{0};
        size_t success_count{0};
        size_t failure_count{0};
        std::chrono::steady_clock::time_point last_used;
        std::chrono::milliseconds average_init_time{0};
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
        std::chrono::milliseconds init_time);
    
    // Member variables
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ProviderRegistration> providers_;
    std::unordered_map<std::string, ProviderStats> stats_;
    std::string default_provider_;
    std::vector<std::string> preference_order_;
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