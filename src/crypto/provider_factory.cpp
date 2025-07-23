#include <dtls/crypto/provider_factory.h>
#include <dtls/crypto/openssl_provider.h>
#include <algorithm>
#include <chrono>

namespace dtls {
namespace v13 {
namespace crypto {

// ProviderFactory implementation
ProviderFactory& ProviderFactory::instance() {
    static ProviderFactory instance;
    return instance;
}

Result<void> ProviderFactory::register_provider(
    const std::string& name,
    const std::string& description,
    ProviderFactoryFunction factory,
    int priority) {
    
    if (name.empty() || !factory) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        // Test provider creation to get capabilities
        auto test_provider = factory();
        if (!test_provider) {
            return Result<void>(DTLSError::CRYPTO_PROVIDER_ERROR);
        }
        
        ProviderRegistration registration;
        registration.name = name;
        registration.description = description;
        registration.factory = std::move(factory);
        registration.priority = priority;
        registration.is_available = test_provider->is_available();
        registration.capabilities = test_provider->capabilities();
        
        providers_[name] = std::move(registration);
        
        // Initialize stats entry
        stats_[name] = ProviderStats{};
        
        return Result<void>();
        
    } catch (const DTLSException& e) {
        return Result<void>(e.dtls_error());
    } catch (...) {
        return Result<void>(DTLSError::INTERNAL_ERROR);
    }
}

void ProviderFactory::unregister_provider(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    providers_.erase(name);
    stats_.erase(name);
    
    // Remove from preference order if present
    auto it = std::find(preference_order_.begin(), preference_order_.end(), name);
    if (it != preference_order_.end()) {
        preference_order_.erase(it);
    }
    
    // Reset default provider if it was unregistered
    if (default_provider_ == name) {
        default_provider_.clear();
    }
}

std::vector<std::string> ProviderFactory::available_providers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> available;
    
    for (const auto& [name, registration] : providers_) {
        if (registration.is_available) {
            available.push_back(name);
        }
    }
    
    // Sort by priority (highest first)
    std::sort(available.begin(), available.end(), 
              [this](const std::string& a, const std::string& b) {
                  return providers_.at(a).priority > providers_.at(b).priority;
              });
    
    return available;
}

std::vector<ProviderRegistration> ProviderFactory::get_all_registrations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProviderRegistration> registrations;
    
    for (const auto& [name, registration] : providers_) {
        registrations.push_back(registration);
    }
    
    return registrations;
}

Result<ProviderRegistration> ProviderFactory::get_registration(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(name);
    if (it == providers_.end()) {
        return Result<ProviderRegistration>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<ProviderRegistration>(it->second);
}

Result<std::unique_ptr<CryptoProvider>> ProviderFactory::create_provider(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(name);
    if (it == providers_.end()) {
        return Result<std::unique_ptr<CryptoProvider>>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    if (!it->second.is_available) {
        return Result<std::unique_ptr<CryptoProvider>>(DTLSError::RESOURCE_UNAVAILABLE);
    }
    
    try {
        auto start_time = std::chrono::steady_clock::now();
        auto provider = it->second.factory();
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        if (!provider) {
            update_provider_stats(name, false, duration);
            return Result<std::unique_ptr<CryptoProvider>>(DTLSError::CRYPTO_PROVIDER_ERROR);
        }
        
        update_provider_stats(name, true, duration);
        return Result<std::unique_ptr<CryptoProvider>>(std::move(provider));
        
    } catch (const DTLSException& e) {
        update_provider_stats(name, false, std::chrono::milliseconds(0));
        return Result<std::unique_ptr<CryptoProvider>>(e.dtls_error());
    } catch (...) {
        update_provider_stats(name, false, std::chrono::milliseconds(0));
        return Result<std::unique_ptr<CryptoProvider>>(DTLSError::INTERNAL_ERROR);
    }
}

Result<std::unique_ptr<CryptoProvider>> ProviderFactory::create_best_provider(const ProviderSelection& criteria) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Score all available providers
    std::vector<std::pair<int, std::string>> scored_providers;
    
    for (const auto& [name, registration] : providers_) {
        if (!registration.is_available) {
            continue;
        }
        
        if (!meets_selection_criteria(registration, criteria)) {
            continue;
        }
        
        int score = calculate_provider_score(registration, criteria);
        scored_providers.emplace_back(score, name);
    }
    
    if (scored_providers.empty()) {
        return Result<std::unique_ptr<CryptoProvider>>(DTLSError::RESOURCE_UNAVAILABLE);
    }
    
    // Sort by score (highest first)
    std::sort(scored_providers.begin(), scored_providers.end(), 
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    // Try to create the highest-scored provider
    for (const auto& [score, name] : scored_providers) {
        auto result = create_provider(name);
        if (result.is_success()) {
            return result;
        }
    }
    
    return Result<std::unique_ptr<CryptoProvider>>(DTLSError::CRYPTO_PROVIDER_ERROR);
}

Result<std::unique_ptr<CryptoProvider>> ProviderFactory::create_default_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try default provider first
    if (!default_provider_.empty()) {
        auto it = providers_.find(default_provider_);
        if (it != providers_.end() && it->second.is_available) {
            auto unlock_guard = std::unique_lock<std::mutex>(mutex_, std::adopt_lock);
            unlock_guard.unlock();
            return create_provider(default_provider_);
        }
    }
    
    // Try preference order
    for (const std::string& name : preference_order_) {
        auto it = providers_.find(name);
        if (it != providers_.end() && it->second.is_available) {
            auto unlock_guard = std::unique_lock<std::mutex>(mutex_, std::adopt_lock);
            unlock_guard.unlock();
            return create_provider(name);
        }
    }
    
    // Fall back to highest priority available provider
    auto available = available_providers();
    if (!available.empty()) {
        auto unlock_guard = std::unique_lock<std::mutex>(mutex_, std::adopt_lock);
        unlock_guard.unlock();
        return create_provider(available[0]);
    }
    
    return Result<std::unique_ptr<CryptoProvider>>(DTLSError::RESOURCE_UNAVAILABLE);
}

bool ProviderFactory::meets_selection_criteria(
    const ProviderRegistration& registration,
    const ProviderSelection& criteria) const {
    
    const auto& caps = registration.capabilities;
    
    // Check preferred provider
    if (!criteria.preferred_provider.empty() && 
        registration.name != criteria.preferred_provider) {
        return false;
    }
    
    // Check hardware acceleration requirement
    if (criteria.require_hardware_acceleration && !caps.hardware_acceleration) {
        return false;
    }
    
    // Check FIPS compliance requirement
    if (criteria.require_fips_compliance && !caps.fips_mode) {
        return false;
    }
    
    // Check required cipher suites
    for (CipherSuite suite : criteria.required_cipher_suites) {
        if (std::find(caps.supported_cipher_suites.begin(), 
                     caps.supported_cipher_suites.end(), suite) == 
            caps.supported_cipher_suites.end()) {
            return false;
        }
    }
    
    // Check required groups
    for (NamedGroup group : criteria.required_groups) {
        if (std::find(caps.supported_groups.begin(), 
                     caps.supported_groups.end(), group) == 
            caps.supported_groups.end()) {
            return false;
        }
    }
    
    // Check required signatures
    for (SignatureScheme sig : criteria.required_signatures) {
        if (std::find(caps.supported_signatures.begin(), 
                     caps.supported_signatures.end(), sig) == 
            caps.supported_signatures.end()) {
            return false;
        }
    }
    
    return true;
}

int ProviderFactory::calculate_provider_score(
    const ProviderRegistration& registration,
    const ProviderSelection& criteria) const {
    
    int score = registration.priority * 10; // Base priority score
    
    const auto& caps = registration.capabilities;
    
    // Bonus points for features
    if (caps.hardware_acceleration) score += 20;
    if (caps.fips_mode) score += 15;
    
    // Bonus for cipher suite support
    score += static_cast<int>(caps.supported_cipher_suites.size());
    
    // Bonus for named group support  
    score += static_cast<int>(caps.supported_groups.size());
    
    // Bonus for signature scheme support
    score += static_cast<int>(caps.supported_signatures.size());
    
    // Provider-specific bonuses
    if (registration.name == "openssl") score += 10; // Prefer OpenSSL
    
    // Success rate bonus
    auto stats_it = stats_.find(registration.name);
    if (stats_it != stats_.end() && stats_it->second.creation_count > 0) {
        double success_rate = static_cast<double>(stats_it->second.success_count) / 
                             stats_it->second.creation_count;
        score += static_cast<int>(success_rate * 25);
    }
    
    return score;
}

void ProviderFactory::update_provider_stats(
    const std::string& name,
    bool success,
    std::chrono::milliseconds init_time) {
    
    auto& stats = stats_[name];
    stats.creation_count++;
    stats.last_used = std::chrono::steady_clock::now();
    
    if (success) {
        stats.success_count++;
    } else {
        stats.failure_count++;
    }
    
    // Update average initialization time
    if (stats.creation_count == 1) {
        stats.average_init_time = init_time;
    } else {
        auto total_time = stats.average_init_time * (stats.creation_count - 1) + init_time;
        stats.average_init_time = total_time / stats.creation_count;
    }
}

Result<ProviderCapabilities> ProviderFactory::get_capabilities(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(name);
    if (it == providers_.end()) {
        return Result<ProviderCapabilities>(DTLSError::CRYPTO_PROVIDER_ERROR);
    }
    
    return Result<ProviderCapabilities>(it->second.capabilities);
}

bool ProviderFactory::supports_cipher_suite(const std::string& provider_name, CipherSuite suite) const {
    auto caps_result = get_capabilities(provider_name);
    if (!caps_result) {
        return false;
    }
    
    const auto& suites = caps_result->supported_cipher_suites;
    return std::find(suites.begin(), suites.end(), suite) != suites.end();
}

bool ProviderFactory::supports_named_group(const std::string& provider_name, NamedGroup group) const {
    auto caps_result = get_capabilities(provider_name);
    if (!caps_result) {
        return false;
    }
    
    const auto& groups = caps_result->supported_groups;
    return std::find(groups.begin(), groups.end(), group) != groups.end();
}

bool ProviderFactory::supports_signature_scheme(const std::string& provider_name, SignatureScheme scheme) const {
    auto caps_result = get_capabilities(provider_name);
    if (!caps_result) {
        return false;
    }
    
    const auto& schemes = caps_result->supported_signatures;
    return std::find(schemes.begin(), schemes.end(), scheme) != schemes.end();
}

bool ProviderFactory::is_provider_available(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = providers_.find(name);
    return it != providers_.end() && it->second.is_available;
}

Result<void> ProviderFactory::refresh_availability() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [name, registration] : providers_) {
        try {
            auto test_provider = registration.factory();
            registration.is_available = test_provider && test_provider->is_available();
            if (registration.is_available) {
                registration.capabilities = test_provider->capabilities();
            }
        } catch (...) {
            registration.is_available = false;
        }
    }
    
    return Result<void>();
}

void ProviderFactory::set_default_provider(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    default_provider_ = name;
}

std::string ProviderFactory::get_default_provider() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return default_provider_;
}

void ProviderFactory::set_provider_preference_order(const std::vector<std::string>& order) {
    std::lock_guard<std::mutex> lock(mutex_);
    preference_order_ = order;
}

std::vector<std::string> ProviderFactory::get_provider_preference_order() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return preference_order_;
}

std::vector<std::string> ProviderFactory::get_fips_compliant_providers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> fips_providers;
    
    for (const auto& [name, registration] : providers_) {
        if (registration.is_available && registration.capabilities.fips_mode) {
            fips_providers.push_back(name);
        }
    }
    
    return fips_providers;
}

std::vector<std::string> ProviderFactory::get_hardware_accelerated_providers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> hw_providers;
    
    for (const auto& [name, registration] : providers_) {
        if (registration.is_available && registration.capabilities.hardware_acceleration) {
            hw_providers.push_back(name);
        }
    }
    
    return hw_providers;
}

Result<std::string> ProviderFactory::select_provider_for_cipher_suite(CipherSuite suite) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, registration] : providers_) {
        if (!registration.is_available) continue;
        
        const auto& suites = registration.capabilities.supported_cipher_suites;
        if (std::find(suites.begin(), suites.end(), suite) != suites.end()) {
            return Result<std::string>(name);
        }
    }
    
    return Result<std::string>(DTLSError::CIPHER_SUITE_NOT_SUPPORTED);
}

Result<std::string> ProviderFactory::select_provider_for_key_exchange(NamedGroup group) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, registration] : providers_) {
        if (!registration.is_available) continue;
        
        const auto& groups = registration.capabilities.supported_groups;
        if (std::find(groups.begin(), groups.end(), group) != groups.end()) {
            return Result<std::string>(name);
        }
    }
    
    return Result<std::string>(DTLSError::KEY_EXCHANGE_FAILED);
}

Result<std::string> ProviderFactory::select_provider_for_signature(SignatureScheme scheme) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, registration] : providers_) {
        if (!registration.is_available) continue;
        
        const auto& schemes = registration.capabilities.supported_signatures;
        if (std::find(schemes.begin(), schemes.end(), scheme) != schemes.end()) {
            return Result<std::string>(name);
        }
    }
    
    return Result<std::string>(DTLSError::SIGNATURE_VERIFICATION_FAILED);
}

ProviderFactory::ProviderStats ProviderFactory::get_provider_stats(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(name);
    return (it != stats_.end()) ? it->second : ProviderStats{};
}

void ProviderFactory::reset_provider_stats(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_[name] = ProviderStats{};
}

void ProviderFactory::reset_all_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [name, stats] : stats_) {
        stats = ProviderStats{};
    }
}

// ProviderManager implementation
ProviderManager::ProviderManager(const ProviderSelection& criteria)
    : selection_criteria_(criteria), creation_time_(std::chrono::steady_clock::now()) {
    initialize_best_provider(criteria);
}

ProviderManager::ProviderManager(const std::string& provider_name)
    : creation_time_(std::chrono::steady_clock::now()) {
    initialize_provider(provider_name);
}

ProviderManager::~ProviderManager() {
    cleanup_current_provider();
}

ProviderManager::ProviderManager(ProviderManager&& other) noexcept
    : provider_(std::move(other.provider_))
    , provider_name_(std::move(other.provider_name_))
    , fallback_providers_(std::move(other.fallback_providers_))
    , selection_criteria_(std::move(other.selection_criteria_))
    , creation_time_(other.creation_time_) {
    other.provider_name_.clear();
}

ProviderManager& ProviderManager::operator=(ProviderManager&& other) noexcept {
    if (this != &other) {
        cleanup_current_provider();
        
        provider_ = std::move(other.provider_);
        provider_name_ = std::move(other.provider_name_);
        fallback_providers_ = std::move(other.fallback_providers_);
        selection_criteria_ = std::move(other.selection_criteria_);
        creation_time_ = other.creation_time_;
        
        other.provider_name_.clear();
    }
    return *this;
}

void ProviderManager::initialize_provider(const std::string& name) {
    auto& factory = ProviderFactory::instance();
    auto result = factory.create_provider(name);
    
    if (result.is_success()) {
        provider_ = std::move(*result);
        provider_name_ = name;
        
        // Initialize the provider
        auto init_result = provider_->initialize();
        if (init_result.is_error()) {
            provider_.reset();
            provider_name_.clear();
        }
    }
}

void ProviderManager::initialize_best_provider(const ProviderSelection& criteria) {
    auto& factory = ProviderFactory::instance();
    auto result = factory.create_best_provider(criteria);
    
    if (result.is_success()) {
        provider_ = std::move(*result);
        provider_name_ = provider_->name();
        
        // Initialize the provider
        auto init_result = provider_->initialize();
        if (init_result.is_error()) {
            provider_.reset();
            provider_name_.clear();
        }
    }
}

void ProviderManager::cleanup_current_provider() {
    if (provider_) {
        provider_->cleanup();
        provider_.reset();
        provider_name_.clear();
    }
}

ProviderCapabilities ProviderManager::current_capabilities() const {
    if (provider_) {
        return provider_->capabilities();
    }
    return ProviderCapabilities{};
}

Result<void> ProviderManager::switch_to_provider(const std::string& name) {
    cleanup_current_provider();
    initialize_provider(name);
    
    if (is_initialized()) {
        return Result<void>();
    }
    
    return Result<void>(DTLSError::CRYPTO_PROVIDER_ERROR);
}

Result<void> ProviderManager::switch_to_fallback() {
    if (fallback_providers_.empty()) {
        return Result<void>(DTLSError::RESOURCE_UNAVAILABLE);
    }
    
    std::string fallback = fallback_providers_.front();
    fallback_providers_.erase(fallback_providers_.begin());
    
    return switch_to_provider(fallback);
}

std::chrono::milliseconds ProviderManager::uptime() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - creation_time_);
}

// Built-in provider registration
namespace builtin {

Result<void> register_all_providers() {
    auto openssl_result = register_openssl_provider();
    if (openssl_result.is_error()) {
        return openssl_result;
    }
    
    // Register other providers when available
    #ifdef DTLS_HAS_BOTAN
    auto botan_result = register_botan_provider();
    if (botan_result.is_error()) {
        // Botan is optional, continue
    }
    #endif
    
    return Result<void>();
}

Result<void> register_openssl_provider() {
    auto& factory = ProviderFactory::instance();
    
    return factory.register_provider(
        "openssl",
        "OpenSSL Cryptographic Provider",
        []() -> std::unique_ptr<CryptoProvider> {
            return std::make_unique<OpenSSLProvider>();
        },
        100 // High priority
    );
}

Result<void> register_botan_provider() {
    // TODO: Implement when Botan provider is available
    return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
}

Result<void> register_null_provider() {
    // TODO: Implement null/mock provider for testing
    return Result<void>(DTLSError::OPERATION_NOT_SUPPORTED);
}

} // namespace builtin

// Convenience functions
Result<std::unique_ptr<CryptoProvider>> create_crypto_provider(const std::string& name) {
    auto& factory = ProviderFactory::instance();
    
    if (name.empty()) {
        return factory.create_default_provider();
    }
    
    return factory.create_provider(name);
}

Result<std::unique_ptr<CryptoProvider>> create_best_crypto_provider(const ProviderSelection& criteria) {
    auto& factory = ProviderFactory::instance();
    return factory.create_best_provider(criteria);
}

std::vector<std::string> list_available_providers() {
    auto& factory = ProviderFactory::instance();
    return factory.available_providers();
}

bool is_provider_available(const std::string& name) {
    auto& factory = ProviderFactory::instance();
    return factory.is_provider_available(name);
}

std::string get_default_provider_name() {
    auto& factory = ProviderFactory::instance();
    return factory.get_default_provider();
}

// Auto-initialization
bool ProviderAutoInit::initialized_ = false;

ProviderAutoInit::ProviderAutoInit() {
    if (!initialized_) {
        // Register built-in providers
        builtin::register_all_providers();
        initialized_ = true;
    }
}

} // namespace crypto
} // namespace v13
} // namespace dtls