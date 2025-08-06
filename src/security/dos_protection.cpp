#include <dtls/security/dos_protection.h>
#include <dtls/crypto/crypto_utils.h>

#include <random>
#include <sstream>
#include <fstream>
#include <cstring>

#ifdef __linux__
#include <unistd.h>
#include <sys/times.h>
#elif _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace dtls {
namespace v13 {
namespace security {

// ProofOfWorkChallenge implementation
ProofOfWorkChallenge::ProofOfWorkChallenge(uint8_t diff, std::chrono::seconds validity)
    : difficulty(diff), expiry(std::chrono::steady_clock::now() + validity) {
    
    // Generate random challenge data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    challenge.resize(32);  // 256-bit challenge
    for (auto& byte : challenge) {
        byte = dist(gen);
    }
}

bool ProofOfWorkChallenge::verify_solution(const std::vector<uint8_t>& solution) const {
    if (is_expired()) {
        return false;
    }
    
    // Combine challenge and solution
    std::vector<uint8_t> combined;
    combined.reserve(challenge.size() + solution.size());
    combined.insert(combined.end(), challenge.begin(), challenge.end());
    combined.insert(combined.end(), solution.begin(), solution.end());
    
    // Compute hash (simplified - in real implementation use proper crypto)
    // This is a placeholder for actual SHA-256 computation
    std::hash<std::string> hasher;
    std::string combined_str(combined.begin(), combined.end());
    auto hash_value = hasher(combined_str);
    
    // Check if leading bits are zero (simplified proof-of-work)
    uint64_t mask = (1ULL << difficulty) - 1;
    uint64_t leading_bits = hash_value >> (64 - difficulty);
    
    return leading_bits == 0;
}

bool ProofOfWorkChallenge::is_expired() const {
    return std::chrono::steady_clock::now() > expiry;
}

// CPUMonitor implementation
CPUMonitor::CPUMonitor() : last_update_(std::chrono::steady_clock::now()) {
}

double CPUMonitor::get_cpu_usage() {
    std::lock_guard<std::mutex> lock(update_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto time_since_update = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_update_);
    
    // Update CPU usage if it's been more than 500ms since last update
    if (time_since_update.count() > 500) {
        update_cpu_usage();
        last_update_ = now;
    }
    
    return current_cpu_usage_.load();
}

bool CPUMonitor::is_over_threshold(double threshold) {
    return get_cpu_usage() > threshold;
}

void CPUMonitor::start_monitoring() {
    monitoring_enabled_ = true;
}

void CPUMonitor::stop_monitoring() {
    monitoring_enabled_ = false;
}

void CPUMonitor::update_cpu_usage() {
    if (!monitoring_enabled_.load()) {
        return;
    }
    
    double cpu_usage = 0.0;
    
#ifdef __linux__
    // Linux CPU usage calculation
    static long prev_total = 0, prev_idle = 0;
    
    std::ifstream stat_file("/proc/stat");
    if (stat_file.is_open()) {
        std::string line;
        std::getline(stat_file, line);
        
        // Parse CPU times from /proc/stat
        long user, nice, system, idle, iowait, irq, softirq, steal;
        if (sscanf(line.c_str(), "cpu %ld %ld %ld %ld %ld %ld %ld %ld",
                  &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) == 8) {
            
            long total = user + nice + system + idle + iowait + irq + softirq + steal;
            long total_diff = total - prev_total;
            long idle_diff = idle - prev_idle;
            
            if (total_diff > 0) {
                cpu_usage = static_cast<double>(total_diff - idle_diff) / total_diff;
            }
            
            prev_total = total;
            prev_idle = idle;
        }
    }
#elif _WIN32
    // Windows CPU usage calculation
    static ULONGLONG prev_idle = 0, prev_kernel = 0, prev_user = 0;
    
    FILETIME idle_time, kernel_time, user_time;
    if (GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
        auto file_time_to_ull = [](const FILETIME& ft) -> ULONGLONG {
            return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        };
        
        ULONGLONG idle = file_time_to_ull(idle_time);
        ULONGLONG kernel = file_time_to_ull(kernel_time);
        ULONGLONG user = file_time_to_ull(user_time);
        
        ULONGLONG total_diff = (kernel - prev_kernel) + (user - prev_user);
        ULONGLONG idle_diff = idle - prev_idle;
        
        if (total_diff > 0) {
            cpu_usage = static_cast<double>(total_diff - idle_diff) / total_diff;
        }
        
        prev_idle = idle;
        prev_kernel = kernel;
        prev_user = user;
    }
#else
    // Fallback: return moderate CPU usage
    cpu_usage = 0.5;
#endif
    
    current_cpu_usage_ = std::max(0.0, std::min(1.0, cpu_usage));
}

// DoSProtection implementation
DoSProtection::DoSProtection(const DoSProtectionConfig& config)
    : config_(config)
    , rate_limiter_(std::make_unique<RateLimiter>(config.rate_limit_config))
    , resource_manager_(std::make_unique<ResourceManager>(config.resource_config))
    , cpu_monitor_(std::make_unique<CPUMonitor>())
    , last_health_check_(std::chrono::steady_clock::now()) {
    
    if (config_.enable_cpu_monitoring) {
        cpu_monitor_->start_monitoring();
    }
    
    // Initialize cookie manager if cookie validation is enabled
    if (config_.enable_cookie_validation) {
        cookie_manager_ = std::make_unique<protocol::CookieManager>(config.cookie_config);
        // Initialize with a default secret key (in production, use proper key management)
        memory::Buffer secret_key(32);
        secret_key.resize(32);
        // Generate a simple secret key for now (in production, use proper key derivation)
        uint8_t* key_data = reinterpret_cast<uint8_t*>(secret_key.mutable_data());
        for (size_t i = 0; i < 32; ++i) {
            key_data[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF); // Simple deterministic pattern
        }
        auto init_result = cookie_manager_->initialize(secret_key);
        if (!init_result.is_success()) {
            // Log error but continue - cookie validation will be disabled
            cookie_manager_.reset();
        }
    }
}

DoSProtection::~DoSProtection() = default;

DoSProtectionResult DoSProtection::check_connection_attempt(
    const NetworkAddress& source_address,
    size_t request_size) {
    
    stats_.total_requests++;
    
    // Source validation
    if (config_.enable_source_validation && !is_source_valid(source_address)) {
        update_statistics(DoSProtectionResult::SOURCE_VALIDATION_FAILED);
        return DoSProtectionResult::SOURCE_VALIDATION_FAILED;
    }
    
    // Geoblocking
    if (config_.enable_geoblocking && is_geoblocked(source_address)) {
        update_statistics(DoSProtectionResult::GEOBLOCKED);
        return DoSProtectionResult::GEOBLOCKED;
    }
    
    // CPU overload protection
    if (config_.enable_cpu_monitoring && 
        cpu_monitor_->is_over_threshold(config_.cpu_threshold)) {
        update_statistics(DoSProtectionResult::CPU_OVERLOADED);
        return DoSProtectionResult::CPU_OVERLOADED;
    }
    
    // Rate limiting check
    auto rate_result = rate_limiter_->check_connection_attempt(source_address);
    if (rate_result != RateLimitResult::ALLOWED) {
        auto dos_result = convert_rate_limit_result(rate_result);
        update_statistics(dos_result);
        return dos_result;
    }
    
    // Resource availability check
    if (!resource_manager_->can_allocate(source_address, ResourceType::CONNECTION_SLOT, 1)) {
        update_statistics(DoSProtectionResult::RESOURCE_EXHAUSTED);
        return DoSProtectionResult::RESOURCE_EXHAUSTED;
    }
    
    update_statistics(DoSProtectionResult::ALLOWED);
    return DoSProtectionResult::ALLOWED;
}

DoSProtectionResult DoSProtection::check_handshake_attempt(
    const NetworkAddress& source_address,
    size_t handshake_size) {
    
    // First check basic connection attempt
    auto result = check_connection_attempt(source_address, handshake_size);
    if (result != DoSProtectionResult::ALLOWED) {
        return result;
    }
    
    // Check handshake-specific rate limits
    auto rate_result = rate_limiter_->check_handshake_attempt(source_address);
    if (rate_result != RateLimitResult::ALLOWED) {
        auto dos_result = convert_rate_limit_result(rate_result);
        update_statistics(dos_result);
        return dos_result;
    }
    
    // Check if handshake resources are available
    if (!resource_manager_->can_allocate(source_address, ResourceType::HANDSHAKE_SLOT, 1)) {
        update_statistics(DoSProtectionResult::RESOURCE_EXHAUSTED);
        return DoSProtectionResult::RESOURCE_EXHAUSTED;
    }
    
    // Check for proof-of-work requirement
    if (config_.enable_proof_of_work) {
        // In a real implementation, you'd check if this source needs PoW
        // This is a simplified check
        auto resource_pressure = resource_manager_->get_pressure_level();
        if (resource_pressure >= PressureLevel::WARNING) {
            update_statistics(DoSProtectionResult::PROOF_OF_WORK_REQUIRED);
            return DoSProtectionResult::PROOF_OF_WORK_REQUIRED;
        }
    }
    
    return DoSProtectionResult::ALLOWED;
}

Result<uint64_t> DoSProtection::allocate_connection_resources(
    const NetworkAddress& source_address,
    size_t memory_estimate) {
    
    auto result = resource_manager_->allocate_connection_resources(source_address, memory_estimate);
    if (result.is_success()) {
        rate_limiter_->record_connection_established(source_address);
        stats_.current_active_connections++;
        if (stats_.current_active_connections > stats_.peak_connections) {
            stats_.peak_connections = stats_.current_active_connections;
        }
    }
    
    return result;
}

Result<uint64_t> DoSProtection::allocate_handshake_resources(
    const NetworkAddress& source_address,
    size_t memory_estimate) {
    
    return resource_manager_->allocate_handshake_resources(source_address, memory_estimate);
}

Result<void> DoSProtection::release_resources(uint64_t allocation_id) {
    auto result = resource_manager_->release_resources(allocation_id);
    if (result.is_success() && stats_.current_active_connections > 0) {
        stats_.current_active_connections--;
    }
    return result;
}

void DoSProtection::record_connection_established(const NetworkAddress& source_address) {
    rate_limiter_->record_connection_established(source_address);
}

void DoSProtection::record_connection_closed(const NetworkAddress& source_address) {
    rate_limiter_->record_connection_closed(source_address);
    if (stats_.current_active_connections > 0) {
        stats_.current_active_connections--;
    }
}

void DoSProtection::record_security_violation(
    const NetworkAddress& source_address,
    const std::string& violation_type,
    const std::string& severity) {
    
    rate_limiter_->record_violation(source_address, violation_type);
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.security_violations++;
    
    if (severity == "high" || severity == "critical") {
        stats_.attack_attempts++;
        stats_.last_attack = std::chrono::steady_clock::now();
    }
}

bool DoSProtection::check_amplification_limits(
    const NetworkAddress& source_address,
    size_t request_size,
    size_t response_size) const {
    
    if (!config_.enable_response_rate_limiting) {
        return true;
    }
    
    // Check amplification ratio
    if (request_size > 0) {
        double ratio = static_cast<double>(response_size) / request_size;
        if (ratio > config_.amplification_ratio_limit) {
            return false;
        }
    }
    
    // Check maximum response size for unverified clients
    // In a real implementation, you'd track client verification status
    if (response_size > config_.max_response_size_unverified) {
        return false;
    }
    
    return true;
}

Result<ProofOfWorkChallenge> DoSProtection::generate_proof_of_work_challenge(
    const NetworkAddress& source_address) {
    
    if (!config_.enable_proof_of_work) {
        return make_error<ProofOfWorkChallenge>(DTLSError::OPERATION_NOT_SUPPORTED, "Proof-of-work not enabled");
    }
    
    std::string source_key = source_address.get_ip() + ":" + std::to_string(source_address.get_port());
    ProofOfWorkChallenge challenge(config_.pow_difficulty, config_.pow_validity);
    
    std::lock_guard<std::mutex> lock(challenges_mutex_);
    active_challenges_[source_key] = challenge;
    
    return make_result(challenge);
}

bool DoSProtection::verify_proof_of_work_solution(
    const NetworkAddress& source_address,
    const ProofOfWorkChallenge& challenge,
    const std::vector<uint8_t>& solution) {
    
    if (!config_.enable_proof_of_work) {
        return true;  // If PoW is disabled, accept all solutions
    }
    
    std::string source_key = source_address.get_ip() + ":" + std::to_string(source_address.get_port());
    
    {
        std::lock_guard<std::mutex> lock(challenges_mutex_);
        auto it = active_challenges_.find(source_key);
        if (it == active_challenges_.end()) {
            return false;  // No active challenge
        }
        
        // Verify the challenge matches
        if (it->second.challenge != challenge.challenge ||
            it->second.difficulty != challenge.difficulty) {
            return false;
        }
        
        // Remove the challenge (single use)
        active_challenges_.erase(it);
    }
    
    return challenge.verify_solution(solution);
}

Result<void> DoSProtection::add_to_whitelist(const NetworkAddress& source_address) {
    return rate_limiter_->add_to_whitelist(source_address);
}

Result<void> DoSProtection::remove_from_whitelist(const NetworkAddress& source_address) {
    return rate_limiter_->remove_from_whitelist(source_address);
}

Result<void> DoSProtection::blacklist_source(
    const NetworkAddress& source_address,
    std::chrono::seconds duration) {
    
    auto result = rate_limiter_->blacklist_source(source_address, duration);
    if (result.is_success()) {
        // Also cleanup all resources from this source
        resource_manager_->cleanup_source_resources(source_address);
    }
    return result;
}

Result<void> DoSProtection::remove_from_blacklist(const NetworkAddress& source_address) {
    return rate_limiter_->remove_from_blacklist(source_address);
}

DoSProtectionStats DoSProtection::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto stats = stats_;
    
    // Update real-time values
    stats.current_cpu_usage = cpu_monitor_->get_cpu_usage();
    
    return stats;
}

RateLimiter::OverallStats DoSProtection::get_rate_limit_stats() const {
    return rate_limiter_->get_overall_stats();
}

ResourceStats DoSProtection::get_resource_stats() const {
    return resource_manager_->get_resource_stats();
}

DoSProtection::SystemHealth DoSProtection::get_system_health() const {
    SystemHealth health;
    
    health.resource_pressure = resource_manager_->get_pressure_level();
    health.cpu_usage = cpu_monitor_->get_cpu_usage();
    health.memory_usage = resource_manager_->get_memory_usage_percentage();
    health.connection_usage = resource_manager_->get_connection_usage_percentage();
    
    // System is healthy if all metrics are within acceptable ranges
    health.is_healthy = (health.resource_pressure <= PressureLevel::WARNING &&
                        health.cpu_usage < config_.cpu_threshold &&
                        health.memory_usage < 0.9 &&
                        health.connection_usage < 0.9);
    
    return health;
}

void DoSProtection::force_cleanup() {
    rate_limiter_->cleanup_expired_entries();
    resource_manager_->force_cleanup();
    
    // Cleanup expired proof-of-work challenges
    std::lock_guard<std::mutex> lock(challenges_mutex_);
    auto it = active_challenges_.begin();
    while (it != active_challenges_.end()) {
        if (it->second.is_expired()) {
            it = active_challenges_.erase(it);
        } else {
            ++it;
        }
    }
}

Result<void> DoSProtection::update_config(const DoSProtectionConfig& new_config) {
    config_ = new_config;
    
    auto rate_result = rate_limiter_->update_config(config_.rate_limit_config);
    if (!rate_result.is_success()) {
        return rate_result;
    }
    
    auto resource_result = resource_manager_->update_config(config_.resource_config);
    if (!resource_result.is_success()) {
        return resource_result;
    }
    
    // Update CPU monitoring
    if (config_.enable_cpu_monitoring) {
        cpu_monitor_->start_monitoring();
    } else {
        cpu_monitor_->stop_monitoring();
    }
    
    return make_result();
}

void DoSProtection::reset() {
    rate_limiter_->reset();
    resource_manager_->reset();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_ = DoSProtectionStats{};
    }
    
    {
        std::lock_guard<std::mutex> lock(challenges_mutex_);
        active_challenges_.clear();
    }
}

void DoSProtection::enable_cpu_monitoring(bool enabled) {
    config_.enable_cpu_monitoring = enabled;
    if (enabled) {
        cpu_monitor_->start_monitoring();
    } else {
        cpu_monitor_->stop_monitoring();
    }
}

void DoSProtection::enable_proof_of_work(bool enabled) {
    config_.enable_proof_of_work = enabled;
}

void DoSProtection::enable_geoblocking(bool enabled) {
    config_.enable_geoblocking = enabled;
}

void DoSProtection::enable_source_validation(bool enabled) {
    config_.enable_source_validation = enabled;
}

void DoSProtection::enable_cookie_validation(bool enabled) {
    config_.enable_cookie_validation = enabled;
    
    if (enabled && !cookie_manager_) {
        // Initialize cookie manager if not already done
        cookie_manager_ = std::make_unique<protocol::CookieManager>(config_.cookie_config);
        // Initialize with a default secret key (in production, use proper key management)
        memory::Buffer secret_key(32);
        secret_key.resize(32);
        uint8_t* key_data = reinterpret_cast<uint8_t*>(secret_key.mutable_data());
        for (size_t i = 0; i < 32; ++i) {
            key_data[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        }
        auto init_result = cookie_manager_->initialize(secret_key);
        if (!init_result.is_success()) {
            cookie_manager_.reset();
        }
    } else if (!enabled) {
        cookie_manager_.reset();
    }
}

// Cookie validation methods
bool DoSProtection::should_require_cookie(const NetworkAddress& source_address,
                                         const std::vector<uint8_t>& client_hello_data) const {
    if (!config_.enable_cookie_validation || !cookie_manager_) {
        return false;
    }
    
    // Always require cookie if explicitly configured
    if (config_.require_cookie_on_overload) {
        // Check system load conditions
        auto system_health = get_system_health();
        
        // Require cookie if CPU usage is above threshold
        if (system_health.cpu_usage > config_.cookie_trigger_cpu_threshold) {
            return true;
        }
        
        // Require cookie if connection count is above threshold
        if (stats_.current_active_connections > config_.cookie_trigger_connection_count) {
            return true;
        }
        
        // Require cookie if system is under high resource pressure
        if (system_health.resource_pressure >= PressureLevel::WARNING) {
            return true;
        }
    }
    
    // Check if client already has valid cookies
    protocol::CookieManager::ClientInfo client_info(
        source_address.get_ip(), 
        source_address.get_port(), 
        client_hello_data
    );
    
    return cookie_manager_->client_needs_cookie(client_info);
}

Result<memory::Buffer> DoSProtection::generate_client_cookie(const NetworkAddress& source_address,
                                                            const std::vector<uint8_t>& client_hello_data) {
    if (!config_.enable_cookie_validation || !cookie_manager_) {
        return make_error<memory::Buffer>(DTLSError::OPERATION_NOT_SUPPORTED, "Cookie validation not enabled");
    }
    
    protocol::CookieManager::ClientInfo client_info(
        source_address.get_ip(), 
        source_address.get_port(), 
        client_hello_data
    );
    
    auto cookie_result = cookie_manager_->generate_cookie(client_info);
    if (!cookie_result.is_success()) {
        record_security_violation(source_address, "cookie_generation_failed", "medium");
        return cookie_result;
    }
    
    // Record successful cookie generation for statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        // Could add cookie-specific statistics here if needed
    }
    
    return cookie_result;
}

DoSProtectionResult DoSProtection::validate_client_cookie(const memory::Buffer& cookie,
                                                         const NetworkAddress& source_address,
                                                         const std::vector<uint8_t>& client_hello_data) {
    if (!config_.enable_cookie_validation || !cookie_manager_) {
        return DoSProtectionResult::ALLOWED; // No cookie validation required
    }
    
    protocol::CookieManager::ClientInfo client_info(
        source_address.get_ip(), 
        source_address.get_port(), 
        client_hello_data
    );
    
    auto validation_result = cookie_manager_->validate_cookie(cookie, client_info);
    
    switch (validation_result) {
        case protocol::CookieManager::CookieValidationResult::VALID:
            return DoSProtectionResult::ALLOWED;
            
        case protocol::CookieManager::CookieValidationResult::EXPIRED:
            record_security_violation(source_address, "cookie_expired", "low");
            return DoSProtectionResult::COOKIE_EXPIRED;
            
        case protocol::CookieManager::CookieValidationResult::INVALID:
        case protocol::CookieManager::CookieValidationResult::CLIENT_MISMATCH:
        case protocol::CookieManager::CookieValidationResult::NOT_FOUND:
            record_security_violation(source_address, "cookie_invalid", "medium");
            return DoSProtectionResult::COOKIE_INVALID;
            
        case protocol::CookieManager::CookieValidationResult::REPLAY_DETECTED:
            record_security_violation(source_address, "cookie_replay", "high");
            return DoSProtectionResult::COOKIE_INVALID;
            
        default:
            record_security_violation(source_address, "cookie_validation_error", "medium");
            return DoSProtectionResult::COOKIE_INVALID;
    }
}

void DoSProtection::consume_client_cookie(const memory::Buffer& cookie,
                                         const NetworkAddress& source_address) {
    if (!config_.enable_cookie_validation || !cookie_manager_) {
        return;
    }
    
    protocol::CookieManager::ClientInfo client_info(
        source_address.get_ip(), 
        source_address.get_port(), 
        {} // ClientHello data not needed for consumption
    );
    
    cookie_manager_->consume_cookie(cookie, client_info);
}

// Private helper methods
bool DoSProtection::is_source_valid(const NetworkAddress& source_address) const {
    // Basic source validation - check for obviously invalid addresses
    std::string ip = source_address.get_ip();
    
    // Check for localhost/loopback (might be valid in development)
    if (ip == "127.0.0.1" || ip == "::1") {
        return true;  // Allow localhost for development
    }
    
    // Check for private/internal addresses
    if (ip.starts_with("192.168.") || ip.starts_with("10.") || 
        ip.starts_with("172.16.") || ip.starts_with("169.254.")) {
        return true;  // Allow private addresses
    }
    
    // Check for multicast/broadcast addresses
    if (ip.starts_with("224.") || ip.starts_with("255.")) {
        return false;  // Reject multicast/broadcast
    }
    
    return true;  // Default to allowing
}

bool DoSProtection::is_geoblocked(const NetworkAddress& source_address) const {
    if (!config_.enable_geoblocking || config_.blocked_countries.empty()) {
        return false;
    }
    
    std::string country_code = get_country_code(source_address);
    return config_.blocked_countries.find(country_code) != config_.blocked_countries.end();
}

std::string DoSProtection::get_country_code(const NetworkAddress& source_address) const {
    // Placeholder implementation - in a real system, you'd use a GeoIP database
    // like MaxMind GeoLite2 or similar
    std::string ip = source_address.get_ip();
    
    // Simple heuristic for demonstration
    if (ip.starts_with("192.168.") || ip.starts_with("10.") || 
        ip.starts_with("172.16.") || ip == "127.0.0.1") {
        return "XX";  // Private/local
    }
    
    return "US";  // Default assumption
}

DoSProtectionResult DoSProtection::convert_rate_limit_result(RateLimitResult result) const {
    switch (result) {
        case RateLimitResult::ALLOWED:
            return DoSProtectionResult::ALLOWED;
        case RateLimitResult::RATE_LIMITED:
            return DoSProtectionResult::RATE_LIMITED;
        case RateLimitResult::BLACKLISTED:
            return DoSProtectionResult::BLACKLISTED;
        case RateLimitResult::RESOURCE_EXHAUSTED:
            return DoSProtectionResult::RESOURCE_EXHAUSTED;
        default:
            return DoSProtectionResult::RATE_LIMITED;
    }
}

DoSProtectionResult DoSProtection::convert_resource_result(ResourceResult result) const {
    switch (result) {
        case ResourceResult::ALLOCATED:
            return DoSProtectionResult::ALLOWED;
        case ResourceResult::MEMORY_LIMIT_EXCEEDED:
        case ResourceResult::CONNECTION_LIMIT_EXCEEDED:
        case ResourceResult::SOURCE_LIMIT_EXCEEDED:
        case ResourceResult::SYSTEM_OVERLOADED:
        case ResourceResult::RESOURCE_UNAVAILABLE:
            return DoSProtectionResult::RESOURCE_EXHAUSTED;
        default:
            return DoSProtectionResult::RESOURCE_EXHAUSTED;
    }
}

void DoSProtection::update_statistics(DoSProtectionResult result) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    switch (result) {
        case DoSProtectionResult::ALLOWED:
            stats_.allowed_requests++;
            break;
        case DoSProtectionResult::RATE_LIMITED:
            stats_.blocked_requests++;
            stats_.rate_limited++;
            break;
        case DoSProtectionResult::RESOURCE_EXHAUSTED:
            stats_.blocked_requests++;
            stats_.resource_exhausted++;
            break;
        case DoSProtectionResult::BLACKLISTED:
            stats_.blocked_requests++;
            stats_.blacklisted++;
            break;
        case DoSProtectionResult::CPU_OVERLOADED:
            stats_.blocked_requests++;
            stats_.cpu_overloaded++;
            break;
        case DoSProtectionResult::AMPLIFICATION_BLOCKED:
            stats_.blocked_requests++;
            stats_.amplification_blocked++;
            break;
        case DoSProtectionResult::PROOF_OF_WORK_REQUIRED:
            stats_.blocked_requests++;
            stats_.proof_of_work_failed++;
            break;
        case DoSProtectionResult::GEOBLOCKED:
            stats_.blocked_requests++;
            stats_.geoblocked++;
            break;
        case DoSProtectionResult::SOURCE_VALIDATION_FAILED:
            stats_.blocked_requests++;
            stats_.source_validation_failed++;
            break;
        case DoSProtectionResult::COOKIE_REQUIRED:
            stats_.blocked_requests++;
            // Could add cookie-specific statistics here
            break;
        case DoSProtectionResult::COOKIE_INVALID:
            stats_.blocked_requests++;
            // Could add cookie-specific statistics here
            break;
        case DoSProtectionResult::COOKIE_EXPIRED:
            stats_.blocked_requests++;
            // Could add cookie-specific statistics here
            break;
    }
}

// Factory implementations
std::unique_ptr<DoSProtection> DoSProtectionFactory::create_development() {
    DoSProtectionConfig config;
    config.rate_limit_config = RateLimiterFactory::create_development()->get_config();
    config.resource_config = ResourceManagerFactory::create_development()->get_config();
    
    // More permissive settings for development
    config.enable_cpu_monitoring = false;
    config.enable_proof_of_work = false;
    config.enable_geoblocking = false;
    config.amplification_ratio_limit = 10.0;
    
    // Cookie validation settings for development (lenient)
    config.enable_cookie_validation = false;  // Disabled for easier development
    config.require_cookie_on_overload = false;
    config.cookie_trigger_cpu_threshold = 0.9;
    config.cookie_trigger_connection_count = 1000;
    
    return std::make_unique<DoSProtection>(config);
}

std::unique_ptr<DoSProtection> DoSProtectionFactory::create_production() {
    DoSProtectionConfig config;
    config.rate_limit_config = RateLimiterFactory::create_production()->get_config();
    config.resource_config = ResourceManagerFactory::create_production()->get_config();
    
    // Balanced settings for production
    config.enable_cpu_monitoring = true;
    config.cpu_threshold = 0.8;
    config.enable_proof_of_work = false;  // Start without PoW
    config.enable_geoblocking = false;    // Start without geoblocking
    config.amplification_ratio_limit = 3.0;
    
    // Cookie validation settings for production (balanced protection)
    config.enable_cookie_validation = true;
    config.require_cookie_on_overload = true;
    config.cookie_trigger_cpu_threshold = 0.7;      // Require cookies at 70% CPU
    config.cookie_trigger_connection_count = 100;   // Require cookies at 100 connections
    
    return std::make_unique<DoSProtection>(config);
}

std::unique_ptr<DoSProtection> DoSProtectionFactory::create_high_security() {
    DoSProtectionConfig config;
    config.rate_limit_config = RateLimiterFactory::create_high_security()->get_config();
    config.resource_config = ResourceManagerFactory::create_production()->get_config();
    
    // Strict settings for high security
    config.enable_cpu_monitoring = true;
    config.cpu_threshold = 0.7;
    config.enable_proof_of_work = true;
    config.pow_difficulty = 20;
    config.enable_source_validation = true;
    config.enable_response_rate_limiting = true;
    config.amplification_ratio_limit = 2.0;
    config.max_response_size_unverified = 512;
    
    // Cookie validation settings for high security (strict protection)
    config.enable_cookie_validation = true;
    config.require_cookie_on_overload = true;
    config.cookie_trigger_cpu_threshold = 0.5;      // Require cookies at 50% CPU
    config.cookie_trigger_connection_count = 50;    // Require cookies at 50 connections
    
    return std::make_unique<DoSProtection>(config);
}

std::unique_ptr<DoSProtection> DoSProtectionFactory::create_embedded() {
    DoSProtectionConfig config;
    config.rate_limit_config = RateLimiterFactory::create_production()->get_config();
    config.resource_config = ResourceManagerFactory::create_embedded()->get_config();
    
    // Resource-constrained settings
    config.enable_cpu_monitoring = false;  // Save CPU cycles
    config.enable_proof_of_work = false;   // Too expensive for embedded
    config.enable_geoblocking = false;     // Save memory
    config.amplification_ratio_limit = 2.0;
    
    // Cookie validation settings for embedded (lightweight protection)
    config.enable_cookie_validation = true;  // Keep for basic protection
    config.require_cookie_on_overload = true;
    config.cookie_trigger_cpu_threshold = 0.8;      // Higher threshold to save resources
    config.cookie_trigger_connection_count = 200;   // Higher threshold to save resources
    
    return std::make_unique<DoSProtection>(config);
}

std::unique_ptr<DoSProtection> DoSProtectionFactory::create_custom(const DoSProtectionConfig& config) {
    return std::make_unique<DoSProtection>(config);
}

}  // namespace security
}  // namespace v13
}  // namespace dtls