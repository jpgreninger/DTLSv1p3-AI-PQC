#pragma once

#include <dtls/security/rate_limiter.h>
#include <dtls/security/resource_manager.h>
#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/error.h>

#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>
#include <unordered_set>

namespace dtls {
namespace v13 {
namespace security {

/**
 * DoS protection configuration combining rate limiting and resource management
 */
struct DoSProtectionConfig {
    RateLimitConfig rate_limit_config;
    ResourceConfig resource_config;
    
    // Computational DoS protection
    bool enable_cpu_monitoring = true;
    double cpu_threshold = 0.8;                        // 80% CPU usage threshold
    std::chrono::milliseconds cpu_check_interval{1000}; // Check CPU every second
    
    // Amplification attack prevention
    size_t max_response_size_unverified = 1024;        // Max response to unverified clients
    double amplification_ratio_limit = 3.0;            // Max amplification ratio
    bool enable_response_rate_limiting = true;         // Limit response rate
    
    // Proof-of-work challenges (optional)
    bool enable_proof_of_work = false;
    uint8_t pow_difficulty = 16;                       // Bits of difficulty
    std::chrono::seconds pow_validity{300};            // 5 minutes validity
    
    // Advanced protection features
    bool enable_source_validation = true;              // Validate source IP
    bool enable_geoblocking = false;                   // Geographic blocking
    std::unordered_set<std::string> blocked_countries; // ISO country codes
    
    // Load balancing hints
    bool enable_load_balancing = false;                // Send load balancing hints
    std::vector<std::string> alternate_servers;        // Alternate server addresses
    
    DoSProtectionConfig() = default;
};

/**
 * DoS protection result
 */
enum class DoSProtectionResult : uint8_t {
    ALLOWED,                    // Request allowed
    RATE_LIMITED,              // Rate limited
    RESOURCE_EXHAUSTED,        // Resources exhausted
    BLACKLISTED,               // Source blacklisted
    CPU_OVERLOADED,            // CPU overload protection
    AMPLIFICATION_BLOCKED,     // Amplification attack blocked
    PROOF_OF_WORK_REQUIRED,    // Proof-of-work challenge needed
    GEOBLOCKED,                // Geographic blocking
    SOURCE_VALIDATION_FAILED   // Source validation failed
};

/**
 * DoS protection statistics
 */
struct DoSProtectionStats {
    // Request statistics
    size_t total_requests = 0;
    size_t allowed_requests = 0;
    size_t blocked_requests = 0;
    
    // Block reason breakdown
    size_t rate_limited = 0;
    size_t resource_exhausted = 0;
    size_t blacklisted = 0;
    size_t cpu_overloaded = 0;
    size_t amplification_blocked = 0;
    size_t proof_of_work_failed = 0;
    size_t geoblocked = 0;
    size_t source_validation_failed = 0;
    
    // Performance metrics
    std::chrono::steady_clock::time_point start_time;
    double current_cpu_usage = 0.0;
    size_t current_active_connections = 0;
    size_t peak_connections = 0;
    
    // Security events
    size_t security_violations = 0;
    size_t attack_attempts = 0;
    std::chrono::steady_clock::time_point last_attack;
    
    DoSProtectionStats() {
        start_time = std::chrono::steady_clock::now();
        last_attack = start_time;
    }
};

/**
 * Proof-of-work challenge
 */
struct ProofOfWorkChallenge {
    std::vector<uint8_t> challenge;     // Random challenge data
    uint8_t difficulty;                 // Required difficulty (bits)
    std::chrono::steady_clock::time_point expiry; // Challenge expiry time
    
    ProofOfWorkChallenge(uint8_t diff, std::chrono::seconds validity);
    
    /**
     * Verify proof-of-work solution
     * @param solution Proposed solution
     * @return true if solution is valid
     */
    bool verify_solution(const std::vector<uint8_t>& solution) const;
    
    /**
     * Check if challenge has expired
     */
    bool is_expired() const;
};

/**
 * CPU monitoring for computational DoS protection
 */
class CPUMonitor {
public:
    CPUMonitor();
    
    /**
     * Get current CPU usage percentage (0.0 to 1.0)
     */
    double get_cpu_usage();
    
    /**
     * Check if CPU usage exceeds threshold
     * @param threshold CPU usage threshold (0.0 to 1.0)
     * @return true if over threshold
     */
    bool is_over_threshold(double threshold);
    
    /**
     * Start monitoring CPU usage
     */
    void start_monitoring();
    
    /**
     * Stop monitoring CPU usage
     */
    void stop_monitoring();

private:
    void update_cpu_usage();
    
    std::atomic<double> current_cpu_usage_{0.0};
    std::atomic<bool> monitoring_enabled_{false};
    std::chrono::steady_clock::time_point last_update_;
    std::mutex update_mutex_;
};

/**
 * Comprehensive DoS protection system
 */
class DTLS_API DoSProtection {
public:
    explicit DoSProtection(const DoSProtectionConfig& config = DoSProtectionConfig{});
    ~DoSProtection();
    
    // Non-copyable, movable
    DoSProtection(const DoSProtection&) = delete;
    DoSProtection& operator=(const DoSProtection&) = delete;
    DoSProtection(DoSProtection&&) noexcept = default;
    DoSProtection& operator=(DoSProtection&&) noexcept = default;
    
    /**
     * Check if connection attempt should be allowed
     * @param source_address Source IP address
     * @param request_size Size of incoming request
     * @return Protection result
     */
    DoSProtectionResult check_connection_attempt(
        const NetworkAddress& source_address,
        size_t request_size = 0
    );
    
    /**
     * Check if handshake attempt should be allowed
     * @param source_address Source IP address
     * @param handshake_size Size of handshake message
     * @return Protection result
     */
    DoSProtectionResult check_handshake_attempt(
        const NetworkAddress& source_address,
        size_t handshake_size = 0
    );
    
    /**
     * Allocate resources for connection
     * @param source_address Source IP address
     * @param memory_estimate Estimated memory usage
     * @return Resource allocation ID or error
     */
    Result<uint64_t> allocate_connection_resources(
        const NetworkAddress& source_address,
        size_t memory_estimate
    );
    
    /**
     * Allocate resources for handshake
     * @param source_address Source IP address
     * @param memory_estimate Estimated memory usage
     * @return Resource allocation ID or error
     */
    Result<uint64_t> allocate_handshake_resources(
        const NetworkAddress& source_address,
        size_t memory_estimate
    );
    
    /**
     * Release allocated resources
     * @param allocation_id Resource allocation ID
     */
    Result<void> release_resources(uint64_t allocation_id);
    
    /**
     * Record successful connection establishment
     * @param source_address Source IP address
     */
    void record_connection_established(const NetworkAddress& source_address);
    
    /**
     * Record connection closure
     * @param source_address Source IP address
     */
    void record_connection_closed(const NetworkAddress& source_address);
    
    /**
     * Record security violation
     * @param source_address Source IP address
     * @param violation_type Type of violation
     * @param severity Severity level
     */
    void record_security_violation(
        const NetworkAddress& source_address,
        const std::string& violation_type,
        const std::string& severity = "medium"
    );
    
    /**
     * Check if response size would cause amplification
     * @param source_address Source IP address
     * @param request_size Size of request
     * @param response_size Size of proposed response
     * @return true if amplification is acceptable
     */
    bool check_amplification_limits(
        const NetworkAddress& source_address,
        size_t request_size,
        size_t response_size
    ) const;
    
    /**
     * Generate proof-of-work challenge
     * @param source_address Source IP address
     * @return Proof-of-work challenge
     */
    Result<ProofOfWorkChallenge> generate_proof_of_work_challenge(
        const NetworkAddress& source_address
    );
    
    /**
     * Verify proof-of-work solution
     * @param source_address Source IP address
     * @param challenge Original challenge
     * @param solution Proposed solution
     * @return true if solution is valid
     */
    bool verify_proof_of_work_solution(
        const NetworkAddress& source_address,
        const ProofOfWorkChallenge& challenge,
        const std::vector<uint8_t>& solution
    );
    
    /**
     * Add source to whitelist
     * @param source_address Source IP address
     */
    Result<void> add_to_whitelist(const NetworkAddress& source_address);
    
    /**
     * Remove source from whitelist
     * @param source_address Source IP address
     */
    Result<void> remove_from_whitelist(const NetworkAddress& source_address);
    
    /**
     * Blacklist source address
     * @param source_address Source IP address
     * @param duration Blacklist duration (0 = use default)
     */
    Result<void> blacklist_source(
        const NetworkAddress& source_address,
        std::chrono::seconds duration = std::chrono::seconds{0}
    );
    
    /**
     * Remove source from blacklist
     * @param source_address Source IP address
     */
    Result<void> remove_from_blacklist(const NetworkAddress& source_address);
    
    /**
     * Get DoS protection statistics
     */
    DoSProtectionStats get_statistics() const;
    
    /**
     * Get rate limiter statistics
     */
    RateLimiter::OverallStats get_rate_limit_stats() const;
    
    /**
     * Get resource management statistics
     */
    ResourceStats get_resource_stats() const;
    
    /**
     * Get system health status
     */
    struct SystemHealth {
        PressureLevel resource_pressure;
        double cpu_usage;
        double memory_usage;
        double connection_usage;
        bool is_healthy;
    };
    SystemHealth get_system_health() const;
    
    /**
     * Force cleanup of resources and expired entries
     */
    void force_cleanup();
    
    /**
     * Update configuration
     * @param new_config New DoS protection configuration
     */
    Result<void> update_config(const DoSProtectionConfig& new_config);
    
    /**
     * Get current configuration
     */
    const DoSProtectionConfig& get_config() const { return config_; }
    
    /**
     * Reset all protection state
     */
    void reset();
    
    /**
     * Enable or disable specific protection features
     */
    void enable_cpu_monitoring(bool enabled);
    void enable_proof_of_work(bool enabled);
    void enable_geoblocking(bool enabled);
    void enable_source_validation(bool enabled);

private:
    // Helper methods
    bool is_source_valid(const NetworkAddress& source_address) const;
    bool is_geoblocked(const NetworkAddress& source_address) const;
    std::string get_country_code(const NetworkAddress& source_address) const;
    DoSProtectionResult convert_rate_limit_result(RateLimitResult result) const;
    DoSProtectionResult convert_resource_result(ResourceResult result) const;
    void update_statistics(DoSProtectionResult result);
    
    // Configuration
    DoSProtectionConfig config_;
    
    // Core protection components
    std::unique_ptr<RateLimiter> rate_limiter_;
    std::unique_ptr<ResourceManager> resource_manager_;
    std::unique_ptr<CPUMonitor> cpu_monitor_;
    
    // Statistics
    mutable DoSProtectionStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Proof-of-work tracking
    std::unordered_map<std::string, ProofOfWorkChallenge> active_challenges_;
    mutable std::mutex challenges_mutex_;
    
    // System health monitoring
    std::atomic<std::chrono::steady_clock::time_point> last_health_check_;
};

/**
 * DoS protection factory for different deployment scenarios
 */
class DoSProtectionFactory {
public:
    /**
     * Create DoS protection for development/testing (permissive)
     */
    static std::unique_ptr<DoSProtection> create_development();
    
    /**
     * Create DoS protection for production (balanced protection)
     */
    static std::unique_ptr<DoSProtection> create_production();
    
    /**
     * Create DoS protection for high-security environments (strict)
     */
    static std::unique_ptr<DoSProtection> create_high_security();
    
    /**
     * Create DoS protection for embedded systems (resource-constrained)
     */
    static std::unique_ptr<DoSProtection> create_embedded();
    
    /**
     * Create DoS protection with custom configuration
     */
    static std::unique_ptr<DoSProtection> create_custom(const DoSProtectionConfig& config);
};

}  // namespace security
}  // namespace v13
}  // namespace dtls