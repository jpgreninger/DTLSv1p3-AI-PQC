#pragma once

#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/error.h>

#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>

namespace dtls {
namespace v13 {
namespace security {

/**
 * Rate limiting configuration
 */
struct RateLimitConfig {
    // Token bucket parameters
    size_t max_tokens = 100;                           // Maximum tokens in bucket
    size_t tokens_per_second = 10;                     // Token refill rate
    std::chrono::milliseconds burst_window{1000};      // Burst detection window
    size_t max_burst_count = 20;                       // Max attempts in burst window
    
    // Automatic blacklisting
    std::chrono::seconds blacklist_duration{300};      // 5 minutes default
    size_t max_violations_per_hour = 5;                // Violations before blacklisting
    std::chrono::seconds violation_window{3600};       // 1 hour violation tracking
    
    // Connection limits per IP
    size_t max_concurrent_connections = 10;            // Max concurrent connections
    size_t max_handshakes_per_minute = 30;            // Max handshake attempts per minute
    
    // Whitelist support
    bool enable_whitelist = true;                      // Enable trusted source whitelist
    
    RateLimitConfig() = default;
};

/**
 * Rate limiting result
 */
enum class RateLimitResult : uint8_t {
    ALLOWED,                // Request allowed
    RATE_LIMITED,          // Rate limit exceeded
    BLACKLISTED,           // Source is blacklisted
    RESOURCE_EXHAUSTED     // System resources exhausted
};

/**
 * Rate limiting statistics per source
 */
struct RateLimitStats {
    size_t total_requests = 0;
    size_t allowed_requests = 0;
    size_t denied_requests = 0;
    size_t blacklist_violations = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_request;
    std::chrono::steady_clock::time_point last_violation;
    
    RateLimitStats() {
        auto now = std::chrono::steady_clock::now();
        first_seen = now;
        last_request = now;
        last_violation = now;
    }
};

/**
 * Token bucket for individual source rate limiting
 */
class TokenBucket {
public:
    TokenBucket(size_t max_tokens, size_t tokens_per_second);
    
    /**
     * Try to consume tokens from bucket
     * @param tokens Number of tokens to consume
     * @return true if tokens were available and consumed
     */
    bool try_consume(size_t tokens = 1);
    
    /**
     * Get current token count
     */
    size_t get_token_count() const;
    
    /**
     * Get bucket capacity
     */
    size_t get_capacity() const { return max_tokens_; }
    
    /**
     * Get refill rate
     */
    size_t get_refill_rate() const { return tokens_per_second_; }
    
    /**
     * Reset bucket to full capacity
     */
    void reset();

private:
    void refill_tokens();
    
    const size_t max_tokens_;
    const size_t tokens_per_second_;
    std::atomic<size_t> current_tokens_;
    std::atomic<std::chrono::steady_clock::time_point> last_refill_;
    mutable std::mutex bucket_mutex_;
};

/**
 * Sliding window for burst detection
 */
class SlidingWindow {
public:
    explicit SlidingWindow(std::chrono::milliseconds window_size);
    
    /**
     * Record an event and check if burst threshold exceeded
     * @param max_events Maximum events allowed in window
     * @return true if burst threshold exceeded
     */
    bool add_event_and_check_burst(size_t max_events);
    
    /**
     * Get current event count in window
     */
    size_t get_event_count() const;
    
    /**
     * Clear all events
     */
    void clear();

private:
    void cleanup_old_events();
    
    const std::chrono::milliseconds window_size_;
    std::vector<std::chrono::steady_clock::time_point> events_;
    mutable std::mutex window_mutex_;
};

/**
 * Source tracking data
 */
struct SourceData {
    std::unique_ptr<TokenBucket> token_bucket;
    std::unique_ptr<SlidingWindow> burst_window;
    std::unique_ptr<SlidingWindow> handshake_window;
    RateLimitStats stats;
    std::atomic<size_t> active_connections{0};
    std::atomic<bool> is_blacklisted{false};
    std::atomic<std::chrono::steady_clock::time_point> blacklist_expiry;
    std::vector<std::chrono::steady_clock::time_point> violations;
    mutable std::mutex violations_mutex;
    
    SourceData(const RateLimitConfig& config);
};

/**
 * Rate limiter with token bucket algorithm and DoS protection
 */
class DTLS_API RateLimiter {
public:
    explicit RateLimiter(const RateLimitConfig& config = RateLimitConfig{});
    ~RateLimiter();
    
    // Non-copyable, movable
    RateLimiter(const RateLimiter&) = delete;
    RateLimiter& operator=(const RateLimiter&) = delete;
    RateLimiter(RateLimiter&&) noexcept = default;
    RateLimiter& operator=(RateLimiter&&) noexcept = default;
    
    /**
     * Check if connection attempt is allowed from source
     * @param source_address Source IP address
     * @return Rate limiting result
     */
    RateLimitResult check_connection_attempt(const NetworkAddress& source_address);
    
    /**
     * Check if handshake attempt is allowed from source
     * @param source_address Source IP address
     * @return Rate limiting result
     */
    RateLimitResult check_handshake_attempt(const NetworkAddress& source_address);
    
    /**
     * Record successful connection from source
     * @param source_address Source IP address
     */
    void record_connection_established(const NetworkAddress& source_address);
    
    /**
     * Record connection closed from source
     * @param source_address Source IP address
     */
    void record_connection_closed(const NetworkAddress& source_address);
    
    /**
     * Record security violation from source
     * @param source_address Source IP address
     * @param violation_type Type of violation
     */
    void record_violation(const NetworkAddress& source_address, 
                         const std::string& violation_type);
    
    /**
     * Add source to whitelist (trusted sources)
     * @param source_address Source IP address
     */
    Result<void> add_to_whitelist(const NetworkAddress& source_address);
    
    /**
     * Remove source from whitelist
     * @param source_address Source IP address
     */
    Result<void> remove_from_whitelist(const NetworkAddress& source_address);
    
    /**
     * Check if source is whitelisted
     * @param source_address Source IP address
     * @return true if whitelisted
     */
    bool is_whitelisted(const NetworkAddress& source_address) const;
    
    /**
     * Manually blacklist a source
     * @param source_address Source IP address
     * @param duration Blacklist duration
     */
    Result<void> blacklist_source(const NetworkAddress& source_address,
                                 std::chrono::seconds duration = std::chrono::seconds{0});
    
    /**
     * Remove source from blacklist
     * @param source_address Source IP address
     */
    Result<void> remove_from_blacklist(const NetworkAddress& source_address);
    
    /**
     * Check if source is blacklisted
     * @param source_address Source IP address
     * @return true if blacklisted
     */
    bool is_blacklisted(const NetworkAddress& source_address);
    
    /**
     * Get rate limiting statistics for source
     * @param source_address Source IP address
     * @return Statistics or error if source not found
     */
    Result<RateLimitStats> get_source_stats(const NetworkAddress& source_address) const;
    
    /**
     * Get overall rate limiter statistics
     */
    struct OverallStats {
        size_t total_sources = 0;
        size_t blacklisted_sources = 0;
        size_t whitelisted_sources = 0;
        size_t active_connections = 0;
        size_t total_violations = 0;
        std::chrono::steady_clock::time_point creation_time;
    };
    OverallStats get_overall_stats() const;
    
    /**
     * Cleanup expired blacklist entries and old source data
     */
    void cleanup_expired_entries();
    
    /**
     * Update configuration
     * @param new_config New rate limit configuration
     */
    Result<void> update_config(const RateLimitConfig& new_config);
    
    /**
     * Get current configuration
     */
    const RateLimitConfig& get_config() const { return config_; }
    
    /**
     * Reset all rate limiting state
     */
    void reset();

private:
    // Helper methods
    SourceData* get_or_create_source_data(const NetworkAddress& source_address);
    SourceData* get_source_data(const NetworkAddress& source_address) const;
    bool should_blacklist_source(SourceData* source_data);
    void apply_blacklist(SourceData* source_data, std::chrono::seconds duration);
    std::string address_to_key(const NetworkAddress& address) const;
    
    // Configuration
    RateLimitConfig config_;
    
    // Source tracking
    std::unordered_map<std::string, std::unique_ptr<SourceData>> sources_;
    mutable std::shared_mutex sources_mutex_;
    
    // Whitelist and blacklist
    std::unordered_set<std::string> whitelist_;
    mutable std::shared_mutex whitelist_mutex_;
    
    // Statistics
    std::atomic<size_t> total_requests_{0};
    std::atomic<size_t> allowed_requests_{0};
    std::atomic<size_t> denied_requests_{0};
    std::atomic<size_t> total_violations_{0};
    std::chrono::steady_clock::time_point creation_time_;
    
    // Cleanup management
    std::atomic<std::chrono::steady_clock::time_point> last_cleanup_;
    std::chrono::seconds cleanup_interval_{60}; // Cleanup every minute
};

/**
 * Rate limiter factory for different use cases
 */
class RateLimiterFactory {
public:
    /**
     * Create rate limiter for development/testing (permissive limits)
     */
    static std::unique_ptr<RateLimiter> create_development();
    
    /**
     * Create rate limiter for production (strict limits)
     */
    static std::unique_ptr<RateLimiter> create_production();
    
    /**
     * Create rate limiter for high-security environments (very strict)
     */
    static std::unique_ptr<RateLimiter> create_high_security();
    
    /**
     * Create rate limiter with custom configuration
     */
    static std::unique_ptr<RateLimiter> create_custom(const RateLimitConfig& config);
};

}  // namespace security
}  // namespace v13
}  // namespace dtls