#include <dtls/security/rate_limiter.h>
#include <algorithm>
#include <sstream>

namespace dtls {
namespace v13 {
namespace security {

// TokenBucket implementation
TokenBucket::TokenBucket(size_t max_tokens, size_t tokens_per_second)
    : max_tokens_(max_tokens)
    , tokens_per_second_(tokens_per_second)
    , current_tokens_(max_tokens)
    , last_refill_(std::chrono::steady_clock::now()) {
}

bool TokenBucket::try_consume(size_t tokens) {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    
    refill_tokens();
    
    // Get current token count and check if we have enough
    size_t current = current_tokens_.load();
    if (current >= tokens) {
        current_tokens_.store(current - tokens);
        return true;
    }
    
    return false;
}

size_t TokenBucket::get_token_count() const {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    const_cast<TokenBucket*>(this)->refill_tokens();
    return current_tokens_.load();
}

void TokenBucket::reset() {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    current_tokens_ = max_tokens_;
    last_refill_ = std::chrono::steady_clock::now();
}

void TokenBucket::refill_tokens() {
    auto now = std::chrono::steady_clock::now();
    auto time_passed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_refill_.load());
    
    if (time_passed.count() > 0) {
        size_t tokens_to_add = (time_passed.count() * tokens_per_second_) / 1000;
        if (tokens_to_add > 0) {
            // Read current tokens atomically, calculate new value, and store atomically
            size_t current = current_tokens_.load();
            size_t new_tokens = std::min(max_tokens_, current + tokens_to_add);
            current_tokens_.store(new_tokens);
            last_refill_.store(now);
        }
    }
}

// SlidingWindow implementation
SlidingWindow::SlidingWindow(std::chrono::milliseconds window_size)
    : window_size_(window_size) {
}

bool SlidingWindow::add_event_and_check_burst(size_t max_events) {
    std::lock_guard<std::mutex> lock(window_mutex_);
    
    cleanup_old_events();
    events_.push_back(std::chrono::steady_clock::now());
    
    return events_.size() > max_events;
}

size_t SlidingWindow::get_event_count() const {
    std::lock_guard<std::mutex> lock(window_mutex_);
    const_cast<SlidingWindow*>(this)->cleanup_old_events();
    return events_.size();
}

void SlidingWindow::clear() {
    std::lock_guard<std::mutex> lock(window_mutex_);
    events_.clear();
}

void SlidingWindow::cleanup_old_events() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - window_size_;
    
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
                      [cutoff](const auto& event_time) {
                          return event_time < cutoff;
                      }),
        events_.end()
    );
}

// SourceData implementation
SourceData::SourceData(const RateLimitConfig& config)
    : token_bucket(std::make_unique<TokenBucket>(config.max_tokens, config.tokens_per_second))
    , burst_window(std::make_unique<SlidingWindow>(config.burst_window))
    , handshake_window(std::make_unique<SlidingWindow>(std::chrono::minutes{1})) {
    blacklist_expiry = std::chrono::steady_clock::now();
}

// RateLimiter implementation
RateLimiter::RateLimiter(const RateLimitConfig& config)
    : config_(config)
    , creation_time_(std::chrono::steady_clock::now())
    , last_cleanup_(std::chrono::steady_clock::now()) {
}

RateLimiter::~RateLimiter() = default;

RateLimitResult RateLimiter::check_connection_attempt(const NetworkAddress& source_address) {
    total_requests_++;
    
    // Check whitelist first
    if (config_.enable_whitelist && is_whitelisted(source_address)) {
        allowed_requests_++;
        return RateLimitResult::ALLOWED;
    }
    
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        denied_requests_++;
        return RateLimitResult::RESOURCE_EXHAUSTED;
    }
    
    // Check if blacklisted
    if (is_blacklisted(source_address)) {
        denied_requests_++;
        source_data->stats.denied_requests++;
        return RateLimitResult::BLACKLISTED;
    }
    
    // Update statistics
    source_data->stats.total_requests++;
    source_data->stats.last_request = std::chrono::steady_clock::now();
    
    // Check concurrent connection limit
    if (source_data->active_connections.load() >= config_.max_concurrent_connections) {
        denied_requests_++;
        source_data->stats.denied_requests++;
        record_violation(source_address, "concurrent_connection_limit");
        return RateLimitResult::RATE_LIMITED;
    }
    
    // Check token bucket
    if (!source_data->token_bucket->try_consume(1)) {
        denied_requests_++;
        source_data->stats.denied_requests++;
        record_violation(source_address, "token_bucket_exhausted");
        return RateLimitResult::RATE_LIMITED;
    }
    
    // Check burst detection
    if (source_data->burst_window->add_event_and_check_burst(config_.max_burst_count)) {
        denied_requests_++;
        source_data->stats.denied_requests++;
        record_violation(source_address, "burst_detected");
        return RateLimitResult::RATE_LIMITED;
    }
    
    allowed_requests_++;
    source_data->stats.allowed_requests++;
    return RateLimitResult::ALLOWED;
}

RateLimitResult RateLimiter::check_handshake_attempt(const NetworkAddress& source_address) {
    // First check connection attempt
    auto result = check_connection_attempt(source_address);
    if (result != RateLimitResult::ALLOWED) {
        return result;
    }
    
    auto* source_data = get_source_data(source_address);
    if (!source_data) {
        return RateLimitResult::RESOURCE_EXHAUSTED;
    }
    
    // Check handshake-specific rate limit
    if (source_data->handshake_window->add_event_and_check_burst(config_.max_handshakes_per_minute)) {
        denied_requests_++;
        source_data->stats.denied_requests++;
        record_violation(source_address, "handshake_rate_exceeded");
        return RateLimitResult::RATE_LIMITED;
    }
    
    return RateLimitResult::ALLOWED;
}

void RateLimiter::record_connection_established(const NetworkAddress& source_address) {
    auto* source_data = get_or_create_source_data(source_address);
    if (source_data) {
        source_data->active_connections++;
        source_data->stats.last_request = std::chrono::steady_clock::now();
    }
}

void RateLimiter::record_connection_closed(const NetworkAddress& source_address) {
    auto* source_data = get_source_data(source_address);
    if (source_data && source_data->active_connections.load() > 0) {
        source_data->active_connections--;
    }
}

void RateLimiter::record_violation(const NetworkAddress& source_address, 
                                  const std::string& violation_type) {
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(source_data->violations_mutex);
        source_data->violations.push_back(now);
        source_data->stats.blacklist_violations++;
        source_data->stats.last_violation = now;
        
        // Clean up old violations
        auto cutoff = now - config_.violation_window;
        source_data->violations.erase(
            std::remove_if(source_data->violations.begin(), source_data->violations.end(),
                          [cutoff](const auto& violation_time) {
                              return violation_time < cutoff;
                          }),
            source_data->violations.end()
        );
    }
    
    total_violations_++;
    
    // Check if source should be blacklisted
    if (should_blacklist_source(source_data)) {
        apply_blacklist(source_data, config_.blacklist_duration);
    }
}

Result<void> RateLimiter::add_to_whitelist(const NetworkAddress& source_address) {
    std::unique_lock<std::shared_mutex> lock(whitelist_mutex_);
    whitelist_.insert(address_to_key(source_address));
    return make_result();
}

Result<void> RateLimiter::remove_from_whitelist(const NetworkAddress& source_address) {
    std::unique_lock<std::shared_mutex> lock(whitelist_mutex_);
    whitelist_.erase(address_to_key(source_address));
    return make_result();
}

bool RateLimiter::is_whitelisted(const NetworkAddress& source_address) const {
    std::shared_lock<std::shared_mutex> lock(whitelist_mutex_);
    return whitelist_.find(address_to_key(source_address)) != whitelist_.end();
}

Result<void> RateLimiter::blacklist_source(const NetworkAddress& source_address,
                                          std::chrono::seconds duration) {
    auto* source_data = get_or_create_source_data(source_address);
    if (!source_data) {
        return make_error<void>(DTLSError::RESOURCE_EXHAUSTED, "Cannot create source data");
    }
    
    auto blacklist_duration = duration.count() > 0 ? duration : config_.blacklist_duration;
    apply_blacklist(source_data, blacklist_duration);
    return make_result();
}

Result<void> RateLimiter::remove_from_blacklist(const NetworkAddress& source_address) {
    auto* source_data = get_source_data(source_address);
    if (source_data) {
        source_data->is_blacklisted = false;
        source_data->blacklist_expiry = std::chrono::steady_clock::now();
    }
    return make_result();
}

bool RateLimiter::is_blacklisted(const NetworkAddress& source_address) {
    auto* source_data = get_source_data(source_address);
    if (!source_data) {
        return false;
    }
    
    if (!source_data->is_blacklisted.load()) {
        return false;
    }
    
    // Check if blacklist has expired
    auto now = std::chrono::steady_clock::now();
    if (now > source_data->blacklist_expiry.load()) {
        source_data->is_blacklisted = false;
        return false;
    }
    
    return true;
}

Result<RateLimitStats> RateLimiter::get_source_stats(const NetworkAddress& source_address) const {
    auto* source_data = get_source_data(source_address);
    if (!source_data) {
        return make_error<RateLimitStats>(DTLSError::MESSAGE_NOT_FOUND, "Source not found");
    }
    
    return make_result(source_data->stats);
}

RateLimiter::OverallStats RateLimiter::get_overall_stats() const {
    OverallStats stats;
    stats.creation_time = creation_time_;
    stats.total_violations = total_violations_.load();
    
    {
        std::shared_lock<std::shared_mutex> sources_lock(sources_mutex_);
        stats.total_sources = sources_.size();
        
        for (const auto& [key, source_data] : sources_) {
            if (source_data->is_blacklisted.load()) {
                stats.blacklisted_sources++;
            }
            stats.active_connections += source_data->active_connections.load();
        }
    }
    
    {
        std::shared_lock<std::shared_mutex> whitelist_lock(whitelist_mutex_);
        stats.whitelisted_sources = whitelist_.size();
    }
    
    return stats;
}

void RateLimiter::cleanup_expired_entries() {
    auto now = std::chrono::steady_clock::now();
    
    // Only run cleanup periodically
    if (now - last_cleanup_.load() < cleanup_interval_) {
        return;
    }
    
    std::unique_lock<std::shared_mutex> lock(sources_mutex_);
    
    auto it = sources_.begin();
    while (it != sources_.end()) {
        auto& source_data = it->second;
        
        // Remove expired blacklist entries and inactive sources
        bool should_remove = false;
        
        if (source_data->is_blacklisted.load() && 
            now > source_data->blacklist_expiry.load()) {
            source_data->is_blacklisted = false;
        }
        
        // Remove completely inactive sources after a long period
        auto inactive_threshold = std::chrono::hours{24};
        if (source_data->active_connections.load() == 0 &&
            now - source_data->stats.last_request > inactive_threshold) {
            should_remove = true;
        }
        
        if (should_remove) {
            it = sources_.erase(it);
        } else {
            ++it;
        }
    }
    
    last_cleanup_ = now;
}

Result<void> RateLimiter::update_config(const RateLimitConfig& new_config) {
    config_ = new_config;
    
    // Update existing token buckets with new configuration
    std::shared_lock<std::shared_mutex> lock(sources_mutex_);
    for (auto& [key, source_data] : sources_) {
        // Note: This is a simplified update. In a full implementation,
        // you might want to create new token buckets with the new configuration
        source_data->token_bucket->reset();
    }
    
    return make_result();
}

void RateLimiter::reset() {
    std::unique_lock<std::shared_mutex> sources_lock(sources_mutex_);
    std::unique_lock<std::shared_mutex> whitelist_lock(whitelist_mutex_);
    
    sources_.clear();
    whitelist_.clear();
    
    total_requests_ = 0;
    allowed_requests_ = 0;
    denied_requests_ = 0;
    total_violations_ = 0;
    
    creation_time_ = std::chrono::steady_clock::now();
    last_cleanup_ = creation_time_;
}

// Private helper methods
SourceData* RateLimiter::get_or_create_source_data(const NetworkAddress& source_address) {
    std::string key = address_to_key(source_address);
    
    {
        std::shared_lock<std::shared_mutex> lock(sources_mutex_);
        auto it = sources_.find(key);
        if (it != sources_.end()) {
            return it->second.get();
        }
    }
    
    {
        std::unique_lock<std::shared_mutex> lock(sources_mutex_);
        // Double-check after acquiring write lock
        auto it = sources_.find(key);
        if (it != sources_.end()) {
            return it->second.get();
        }
        
        // Create new source data
        auto source_data = std::make_unique<SourceData>(config_);
        auto* ptr = source_data.get();
        sources_[key] = std::move(source_data);
        return ptr;
    }
}

SourceData* RateLimiter::get_source_data(const NetworkAddress& source_address) const {
    std::string key = address_to_key(source_address);
    std::shared_lock<std::shared_mutex> lock(sources_mutex_);
    
    auto it = sources_.find(key);
    return (it != sources_.end()) ? it->second.get() : nullptr;
}

bool RateLimiter::should_blacklist_source(SourceData* source_data) {
    std::lock_guard<std::mutex> lock(source_data->violations_mutex);
    return source_data->violations.size() >= config_.max_violations_per_hour;
}

void RateLimiter::apply_blacklist(SourceData* source_data, std::chrono::seconds duration) {
    auto now = std::chrono::steady_clock::now();
    source_data->is_blacklisted = true;
    source_data->blacklist_expiry = now + duration;
}

std::string RateLimiter::address_to_key(const NetworkAddress& address) const {
    std::ostringstream oss;
    oss << address.get_ip() << ":" << address.get_port();
    return oss.str();
}

// Factory implementations
std::unique_ptr<RateLimiter> RateLimiterFactory::create_development() {
    RateLimitConfig config;
    config.max_tokens = 1000;
    config.tokens_per_second = 100;
    config.max_concurrent_connections = 1000;
    config.max_handshakes_per_minute = 300;
    config.blacklist_duration = std::chrono::seconds{60};  // 1 minute
    return std::make_unique<RateLimiter>(config);
}

std::unique_ptr<RateLimiter> RateLimiterFactory::create_production() {
    RateLimitConfig config;
    config.max_tokens = 100;
    config.tokens_per_second = 10;
    config.max_concurrent_connections = 100;
    config.max_handshakes_per_minute = 30;
    config.blacklist_duration = std::chrono::seconds{300};  // 5 minutes
    return std::make_unique<RateLimiter>(config);
}

std::unique_ptr<RateLimiter> RateLimiterFactory::create_high_security() {
    RateLimitConfig config;
    config.max_tokens = 50;
    config.tokens_per_second = 5;
    config.max_concurrent_connections = 50;
    config.max_handshakes_per_minute = 10;
    config.blacklist_duration = std::chrono::seconds{900};  // 15 minutes
    config.max_violations_per_hour = 3;
    return std::make_unique<RateLimiter>(config);
}

std::unique_ptr<RateLimiter> RateLimiterFactory::create_custom(const RateLimitConfig& config) {
    return std::make_unique<RateLimiter>(config);
}

}  // namespace security
}  // namespace v13
}  // namespace dtls