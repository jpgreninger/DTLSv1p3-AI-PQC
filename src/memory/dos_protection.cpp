#include <dtls/memory/dos_protection.h>
#include <dtls/memory/leak_detection.h>
#include <dtls/memory/smart_recycling.h>
#include <dtls/error.h>
#include <algorithm>
#include <numeric>
#include <sstream>

namespace dtls {
namespace v13 {
namespace memory {

// DoSProtectionEngine implementation
DoSProtectionEngine& DoSProtectionEngine::instance() {
    static DoSProtectionEngine instance_;
    return instance_;
}

Result<void> DoSProtectionEngine::check_connection_allowed(const std::string& source_ip) {
    if (!protection_enabled_.load()) {
        return Result<void>();
    }
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    
    // Check if IP is blacklisted
    if (is_ip_blacklisted(source_ip)) {
        stats_.total_connections_blocked++;
        return Result<void>(DTLSError::CONNECTION_REJECTED);
    }
    
    // Check global connection limits
    if (current_connection_count_.load() >= config_.max_concurrent_connections) {
        if (emergency_mode_active_.load() || 
            current_connection_count_.load() >= config_.emergency_connection_limit) {
            stats_.total_connections_blocked++;
            return Result<void>(DTLSError::CONNECTION_LIMIT_EXCEEDED);
        }
    }
    
    // Check per-IP connection limits
    auto& ip_usage = ip_usage_map_[source_ip];
    if (ip_usage.active_connections >= config_.max_connections_per_ip) {
        stats_.total_connections_blocked++;
        return Result<void>(DTLSError::CONNECTION_LIMIT_EXCEEDED);
    }
    
    // Check for rapid connection attempts (potential flooding)
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - config_.attack_detection_window;
    
    // Clean up old timestamps
    ip_usage.connection_timestamps.erase(
        std::remove_if(ip_usage.connection_timestamps.begin(), 
                      ip_usage.connection_timestamps.end(),
                      [window_start](const auto& timestamp) {
                          return timestamp < window_start;
                      }),
        ip_usage.connection_timestamps.end());
    
    // Check connection rate
    if (ip_usage.connection_timestamps.size() >= config_.max_new_connections_per_second) {
        apply_rate_limiting(source_ip);
        stats_.total_connections_blocked++;
        return Result<void>(DTLSError::RATE_LIMIT_EXCEEDED);
    }
    
    return Result<void>();
}

Result<void> DoSProtectionEngine::check_memory_allocation(size_t requested_size, 
                                                         const std::string& source_ip) {
    if (!protection_enabled_.load()) {
        return Result<void>();
    }
    
    // Check global memory limits
    size_t current_memory = current_total_memory_.load();
    if (current_memory + requested_size > config_.max_total_memory) {
        stats_.total_memory_requests_denied++;
        
        // Try emergency cleanup first
        if (emergency_cleanup() > requested_size) {
            return Result<void>();
        }
        
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
    
    // Check per-IP memory limits
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    
    if (ip_usage.total_memory_usage + requested_size > config_.max_per_connection_memory) {
        stats_.total_memory_requests_denied++;
        return Result<void>(DTLSError::MEMORY_LIMIT_EXCEEDED);
    }
    
    // Check if allocation size is suspicious
    if (requested_size > config_.max_buffer_size) {
        ip_usage.oversized_requests++;
        ip_usage.violation_count++;
        
        if (ip_usage.oversized_requests > 5) {
            // Potential memory exhaustion attack
            AttackEvent event;
            event.type = AttackType::MEMORY_EXHAUSTION;
            event.source_ip = source_ip;
            event.timestamp = std::chrono::steady_clock::now();
            event.severity = 7;
            event.resource_impact = requested_size;
            event.description = "Repeated oversized memory allocation requests";
            
            report_attack_event(event);
            return Result<void>(DTLSError::MEMORY_LIMIT_EXCEEDED);
        }
    }
    
    return Result<void>();
}

Result<void> DoSProtectionEngine::check_packet_rate(const std::string& source_ip) {
    if (!protection_enabled_.load()) {
        return Result<void>();
    }
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::seconds(1); // 1-second window
    
    // Clean up old packet timestamps
    ip_usage.packet_timestamps.erase(
        std::remove_if(ip_usage.packet_timestamps.begin(), 
                      ip_usage.packet_timestamps.end(),
                      [window_start](const auto& timestamp) {
                          return timestamp < window_start;
                      }),
        ip_usage.packet_timestamps.end());
    
    // Check packet rate
    if (ip_usage.packet_timestamps.size() >= config_.max_packets_per_second) {
        if (!ip_usage.is_rate_limited) {
            rate_limit_ip(source_ip, config_.max_packets_per_second / 2, 
                         std::chrono::minutes(5));
        }
        
        stats_.total_packets_dropped++;
        return Result<void>(DTLSError::RATE_LIMIT_EXCEEDED);
    }
    
    return Result<void>();
}

void DoSProtectionEngine::track_connection_start(const std::string& source_ip, void* connection_id) {
    if (!protection_enabled_.load()) return;
    
    current_connection_count_.fetch_add(1);
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    
    ip_usage.active_connections++;
    ip_usage.connection_timestamps.push_back(std::chrono::steady_clock::now());
    ip_usage.last_activity = std::chrono::steady_clock::now();
    
    if (ip_usage.first_seen == std::chrono::steady_clock::time_point{}) {
        ip_usage.first_seen = std::chrono::steady_clock::now();
    }
}

void DoSProtectionEngine::track_connection_end(const std::string& source_ip, void* connection_id) {
    if (!protection_enabled_.load()) return;
    
    current_connection_count_.fetch_sub(1);
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    
    if (ip_usage.active_connections > 0) {
        ip_usage.active_connections--;
    }
    
    ip_usage.last_activity = std::chrono::steady_clock::now();
}

void DoSProtectionEngine::track_memory_allocation(const std::string& source_ip, size_t size) {
    if (!protection_enabled_.load()) return;
    
    current_total_memory_.fetch_add(size);
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    ip_usage.total_memory_usage += size;
}

void DoSProtectionEngine::track_memory_deallocation(const std::string& source_ip, size_t size) {
    if (!protection_enabled_.load()) return;
    
    current_total_memory_.fetch_sub(size);
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    if (ip_usage.total_memory_usage >= size) {
        ip_usage.total_memory_usage -= size;
    } else {
        ip_usage.total_memory_usage = 0;
    }
}

void DoSProtectionEngine::track_packet_received(const std::string& source_ip, size_t packet_size) {
    if (!protection_enabled_.load()) return;
    
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[source_ip];
    
    ip_usage.packet_timestamps.push_back(std::chrono::steady_clock::now());
    ip_usage.packets_in_window++;
    ip_usage.bytes_in_window += packet_size;
    ip_usage.last_activity = std::chrono::steady_clock::now();
}

AttackType DoSProtectionEngine::detect_attack_pattern(const std::string& source_ip) {
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto it = ip_usage_map_.find(source_ip);
    if (it == ip_usage_map_.end()) {
        return AttackType::NONE;
    }
    
    return analyze_ip_behavior(it->second);
}

AttackType DoSProtectionEngine::analyze_ip_behavior(const IPResourceUsage& usage) const {
    // Memory exhaustion attack detection
    if (usage.oversized_requests > 5 || usage.total_memory_usage > config_.max_per_connection_memory * 0.9) {
        return AttackType::MEMORY_EXHAUSTION;
    }
    
    // Connection flooding detection
    if (usage.active_connections > config_.max_connections_per_ip * 0.8 ||
        usage.connection_timestamps.size() > config_.max_new_connections_per_second * 2) {
        return AttackType::CONNECTION_FLOODING;
    }
    
    // Packet flooding detection
    if (usage.packets_in_window > config_.max_packets_per_second * 2) {
        return AttackType::PACKET_FLOODING;
    }
    
    // Handshake flooding detection
    if (usage.pending_handshakes > config_.max_incomplete_handshakes_per_ip * 0.8) {
        return AttackType::HANDSHAKE_FLOODING;
    }
    
    // Malformed packet detection
    if (usage.malformed_packets > 10) {
        return AttackType::COMPUTATIONAL_EXHAUSTION;
    }
    
    return AttackType::NONE;
}

void DoSProtectionEngine::report_attack_event(const AttackEvent& event) {
    std::lock_guard<std::mutex> lock(attack_history_mutex_);
    attack_history_.push_back(event);
    
    // Keep only recent attack events
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(24);
    attack_history_.erase(
        std::remove_if(attack_history_.begin(), attack_history_.end(),
                      [cutoff](const AttackEvent& e) { return e.timestamp < cutoff; }),
        attack_history_.end());
    
    stats_.attacks_detected++;
    
    // Auto-respond to high-severity attacks
    if (event.severity >= 8) {
        blacklist_ip(event.source_ip, std::chrono::minutes(60));
    } else if (event.severity >= 6) {
        rate_limit_ip(event.source_ip, config_.max_packets_per_second / 4, 
                     std::chrono::minutes(30));
    }
}

void DoSProtectionEngine::blacklist_ip(const std::string& ip, std::chrono::minutes duration) {
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[ip];
    ip_usage.is_blacklisted = true;
    ip_usage.trust_score = 0.0;
    stats_.ips_blacklisted++;
    
    // Set timer to remove blacklist after duration
    auto removal_time = std::chrono::steady_clock::now() + duration;
    
    // Add to scheduled removals
    std::lock_guard<std::mutex> timer_lock(timer_mutex_);
    scheduled_blacklist_removals_.emplace(removal_time, ip);
}

void DoSProtectionEngine::rate_limit_ip(const std::string& ip, size_t max_rate, 
                                       std::chrono::minutes duration) {
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    auto& ip_usage = ip_usage_map_[ip];
    ip_usage.is_rate_limited = true;
    ip_usage.trust_score *= 0.5; // Reduce trust score
    
    // Set timer to remove rate limiting after duration  
    auto removal_time = std::chrono::steady_clock::now() + duration;
    
    // Add to scheduled removals
    std::lock_guard<std::mutex> timer_lock(timer_mutex_);
    scheduled_rate_limit_removals_.emplace(removal_time, std::make_pair(ip, max_rate));
}

void DoSProtectionEngine::trigger_emergency_mode() {
    if (emergency_mode_active_.exchange(true)) {
        return; // Already in emergency mode
    }
    
    stats_.emergency_activations++;
    stats_.last_emergency_activation = std::chrono::steady_clock::now();
    
    // Reduce resource limits
    config_.max_concurrent_connections = config_.emergency_connection_limit;
    config_.max_per_connection_memory /= 2;
    config_.max_buffer_size /= 2;
    
    // Trigger emergency cleanup
    emergency_cleanup();
    
    // Enable aggressive memory recycling
    BufferRecyclingManager::instance().enable_aggressive_recycling(true);
    
    // Activate memory pressure response
    MemoryPressureResponse::instance().emergency_memory_reclaim();
}

void DoSProtectionEngine::exit_emergency_mode() {
    if (!emergency_mode_active_.exchange(false)) {
        return; // Not in emergency mode
    }
    
    // Restore normal resource limits (could reload from config)
    // For now, this is a simplified restoration
    BufferRecyclingManager::instance().enable_aggressive_recycling(false);
}

size_t DoSProtectionEngine::emergency_cleanup() {
    size_t bytes_freed = 0;
    
    // Clean up leak detection system
    bytes_freed += LeakDetector::instance().cleanup_leaked_resources();
    
    // Reclaim memory from smart recycling system
    bytes_freed += BufferRecyclingManager::instance().handle_memory_pressure();
    
    // Memory pressure response
    bytes_freed += MemoryPressureResponse::instance().emergency_memory_reclaim();
    
    // Clean up old IP tracking data
    cleanup_old_tracking_data();
    
    return bytes_freed;
}

bool DoSProtectionEngine::is_ip_blacklisted(const std::string& ip) const {
    auto it = ip_usage_map_.find(ip);
    return it != ip_usage_map_.end() && it->second.is_blacklisted;
}

bool DoSProtectionEngine::is_ip_rate_limited(const std::string& ip) const {
    auto it = ip_usage_map_.find(ip);
    return it != ip_usage_map_.end() && it->second.is_rate_limited;
}

void DoSProtectionEngine::cleanup_old_tracking_data() {
    std::lock_guard<std::mutex> lock(ip_tracking_mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(1);
    
    for (auto it = ip_usage_map_.begin(); it != ip_usage_map_.end();) {
        auto& usage = it->second;
        
        // Remove IPs with no recent activity and no active connections
        if (usage.last_activity < cutoff && usage.active_connections == 0 && 
            !usage.is_blacklisted) {
            it = ip_usage_map_.erase(it);
        } else {
            // Clean up old timestamps for remaining IPs
            usage.connection_timestamps.erase(
                std::remove_if(usage.connection_timestamps.begin(), 
                              usage.connection_timestamps.end(),
                              [cutoff](const auto& timestamp) {
                                  return timestamp < cutoff;
                              }),
                usage.connection_timestamps.end());
                
            usage.packet_timestamps.erase(
                std::remove_if(usage.packet_timestamps.begin(), 
                              usage.packet_timestamps.end(),
                              [cutoff](const auto& timestamp) {
                                  return timestamp < cutoff;
                              }),
                usage.packet_timestamps.end());
            ++it;
        }
    }
    
    // Process scheduled blacklist and rate limit removals
    process_scheduled_removals();
}

void DoSProtectionEngine::process_scheduled_removals() {
    auto now = std::chrono::steady_clock::now();
    
    // Process blacklist removals
    {
        std::lock_guard<std::mutex> timer_lock(timer_mutex_);
        std::lock_guard<std::mutex> ip_lock(ip_tracking_mutex_);
        
        auto it = scheduled_blacklist_removals_.begin();
        while (it != scheduled_blacklist_removals_.end() && it->first <= now) {
            const auto& ip = it->second;
            auto ip_it = ip_usage_map_.find(ip);
            if (ip_it != ip_usage_map_.end()) {
                ip_it->second.is_blacklisted = false;
                // Restore partial trust score
                ip_it->second.trust_score = std::min(0.5, ip_it->second.trust_score + 0.2);
            }
            it = scheduled_blacklist_removals_.erase(it);
        }
    }
    
    // Process rate limit removals
    {
        std::lock_guard<std::mutex> timer_lock(timer_mutex_);
        std::lock_guard<std::mutex> ip_lock(ip_tracking_mutex_);
        
        auto it = scheduled_rate_limit_removals_.begin();
        while (it != scheduled_rate_limit_removals_.end() && it->first <= now) {
            const auto& ip = it->second.first;
            auto ip_it = ip_usage_map_.find(ip);
            if (ip_it != ip_usage_map_.end()) {
                ip_it->second.is_rate_limited = false;
                // Restore partial trust score
                ip_it->second.trust_score = std::min(0.8, ip_it->second.trust_score + 0.1);
            }
            it = scheduled_rate_limit_removals_.erase(it);
        }
    }
}

void DoSProtectionEngine::apply_rate_limiting(const std::string& ip) {
    rate_limit_ip(ip, config_.max_packets_per_second / 2, std::chrono::minutes(15));
}

DoSProtectionEngine::ProtectionStats DoSProtectionEngine::get_protection_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto stats = stats_;
    stats.current_memory_usage_ratio = 
        static_cast<double>(current_total_memory_.load()) / config_.max_total_memory;
    return stats;
}

void DoSProtectionEngine::set_config(const DoSProtectionConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

DoSProtectionConfig DoSProtectionEngine::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

// ResourceQuotaManager implementation
ResourceQuotaManager& ResourceQuotaManager::instance() {
    static ResourceQuotaManager instance_;
    return instance_;
}

Result<void> ResourceQuotaManager::allocate_connection_quota(const std::string& source_ip, 
                                                           void* connection_id) {
    std::lock_guard<std::mutex> lock(quotas_mutex_);
    
    auto& ip_connections = per_ip_connections_[source_ip];
    if (ip_connections >= per_ip_connection_limit_.load()) {
        return Result<void>(DTLSError::CONNECTION_LIMIT_EXCEEDED);
    }
    
    ip_connections++;
    return Result<void>();
}

void ResourceQuotaManager::release_connection_quota(const std::string& source_ip, void* connection_id) {
    std::lock_guard<std::mutex> lock(quotas_mutex_);
    
    auto& ip_connections = per_ip_connections_[source_ip];
    if (ip_connections > 0) {
        ip_connections--;
    }
}

Result<void> ResourceQuotaManager::allocate_memory_quota(const std::string& source_ip, size_t size) {
    // Check global limit
    size_t current_global = global_memory_used_.load();
    if (current_global + size > global_memory_limit_.load()) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
    
    std::lock_guard<std::mutex> lock(quotas_mutex_);
    
    // Check per-IP limit
    auto& ip_memory = per_ip_memory_usage_[source_ip];
    if (ip_memory + size > per_ip_memory_limit_.load()) {
        return Result<void>(DTLSError::MEMORY_LIMIT_EXCEEDED);
    }
    
    // Allocate quotas
    global_memory_used_.fetch_add(size);
    ip_memory += size;
    
    return Result<void>();
}

void ResourceQuotaManager::release_memory_quota(const std::string& source_ip, size_t size) {
    global_memory_used_.fetch_sub(size);
    
    std::lock_guard<std::mutex> lock(quotas_mutex_);
    auto& ip_memory = per_ip_memory_usage_[source_ip];
    if (ip_memory >= size) {
        ip_memory -= size;
    } else {
        ip_memory = 0;
    }
}

// MemoryPressureResponse implementation
MemoryPressureResponse& MemoryPressureResponse::instance() {
    static MemoryPressureResponse instance_;
    return instance_;
}

MemoryPressureResponse::PressureLevel MemoryPressureResponse::detect_current_pressure() const {
    auto& engine = DoSProtectionEngine::instance();
    auto config = engine.get_config();
    auto stats = engine.get_protection_statistics();
    
    return calculate_pressure_level(
        DoSProtectionEngine::instance().current_total_memory_.load(),
        config.max_total_memory);
}

MemoryPressureResponse::PressureLevel 
MemoryPressureResponse::calculate_pressure_level(size_t used_memory, size_t total_memory) const {
    double usage_ratio = static_cast<double>(used_memory) / total_memory;
    
    if (usage_ratio >= 0.95) return PressureLevel::CRITICAL_PRESSURE;
    if (usage_ratio >= 0.90) return PressureLevel::HIGH_PRESSURE;
    if (usage_ratio >= 0.80) return PressureLevel::MEDIUM_PRESSURE;
    if (usage_ratio >= 0.70) return PressureLevel::LOW_PRESSURE;
    return PressureLevel::NORMAL;
}

void MemoryPressureResponse::handle_pressure_level(PressureLevel level) {
    switch (level) {
        case PressureLevel::CRITICAL_PRESSURE:
            emergency_memory_reclaim();
            DoSProtectionEngine::instance().trigger_emergency_mode();
            break;
            
        case PressureLevel::HIGH_PRESSURE:
            emergency_memory_reclaim();
            break;
            
        case PressureLevel::MEDIUM_PRESSURE:
            free_low_priority_buffers();
            close_idle_connections();
            break;
            
        case PressureLevel::LOW_PRESSURE:
            reduce_buffer_cache_sizes();
            break;
            
        case PressureLevel::NORMAL:
        default:
            // No action needed
            break;
    }
    
    // Notify registered callbacks
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (auto& [name, callback] : pressure_callbacks_) {
        try {
            callback(level);
        } catch (...) {
            // Ignore callback exceptions during emergency response
        }
    }
}

size_t MemoryPressureResponse::emergency_memory_reclaim() {
    size_t total_freed = 0;
    
    total_freed += free_low_priority_buffers();
    total_freed += consolidate_fragmented_memory();
    total_freed += close_idle_connections();
    total_freed += reduce_buffer_cache_sizes();
    trigger_emergency_gc();
    
    return total_freed;
}

size_t MemoryPressureResponse::free_low_priority_buffers() {
    // Free buffers from recycling system
    return BufferRecyclingManager::instance().handle_memory_pressure();
}

size_t MemoryPressureResponse::consolidate_fragmented_memory() {
    // This would require platform-specific memory defragmentation
    // For now, just return 0
    return 0;
}

size_t MemoryPressureResponse::close_idle_connections() {
    // This would require integration with connection manager
    // For now, just return 0
    return 0;
}

size_t MemoryPressureResponse::reduce_buffer_cache_sizes() {
    // Reduce pool sizes in adaptive pools
    AdaptivePoolManager::instance().handle_memory_pressure();
    return 0; // Size reduction not directly measurable
}

void MemoryPressureResponse::trigger_emergency_gc() {
    // Force garbage collection of leaked resources
    LeakDetector::instance().cleanup_leaked_resources();
}

// DoSResistantAllocator implementation
DoSResistantAllocator& DoSResistantAllocator::instance() {
    static DoSResistantAllocator instance_;
    return instance_;
}

Result<std::unique_ptr<ZeroCopyBuffer>> 
DoSResistantAllocator::allocate_protected_buffer(size_t size, const std::string& source_ip, 
                                               const std::string& purpose) {
    if (allocation_lockdown_.load()) {
        return Result<std::unique_ptr<ZeroCopyBuffer>>(DTLSError::SERVICE_UNAVAILABLE);
    }
    
    // Validate buffer size
    if (!validate_buffer_size(size, purpose)) {
        return Result<std::unique_ptr<ZeroCopyBuffer>>(DTLSError::BUFFER_TOO_LARGE);
    }
    
    // Check DoS protection
    auto protection_result = DoSProtectionEngine::instance().check_memory_allocation(size, source_ip);
    if (!protection_result) {
        return Result<std::unique_ptr<ZeroCopyBuffer>>(protection_result.error());
    }
    
    // Check resource quotas
    auto quota_result = ResourceQuotaManager::instance().allocate_memory_quota(source_ip, size);
    if (!quota_result) {
        return Result<std::unique_ptr<ZeroCopyBuffer>>(quota_result.error());
    }
    
    // Track allocation pattern
    track_allocation_pattern(source_ip, size, purpose);
    
    // Check for suspicious patterns
    if (detect_allocation_abuse(source_ip)) {
        ResourceQuotaManager::instance().release_memory_quota(source_ip, size);
        return Result<std::unique_ptr<ZeroCopyBuffer>>(DTLSError::ABUSE_DETECTED);
    }
    
    // Allocate buffer
    auto buffer = std::make_unique<ZeroCopyBuffer>(size);
    
    // Track allocation in DoS protection system
    DoSProtectionEngine::instance().track_memory_allocation(source_ip, size);
    
    return Result<std::unique_ptr<ZeroCopyBuffer>>(std::move(buffer));
}

bool DoSResistantAllocator::validate_buffer_size(size_t requested_size, 
                                                const std::string& purpose) const {
    size_t max_allowed = get_max_allowed_size(purpose);
    return requested_size <= max_allowed;
}

size_t DoSResistantAllocator::get_max_allowed_size(const std::string& purpose) const {
    auto config = DoSProtectionEngine::instance().get_config();
    
    if (purpose == "handshake") {
        return config.max_handshake_memory;
    } else if (purpose == "certificate") {
        return config.max_certificate_chain_size;
    } else if (purpose == "fragment") {
        return config.max_fragmented_message_size;
    } else {
        return config.max_buffer_size;
    }
}

void DoSResistantAllocator::track_allocation_pattern(const std::string& source_ip, 
                                                   size_t size, const std::string& purpose) {
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    auto& pattern = ip_allocation_patterns_[source_ip];
    
    pattern.total_bytes_requested += size;
    pattern.allocation_count++;
    pattern.recent_allocations.push_back(std::chrono::steady_clock::now());
    pattern.purpose_breakdown[purpose] += size;
    
    // Clean up old allocation timestamps
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(5);
    pattern.recent_allocations.erase(
        std::remove_if(pattern.recent_allocations.begin(), 
                      pattern.recent_allocations.end(),
                      [cutoff](const auto& timestamp) {
                          return timestamp < cutoff;
                      }),
        pattern.recent_allocations.end());
}

bool DoSResistantAllocator::detect_allocation_abuse(const std::string& source_ip) const {
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    auto it = ip_allocation_patterns_.find(source_ip);
    if (it == ip_allocation_patterns_.end()) {
        return false;
    }
    
    const auto& pattern = it->second;
    
    // Check for rapid allocation bursts
    if (pattern.recent_allocations.size() > 50) { // 50 allocations in 5 minutes
        return true;
    }
    
    // Check for excessive total allocation
    if (pattern.total_bytes_requested > 10 * 1024 * 1024) { // 10MB total
        return true;
    }
    
    return false;
}

// Factory functions
Result<std::unique_ptr<ZeroCopyBuffer>> make_protected_buffer(size_t size, 
                                                            const std::string& source_ip, 
                                                            const std::string& purpose) {
    return DoSResistantAllocator::instance().allocate_protected_buffer(size, source_ip, purpose);
}

// Utility functions
void enable_dos_protection(bool enabled) {
    DoSProtectionEngine::instance().enable_protection(enabled);
}

bool is_dos_protection_enabled() {
    return DoSProtectionEngine::instance().is_protection_enabled();
}

void configure_dos_protection(const DoSProtectionConfig& config) {
    DoSProtectionEngine::instance().set_config(config);
}

void trigger_emergency_dos_response() {
    DoSProtectionEngine::instance().trigger_emergency_mode();
}

DoSProtectionEngine::ProtectionStats get_dos_protection_stats() {
    return DoSProtectionEngine::instance().get_protection_statistics();
}

void blacklist_malicious_ip(const std::string& ip, std::chrono::minutes duration) {
    DoSProtectionEngine::instance().blacklist_ip(ip, duration);
}

} // namespace memory
} // namespace v13
} // namespace dtls