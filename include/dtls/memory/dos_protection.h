#ifndef DTLS_MEMORY_DOS_PROTECTION_H
#define DTLS_MEMORY_DOS_PROTECTION_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/connection_pools.h>
#include <memory>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <chrono>
#include <vector>
#include <functional>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * DoS Protection Memory Bounds System for DTLS v1.3
 * 
 * This system implements comprehensive memory-based DoS protection mechanisms
 * including rate limiting, resource quotas, connection throttling, and
 * emergency cleanup procedures to maintain service availability under attack.
 */

// DoS protection configuration
struct DoSProtectionConfig {
    // Global memory limits
    size_t max_total_memory{256 * 1024 * 1024};        // 256MB total
    size_t max_per_connection_memory{1024 * 1024};     // 1MB per connection
    size_t max_handshake_memory{512 * 1024};           // 512KB for handshake state
    
    // Connection limits
    size_t max_concurrent_connections{10000};
    size_t max_connections_per_ip{100};
    size_t max_pending_handshakes{1000};
    size_t max_incomplete_handshakes_per_ip{10};
    
    // Rate limiting
    size_t max_packets_per_second{1000};
    size_t max_bytes_per_second{10 * 1024 * 1024};     // 10MB/s
    size_t max_new_connections_per_second{50};
    
    // Buffer limits
    size_t max_buffer_size{64 * 1024};                 // 64KB max buffer
    size_t max_fragmented_message_size{16 * 1024};     // 16KB max fragmented message
    size_t max_certificate_chain_size{32 * 1024};      // 32KB max cert chain
    
    // Timing thresholds
    std::chrono::seconds handshake_timeout{30};
    std::chrono::seconds connection_idle_timeout{300}; // 5 minutes
    std::chrono::seconds attack_detection_window{60};  // 1 minute
    
    // Emergency thresholds (when to trigger emergency measures)
    double emergency_memory_threshold{0.9};            // 90% memory usage
    double critical_memory_threshold{0.95};            // 95% memory usage
    size_t emergency_connection_limit{5000};
};

// Attack detection and classification
enum class AttackType {
    NONE,
    MEMORY_EXHAUSTION,
    CONNECTION_FLOODING,
    PACKET_FLOODING,
    AMPLIFICATION_ATTACK,
    HANDSHAKE_FLOODING,
    FRAGMENTATION_ATTACK,
    SLOWLORIS,
    COMPUTATIONAL_EXHAUSTION
};

struct AttackEvent {
    AttackType type{AttackType::NONE};
    std::string source_ip;
    std::chrono::steady_clock::time_point timestamp;
    size_t severity{0};         // 0-10 severity scale
    size_t resource_impact{0};  // Bytes of memory/resources consumed
    std::string description;
    
    // Attack characteristics
    size_t packet_rate{0};
    size_t connection_rate{0};
    size_t memory_usage{0};
    std::chrono::milliseconds response_time{0};
};

// Per-IP resource tracking
struct IPResourceUsage {
    std::string ip_address;
    
    // Current usage
    size_t active_connections{0};
    size_t pending_handshakes{0};
    size_t total_memory_usage{0};
    size_t packets_in_window{0};
    size_t bytes_in_window{0};
    
    // Historical data
    std::vector<std::chrono::steady_clock::time_point> connection_timestamps;
    std::vector<std::chrono::steady_clock::time_point> packet_timestamps;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_activity;
    
    // Reputation and risk
    double trust_score{1.0};    // 0.0 = untrusted, 1.0 = trusted
    size_t violation_count{0};
    bool is_blacklisted{false};
    bool is_rate_limited{false};
    
    // Attack indicators
    size_t consecutive_failures{0};
    size_t malformed_packets{0};
    size_t oversized_requests{0};
};

// DoS protection enforcement engine
class DTLS_API DoSProtectionEngine {
public:
    static DoSProtectionEngine& instance();
    
    // Protection enforcement
    Result<void> check_connection_allowed(const std::string& source_ip);
    Result<void> check_memory_allocation(size_t requested_size, const std::string& source_ip);
    Result<void> check_packet_rate(const std::string& source_ip);
    Result<void> check_handshake_resources(const std::string& source_ip);
    
    // Resource tracking
    void track_connection_start(const std::string& source_ip, void* connection_id);
    void track_connection_end(const std::string& source_ip, void* connection_id);
    void track_memory_allocation(const std::string& source_ip, size_t size);
    void track_memory_deallocation(const std::string& source_ip, size_t size);
    void track_packet_received(const std::string& source_ip, size_t packet_size);
    
    // Attack detection
    AttackType detect_attack_pattern(const std::string& source_ip);
    void report_attack_event(const AttackEvent& event);
    std::vector<AttackEvent> get_recent_attacks(std::chrono::minutes time_window) const;
    
    // Mitigation actions
    void blacklist_ip(const std::string& ip, std::chrono::minutes duration);
    void rate_limit_ip(const std::string& ip, size_t max_rate, std::chrono::minutes duration);
    void prioritize_connections(const std::vector<std::string>& trusted_ips);
    
    // Emergency procedures
    void trigger_emergency_mode();
    void exit_emergency_mode();
    bool is_emergency_mode_active() const { return emergency_mode_active_.load(); }
    size_t emergency_cleanup();
    
    // Configuration
    void set_config(const DoSProtectionConfig& config);
    DoSProtectionConfig get_config() const;
    void enable_protection(bool enabled) { protection_enabled_ = enabled; }
    bool is_protection_enabled() const { return protection_enabled_.load(); }
    
    // Statistics and monitoring
    struct ProtectionStats {
        size_t total_connections_blocked{0};
        size_t total_packets_dropped{0};
        size_t total_memory_requests_denied{0};
        size_t attacks_detected{0};
        size_t ips_blacklisted{0};
        size_t emergency_activations{0};
        std::chrono::steady_clock::time_point last_emergency_activation;
        double current_memory_usage_ratio{0.0};
    };
    
    ProtectionStats get_protection_statistics() const;
    void reset_statistics();
    
    // IP management
    IPResourceUsage get_ip_usage(const std::string& ip) const;
    std::vector<IPResourceUsage> get_top_resource_consumers(size_t count = 10) const;
    void update_ip_trust_score(const std::string& ip, double score);

private:
    DoSProtectionEngine() = default;
    ~DoSProtectionEngine() = default;
    
    mutable std::mutex config_mutex_;
    DoSProtectionConfig config_;
    
    mutable std::mutex ip_tracking_mutex_;
    std::unordered_map<std::string, IPResourceUsage> ip_usage_map_;
    
    mutable std::mutex attack_history_mutex_;
    std::vector<AttackEvent> attack_history_;
    
    mutable std::mutex stats_mutex_;
    ProtectionStats stats_;
    
    std::atomic<bool> protection_enabled_{true};
    std::atomic<bool> emergency_mode_active_{false};
    std::atomic<size_t> current_total_memory_{0};
    std::atomic<size_t> current_connection_count_{0};
    
    // Timer management for blacklist and rate limit removal
    mutable std::mutex timer_mutex_;
    std::multimap<std::chrono::steady_clock::time_point, std::string> scheduled_blacklist_removals_;
    std::multimap<std::chrono::steady_clock::time_point, std::pair<std::string, size_t>> scheduled_rate_limit_removals_;
    
    // Internal methods
    bool is_ip_blacklisted(const std::string& ip) const;
    bool is_ip_rate_limited(const std::string& ip) const;
    void update_ip_usage_stats(const std::string& ip);
    void cleanup_old_tracking_data();
    void process_scheduled_removals();
    AttackType analyze_ip_behavior(const IPResourceUsage& usage) const;
    double calculate_threat_level(const IPResourceUsage& usage) const;
    void apply_rate_limiting(const std::string& ip);
    size_t calculate_memory_pressure() const;
};

// Resource quota management
class DTLS_API ResourceQuotaManager {
public:
    static ResourceQuotaManager& instance();
    
    // Quota management
    Result<void> allocate_connection_quota(const std::string& source_ip, void* connection_id);
    void release_connection_quota(const std::string& source_ip, void* connection_id);
    
    Result<void> allocate_memory_quota(const std::string& source_ip, size_t size);
    void release_memory_quota(const std::string& source_ip, size_t size);
    
    Result<void> allocate_handshake_quota(const std::string& source_ip);
    void release_handshake_quota(const std::string& source_ip);
    
    // Quota limits
    void set_per_ip_connection_limit(size_t limit);
    void set_per_ip_memory_limit(size_t limit);
    void set_global_memory_limit(size_t limit);
    
    // Emergency quota reduction
    void reduce_quotas_for_emergency(double reduction_factor);
    void restore_normal_quotas();
    
    // Quota statistics
    struct QuotaStats {
        size_t global_memory_used{0};
        size_t global_memory_limit{0};
        size_t total_connections{0};
        size_t total_handshakes{0};
        std::unordered_map<std::string, size_t> per_ip_usage;
    };
    
    QuotaStats get_quota_statistics() const;

private:
    ResourceQuotaManager() = default;
    ~ResourceQuotaManager() = default;
    
    mutable std::mutex quotas_mutex_;
    std::unordered_map<std::string, size_t> per_ip_connections_;
    std::unordered_map<std::string, size_t> per_ip_memory_usage_;
    std::unordered_map<std::string, size_t> per_ip_handshakes_;
    
    std::atomic<size_t> global_memory_used_{0};
    std::atomic<size_t> global_memory_limit_{256 * 1024 * 1024};
    std::atomic<size_t> per_ip_connection_limit_{100};
    std::atomic<size_t> per_ip_memory_limit_{1024 * 1024};
    
    bool is_quota_available(const std::string& ip, size_t requested_connections, 
                           size_t requested_memory) const;
};

// Memory pressure response system
class DTLS_API MemoryPressureResponse {
public:
    static MemoryPressureResponse& instance();
    
    // Pressure level detection
    enum class PressureLevel {
        NORMAL,
        LOW_PRESSURE,
        MEDIUM_PRESSURE,
        HIGH_PRESSURE,
        CRITICAL_PRESSURE
    };
    
    PressureLevel detect_current_pressure() const;
    void handle_pressure_level(PressureLevel level);
    
    // Response actions
    size_t free_low_priority_buffers();
    size_t consolidate_fragmented_memory();
    size_t close_idle_connections();
    size_t reduce_buffer_cache_sizes();
    
    // Emergency response
    size_t emergency_memory_reclaim();
    void trigger_emergency_gc();
    
    // Callbacks for custom pressure responses
    using PressureCallback = std::function<size_t(PressureLevel)>;
    void register_pressure_callback(const std::string& name, PressureCallback callback);
    void unregister_pressure_callback(const std::string& name);

private:
    MemoryPressureResponse() = default;
    ~MemoryPressureResponse() = default;
    
    std::unordered_map<std::string, PressureCallback> pressure_callbacks_;
    mutable std::mutex callbacks_mutex_;
    
    PressureLevel calculate_pressure_level(size_t used_memory, size_t total_memory) const;
};

// DoS-resistant buffer allocation
class DTLS_API DoSResistantAllocator {
public:
    static DoSResistantAllocator& instance();
    
    // Protected allocation
    Result<std::unique_ptr<ZeroCopyBuffer>> allocate_protected_buffer(
        size_t size, const std::string& source_ip, const std::string& purpose);
    
    Result<ConnectionBuffer> allocate_connection_buffer_protected(
        void* connection_id, size_t size, const std::string& source_ip);
    
    // Buffer size validation
    bool validate_buffer_size(size_t requested_size, const std::string& purpose) const;
    size_t get_max_allowed_size(const std::string& purpose) const;
    
    // Allocation tracking for DoS detection
    void track_allocation_pattern(const std::string& source_ip, size_t size, 
                                 const std::string& purpose);
    
    // Suspicious pattern detection
    bool detect_allocation_abuse(const std::string& source_ip) const;
    
    // Emergency allocation limits
    void enter_allocation_lockdown();
    void exit_allocation_lockdown();
    bool is_allocation_lockdown_active() const { return allocation_lockdown_.load(); }

private:
    DoSResistantAllocator() = default;
    ~DoSResistantAllocator() = default;
    
    std::atomic<bool> allocation_lockdown_{false};
    
    struct AllocationPattern {
        size_t total_bytes_requested{0};
        size_t allocation_count{0};
        std::vector<std::chrono::steady_clock::time_point> recent_allocations;
        std::unordered_map<std::string, size_t> purpose_breakdown;
    };
    
    mutable std::mutex patterns_mutex_;
    std::unordered_map<std::string, AllocationPattern> ip_allocation_patterns_;
    
    bool is_allocation_request_suspicious(const std::string& source_ip, 
                                        size_t size, const std::string& purpose) const;
};

// Factory functions for DoS-protected memory allocation
DTLS_API Result<std::unique_ptr<ZeroCopyBuffer>> make_protected_buffer(
    size_t size, const std::string& source_ip, const std::string& purpose = "general");

DTLS_API Result<ConnectionBuffer> make_protected_connection_buffer(
    void* connection_id, size_t size, const std::string& source_ip);

// DoS protection utilities
DTLS_API void enable_dos_protection(bool enabled = true);
DTLS_API bool is_dos_protection_enabled();
DTLS_API void configure_dos_protection(const DoSProtectionConfig& config);
DTLS_API void trigger_emergency_dos_response();
DTLS_API DoSProtectionEngine::ProtectionStats get_dos_protection_stats();

// IP management utilities  
DTLS_API void blacklist_malicious_ip(const std::string& ip, std::chrono::minutes duration);
DTLS_API void whitelist_trusted_ip(const std::string& ip);
DTLS_API bool is_ip_trusted(const std::string& ip);

} // namespace memory
} // namespace v13  
} // namespace dtls

#endif // DTLS_MEMORY_DOS_PROTECTION_H