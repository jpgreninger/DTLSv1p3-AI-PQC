#pragma once

#include <dtls/result.h>
#include <dtls/types.h>
#include <dtls/error.h>

#include <chrono>
#include <memory>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace dtls {
namespace v13 {
namespace security {

/**
 * Resource management configuration
 */
struct ResourceConfig {
    // Memory limits
    size_t max_total_memory = 256 * 1024 * 1024;      // 256MB total memory
    size_t max_memory_per_connection = 64 * 1024;     // 64KB per connection
    size_t max_handshake_memory = 32 * 1024;          // 32KB per handshake
    size_t max_buffer_memory = 128 * 1024 * 1024;     // 128MB for buffers
    
    // Connection limits
    size_t max_total_connections = 10000;             // Maximum total connections
    size_t max_connections_per_source = 100;          // Maximum per source IP
    size_t max_pending_handshakes = 1000;             // Maximum pending handshakes
    size_t max_handshakes_per_source = 10;            // Maximum handshakes per source
    
    // Time-based limits
    std::chrono::seconds connection_timeout{300};      // 5 minutes default
    std::chrono::seconds handshake_timeout{30};        // 30 seconds for handshake
    std::chrono::seconds cleanup_interval{60};         // Cleanup every minute
    
    // Resource pressure thresholds
    double memory_warning_threshold = 0.8;            // Warn at 80% memory usage
    double memory_critical_threshold = 0.95;          // Critical at 95% memory usage
    double connection_warning_threshold = 0.8;        // Warn at 80% connection limit
    double connection_critical_threshold = 0.95;      // Critical at 95% connection limit
    
    // Auto-cleanup settings
    bool enable_auto_cleanup = true;                  // Enable automatic cleanup
    bool enable_memory_pressure_cleanup = true;       // Cleanup under memory pressure
    size_t cleanup_batch_size = 100;                 // Cleanup this many at once
    
    ResourceConfig() = default;
};

/**
 * Resource allocation result
 */
enum class ResourceResult : uint8_t {
    ALLOCATED,              // Resource successfully allocated
    MEMORY_LIMIT_EXCEEDED,  // Memory limit would be exceeded
    CONNECTION_LIMIT_EXCEEDED, // Connection limit would be exceeded
    SOURCE_LIMIT_EXCEEDED,  // Per-source limit would be exceeded
    SYSTEM_OVERLOADED,     // System is overloaded
    RESOURCE_UNAVAILABLE   // Resource temporarily unavailable
};

/**
 * Resource pressure level
 */
enum class PressureLevel : uint8_t {
    NORMAL,     // Normal operation
    WARNING,    // Approaching limits
    CRITICAL,   // At or near limits
    EMERGENCY   // System overloaded
};

/**
 * Resource type enumeration
 */
enum class ResourceType : uint8_t {
    CONNECTION_MEMORY,
    HANDSHAKE_MEMORY,
    BUFFER_MEMORY,
    CONNECTION_SLOT,
    HANDSHAKE_SLOT
};

/**
 * Resource allocation tracking
 */
struct ResourceAllocation {
    ResourceType type;
    size_t amount;
    std::string source_key;
    std::chrono::steady_clock::time_point allocated_time;
    std::chrono::steady_clock::time_point last_activity;
    bool is_active;
    
    ResourceAllocation(ResourceType t, size_t amt, const std::string& src)
        : type(t), amount(amt), source_key(src), is_active(true) {
        auto now = std::chrono::steady_clock::now();
        allocated_time = now;
        last_activity = now;
    }
};

/**
 * Per-source resource tracking
 */
struct SourceResourceData {
    std::atomic<size_t> total_memory{0};
    std::atomic<size_t> connection_count{0};
    std::atomic<size_t> handshake_count{0};
    std::atomic<size_t> buffer_memory{0};
    std::unordered_set<uint64_t> allocation_ids;
    std::chrono::steady_clock::time_point first_allocation;
    std::chrono::steady_clock::time_point last_activity;
    mutable std::mutex allocation_mutex;
    
    SourceResourceData() {
        auto now = std::chrono::steady_clock::now();
        first_allocation = now;
        last_activity = now;
    }
    
    // Delete copy and move constructors/assignments due to atomic and mutex members
    SourceResourceData(const SourceResourceData&) = delete;
    SourceResourceData& operator=(const SourceResourceData&) = delete;
    SourceResourceData(SourceResourceData&&) = delete;
    SourceResourceData& operator=(SourceResourceData&&) = delete;
};

/**
 * System resource statistics
 */
struct ResourceStats {
    // Memory statistics
    size_t total_allocated_memory = 0;
    size_t peak_memory_usage = 0;
    size_t connection_memory = 0;
    size_t handshake_memory = 0;
    size_t buffer_memory = 0;
    
    // Connection statistics
    size_t total_connections = 0;
    size_t active_connections = 0;
    size_t pending_handshakes = 0;
    size_t completed_handshakes = 0;
    size_t failed_allocations = 0;
    
    // Pressure statistics
    PressureLevel current_pressure = PressureLevel::NORMAL;
    size_t pressure_events = 0;
    std::chrono::steady_clock::time_point last_pressure_event;
    
    // Cleanup statistics
    size_t cleanup_operations = 0;
    size_t resources_cleaned = 0;
    std::chrono::steady_clock::time_point last_cleanup;
    
    ResourceStats() {
        auto now = std::chrono::steady_clock::now();
        last_pressure_event = now;
        last_cleanup = now;
    }
};

/**
 * Resource manager for DoS protection and system health
 */
class DTLS_API ResourceManager {
public:
    explicit ResourceManager(const ResourceConfig& config = ResourceConfig{});
    ~ResourceManager();
    
    // Non-copyable, movable
    ResourceManager(const ResourceManager&) = delete;
    ResourceManager& operator=(const ResourceManager&) = delete;
    ResourceManager(ResourceManager&&) noexcept = default;
    ResourceManager& operator=(ResourceManager&&) noexcept = default;
    
    /**
     * Allocate resources for a new connection
     * @param source_address Source IP address
     * @param memory_estimate Estimated memory usage
     * @return Allocation result and unique allocation ID
     */
    Result<uint64_t> allocate_connection_resources(
        const NetworkAddress& source_address,
        size_t memory_estimate
    );
    
    /**
     * Allocate resources for a handshake
     * @param source_address Source IP address
     * @param memory_estimate Estimated memory usage
     * @return Allocation result and unique allocation ID
     */
    Result<uint64_t> allocate_handshake_resources(
        const NetworkAddress& source_address,
        size_t memory_estimate
    );
    
    /**
     * Allocate buffer memory
     * @param source_address Source IP address
     * @param buffer_size Buffer size needed
     * @return Allocation result and unique allocation ID
     */
    Result<uint64_t> allocate_buffer_memory(
        const NetworkAddress& source_address,
        size_t buffer_size
    );
    
    /**
     * Release allocated resources
     * @param allocation_id Allocation ID to release
     */
    Result<void> release_resources(uint64_t allocation_id);
    
    /**
     * Update resource activity (prevents cleanup)
     * @param allocation_id Allocation ID to update
     */
    Result<void> update_activity(uint64_t allocation_id);
    
    /**
     * Check if resource allocation would succeed
     * @param source_address Source IP address
     * @param type Resource type to check
     * @param amount Amount to allocate
     * @return True if allocation would succeed
     */
    bool can_allocate(const NetworkAddress& source_address,
                     ResourceType type,
                     size_t amount) const;
    
    /**
     * Get current resource pressure level
     */
    PressureLevel get_pressure_level() const;
    
    /**
     * Get memory usage percentage (0.0 to 1.0)
     */
    double get_memory_usage_percentage() const;
    
    /**
     * Get connection usage percentage (0.0 to 1.0)
     */
    double get_connection_usage_percentage() const;
    
    /**
     * Get resource statistics
     */
    ResourceStats get_resource_stats() const;
    
    /**
     * Get per-source resource usage
     * @param source_address Source IP address
     * @return Source resource summary or error if not found
     */
    struct SourceResourceSummary {
        size_t total_memory = 0;
        size_t connection_count = 0;
        size_t handshake_count = 0;
        size_t buffer_memory = 0;
        std::chrono::steady_clock::time_point first_allocation;
        std::chrono::steady_clock::time_point last_activity;
    };
    Result<SourceResourceSummary> get_source_usage(const NetworkAddress& source_address) const;
    
    /**
     * Force cleanup of idle resources
     * @param max_cleanup_count Maximum number of resources to cleanup
     * @return Number of resources cleaned up
     */
    size_t force_cleanup(size_t max_cleanup_count = 0);
    
    /**
     * Cleanup resources from specific source
     * @param source_address Source IP address
     * @return Number of resources cleaned up
     */
    size_t cleanup_source_resources(const NetworkAddress& source_address);
    
    /**
     * Check system health and trigger cleanup if needed
     * @return Current pressure level after cleanup
     */
    PressureLevel check_system_health();
    
    /**
     * Update configuration
     * @param new_config New resource configuration
     */
    Result<void> update_config(const ResourceConfig& new_config);
    
    /**
     * Get current configuration
     */
    const ResourceConfig& get_config() const { return config_; }
    
    /**
     * Enable/disable memory pressure monitoring
     * @param enabled True to enable monitoring
     */
    void set_memory_monitoring(bool enabled);
    
    /**
     * Get list of sources with high resource usage
     * @param threshold Usage threshold (0.0 to 1.0)
     * @return List of source addresses
     */
    std::vector<NetworkAddress> get_high_usage_sources(double threshold = 0.8) const;
    
    /**
     * Reset all resource tracking
     */
    void reset();

private:
    // Helper methods
    SourceResourceData* get_or_create_source_data(const NetworkAddress& source_address);
    SourceResourceData* get_source_data(const NetworkAddress& source_address) const;
    uint64_t generate_allocation_id();
    std::string address_to_key(const NetworkAddress& address) const;
    bool check_memory_limits(const std::string& source_key, size_t additional_memory) const;
    bool check_connection_limits(const std::string& source_key, ResourceType type) const;
    void update_pressure_level();
    size_t cleanup_expired_allocations();
    size_t cleanup_inactive_sources();
    void record_allocation_failure(ResourceResult reason);
    
    // Configuration
    ResourceConfig config_;
    
    // Resource tracking
    std::unordered_map<uint64_t, std::unique_ptr<ResourceAllocation>> allocations_;
    std::unordered_map<std::string, std::unique_ptr<SourceResourceData>> source_data_;
    mutable std::shared_mutex allocations_mutex_;
    mutable std::shared_mutex source_data_mutex_;
    
    // System statistics
    mutable ResourceStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Allocation ID generation
    std::atomic<uint64_t> next_allocation_id_{1};
    
    // Memory tracking
    std::atomic<size_t> total_allocated_memory_{0};
    std::atomic<size_t> connection_memory_{0};
    std::atomic<size_t> handshake_memory_{0};
    std::atomic<size_t> buffer_memory_{0};
    
    // Connection tracking
    std::atomic<size_t> total_connections_{0};
    std::atomic<size_t> pending_handshakes_{0};
    
    // Pressure monitoring
    std::atomic<PressureLevel> current_pressure_{PressureLevel::NORMAL};
    std::atomic<bool> memory_monitoring_enabled_{true};
    
    // Cleanup management
    std::atomic<std::chrono::steady_clock::time_point> last_cleanup_;
    std::atomic<std::chrono::steady_clock::time_point> last_health_check_;
};

/**
 * Resource manager factory for different deployment scenarios
 */
class ResourceManagerFactory {
public:
    /**
     * Create resource manager for development/testing (generous limits)
     */
    static std::unique_ptr<ResourceManager> create_development();
    
    /**
     * Create resource manager for production (balanced limits)
     */
    static std::unique_ptr<ResourceManager> create_production();
    
    /**
     * Create resource manager for embedded/low-memory systems (strict limits)
     */
    static std::unique_ptr<ResourceManager> create_embedded();
    
    /**
     * Create resource manager for high-capacity servers (high limits)
     */
    static std::unique_ptr<ResourceManager> create_high_capacity();
    
    /**
     * Create resource manager with custom configuration
     */
    static std::unique_ptr<ResourceManager> create_custom(const ResourceConfig& config);
};

/**
 * RAII resource guard for automatic cleanup
 */
class ResourceGuard {
public:
    ResourceGuard(ResourceManager* manager, uint64_t allocation_id);
    ~ResourceGuard();
    
    // Non-copyable, movable
    ResourceGuard(const ResourceGuard&) = delete;
    ResourceGuard& operator=(const ResourceGuard&) = delete;
    ResourceGuard(ResourceGuard&& other) noexcept;
    ResourceGuard& operator=(ResourceGuard&& other) noexcept;
    
    /**
     * Release the resource early
     */
    void release();
    
    /**
     * Get allocation ID
     */
    uint64_t get_allocation_id() const { return allocation_id_; }
    
    /**
     * Check if resource is still held
     */
    bool is_active() const { return manager_ != nullptr && allocation_id_ != 0; }

private:
    ResourceManager* manager_;
    uint64_t allocation_id_;
};

}  // namespace security
}  // namespace v13
}  // namespace dtls