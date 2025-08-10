#ifndef DTLS_MEMORY_LEAK_DETECTION_H
#define DTLS_MEMORY_LEAK_DETECTION_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <atomic>
#include <mutex>
#include <thread>
#include <functional>
#include <vector>
#include <string>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Comprehensive resource leak detection and cleanup system
 * 
 * This system tracks all resource allocations, detects potential leaks,
 * provides automatic cleanup capabilities, and generates detailed reports
 * for debugging memory issues in DTLS v1.3 implementations.
 */

// Resource types that can be tracked
enum class ResourceType {
    BUFFER,
    CONNECTION,
    CRYPTO_KEY,
    CRYPTO_CONTEXT,
    SSL_SESSION,
    CERTIFICATE,
    HANDSHAKE_STATE,
    RECORD_LAYER_STATE,
    TIMER,
    SOCKET,
    THREAD,
    MEMORY_POOL,
    OTHER
};

// Resource information for tracking
struct ResourceInfo {
    void* resource_ptr{nullptr};
    ResourceType type{ResourceType::OTHER};
    size_t size{0};
    std::string allocation_site;  // File:line or function name
    std::thread::id thread_id;
    std::chrono::steady_clock::time_point allocation_time;
    std::chrono::steady_clock::time_point last_access_time;
    std::string description;
    bool is_critical{false};  // Critical resources need immediate cleanup
    uint64_t access_count{0};
    
    // Additional metadata
    std::unordered_map<std::string, std::string> metadata;
};

// Leak detection thresholds and configuration
struct LeakDetectionConfig {
    std::chrono::minutes max_resource_age{60};  // Resources older than this are suspicious
    std::chrono::minutes critical_resource_age{10};  // Critical resources older than this are leaks
    size_t max_resources_per_type{1000};  // Max resources of each type before warning
    size_t max_total_resources{10000};  // Max total resources before warning
    bool enable_automatic_cleanup{true};  // Enable automatic cleanup of detected leaks
    bool enable_stack_traces{false};  // Enable stack trace collection (expensive)
    bool enable_periodic_checks{true};  // Enable periodic leak detection
    std::chrono::seconds check_interval{30};  // How often to check for leaks
    double memory_growth_threshold{0.2};  // 20% growth triggers leak check
};

// Comprehensive leak detection system
class DTLS_API LeakDetector {
public:
    static LeakDetector& instance();
    
    // Resource tracking
    void track_resource(void* resource_ptr, ResourceType type, size_t size, 
                       const std::string& allocation_site, const std::string& description = "");
    void update_resource_access(void* resource_ptr);
    void untrack_resource(void* resource_ptr);
    
    // Resource management
    bool is_resource_tracked(void* resource_ptr) const;
    ResourceInfo get_resource_info(void* resource_ptr) const;
    void set_resource_critical(void* resource_ptr, bool critical);
    void add_resource_metadata(void* resource_ptr, const std::string& key, const std::string& value);
    
    // Leak detection
    struct LeakReport {
        size_t total_leaks{0};
        size_t critical_leaks{0};
        size_t total_leaked_memory{0};
        std::vector<ResourceInfo> leaked_resources;
        std::unordered_map<ResourceType, size_t> leaks_by_type;
        std::chrono::steady_clock::time_point detection_time;
        std::chrono::milliseconds detection_duration{0};
    };
    
    Result<LeakReport> detect_leaks();
    Result<LeakReport> detect_leaks_for_type(ResourceType type);
    
    // Automatic cleanup
    using CleanupCallback = std::function<bool(const ResourceInfo&)>;
    void register_cleanup_callback(ResourceType type, CleanupCallback callback);
    void unregister_cleanup_callback(ResourceType type);
    
    size_t cleanup_leaked_resources();
    size_t cleanup_resources_of_type(ResourceType type);
    size_t cleanup_old_resources(std::chrono::minutes max_age);
    
    // Configuration
    void set_config(const LeakDetectionConfig& config);
    LeakDetectionConfig get_config() const;
    void enable_detection(bool enabled) { detection_enabled_ = enabled; }
    bool is_detection_enabled() const { return detection_enabled_.load(); }
    
    // Statistics and monitoring
    struct DetectionStats {
        size_t total_resources_tracked{0};
        size_t resources_by_type[static_cast<size_t>(ResourceType::OTHER) + 1]{0};
        size_t total_leaks_detected{0};
        size_t total_resources_cleaned{0};
        size_t total_cleanup_failures{0};
        std::chrono::steady_clock::time_point last_detection_time;
        std::chrono::milliseconds average_detection_time{0};
        size_t detection_runs{0};
    };
    
    DetectionStats get_statistics() const;
    void reset_statistics();
    
    // Periodic detection control
    void start_periodic_detection();
    void stop_periodic_detection();
    bool is_periodic_detection_active() const { return periodic_thread_running_.load(); }
    
    // Manual validation
    Result<void> validate_all_resources();
    Result<void> validate_resources_of_type(ResourceType type);
    
    // Reporting
    std::string generate_leak_report(const LeakReport& report) const;
    std::string generate_resource_summary() const;
    void dump_all_resources() const;
    
private:
    LeakDetector() = default;
    ~LeakDetector();
    
    mutable std::mutex resources_mutex_;
    std::unordered_map<void*, ResourceInfo> tracked_resources_;
    
    mutable std::mutex config_mutex_;
    LeakDetectionConfig config_;
    
    mutable std::mutex stats_mutex_;
    DetectionStats stats_;
    
    mutable std::mutex callbacks_mutex_;
    std::unordered_map<ResourceType, CleanupCallback> cleanup_callbacks_;
    
    std::atomic<bool> detection_enabled_{true};
    std::atomic<bool> periodic_thread_running_{false};
    std::unique_ptr<std::thread> periodic_thread_;
    
    // Internal methods
    void periodic_detection_loop();
    bool is_resource_leaked(const ResourceInfo& info, std::chrono::steady_clock::time_point now) const;
    bool cleanup_resource(const ResourceInfo& info);
    void update_statistics(const LeakReport& report, std::chrono::milliseconds detection_time);
    std::string resource_type_to_string(ResourceType type) const;
};

// RAII resource tracker for automatic tracking
template<typename T>
class DTLS_API ResourceTracker {
public:
    ResourceTracker(T* resource, ResourceType type, size_t size, 
                   const std::string& allocation_site, const std::string& description = "")
        : resource_(resource), tracked_(resource != nullptr) {
        if (tracked_) {
            LeakDetector::instance().track_resource(resource, type, size, allocation_site, description);
        }
    }
    
    ~ResourceTracker() {
        if (tracked_ && resource_) {
            LeakDetector::instance().untrack_resource(resource_);
        }
    }
    
    // Non-copyable, movable
    ResourceTracker(const ResourceTracker&) = delete;
    ResourceTracker& operator=(const ResourceTracker&) = delete;
    
    ResourceTracker(ResourceTracker&& other) noexcept 
        : resource_(other.resource_), tracked_(other.tracked_) {
        other.resource_ = nullptr;
        other.tracked_ = false;
    }
    
    ResourceTracker& operator=(ResourceTracker&& other) noexcept {
        if (this != &other) {
            if (tracked_ && resource_) {
                LeakDetector::instance().untrack_resource(resource_);
            }
            resource_ = other.resource_;
            tracked_ = other.tracked_;
            other.resource_ = nullptr;
            other.tracked_ = false;
        }
        return *this;
    }
    
    T* get() const { return resource_; }
    T* operator->() const { return resource_; }
    T& operator*() const { return *resource_; }
    
    void update_access() {
        if (tracked_ && resource_) {
            LeakDetector::instance().update_resource_access(resource_);
        }
    }
    
    T* release() {
        if (tracked_ && resource_) {
            LeakDetector::instance().untrack_resource(resource_);
            tracked_ = false;
        }
        T* result = resource_;
        resource_ = nullptr;
        return result;
    }

private:
    T* resource_;
    bool tracked_;
};

// Resource cleanup utilities
class DTLS_API ResourceCleanupManager {
public:
    static ResourceCleanupManager& instance();
    
    // Partial cleanup for memory pressure situations
    size_t cleanup_non_critical_resources();
    size_t cleanup_old_resources(std::chrono::minutes max_age);
    size_t cleanup_unused_resources(std::chrono::minutes max_idle_time);
    
    // Emergency cleanup
    size_t emergency_cleanup();
    
    // Resource validation and repair
    Result<size_t> validate_and_repair_resources();
    
    // Cleanup policies
    enum class CleanupPolicy {
        CONSERVATIVE,  // Only clean obviously leaked resources
        MODERATE,      // Clean resources based on age and usage
        AGGRESSIVE     // Clean all old resources
    };
    
    void set_cleanup_policy(CleanupPolicy policy) { cleanup_policy_ = policy; }
    CleanupPolicy get_cleanup_policy() const { return cleanup_policy_; }
    
    // Resource lifecycle callbacks
    using ResourceCallback = std::function<void(const ResourceInfo&)>;
    void register_resource_created_callback(ResourceCallback callback);
    void register_resource_destroyed_callback(ResourceCallback callback);
    
private:
    ResourceCleanupManager() = default;
    ~ResourceCleanupManager() = default;
    
    CleanupPolicy cleanup_policy_{CleanupPolicy::MODERATE};
    std::vector<ResourceCallback> creation_callbacks_;
    std::vector<ResourceCallback> destruction_callbacks_;
    mutable std::mutex callbacks_mutex_;
    
    bool should_cleanup_resource(const ResourceInfo& info, CleanupPolicy policy) const;
};

// Convenience macros for resource tracking
#define DTLS_TRACK_RESOURCE(ptr, type, size, desc) \
    dtls::v13::memory::LeakDetector::instance().track_resource(ptr, type, size, __FILE__ ":" DTLS_STRINGIFY(__LINE__), desc)

#define DTLS_UNTRACK_RESOURCE(ptr) \
    dtls::v13::memory::LeakDetector::instance().untrack_resource(ptr)

#define DTLS_UPDATE_RESOURCE_ACCESS(ptr) \
    dtls::v13::memory::LeakDetector::instance().update_resource_access(ptr)

#define DTLS_MAKE_RESOURCE_TRACKER(var, ptr, type, size, desc) \
    auto var = dtls::v13::memory::ResourceTracker<std::remove_pointer_t<decltype(ptr)>>( \
        ptr, type, size, __FILE__ ":" DTLS_STRINGIFY(__LINE__), desc)

// Utility functions
DTLS_API void enable_leak_detection(bool enabled = true);
DTLS_API bool is_leak_detection_enabled();
DTLS_API size_t get_tracked_resource_count();
DTLS_API size_t cleanup_all_leaked_resources();
DTLS_API std::string generate_resource_report();

// Default cleanup callbacks for common resource types
DTLS_API void register_default_cleanup_callbacks();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_LEAK_DETECTION_H