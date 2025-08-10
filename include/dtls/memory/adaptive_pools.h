#ifndef DTLS_MEMORY_ADAPTIVE_POOLS_H
#define DTLS_MEMORY_ADAPTIVE_POOLS_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/pool.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <algorithm>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Advanced adaptive memory pool system for DTLS v1.3
 * 
 * This system provides intelligent memory pool management with:
 * - Dynamic sizing based on usage patterns
 * - Predictive allocation based on connection patterns  
 * - Memory pressure adaptation
 * - Performance optimization for high-concurrency scenarios
 * - Automatic pool lifecycle management
 */

// Pool usage pattern analysis
struct PoolUsagePattern {
    size_t buffer_size{0};
    
    // Usage statistics
    double allocation_rate{0.0};        // Allocations per second
    double deallocation_rate{0.0};      // Deallocations per second
    double peak_concurrent_usage{0.0};  // Peak simultaneous allocations
    double average_lifetime{0.0};       // Average buffer lifetime in seconds
    
    // Trend analysis
    bool is_growing{false};              // Usage trend
    bool is_volatile{false};             // High variance in usage
    double growth_rate{0.0};             // Rate of growth/decline
    
    // Timing patterns
    std::chrono::steady_clock::time_point peak_time;  // When peak usage occurred
    std::vector<double> hourly_patterns;               // Usage patterns by hour
    
    // Quality metrics
    double hit_rate{0.0};                // Successful pool allocations / total requests
    double fragmentation_ratio{0.0};     // Internal fragmentation
    double efficiency_score{0.0};        // Overall pool efficiency
};

// Adaptive pool sizing algorithms
class DTLS_API AdaptivePoolSizer {
public:
    // Sizing algorithms
    enum class Algorithm {
        CONSERVATIVE,    // Minimal sizing with slow growth
        BALANCED,       // Balance between memory usage and performance
        AGGRESSIVE,     // Optimize for performance over memory
        PREDICTIVE,     // Use machine learning for prediction
        CUSTOM          // User-defined algorithm
    };
    
    // Sizing configuration
    struct SizingConfig {
        Algorithm algorithm{Algorithm::BALANCED};
        double growth_factor{1.5};          // Multiplier for pool expansion
        double shrink_threshold{0.3};       // Utilization below which to shrink
        double expand_threshold{0.8};       // Utilization above which to expand
        size_t min_pool_size{4};           // Minimum pool size
        size_t max_pool_size{256};         // Maximum pool size
        std::chrono::minutes adaptation_window{15};  // Time window for adaptation
        bool enable_predictive_sizing{true}; // Enable predictive algorithms
    };
    
    explicit AdaptivePoolSizer(const SizingConfig& config = SizingConfig{});
    
    // Sizing decisions
    size_t calculate_optimal_size(const PoolUsagePattern& pattern) const;
    bool should_expand_pool(const PoolUsagePattern& pattern, size_t current_size) const;
    bool should_shrink_pool(const PoolUsagePattern& pattern, size_t current_size) const;
    
    // Prediction
    size_t predict_future_size(const PoolUsagePattern& pattern, 
                              std::chrono::minutes time_horizon) const;
    
    // Configuration
    void set_config(const SizingConfig& config) { config_ = config; }
    const SizingConfig& get_config() const { return config_; }

private:
    SizingConfig config_;
    
    size_t calculate_conservative_size(const PoolUsagePattern& pattern) const;
    size_t calculate_balanced_size(const PoolUsagePattern& pattern) const;
    size_t calculate_aggressive_size(const PoolUsagePattern& pattern) const;
    size_t calculate_predictive_size(const PoolUsagePattern& pattern) const;
};

// Enhanced buffer pool with adaptive sizing
class DTLS_API AdaptiveBufferPool : public BufferPool {
public:
    AdaptiveBufferPool(size_t buffer_size, size_t initial_pool_size = 16,
                      const AdaptivePoolSizer::SizingConfig& config = {});
    
    // Enhanced pool operations
    std::unique_ptr<ZeroCopyBuffer> acquire() override;
    void release(std::unique_ptr<ZeroCopyBuffer> buffer) override;
    
    // Adaptive management
    void update_usage_statistics();
    void adapt_pool_size();
    void force_adaptation();
    
    // Pattern analysis
    PoolUsagePattern get_usage_pattern() const;
    void reset_usage_pattern();
    
    // Performance monitoring
    struct PerformanceMetrics {
        std::chrono::nanoseconds average_acquire_time{0};
        std::chrono::nanoseconds average_release_time{0};
        double contention_ratio{0.0};     // Lock contention percentage
        size_t cache_misses{0};           // Pool misses requiring new allocation
        size_t adaptations_performed{0};  // Number of size adaptations
    };
    
    PerformanceMetrics get_performance_metrics() const;
    void reset_performance_metrics();
    
    // Configuration
    void set_auto_adaptation(bool enabled) { auto_adaptation_enabled_ = enabled; }
    bool is_auto_adaptation_enabled() const { return auto_adaptation_enabled_.load(); }
    
    void set_adaptation_interval(std::chrono::seconds interval) { adaptation_interval_ = interval; }
    std::chrono::seconds get_adaptation_interval() const { return adaptation_interval_; }

private:
    AdaptivePoolSizer sizer_;
    
    // Usage tracking
    mutable std::mutex usage_mutex_;
    PoolUsagePattern current_pattern_;
    std::vector<std::chrono::steady_clock::time_point> allocation_timestamps_;
    std::vector<std::chrono::steady_clock::time_point> deallocation_timestamps_;
    std::vector<std::chrono::nanoseconds> buffer_lifetimes_;
    
    // Performance tracking
    mutable std::mutex perf_mutex_;
    PerformanceMetrics performance_metrics_;
    std::vector<std::chrono::nanoseconds> acquire_times_;
    std::vector<std::chrono::nanoseconds> release_times_;
    
    // Adaptive behavior
    std::atomic<bool> auto_adaptation_enabled_{true};
    std::atomic<std::chrono::steady_clock::time_point> last_adaptation_;
    std::chrono::seconds adaptation_interval_{30};
    
    // Internal methods
    void record_allocation();
    void record_deallocation();
    void record_buffer_lifetime(std::chrono::nanoseconds lifetime);
    void update_performance_metrics(std::chrono::nanoseconds acquire_time,
                                   std::chrono::nanoseconds release_time);
    void calculate_usage_rates();
    void analyze_usage_trends();
    void cleanup_old_timestamps();
};

// Global adaptive pool manager
class DTLS_API AdaptivePoolManager {
public:
    static AdaptivePoolManager& instance();
    
    // Pool management
    AdaptiveBufferPool& get_adaptive_pool(size_t buffer_size);
    Result<void> create_adaptive_pool(size_t buffer_size, size_t initial_size,
                                     const AdaptivePoolSizer::SizingConfig& config = {});
    void remove_adaptive_pool(size_t buffer_size);
    
    // Global adaptation
    void adapt_all_pools();
    void force_adapt_all_pools();
    
    // Global configuration
    void set_global_adaptation_config(const AdaptivePoolSizer::SizingConfig& config);
    AdaptivePoolSizer::SizingConfig get_global_adaptation_config() const;
    
    // System-wide statistics
    struct SystemStats {
        size_t total_pools{0};
        size_t total_buffers{0};
        size_t total_memory_usage{0};
        double average_hit_rate{0.0};
        double average_efficiency{0.0};
        size_t total_adaptations{0};
        std::chrono::steady_clock::time_point last_global_adaptation;
    };
    
    SystemStats get_system_statistics() const;
    
    // Automatic adaptation control
    void enable_global_adaptation(bool enabled);
    bool is_global_adaptation_enabled() const { return global_adaptation_enabled_.load(); }
    
    void start_adaptation_thread();
    void stop_adaptation_thread();
    
    // Memory pressure integration
    void handle_memory_pressure();
    void handle_memory_relief();

private:
    AdaptivePoolManager() = default;
    ~AdaptivePoolManager();
    
    mutable std::mutex pools_mutex_;
    std::unordered_map<size_t, std::unique_ptr<AdaptiveBufferPool>> adaptive_pools_;
    
    AdaptivePoolSizer::SizingConfig global_config_;
    std::atomic<bool> global_adaptation_enabled_{true};
    
    // Adaptation thread
    std::unique_ptr<std::thread> adaptation_thread_;
    std::atomic<bool> adaptation_thread_running_{false};
    
    void adaptation_thread_loop();
};

// Connection-aware pool allocation
class DTLS_API ConnectionAwarePoolManager {
public:
    static ConnectionAwarePoolManager& instance();
    
    // Connection lifecycle integration
    void register_connection(void* connection_id, size_t expected_throughput);
    void update_connection_usage(void* connection_id, size_t bytes_allocated);
    void unregister_connection(void* connection_id);
    
    // Connection-specific buffer allocation
    PooledBuffer allocate_for_connection(void* connection_id, size_t buffer_size);
    
    // Connection patterns
    struct ConnectionPattern {
        void* connection_id{nullptr};
        size_t total_bytes_allocated{0};
        size_t peak_concurrent_buffers{0};
        std::chrono::steady_clock::time_point creation_time;
        std::chrono::steady_clock::time_point last_activity;
        std::vector<size_t> buffer_size_preferences;
        double activity_score{0.0};
    };
    
    std::vector<ConnectionPattern> get_connection_patterns() const;
    
    // Predictive allocation
    void pre_allocate_for_connections(size_t expected_connections);
    size_t predict_buffer_needs(std::chrono::minutes time_window) const;

private:
    ConnectionAwarePoolManager() = default;
    
    mutable std::mutex connections_mutex_;
    std::unordered_map<void*, ConnectionPattern> active_connections_;
    
    void update_connection_pattern(void* connection_id, size_t buffer_size);
    size_t estimate_connection_needs(const ConnectionPattern& pattern) const;
};

// High-performance pool optimizations
class DTLS_API HighPerformancePoolOptimizer {
public:
    static HighPerformancePoolOptimizer& instance();
    
    // Lock-free optimizations
    void enable_lock_free_pools(bool enabled);
    bool are_lock_free_pools_enabled() const;
    
    // NUMA awareness
    void enable_numa_awareness(bool enabled);
    bool is_numa_awareness_enabled() const;
    
    // Thread-local pool caching
    void enable_thread_local_caching(bool enabled, size_t cache_size = 16);
    bool is_thread_local_caching_enabled() const;
    
    // CPU cache optimizations
    void optimize_for_cpu_cache();
    void set_cache_line_alignment(bool enabled);
    
    // Performance profiling
    struct OptimizationReport {
        bool lock_contention_detected{false};
        double average_wait_time{0.0};
        size_t false_sharing_events{0};
        size_t cache_misses{0};
        std::vector<std::string> recommendations;
    };
    
    OptimizationReport analyze_performance() const;
    void apply_optimizations(const OptimizationReport& report);

private:
    HighPerformancePoolOptimizer() = default;
    
    std::atomic<bool> lock_free_enabled_{false};
    std::atomic<bool> numa_aware_{false};
    std::atomic<bool> thread_caching_enabled_{false};
    std::atomic<size_t> thread_cache_size_{16};
};

// Factory functions for adaptive pools
DTLS_API AdaptiveBufferPool& get_adaptive_pool(size_t buffer_size);
DTLS_API PooledBuffer make_adaptive_buffer(size_t size);
DTLS_API void configure_adaptive_pools(const AdaptivePoolSizer::SizingConfig& config = {});
DTLS_API void enable_adaptive_sizing(bool enabled = true);
DTLS_API void optimize_pools_for_high_concurrency();

// Configuration presets
namespace presets {
    DTLS_API AdaptivePoolSizer::SizingConfig conservative_config();
    DTLS_API AdaptivePoolSizer::SizingConfig balanced_config();
    DTLS_API AdaptivePoolSizer::SizingConfig aggressive_config();
    DTLS_API AdaptivePoolSizer::SizingConfig high_throughput_config();
    DTLS_API AdaptivePoolSizer::SizingConfig low_memory_config();
}

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_ADAPTIVE_POOLS_H