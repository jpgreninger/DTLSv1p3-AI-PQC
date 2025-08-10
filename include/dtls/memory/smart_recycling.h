#ifndef DTLS_MEMORY_SMART_RECYCLING_H
#define DTLS_MEMORY_SMART_RECYCLING_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/pool.h>
#include <memory>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Advanced buffer recycling system for DTLS v1.3
 * 
 * This system tracks buffer usage patterns, analyzes memory access,
 * and intelligently optimizes buffer allocation and recycling strategies
 * for maximum performance and minimal memory overhead.
 */

// Advanced buffer recycling management
class DTLS_API BufferRecyclingManager {
public:
    static BufferRecyclingManager& instance();
    
    // Buffer lifecycle tracking
    void track_buffer_usage(size_t buffer_size, std::chrono::steady_clock::time_point access_time);
    void register_buffer_death(size_t buffer_size, std::chrono::steady_clock::time_point death_time);
    
    // Smart recycling decisions
    bool should_recycle_buffer(size_t buffer_size) const;
    size_t get_optimal_pool_size(size_t buffer_size) const;
    
    // Usage pattern analysis
    struct BufferUsageStats {
        size_t buffer_size{0};
        size_t total_accesses{0};
        size_t recent_accesses{0};
        std::chrono::steady_clock::time_point last_access;
        std::chrono::milliseconds average_lifetime{0};
        double utilization_score{0.0};
        double access_frequency{0.0};
        bool is_trending_up{false};
    };
    
    std::vector<BufferUsageStats> get_usage_statistics() const;
    void optimize_pools_based_on_usage();
    
    // Memory pressure handling
    void handle_memory_pressure();
    void enable_aggressive_recycling(bool enabled) { aggressive_recycling_ = enabled; }
    bool is_aggressive_recycling_enabled() const { return aggressive_recycling_.load(); }
    
    // Configuration
    void set_recycling_threshold(double threshold) { recycling_threshold_ = threshold; }
    double get_recycling_threshold() const { return recycling_threshold_.load(); }
    void set_usage_window(std::chrono::minutes window) { usage_window_ = window; }
    std::chrono::minutes get_usage_window() const { return usage_window_; }
    
    // Statistics and monitoring
    struct RecyclingStats {
        size_t buffers_recycled{0};
        size_t buffers_created{0};
        size_t memory_saved{0};
        size_t pools_optimized{0};
        double average_utilization{0.0};
        std::chrono::steady_clock::time_point last_optimization;
    };
    
    RecyclingStats get_recycling_statistics() const;
    void reset_statistics();
    
private:
    BufferRecyclingManager();
    ~BufferRecyclingManager() = default;
    
    mutable std::mutex stats_mutex_;
    std::unordered_map<size_t, BufferUsageStats> usage_stats_;
    
    std::atomic<bool> aggressive_recycling_{false};
    std::atomic<double> recycling_threshold_{0.3};
    std::chrono::minutes usage_window_{30};
    
    // Internal statistics
    mutable std::mutex recycling_stats_mutex_;
    RecyclingStats recycling_stats_;
    
    void update_usage_stats(size_t buffer_size);
    double calculate_utilization_score(const BufferUsageStats& stats) const;
    void cleanup_old_stats();
    bool should_optimize_pools() const;
};

// Smart buffer factory with recycling intelligence
class DTLS_API SmartBufferFactory {
public:
    static SmartBufferFactory& instance();
    
    // Smart buffer creation with recycling
    PooledBuffer create_smart_buffer(size_t size);
    std::unique_ptr<ZeroCopyBuffer> create_optimized_buffer(size_t size);
    
    // Buffer type recommendations
    enum class BufferType {
        POOLED,      // Use pooled buffer
        DIRECT,      // Direct allocation
        SHARED       // Shared/reference-counted buffer
    };
    
    BufferType recommend_buffer_type(size_t size, bool likely_to_share = false) const;
    
    // Buffer sizing optimization
    size_t optimize_buffer_size(size_t requested_size) const;
    
    // Memory usage prediction
    size_t predict_memory_usage(size_t connection_count, std::chrono::minutes time_window) const;
    
    // Factory statistics
    struct FactoryStats {
        size_t pooled_buffers_created{0};
        size_t direct_buffers_created{0};
        size_t shared_buffers_created{0};
        size_t optimizations_applied{0};
        size_t memory_saved_by_optimization{0};
        double hit_rate{0.0};
    };
    
    FactoryStats get_factory_statistics() const;
    void reset_statistics();
    
    // Configuration
    void enable_size_optimization(bool enabled) { size_optimization_enabled_ = enabled; }
    bool is_size_optimization_enabled() const { return size_optimization_enabled_.load(); }
    
    void set_optimization_threshold(double threshold) { optimization_threshold_ = threshold; }
    double get_optimization_threshold() const { return optimization_threshold_.load(); }
    
private:
    SmartBufferFactory() = default;
    ~SmartBufferFactory() = default;
    
    BufferType analyze_usage_pattern(size_t size) const;
    size_t round_to_optimal_size(size_t size) const;
    bool should_use_shared_buffer(size_t size, bool likely_to_share) const;
    
    std::atomic<bool> size_optimization_enabled_{true};
    std::atomic<double> optimization_threshold_{0.15}; // 15% threshold
    
    mutable std::mutex factory_stats_mutex_;
    FactoryStats factory_stats_;
};

// Memory pressure detector and handler
class DTLS_API MemoryPressureDetector {
public:
    static MemoryPressureDetector& instance();
    
    // Memory pressure levels
    enum class PressureLevel {
        NONE,       // Normal operation
        LOW,        // Minor pressure, start optimization
        MEDIUM,     // Moderate pressure, aggressive recycling
        HIGH,       // High pressure, emergency cleanup
        CRITICAL    // Critical pressure, emergency measures
    };
    
    // Pressure detection
    PressureLevel detect_memory_pressure() const;
    void update_memory_statistics(size_t current_usage, size_t available_memory);
    
    // Pressure handling callbacks
    using PressureCallback = std::function<void(PressureLevel)>;
    void register_pressure_callback(const std::string& name, PressureCallback callback);
    void unregister_pressure_callback(const std::string& name);
    
    // Configuration
    void set_pressure_thresholds(double low, double medium, double high, double critical);
    struct PressureThresholds {
        double low{0.7};      // 70% memory usage
        double medium{0.8};   // 80% memory usage
        double high{0.9};     // 90% memory usage
        double critical{0.95}; // 95% memory usage
    };
    
    PressureThresholds get_pressure_thresholds() const;
    
    // Monitoring
    struct PressureStats {
        PressureLevel current_level{PressureLevel::NONE};
        size_t current_memory_usage{0};
        size_t available_memory{0};
        double usage_ratio{0.0};
        size_t pressure_events{0};
        std::chrono::steady_clock::time_point last_pressure_event;
    };
    
    PressureStats get_pressure_statistics() const;
    
    // Auto-monitoring
    void enable_auto_monitoring(bool enabled) { auto_monitoring_enabled_ = enabled; }
    bool is_auto_monitoring_enabled() const { return auto_monitoring_enabled_.load(); }
    void set_monitoring_interval(std::chrono::seconds interval) { monitoring_interval_ = interval; }
    
private:
    MemoryPressureDetector() = default;
    ~MemoryPressureDetector() = default;
    
    mutable std::mutex pressure_mutex_;
    PressureThresholds thresholds_;
    PressureStats current_stats_;
    
    std::unordered_map<std::string, PressureCallback> pressure_callbacks_;
    
    std::atomic<bool> auto_monitoring_enabled_{false};
    std::chrono::seconds monitoring_interval_{5}; // 5 seconds default
    
    void trigger_pressure_callbacks(PressureLevel level);
    PressureLevel calculate_pressure_level(double usage_ratio) const;
};

// Smart factory functions with recycling intelligence
DTLS_API PooledBuffer make_smart_buffer(size_t size);
DTLS_API std::unique_ptr<ZeroCopyBuffer> make_optimized_buffer(size_t size);

// Pool configuration with smart recycling
DTLS_API void configure_smart_pools();
DTLS_API void enable_smart_recycling(bool enabled = true);
DTLS_API void optimize_all_pools();

// Memory pressure management
DTLS_API void enable_memory_pressure_monitoring(bool enabled = true);
DTLS_API MemoryPressureDetector::PressureLevel get_current_memory_pressure();
DTLS_API void handle_memory_pressure();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_SMART_RECYCLING_H