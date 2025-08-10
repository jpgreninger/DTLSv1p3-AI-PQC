#ifndef DTLS_MEMORY_CONNECTION_POOLS_H
#define DTLS_MEMORY_CONNECTION_POOLS_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/pool.h>
#include <dtls/memory/adaptive_pools.h>
#include <memory>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Per-Connection Memory Optimization for DTLS v1.3
 * 
 * This system provides connection-specific memory management to minimize
 * overhead and optimize allocation patterns based on individual connection
 * characteristics, usage patterns, and lifecycle requirements.
 */

// Forward declarations
class ConnectionPool;
class ConnectionMemoryManager;
class PerConnectionOptimizer;

// Connection characteristics and patterns
struct ConnectionCharacteristics {
    void* connection_id{nullptr};
    
    // Basic connection info
    std::chrono::steady_clock::time_point creation_time;
    std::chrono::steady_clock::time_point last_activity;
    bool is_active{true};
    
    // Traffic patterns
    size_t total_bytes_sent{0};
    size_t total_bytes_received{0};
    size_t peak_concurrent_buffers{0};
    size_t average_message_size{0};
    double message_frequency{0.0}; // Messages per second
    
    // Buffer usage patterns
    std::vector<size_t> preferred_buffer_sizes;
    std::unordered_map<size_t, size_t> buffer_size_usage; // size -> count
    size_t total_allocations{0};
    size_t failed_allocations{0};
    
    // Performance characteristics
    std::chrono::nanoseconds average_allocation_time{0};
    std::chrono::nanoseconds average_release_time{0};
    double allocation_success_rate{1.0};
    
    // Connection type hints
    enum class ConnectionType {
        UNKNOWN,
        LOW_LATENCY,     // Real-time applications
        HIGH_THROUGHPUT, // Bulk data transfer
        INTERACTIVE,     // Web browsing, etc.
        STREAMING,       // Video/audio streaming
        IOT_SENSOR      // IoT device communications
    } type{ConnectionType::UNKNOWN};
    
    // Quality of Service requirements
    struct QoSRequirements {
        std::chrono::milliseconds max_latency{100};
        double min_throughput{0.0}; // bytes/sec
        bool requires_low_jitter{false};
        bool memory_constrained{false};
    } qos_requirements;
};

// Per-connection buffer pool
class DTLS_API ConnectionPool {
public:
    ConnectionPool(void* connection_id, const ConnectionCharacteristics& characteristics);
    ~ConnectionPool();
    
    // Buffer operations optimized for this connection
    std::unique_ptr<ZeroCopyBuffer> acquire_buffer(size_t size);
    void release_buffer(std::unique_ptr<ZeroCopyBuffer> buffer);
    
    // Specialized buffer types
    std::unique_ptr<ZeroCopyBuffer> acquire_message_buffer();    // For typical message size
    std::unique_ptr<ZeroCopyBuffer> acquire_header_buffer();     // For DTLS headers
    std::unique_ptr<ZeroCopyBuffer> acquire_payload_buffer();    // For payload data
    std::unique_ptr<ZeroCopyBuffer> acquire_crypto_buffer();     // For crypto operations
    
    // Pool management
    void optimize_for_characteristics();
    void adapt_to_usage_pattern();
    void prepare_for_burst_traffic();
    void scale_down_for_idle();
    
    // Statistics and monitoring
    struct PoolStats {
        size_t total_buffers_allocated{0};
        size_t buffers_in_use{0};
        size_t pool_hits{0};
        size_t pool_misses{0};
        double hit_rate{0.0};
        size_t memory_footprint{0};
        std::chrono::nanoseconds average_acquire_time{0};
        std::chrono::nanoseconds average_release_time{0};
        size_t adaptations_performed{0};
    };
    
    PoolStats get_statistics() const;
    void reset_statistics();
    
    // Configuration
    void set_optimization_level(int level); // 0=minimal, 5=aggressive
    void enable_predictive_allocation(bool enabled);
    void set_memory_limit(size_t max_bytes);
    
    // Connection lifecycle integration
    void on_connection_established();
    void on_handshake_completed();
    void on_data_transfer_started();
    void on_connection_idle();
    void on_connection_closing();

private:
    void* connection_id_;
    ConnectionCharacteristics characteristics_;
    
    // Per-connection pools for different buffer sizes
    std::unordered_map<size_t, std::unique_ptr<BufferPool>> size_specific_pools_;
    
    // Specialized pools
    std::unique_ptr<BufferPool> message_pool_;   // Most common message size
    std::unique_ptr<BufferPool> header_pool_;    // DTLS header size (~25 bytes)
    std::unique_ptr<BufferPool> payload_pool_;   // Common payload sizes
    std::unique_ptr<BufferPool> crypto_pool_;    // Crypto operation buffers
    
    // Usage tracking
    mutable std::mutex usage_mutex_;
    PoolStats current_stats_;
    std::vector<std::chrono::steady_clock::time_point> allocation_times_;
    std::vector<std::chrono::nanoseconds> allocation_durations_;
    std::vector<std::chrono::nanoseconds> release_durations_;
    
    // Optimization state
    std::atomic<int> optimization_level_{3}; // Default: moderate optimization
    std::atomic<bool> predictive_enabled_{true};
    std::atomic<size_t> memory_limit_{1024 * 1024}; // 1MB default limit per connection
    std::atomic<size_t> current_memory_usage_{0};
    
    // Internal methods
    void create_specialized_pools();
    void update_usage_statistics();
    size_t calculate_optimal_pool_size(size_t buffer_size) const;
    bool should_create_dedicated_pool(size_t buffer_size) const;
    void cleanup_unused_pools();
    void predict_and_preallocate();
};

// Connection memory manager - coordinates multiple connection pools
class DTLS_API ConnectionMemoryManager {
public:
    static ConnectionMemoryManager& instance();
    
    // Connection lifecycle management
    Result<void> create_connection_pool(void* connection_id, 
                                       const ConnectionCharacteristics& characteristics);
    void destroy_connection_pool(void* connection_id);
    
    // Connection pool access
    ConnectionPool* get_connection_pool(void* connection_id);
    
    // Connection-aware allocation
    std::unique_ptr<ZeroCopyBuffer> allocate_for_connection(void* connection_id, size_t size);
    void deallocate_for_connection(void* connection_id, std::unique_ptr<ZeroCopyBuffer> buffer);
    
    // Batch operations for efficiency
    std::vector<std::unique_ptr<ZeroCopyBuffer>> allocate_batch_for_connection(
        void* connection_id, const std::vector<size_t>& sizes);
    void deallocate_batch_for_connection(void* connection_id, 
        std::vector<std::unique_ptr<ZeroCopyBuffer>> buffers);
    
    // System-wide optimization
    void optimize_all_connection_pools();
    void balance_memory_across_connections();
    void cleanup_inactive_connections(std::chrono::minutes max_idle_time);
    
    // Global statistics
    struct SystemStats {
        size_t total_connections{0};
        size_t active_connections{0};
        size_t total_memory_usage{0};
        size_t total_buffers_allocated{0};
        double average_hit_rate{0.0};
        size_t memory_optimizations_performed{0};
        std::chrono::steady_clock::time_point last_optimization;
    };
    
    SystemStats get_system_statistics() const;
    
    // Memory pressure handling
    void handle_memory_pressure();
    void handle_memory_relief();
    size_t reclaim_memory_from_connections(size_t target_bytes);
    
    // Configuration
    void set_global_memory_limit(size_t max_bytes);
    void set_per_connection_limit(size_t max_bytes);
    void enable_automatic_optimization(bool enabled);
    
    // Monitoring and debugging
    std::vector<ConnectionCharacteristics> get_all_connection_characteristics() const;
    std::string generate_memory_usage_report() const;
    void dump_connection_pool_states() const;

private:
    ConnectionMemoryManager() = default;
    ~ConnectionMemoryManager() = default;
    
    mutable std::mutex connections_mutex_;
    std::unordered_map<void*, std::unique_ptr<ConnectionPool>> connection_pools_;
    std::unordered_map<void*, ConnectionCharacteristics> connection_characteristics_;
    
    // Global limits and configuration
    std::atomic<size_t> global_memory_limit_{256 * 1024 * 1024}; // 256MB default
    std::atomic<size_t> per_connection_limit_{1024 * 1024};      // 1MB per connection
    std::atomic<bool> auto_optimization_enabled_{true};
    std::atomic<size_t> current_global_usage_{0};
    
    // System statistics
    mutable std::mutex stats_mutex_;
    SystemStats system_stats_;
    
    // Internal methods
    void update_connection_characteristics(void* connection_id);
    bool enforce_memory_limits(void* connection_id, size_t requested_size);
    void rebalance_connection_memory();
    void optimize_connection_pool(ConnectionPool* pool);
    size_t calculate_connection_priority(const ConnectionCharacteristics& chars) const;
};

// Per-connection optimizer - applies specific optimization strategies
class DTLS_API PerConnectionOptimizer {
public:
    explicit PerConnectionOptimizer(ConnectionPool* pool);
    
    // Optimization strategies
    void apply_low_latency_optimization();
    void apply_high_throughput_optimization();
    void apply_memory_constrained_optimization();
    void apply_interactive_optimization();
    void apply_streaming_optimization();
    void apply_iot_optimization();
    
    // Dynamic optimization
    void auto_optimize_based_on_patterns();
    void optimize_for_message_pattern(const std::vector<size_t>& message_sizes);
    void optimize_for_burst_pattern(size_t burst_size, std::chrono::milliseconds duration);
    
    // Buffer size optimization
    struct BufferSizeRecommendations {
        size_t optimal_message_buffer_size{1024};
        size_t optimal_header_buffer_size{32};
        size_t optimal_payload_buffer_size{8192};
        size_t optimal_crypto_buffer_size{256};
        std::vector<size_t> recommended_pool_sizes;
        size_t recommended_pool_depth{8};
    };
    
    BufferSizeRecommendations analyze_buffer_requirements() const;
    void apply_buffer_size_recommendations(const BufferSizeRecommendations& recommendations);
    
    // Memory layout optimization
    void optimize_memory_layout_for_cache_efficiency();
    void enable_numa_local_allocation(bool enabled);
    void set_preferred_numa_node(int node);
    
    // Performance analysis
    struct PerformanceAnalysis {
        double allocation_efficiency{0.0};
        double memory_utilization{0.0};
        double fragmentation_ratio{0.0};
        std::chrono::nanoseconds average_latency{0};
        size_t cache_miss_ratio{0};
        std::vector<std::string> optimization_recommendations;
    };
    
    PerformanceAnalysis analyze_performance() const;
    void apply_performance_recommendations(const PerformanceAnalysis& analysis);

private:
    ConnectionPool* pool_;
    
    void configure_pool_for_latency();
    void configure_pool_for_throughput();
    void configure_pool_for_memory_efficiency();
    void tune_pool_parameters();
};

// Connection-aware buffer allocation wrapper
class DTLS_API ConnectionBuffer {
public:
    ConnectionBuffer(void* connection_id, std::unique_ptr<ZeroCopyBuffer> buffer);
    ~ConnectionBuffer();
    
    // Move-only semantics
    ConnectionBuffer(const ConnectionBuffer&) = delete;
    ConnectionBuffer& operator=(const ConnectionBuffer&) = delete;
    ConnectionBuffer(ConnectionBuffer&& other) noexcept;
    ConnectionBuffer& operator=(ConnectionBuffer&& other) noexcept;
    
    // Buffer access
    ZeroCopyBuffer* get() const noexcept { return buffer_.get(); }
    ZeroCopyBuffer* operator->() const noexcept { return buffer_.get(); }
    ZeroCopyBuffer& operator*() const noexcept { return *buffer_; }
    
    // Ownership transfer
    std::unique_ptr<ZeroCopyBuffer> release();
    
    // Connection association
    void* get_connection_id() const noexcept { return connection_id_; }

private:
    void* connection_id_;
    std::unique_ptr<ZeroCopyBuffer> buffer_;
};

// Factory functions for connection-aware allocation
DTLS_API Result<void> create_connection_memory_pool(void* connection_id, 
    const ConnectionCharacteristics& characteristics = {});
DTLS_API void destroy_connection_memory_pool(void* connection_id);

DTLS_API ConnectionBuffer allocate_connection_buffer(void* connection_id, size_t size);
DTLS_API std::vector<ConnectionBuffer> allocate_connection_buffers(
    void* connection_id, const std::vector<size_t>& sizes);

// Specialized allocation functions
DTLS_API ConnectionBuffer allocate_message_buffer(void* connection_id);
DTLS_API ConnectionBuffer allocate_header_buffer(void* connection_id);
DTLS_API ConnectionBuffer allocate_payload_buffer(void* connection_id);
DTLS_API ConnectionBuffer allocate_crypto_buffer(void* connection_id);

// Connection lifecycle helpers
DTLS_API void on_connection_established(void* connection_id, 
    const ConnectionCharacteristics& characteristics);
DTLS_API void on_connection_handshake_complete(void* connection_id);
DTLS_API void on_connection_data_phase(void* connection_id);
DTLS_API void on_connection_idle(void* connection_id);
DTLS_API void on_connection_closing(void* connection_id);

// System optimization functions
DTLS_API void optimize_all_connection_memory();
DTLS_API void enable_connection_memory_optimization(bool enabled);
DTLS_API size_t reclaim_connection_memory(size_t target_bytes);

// Configuration presets for different connection types
namespace connection_presets {
    DTLS_API ConnectionCharacteristics low_latency_connection();
    DTLS_API ConnectionCharacteristics high_throughput_connection();
    DTLS_API ConnectionCharacteristics interactive_connection();
    DTLS_API ConnectionCharacteristics streaming_connection();
    DTLS_API ConnectionCharacteristics iot_sensor_connection();
    DTLS_API ConnectionCharacteristics memory_constrained_connection();
}

// Integration with existing systems
class DTLS_API ConnectionMemoryIntegration {
public:
    // Integration with adaptive pools
    static void integrate_with_adaptive_pools();
    static void sync_connection_patterns_to_adaptive_pools();
    
    // Integration with leak detection
    static void integrate_with_leak_detection();
    static void register_connection_cleanup_callbacks();
    
    // Integration with crypto system
    static void integrate_with_zero_copy_crypto();
    static void optimize_crypto_buffer_allocation();
    
    // Integration with protocol layer
    static void integrate_with_record_layer();
    static void integrate_with_handshake_layer();
};

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_CONNECTION_POOLS_H