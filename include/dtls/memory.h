#ifndef DTLS_MEMORY_H
#define DTLS_MEMORY_H

/**
 * DTLS v1.3 Memory Management System
 * 
 * This header provides access to the complete memory management subsystem
 * for DTLS v1.3, including:
 * 
 * - Zero-copy buffer management
 * - High-performance memory pools
 * - Memory tracking and statistics
 * - Security-focused memory operations
 * - Performance monitoring
 * - Memory debugging utilities
 * 
 * Usage:
 *   #include <dtls/memory.h>
 * 
 * Basic usage example:
 * 
 *   using namespace dtls::v13::memory;
 *   
 *   // Create a pooled buffer for efficient reuse
 *   auto buffer = make_pooled_buffer(1024);
 *   if (buffer) {
 *       // Use the buffer
 *       auto result = buffer->append(data, length);
 *       
 *       // Buffer automatically returns to pool when destroyed
 *   }
 *   
 *   // Or use zero-copy buffers directly
 *   ZeroCopyBuffer my_buffer(512);
 *   my_buffer.append(some_data, data_length);
 *   
 *   // Create buffer views for non-owning access
 *   BufferView view(my_buffer);
 *   auto hex_dump = to_hex_string(view);
 */

// Core buffer management
#include <dtls/memory/buffer.h>
#include <dtls/memory/pool.h>
#include <dtls/memory/memory_utils.h>

namespace dtls {
namespace v13 {

/**
 * Memory namespace contains all memory management functionality
 * for DTLS v1.3 implementation.
 */
namespace memory {

/**
 * Initialize the memory management system
 * 
 * This function should be called once at application startup
 * to initialize memory pools and configure the memory system.
 * 
 * @return Success or error result
 */
DTLS_API Result<void> initialize_memory_system();

/**
 * Cleanup the memory management system
 * 
 * This function should be called once at application shutdown
 * to cleanup memory pools and free resources.
 */
DTLS_API void cleanup_memory_system();

/**
 * Check if the memory system is initialized
 * 
 * @return true if initialized, false otherwise
 */
DTLS_API bool is_memory_system_initialized();

/**
 * Memory system configuration
 */
struct MemorySystemConfig {
    // Pool configuration
    size_t default_pool_size{32};
    size_t max_pool_size{128};
    bool enable_pool_statistics{true};
    
    // Buffer configuration
    size_t default_buffer_alignment{16};
    bool enable_buffer_debugging{false};
    bool enable_guard_patterns{false};
    
    // Statistics and monitoring
    bool enable_allocation_tracking{false};
    bool enable_performance_monitoring{false};
    bool enable_leak_detection{false};
    
    // Memory limits
    size_t max_total_memory{1024 * 1024 * 1024}; // 1GB
    size_t warning_threshold{512 * 1024 * 1024}; // 512MB
    
    // Security settings
    bool secure_zero_on_free{true};
    bool enable_memory_protection{true};
};

/**
 * Set system-wide memory configuration
 * 
 * @param config The configuration to apply
 * @return Success or error result
 */
DTLS_API Result<void> set_memory_system_config(const MemorySystemConfig& config);

/**
 * Get current system-wide memory configuration
 * 
 * @return Current configuration
 */
DTLS_API MemorySystemConfig get_memory_system_config();

/**
 * Reset memory configuration to defaults
 */
DTLS_API void reset_memory_system_config();

/**
 * Memory system status information
 */
struct MemorySystemStatus {
    bool is_initialized{false};
    size_t total_memory_usage{0};
    size_t pool_memory_usage{0};
    size_t direct_memory_usage{0};
    size_t active_allocations{0};
    size_t peak_allocations{0};
    size_t total_pools{0};
    size_t active_pools{0};
    double average_pool_utilization{0.0};
    std::chrono::steady_clock::time_point initialization_time;
    std::chrono::milliseconds uptime{0};
};

/**
 * Get current memory system status
 * 
 * @return Current system status
 */
DTLS_API MemorySystemStatus get_memory_system_status();

/**
 * Memory system health check
 * 
 * Performs comprehensive health check of the memory system
 * including pool status, leak detection, and performance validation.
 * 
 * @return Health check results
 */
struct MemoryHealthCheckResult {
    bool overall_healthy{false};
    size_t total_memory_usage{0};
    size_t memory_leaks{0};
    double fragmentation_ratio{0.0};
    std::vector<std::string> pool_issues;
    std::vector<std::string> allocation_issues;
    std::vector<std::string> performance_issues;
    std::chrono::milliseconds check_duration{0};
    std::chrono::steady_clock::time_point check_time;
};

DTLS_API Result<MemoryHealthCheckResult> perform_memory_health_check();

/**
 * Run memory system self-tests
 * 
 * Executes comprehensive self-tests to validate that all
 * memory management operations are working correctly.
 * 
 * @return Self-test results
 */
struct MemoryTestResult {
    bool all_tests_passed{false};
    size_t tests_run{0};
    size_t tests_passed{0};
    size_t tests_failed{0};
    std::vector<std::string> failed_test_names;
    std::chrono::milliseconds total_test_time{0};
};

DTLS_API Result<MemoryTestResult> run_memory_self_tests();

/**
 * Memory optimization utilities
 */
namespace optimization {

/**
 * Optimize memory pools based on usage patterns
 * 
 * Analyzes pool usage and adjusts pool sizes for optimal performance.
 * 
 * @return Number of pools optimized
 */
DTLS_API size_t optimize_memory_pools();

/**
 * Compact fragmented memory
 * 
 * Attempts to reduce memory fragmentation by reorganizing pools.
 * 
 * @return Amount of memory freed (bytes)
 */
DTLS_API size_t compact_memory();

/**
 * Preload memory pools
 * 
 * Pre-allocates buffers in pools based on expected usage patterns.
 * 
 * @param usage_hints Expected buffer size usage patterns
 * @return Success or error result
 */
DTLS_API Result<void> preload_pools(const std::vector<std::pair<size_t, size_t>>& usage_hints);

/**
 * Memory usage prediction
 * 
 * Predicts future memory usage based on current patterns.
 * 
 * @param time_horizon How far ahead to predict
 * @return Predicted memory usage in bytes
 */
DTLS_API size_t predict_memory_usage(std::chrono::minutes time_horizon);

} // namespace optimization

/**
 * Memory debugging utilities
 */
namespace debugging {

/**
 * Enable memory debugging features
 * 
 * Activates additional debugging checks and validations.
 * 
 * @param enable_guards Enable buffer guard patterns
 * @param enable_tracking Enable allocation tracking
 * @param enable_validation Enable buffer validation
 */
DTLS_API void enable_debugging(bool enable_guards = true, 
                              bool enable_tracking = true,
                              bool enable_validation = true);

/**
 * Disable memory debugging features
 */
DTLS_API void disable_debugging();

/**
 * Generate comprehensive memory report
 * 
 * Creates detailed report of memory usage, pools, and statistics.
 * 
 * @param include_details Include detailed per-pool statistics
 * @return Formatted memory report string
 */
DTLS_API std::string generate_memory_report(bool include_details = true);

/**
 * Validate all active buffers
 * 
 * Checks integrity of all currently active buffers.
 * 
 * @return Number of validation errors found
 */
DTLS_API size_t validate_all_buffers();

/**
 * Dump memory statistics to stream
 * 
 * Outputs detailed memory statistics in human-readable format.
 * 
 * @param output Output stream to write to
 */
DTLS_API void dump_memory_statistics(std::ostream& output);

} // namespace debugging

// Convenience aliases for commonly used types
using Buffer = ZeroCopyBuffer;
using BufferPtr = std::unique_ptr<ZeroCopyBuffer>;
using PooledBufferPtr = PooledBuffer;
using View = BufferView;
using MutableView = MutableBufferView;

// Factory functions with error handling
DTLS_API Result<PooledBuffer> create_pooled_buffer(size_t size);
DTLS_API Result<BufferPtr> create_buffer(size_t size);
DTLS_API Result<BufferPtr> create_aligned_buffer(size_t size, size_t alignment);

// Buffer operation helpers
DTLS_API Result<BufferPtr> clone_buffer(const BufferView& source);
DTLS_API Result<BufferPtr> merge_buffers(const std::vector<BufferView>& buffers);
DTLS_API Result<std::vector<BufferPtr>> split_buffer(const BufferView& source, 
                                                     const std::vector<size_t>& split_points);

// Security-focused buffer operations
DTLS_API Result<BufferPtr> create_secure_buffer(size_t size);
DTLS_API void secure_clear_buffer(Buffer& buffer);
DTLS_API bool compare_buffers_secure(const BufferView& a, const BufferView& b);

// High-level memory management operations
DTLS_API void trigger_garbage_collection();
DTLS_API size_t get_total_memory_usage();
DTLS_API size_t get_available_memory();
DTLS_API double get_memory_fragmentation_ratio();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_H