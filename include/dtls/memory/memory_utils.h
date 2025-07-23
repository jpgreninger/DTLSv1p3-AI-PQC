#ifndef DTLS_MEMORY_UTILS_H
#define DTLS_MEMORY_UTILS_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <dtls/memory/pool.h>
#include <memory>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <thread>

namespace dtls {
namespace v13 {
namespace memory {

/**
 * Memory utilities for DTLS v1.3 implementation
 * 
 * Provides memory management helpers, statistics collection,
 * allocation tracking, and memory security utilities.
 */
namespace utils {

// Memory allocation tracking
struct AllocationInfo {
    size_t size{0};
    std::chrono::steady_clock::time_point allocation_time;
    std::string location; // File:line or function name
    std::thread::id thread_id;
};

// Global memory statistics
struct MemoryStats {
    std::atomic<size_t> total_allocations{0};
    std::atomic<size_t> total_deallocations{0};
    std::atomic<size_t> current_allocations{0};
    std::atomic<size_t> peak_allocations{0};
    std::atomic<size_t> total_bytes_allocated{0};
    std::atomic<size_t> total_bytes_deallocated{0};
    std::atomic<size_t> current_bytes_allocated{0};
    std::atomic<size_t> peak_bytes_allocated{0};
    std::atomic<size_t> allocation_failures{0};
    std::chrono::steady_clock::time_point start_time;
};

// Memory statistics collector
class DTLS_API MemoryStatsCollector {
public:
    static MemoryStatsCollector& instance();
    
    // Statistics tracking
    void record_allocation(size_t size, const std::string& location = "");
    void record_deallocation(size_t size);
    void record_allocation_failure(size_t size);
    
    // Statistics retrieval
    MemoryStats get_statistics() const;
    void reset_statistics();
    
    // Allocation tracking
    void enable_tracking(bool enabled) { tracking_enabled_ = enabled; }
    bool is_tracking_enabled() const { return tracking_enabled_; }
    
    // Leak detection
    std::vector<AllocationInfo> get_active_allocations() const;
    size_t get_leak_count() const;
    void dump_leaks() const;

private:
    MemoryStatsCollector();
    ~MemoryStatsCollector() = default;
    
    MemoryStats stats_;
    mutable std::mutex tracking_mutex_;
    std::unordered_map<void*, AllocationInfo> active_allocations_;
    std::atomic<bool> tracking_enabled_{false};
};

// RAII memory tracker for automatic allocation/deallocation tracking
class DTLS_API MemoryTracker {
public:
    explicit MemoryTracker(size_t size, const std::string& location = "");
    ~MemoryTracker();
    
    MemoryTracker(const MemoryTracker&) = delete;
    MemoryTracker& operator=(const MemoryTracker&) = delete;
    MemoryTracker(MemoryTracker&&) = delete;
    MemoryTracker& operator=(MemoryTracker&&) = delete;

private:
    size_t size_;
};

// Memory alignment utilities
DTLS_API bool is_aligned(const void* ptr, size_t alignment) noexcept;
DTLS_API void* align_pointer(void* ptr, size_t alignment) noexcept;
DTLS_API size_t align_size(size_t size, size_t alignment) noexcept;

// Memory comparison utilities
DTLS_API bool secure_compare(const void* a, const void* b, size_t size) noexcept;
DTLS_API int secure_memcmp(const void* a, const void* b, size_t size) noexcept;

// Memory security utilities
DTLS_API void secure_memzero(void* ptr, size_t size) noexcept;
DTLS_API void secure_memset(void* ptr, int value, size_t size) noexcept;
DTLS_API bool is_memory_cleared(const void* ptr, size_t size) noexcept;

// Buffer conversion utilities
DTLS_API std::vector<uint8_t> buffer_to_vector(const BufferView& buffer);
DTLS_API ZeroCopyBuffer vector_to_buffer(const std::vector<uint8_t>& vec);
DTLS_API std::string buffer_to_string(const BufferView& buffer);
DTLS_API ZeroCopyBuffer string_to_buffer(const std::string& str);

// Buffer manipulation utilities
DTLS_API Result<ZeroCopyBuffer> copy_buffer(const BufferView& source);
DTLS_API Result<void> copy_buffer_to(const BufferView& source, MutableBufferView& destination);
DTLS_API Result<ZeroCopyBuffer> resize_buffer(ZeroCopyBuffer&& buffer, size_t new_size);
DTLS_API Result<ZeroCopyBuffer> concat_buffers(const std::vector<BufferView>& buffers);

// Buffer search utilities
DTLS_API size_t find_pattern(const BufferView& buffer, const BufferView& pattern) noexcept;
DTLS_API size_t find_byte_sequence(const BufferView& buffer, const std::vector<std::byte>& sequence) noexcept;
DTLS_API std::vector<size_t> find_all_occurrences(const BufferView& buffer, std::byte value) noexcept;

// Buffer validation utilities
DTLS_API bool validate_buffer_bounds(const BufferView& buffer, size_t offset, size_t length) noexcept;
DTLS_API bool is_buffer_zero(const BufferView& buffer) noexcept;
DTLS_API bool is_buffer_pattern(const BufferView& buffer, std::byte pattern) noexcept;

// Memory debugging utilities
class DTLS_API MemoryDebugger {
public:
    static MemoryDebugger& instance();
    
    // Guard patterns for buffer overflow detection
    void enable_guard_patterns(bool enabled) { guard_patterns_enabled_ = enabled; }
    bool are_guard_patterns_enabled() const { return guard_patterns_enabled_; }
    
    // Memory corruption detection
    bool check_buffer_integrity(const ZeroCopyBuffer& buffer) const;
    void add_buffer_checksum(const ZeroCopyBuffer& buffer);
    bool verify_buffer_checksum(const ZeroCopyBuffer& buffer) const;
    
    // Memory usage profiling
    void start_profiling();
    void stop_profiling();
    bool is_profiling() const { return profiling_enabled_; }
    
    // Memory usage report
    void generate_memory_report() const;
    void dump_buffer_contents(const BufferView& buffer, const std::string& label = "") const;

private:
    MemoryDebugger() = default;
    ~MemoryDebugger() = default;
    
    std::atomic<bool> guard_patterns_enabled_{false};
    std::atomic<bool> profiling_enabled_{false};
    mutable std::mutex checksums_mutex_;
    std::unordered_map<const void*, uint32_t> buffer_checksums_;
};

// Performance monitoring for memory operations
class DTLS_API MemoryPerformanceMonitor {
public:
    static MemoryPerformanceMonitor& instance();
    
    // Operation timing
    void record_operation(const std::string& operation, std::chrono::nanoseconds duration);
    
    // Performance statistics
    struct OperationStats {
        std::string name;
        size_t count{0};
        std::chrono::nanoseconds total_time{0};
        std::chrono::nanoseconds min_time{std::chrono::nanoseconds::max()};
        std::chrono::nanoseconds max_time{0};
        std::chrono::nanoseconds average_time() const {
            return count > 0 ? std::chrono::nanoseconds(total_time / count) : std::chrono::nanoseconds{0};
        }
    };
    
    std::vector<OperationStats> get_all_stats() const;
    OperationStats get_operation_stats(const std::string& operation) const;
    void reset_stats();
    
    // Configuration
    void enable_monitoring(bool enabled) { monitoring_enabled_ = enabled; }
    bool is_monitoring_enabled() const { return monitoring_enabled_; }

private:
    MemoryPerformanceMonitor() = default;
    ~MemoryPerformanceMonitor() = default;
    
    std::atomic<bool> monitoring_enabled_{false};
    mutable std::mutex stats_mutex_;
    std::unordered_map<std::string, OperationStats> operation_stats_;
};

// RAII timer for memory operations
class DTLS_API MemoryOperationTimer {
public:
    explicit MemoryOperationTimer(const std::string& operation_name);
    ~MemoryOperationTimer();
    
    MemoryOperationTimer(const MemoryOperationTimer&) = delete;
    MemoryOperationTimer& operator=(const MemoryOperationTimer&) = delete;

private:
    std::string operation_name_;
    std::chrono::steady_clock::time_point start_time_;
};

// Memory configuration and limits
struct MemoryConfig {
    size_t max_total_memory{1024 * 1024 * 1024}; // 1GB default
    size_t max_single_allocation{64 * 1024 * 1024}; // 64MB default
    size_t warning_threshold{512 * 1024 * 1024}; // 512MB warning
    bool enable_statistics{true};
    bool enable_tracking{false};
    bool enable_debugging{false};
    bool enable_performance_monitoring{false};
};

// Global memory configuration
DTLS_API Result<void> configure_memory_system(const MemoryConfig& config);
DTLS_API MemoryConfig get_memory_configuration();
DTLS_API void reset_memory_configuration();

// Memory health check
struct MemoryHealthReport {
    bool overall_healthy{true};
    size_t total_memory_usage{0};
    size_t active_allocations{0};
    size_t memory_leaks{0};
    double fragmentation_ratio{0.0};
    std::vector<std::string> issues;
    std::chrono::steady_clock::time_point check_time;
};

DTLS_API Result<MemoryHealthReport> perform_memory_health_check();

// Memory cleanup utilities
DTLS_API void cleanup_memory_system();
DTLS_API void force_garbage_collection();
DTLS_API size_t compact_memory_pools();

} // namespace utils

// Convenience macros for memory tracking
#define DTLS_MEMORY_TRACK(size) \
    dtls::v13::memory::utils::MemoryTracker _tracker(size, __FILE__ ":" DTLS_STRINGIFY(__LINE__))

#define DTLS_MEMORY_TIMER(op_name) \
    dtls::v13::memory::utils::MemoryOperationTimer _timer(op_name)

#ifndef DTLS_STRINGIFY
#define DTLS_STRINGIFY_IMPL(x) #x
#define DTLS_STRINGIFY(x) DTLS_STRINGIFY_IMPL(x)
#endif

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_UTILS_H