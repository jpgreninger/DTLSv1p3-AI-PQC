#include <dtls/memory/memory_utils.h>
#include <dtls/error.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <cstring>
#include <cstdint>

namespace dtls {
namespace v13 {
namespace memory {
namespace utils {

// Global memory configuration
namespace {
    MemoryConfig g_memory_config;
    std::mutex g_config_mutex;
}

// MemoryStatsCollector implementation
MemoryStatsCollector& MemoryStatsCollector::instance() {
    static MemoryStatsCollector instance;
    return instance;
}

MemoryStatsCollector::MemoryStatsCollector() {
    stats_.start_time = std::chrono::steady_clock::now();
}

void MemoryStatsCollector::record_allocation(size_t size, const std::string& location) {
    stats_.total_allocations.fetch_add(1, std::memory_order_relaxed);
    stats_.total_bytes_allocated.fetch_add(size, std::memory_order_relaxed);
    
    size_t current_allocs = stats_.current_allocations.fetch_add(1, std::memory_order_relaxed) + 1;
    size_t current_bytes = stats_.current_bytes_allocated.fetch_add(size, std::memory_order_relaxed) + size;
    
    // Update peak allocations
    size_t current_peak_allocs = stats_.peak_allocations.load();
    while (current_allocs > current_peak_allocs && 
           !stats_.peak_allocations.compare_exchange_weak(current_peak_allocs, current_allocs)) {
        // Retry if another thread updated peak
    }
    
    // Update peak bytes
    size_t current_peak_bytes = stats_.peak_bytes_allocated.load();
    while (current_bytes > current_peak_bytes && 
           !stats_.peak_bytes_allocated.compare_exchange_weak(current_peak_bytes, current_bytes)) {
        // Retry if another thread updated peak
    }
    
    // Track individual allocations if enabled
    if (tracking_enabled_.load()) {
        std::lock_guard<std::mutex> lock(tracking_mutex_);
        
        AllocationInfo info;
        info.size = size;
        info.allocation_time = std::chrono::steady_clock::now();
        info.location = location;
        info.thread_id = std::this_thread::get_id();
        
        // Note: In a real implementation, we'd need the actual pointer
        // For now, we use a placeholder
        active_allocations_[reinterpret_cast<void*>(current_allocs)] = info;
    }
}

void MemoryStatsCollector::record_deallocation(size_t size) {
    stats_.total_deallocations.fetch_add(1, std::memory_order_relaxed);
    stats_.total_bytes_deallocated.fetch_add(size, std::memory_order_relaxed);
    stats_.current_allocations.fetch_sub(1, std::memory_order_relaxed);
    stats_.current_bytes_allocated.fetch_sub(size, std::memory_order_relaxed);
}

void MemoryStatsCollector::record_allocation_failure(size_t size) {
    stats_.allocation_failures.fetch_add(1, std::memory_order_relaxed);
}

MemoryStats MemoryStatsCollector::get_statistics() const {
    MemoryStats stats_copy;
    stats_copy.total_allocations = stats_.total_allocations.load();
    stats_copy.total_deallocations = stats_.total_deallocations.load();
    stats_copy.current_allocations = stats_.current_allocations.load();
    stats_copy.peak_allocations = stats_.peak_allocations.load();
    stats_copy.total_bytes_allocated = stats_.total_bytes_allocated.load();
    stats_copy.total_bytes_deallocated = stats_.total_bytes_deallocated.load();
    stats_copy.current_bytes_allocated = stats_.current_bytes_allocated.load();
    stats_copy.peak_bytes_allocated = stats_.peak_bytes_allocated.load();
    stats_copy.allocation_failures = stats_.allocation_failures.load();
    stats_copy.start_time = stats_.start_time;
    return stats_copy;
}

void MemoryStatsCollector::reset_statistics() {
    stats_.total_allocations.store(0);
    stats_.total_deallocations.store(0);
    stats_.current_allocations.store(0);
    stats_.peak_allocations.store(0);
    stats_.total_bytes_allocated.store(0);
    stats_.total_bytes_deallocated.store(0);
    stats_.current_bytes_allocated.store(0);
    stats_.peak_bytes_allocated.store(0);
    stats_.allocation_failures.store(0);
    stats_.start_time = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(tracking_mutex_);
    active_allocations_.clear();
}

std::vector<AllocationInfo> MemoryStatsCollector::get_active_allocations() const {
    std::lock_guard<std::mutex> lock(tracking_mutex_);
    
    std::vector<AllocationInfo> allocations;
    allocations.reserve(active_allocations_.size());
    
    for (const auto& [ptr, info] : active_allocations_) {
        allocations.push_back(info);
    }
    
    return allocations;
}

size_t MemoryStatsCollector::get_leak_count() const {
    std::lock_guard<std::mutex> lock(tracking_mutex_);
    return active_allocations_.size();
}

void MemoryStatsCollector::dump_leaks() const {
    auto allocations = get_active_allocations();
    
    if (allocations.empty()) {
        std::cout << "No memory leaks detected.\n";
        return;
    }
    
    std::cout << "Memory leaks detected (" << allocations.size() << " allocations):\n";
    
    for (const auto& alloc : allocations) {
        std::cout << "  Size: " << alloc.size << " bytes"
                  << ", Location: " << alloc.location
                  << ", Thread: " << alloc.thread_id << "\n";
    }
}

// MemoryTracker implementation
MemoryTracker::MemoryTracker(size_t size, const std::string& location)
    : size_(size) {
    MemoryStatsCollector::instance().record_allocation(size, location);
}

MemoryTracker::~MemoryTracker() {
    MemoryStatsCollector::instance().record_deallocation(size_);
}

// Memory alignment utilities
bool is_aligned(const void* ptr, size_t alignment) noexcept {
    if (alignment == 0) return true;
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

void* align_pointer(void* ptr, size_t alignment) noexcept {
    if (alignment == 0) return ptr;
    
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    return reinterpret_cast<void*>(aligned);
}

size_t align_size(size_t size, size_t alignment) noexcept {
    if (alignment == 0) return size;
    return (size + alignment - 1) & ~(alignment - 1);
}

// Memory comparison utilities
bool secure_compare(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) return false;
    
    const uint8_t* ptr_a = static_cast<const uint8_t*>(a);
    const uint8_t* ptr_b = static_cast<const uint8_t*>(b);
    
    uint8_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= (ptr_a[i] ^ ptr_b[i]);
    }
    
    return result == 0;
}

int secure_memcmp(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) return -1;
    
    const uint8_t* ptr_a = static_cast<const uint8_t*>(a);
    const uint8_t* ptr_b = static_cast<const uint8_t*>(b);
    
    int result = 0;
    for (size_t i = 0; i < size; ++i) {
        int diff = static_cast<int>(ptr_a[i]) - static_cast<int>(ptr_b[i]);
        if (result == 0 && diff != 0) {
            result = diff;
        }
    }
    
    return result;
}

// Memory security utilities
void secure_memzero(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    
    volatile uint8_t* volatile_ptr = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = 0;
    }
}

void secure_memset(void* ptr, int value, size_t size) noexcept {
    if (!ptr || size == 0) return;
    
    volatile uint8_t* volatile_ptr = static_cast<volatile uint8_t*>(ptr);
    uint8_t byte_value = static_cast<uint8_t>(value);
    
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = byte_value;
    }
}

bool is_memory_cleared(const void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return true;
    
    const uint8_t* byte_ptr = static_cast<const uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        if (byte_ptr[i] != 0) {
            return false;
        }
    }
    
    return true;
}

// Buffer conversion utilities
std::vector<uint8_t> buffer_to_vector(const BufferView& buffer) {
    if (buffer.empty()) {
        return {};
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    return std::vector<uint8_t>(data, data + buffer.size());
}

ZeroCopyBuffer vector_to_buffer(const std::vector<uint8_t>& vec) {
    if (vec.empty()) {
        return ZeroCopyBuffer();
    }
    
    const std::byte* data = reinterpret_cast<const std::byte*>(vec.data());
    return ZeroCopyBuffer(data, vec.size());
}

std::string buffer_to_string(const BufferView& buffer) {
    if (buffer.empty()) {
        return "";
    }
    
    const char* data = reinterpret_cast<const char*>(buffer.data());
    return std::string(data, buffer.size());
}

ZeroCopyBuffer string_to_buffer(const std::string& str) {
    if (str.empty()) {
        return ZeroCopyBuffer();
    }
    
    const std::byte* data = reinterpret_cast<const std::byte*>(str.data());
    return ZeroCopyBuffer(data, str.size());
}

// Buffer manipulation utilities
Result<ZeroCopyBuffer> copy_buffer(const BufferView& source) {
    if (source.empty()) {
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer());
    }
    
    return Result<ZeroCopyBuffer>(ZeroCopyBuffer(source.data(), source.size()));
}

Result<void> copy_buffer_to(const BufferView& source, MutableBufferView& destination) {
    if (source.size() > destination.size()) {
        return Result<void>(DTLSError::INSUFFICIENT_BUFFER);
    }
    
    if (source.size() > 0) {
        std::memcpy(destination.data(), source.data(), source.size());
    }
    
    return Result<void>();
}

Result<ZeroCopyBuffer> resize_buffer(ZeroCopyBuffer&& buffer, size_t new_size) {
    auto result = buffer.resize(new_size);
    if (!result) {
        return Result<ZeroCopyBuffer>(result.error());
    }
    
    return Result<ZeroCopyBuffer>(std::move(buffer));
}

Result<ZeroCopyBuffer> concat_buffers(const std::vector<BufferView>& buffers) {
    return concatenate_buffers(buffers);
}

// Buffer search utilities
size_t find_pattern(const BufferView& buffer, const BufferView& pattern) noexcept {
    if (pattern.empty() || pattern.size() > buffer.size()) {
        return buffer.size(); // Not found
    }
    
    const std::byte* buffer_data = buffer.data();
    const std::byte* pattern_data = pattern.data();
    size_t buffer_size = buffer.size();
    size_t pattern_size = pattern.size();
    
    for (size_t i = 0; i <= buffer_size - pattern_size; ++i) {
        if (std::memcmp(buffer_data + i, pattern_data, pattern_size) == 0) {
            return i;
        }
    }
    
    return buffer_size; // Not found
}

size_t find_byte_sequence(const BufferView& buffer, const std::vector<std::byte>& sequence) noexcept {
    if (sequence.empty() || sequence.size() > buffer.size()) {
        return buffer.size(); // Not found
    }
    
    const std::byte* buffer_data = buffer.data();
    const std::byte* sequence_data = sequence.data();
    size_t buffer_size = buffer.size();
    size_t sequence_size = sequence.size();
    
    for (size_t i = 0; i <= buffer_size - sequence_size; ++i) {
        if (std::memcmp(buffer_data + i, sequence_data, sequence_size) == 0) {
            return i;
        }
    }
    
    return buffer_size; // Not found
}

std::vector<size_t> find_all_occurrences(const BufferView& buffer, std::byte value) noexcept {
    std::vector<size_t> occurrences;
    
    const std::byte* data = buffer.data();
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (data[i] == value) {
            occurrences.push_back(i);
        }
    }
    
    return occurrences;
}

// Buffer validation utilities
bool validate_buffer_bounds(const BufferView& buffer, size_t offset, size_t length) noexcept {
    if (offset > buffer.size()) {
        return false;
    }
    
    return (offset + length) <= buffer.size();
}

bool is_buffer_zero(const BufferView& buffer) noexcept {
    return is_memory_cleared(buffer.data(), buffer.size());
}

bool is_buffer_pattern(const BufferView& buffer, std::byte pattern) noexcept {
    const std::byte* data = buffer.data();
    for (size_t i = 0; i < buffer.size(); ++i) {
        if (data[i] != pattern) {
            return false;
        }
    }
    return true;
}

// MemoryDebugger implementation
MemoryDebugger& MemoryDebugger::instance() {
    static MemoryDebugger instance;
    return instance;
}

bool MemoryDebugger::check_buffer_integrity(const ZeroCopyBuffer& buffer) const {
    // Basic integrity checks
    if (buffer.size() > buffer.capacity()) {
        return false;
    }
    
    if (buffer.capacity() > 0 && buffer.data() == nullptr) {
        return false;
    }
    
    return true;
}

void MemoryDebugger::add_buffer_checksum(const ZeroCopyBuffer& buffer) {
    if (!buffer.data() || buffer.size() == 0) {
        return;
    }
    
    // Simple checksum calculation
    uint32_t checksum = 0;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    
    for (size_t i = 0; i < buffer.size(); ++i) {
        checksum = (checksum << 1) ^ data[i];
    }
    
    std::lock_guard<std::mutex> lock(checksums_mutex_);
    buffer_checksums_[buffer.data()] = checksum;
}

bool MemoryDebugger::verify_buffer_checksum(const ZeroCopyBuffer& buffer) const {
    if (!buffer.data() || buffer.size() == 0) {
        return true; // Empty buffers are always valid
    }
    
    std::lock_guard<std::mutex> lock(checksums_mutex_);
    auto it = buffer_checksums_.find(buffer.data());
    if (it == buffer_checksums_.end()) {
        return false; // No checksum recorded
    }
    
    // Recalculate checksum
    uint32_t checksum = 0;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buffer.data());
    
    for (size_t i = 0; i < buffer.size(); ++i) {
        checksum = (checksum << 1) ^ data[i];
    }
    
    return checksum == it->second;
}

void MemoryDebugger::start_profiling() {
    profiling_enabled_.store(true);
}

void MemoryDebugger::stop_profiling() {
    profiling_enabled_.store(false);
}

void MemoryDebugger::generate_memory_report() const {
    auto stats = MemoryStatsCollector::instance().get_statistics();
    
    std::cout << "=== DTLS Memory Report ===\n";
    std::cout << "Total allocations: " << stats.total_allocations << "\n";
    std::cout << "Total deallocations: " << stats.total_deallocations << "\n";
    std::cout << "Current allocations: " << stats.current_allocations << "\n";
    std::cout << "Peak allocations: " << stats.peak_allocations << "\n";
    std::cout << "Total bytes allocated: " << stats.total_bytes_allocated << "\n";
    std::cout << "Total bytes deallocated: " << stats.total_bytes_deallocated << "\n";
    std::cout << "Current bytes allocated: " << stats.current_bytes_allocated << "\n";
    std::cout << "Peak bytes allocated: " << stats.peak_bytes_allocated << "\n";
    std::cout << "Allocation failures: " << stats.allocation_failures << "\n";
    
    if (stats.current_allocations > 0) {
        std::cout << "\nPotential memory leaks detected!\n";
        MemoryStatsCollector::instance().dump_leaks();
    }
    
    std::cout << "=== End Report ===\n";
}

void MemoryDebugger::dump_buffer_contents(const BufferView& buffer, const std::string& label) const {
    std::cout << "=== Buffer Dump";
    if (!label.empty()) {
        std::cout << ": " << label;
    }
    std::cout << " ===\n";
    
    std::cout << "Size: " << buffer.size() << " bytes\n";
    std::cout << "Data: " << to_hex_string(buffer) << "\n";
    std::cout << "=== End Dump ===\n";
}

// MemoryPerformanceMonitor implementation
MemoryPerformanceMonitor& MemoryPerformanceMonitor::instance() {
    static MemoryPerformanceMonitor instance;
    return instance;
}

void MemoryPerformanceMonitor::record_operation(const std::string& operation, std::chrono::nanoseconds duration) {
    if (!monitoring_enabled_.load()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto& stats = operation_stats_[operation];
    
    stats.name = operation;
    stats.count++;
    stats.total_time += duration;
    
    if (duration < stats.min_time) {
        stats.min_time = duration;
    }
    
    if (duration > stats.max_time) {
        stats.max_time = duration;
    }
}

std::vector<MemoryPerformanceMonitor::OperationStats> MemoryPerformanceMonitor::get_all_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    std::vector<OperationStats> all_stats;
    all_stats.reserve(operation_stats_.size());
    
    for (const auto& [name, stats] : operation_stats_) {
        all_stats.push_back(stats);
    }
    
    return all_stats;
}

MemoryPerformanceMonitor::OperationStats MemoryPerformanceMonitor::get_operation_stats(const std::string& operation) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = operation_stats_.find(operation);
    return (it != operation_stats_.end()) ? it->second : OperationStats{};
}

void MemoryPerformanceMonitor::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    operation_stats_.clear();
}

// MemoryOperationTimer implementation
MemoryOperationTimer::MemoryOperationTimer(const std::string& operation_name)
    : operation_name_(operation_name)
    , start_time_(std::chrono::steady_clock::now()) {}

MemoryOperationTimer::~MemoryOperationTimer() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time_);
    
    MemoryPerformanceMonitor::instance().record_operation(operation_name_, duration);
}

// Global memory configuration
Result<void> configure_memory_system(const MemoryConfig& config) {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    
    g_memory_config = config;
    
    // Apply configuration
    MemoryStatsCollector::instance().enable_tracking(config.enable_tracking);
    MemoryDebugger::instance().enable_guard_patterns(config.enable_debugging);
    MemoryPerformanceMonitor::instance().enable_monitoring(config.enable_performance_monitoring);
    
    return Result<void>();
}

MemoryConfig get_memory_configuration() {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    return g_memory_config;
}

void reset_memory_configuration() {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    g_memory_config = MemoryConfig{};
}

// Memory health check
Result<MemoryHealthReport> perform_memory_health_check() {
    MemoryHealthReport report;
    report.check_time = std::chrono::steady_clock::now();
    
    auto stats = MemoryStatsCollector::instance().get_statistics();
    
    report.total_memory_usage = stats.current_bytes_allocated;
    report.active_allocations = stats.current_allocations;
    report.memory_leaks = MemoryStatsCollector::instance().get_leak_count();
    
    // Calculate fragmentation ratio (simplified)
    auto pool_stats = GlobalPoolManager::instance().get_all_statistics();
    size_t total_pool_memory = 0;
    size_t available_pool_memory = 0;
    
    for (const auto& pool_stat : pool_stats) {
        total_pool_memory += pool_stat.total_buffers * pool_stat.buffer_size;
        available_pool_memory += pool_stat.available_buffers * pool_stat.buffer_size;
    }
    
    if (total_pool_memory > 0) {
        report.fragmentation_ratio = 1.0 - (static_cast<double>(available_pool_memory) / total_pool_memory);
    }
    
    // Check for issues
    auto config = get_memory_configuration();
    
    if (report.total_memory_usage > config.warning_threshold) {
        report.issues.push_back("Memory usage exceeds warning threshold");
    }
    
    if (report.memory_leaks > 0) {
        report.issues.push_back("Memory leaks detected: " + std::to_string(report.memory_leaks));
        report.overall_healthy = false;
    }
    
    if (report.fragmentation_ratio > 0.5) {
        report.issues.push_back("High memory fragmentation detected");
    }
    
    if (stats.allocation_failures > 0) {
        report.issues.push_back("Allocation failures detected: " + std::to_string(stats.allocation_failures));
        report.overall_healthy = false;
    }
    
    return Result<MemoryHealthReport>(std::move(report));
}

// Memory cleanup utilities
void cleanup_memory_system() {
    MemoryStatsCollector::instance().reset_statistics();
    MemoryPerformanceMonitor::instance().reset_stats();
    GlobalPoolManager::instance().clear_all_pools();
}

void force_garbage_collection() {
    // In C++, we don't have automatic garbage collection
    // This function would trigger cleanup of pooled resources
    GlobalPoolManager::instance().clear_all_pools();
}

size_t compact_memory_pools() {
    size_t total_freed = 0;
    
    // This would implement pool compaction logic
    // For now, we just get the current memory usage
    auto pool_stats = GlobalPoolManager::instance().get_all_statistics();
    
    for (const auto& stats : pool_stats) {
        // In a real implementation, we'd compact fragmented pools
        total_freed += stats.available_buffers * stats.buffer_size;
    }
    
    return total_freed;
}

} // namespace utils
} // namespace memory
} // namespace v13
} // namespace dtls