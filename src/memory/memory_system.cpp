#include <dtls/memory.h>
#include <dtls/error.h>
#include <mutex>
#include <atomic>
#include <iostream>
#include <algorithm>
#include <sstream>

namespace dtls {
namespace v13 {
namespace memory {

// Global state management
namespace {
    std::atomic<bool> g_memory_initialized{false};
    std::mutex g_memory_mutex;
    MemorySystemConfig g_memory_config;
    std::chrono::steady_clock::time_point g_initialization_time;
}

// System initialization
Result<void> initialize_memory_system() {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    
    if (g_memory_initialized.load()) {
        return Result<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    try {
        // Initialize default configuration
        g_memory_config = MemorySystemConfig{};
        
        // Configure default memory pools
        configure_default_pools();
        
        // Set up memory utilities configuration
        utils::MemoryConfig utils_config;
        utils_config.enable_statistics = g_memory_config.enable_pool_statistics;
        utils_config.enable_tracking = g_memory_config.enable_allocation_tracking;
        utils_config.enable_debugging = g_memory_config.enable_buffer_debugging;
        utils_config.enable_performance_monitoring = g_memory_config.enable_performance_monitoring;
        utils_config.max_total_memory = g_memory_config.max_total_memory;
        utils_config.warning_threshold = g_memory_config.warning_threshold;
        
        auto utils_result = utils::configure_memory_system(utils_config);
        if (!utils_result) {
            return utils_result;
        }
        
        // Configure global pool manager
        auto& pool_manager = GlobalPoolManager::instance();
        pool_manager.set_default_pool_size(g_memory_config.default_pool_size);
        
        g_initialization_time = std::chrono::steady_clock::now();
        g_memory_initialized.store(true);
        
        return Result<void>();
        
    } catch (const DTLSException& e) {
        return Result<void>(e.dtls_error());
    } catch (...) {
        return Result<void>(DTLSError::INTERNAL_ERROR);
    }
}

void cleanup_memory_system() {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    
    if (!g_memory_initialized.load()) {
        return;
    }
    
    try {
        // Clean up all pools
        cleanup_all_pools();
        
        // Clean up memory utilities
        utils::cleanup_memory_system();
        
        g_memory_initialized.store(false);
        
    } catch (...) {
        // Ignore cleanup errors
    }
}

bool is_memory_system_initialized() {
    return g_memory_initialized.load();
}

// Configuration management
Result<void> set_memory_system_config(const MemorySystemConfig& config) {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    
    if (!g_memory_initialized.load()) {
        return Result<void>(DTLSError::NOT_INITIALIZED);
    }
    
    try {
        g_memory_config = config;
        
        // Apply configuration changes
        auto& pool_manager = GlobalPoolManager::instance();
        pool_manager.set_default_pool_size(config.default_pool_size);
        
        // Update utilities configuration
        utils::MemoryConfig utils_config;
        utils_config.enable_statistics = config.enable_pool_statistics;
        utils_config.enable_tracking = config.enable_allocation_tracking;
        utils_config.enable_debugging = config.enable_buffer_debugging;
        utils_config.enable_performance_monitoring = config.enable_performance_monitoring;
        utils_config.max_total_memory = config.max_total_memory;
        utils_config.warning_threshold = config.warning_threshold;
        
        auto utils_result = utils::configure_memory_system(utils_config);
        if (!utils_result) {
            return utils_result;
        }
        
        // Configure debugging features
        if (config.enable_buffer_debugging) {
            debugging::enable_debugging(config.enable_guard_patterns, 
                                       config.enable_allocation_tracking,
                                       true);
        } else {
            debugging::disable_debugging();
        }
        
        return Result<void>();
        
    } catch (const DTLSException& e) {
        return Result<void>(e.dtls_error());
    } catch (...) {
        return Result<void>(DTLSError::INTERNAL_ERROR);
    }
}

MemorySystemConfig get_memory_system_config() {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    return g_memory_config;
}

void reset_memory_system_config() {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    g_memory_config = MemorySystemConfig{};
}

// System status
MemorySystemStatus get_memory_system_status() {
    std::lock_guard<std::mutex> lock(g_memory_mutex);
    
    MemorySystemStatus status;
    status.is_initialized = g_memory_initialized.load();
    
    if (!status.is_initialized) {
        return status;
    }
    
    // Get pool statistics
    auto& pool_manager = GlobalPoolManager::instance();
    auto pool_stats = pool_manager.get_all_statistics();
    
    status.total_pools = pool_stats.size();
    status.active_pools = pool_stats.size(); // All pools are considered active
    
    size_t total_pool_memory = 0;
    size_t total_utilization = 0;
    
    for (const auto& pool_stat : pool_stats) {
        size_t pool_memory = pool_stat.total_buffers * pool_stat.buffer_size;
        total_pool_memory += pool_memory;
        total_utilization += static_cast<size_t>(pool_stat.utilization_ratio * 100);
    }
    
    status.pool_memory_usage = total_pool_memory;
    
    if (!pool_stats.empty()) {
        status.average_pool_utilization = static_cast<double>(total_utilization) / pool_stats.size() / 100.0;
    }
    
    // Get memory statistics
    auto memory_stats = utils::MemoryStatsCollector::instance().get_statistics();
    status.total_memory_usage = memory_stats.current_bytes_allocated;
    status.direct_memory_usage = status.total_memory_usage - status.pool_memory_usage;
    status.active_allocations = memory_stats.current_allocations;
    status.peak_allocations = memory_stats.peak_allocations;
    
    status.initialization_time = g_initialization_time;
    auto now = std::chrono::steady_clock::now();
    status.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - g_initialization_time);
    
    return status;
}

// Health check
Result<MemoryHealthCheckResult> perform_memory_health_check() {
    auto start_time = std::chrono::steady_clock::now();
    
    MemoryHealthCheckResult result;
    result.check_time = start_time;
    
    if (!g_memory_initialized.load()) {
        result.overall_healthy = false;
        result.allocation_issues.push_back("Memory system not initialized");
        
        auto end_time = std::chrono::steady_clock::now();
        result.check_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        return Result<MemoryHealthCheckResult>(std::move(result));
    }
    
    // Check memory usage
    auto memory_health = utils::perform_memory_health_check();
    if (memory_health) {
        auto health_report = *memory_health;
        result.total_memory_usage = health_report.total_memory_usage;
        result.memory_leaks = health_report.memory_leaks;
        result.fragmentation_ratio = health_report.fragmentation_ratio;
        
        if (!health_report.overall_healthy) {
            result.overall_healthy = false;
            result.allocation_issues.insert(result.allocation_issues.end(),
                                          health_report.issues.begin(),
                                          health_report.issues.end());
        }
    }
    
    // Check pool health
    auto& pool_manager = GlobalPoolManager::instance();
    auto pool_stats = pool_manager.get_all_statistics();
    
    for (const auto& pool_stat : pool_stats) {
        // Check for pool issues
        if (pool_stat.allocation_failures > 0) {
            result.pool_issues.push_back(
                "Pool (size=" + std::to_string(pool_stat.buffer_size) + 
                ") has " + std::to_string(pool_stat.allocation_failures) + " allocation failures");
        }
        
        if (pool_stat.utilization_ratio > 0.9) {
            result.pool_issues.push_back(
                "Pool (size=" + std::to_string(pool_stat.buffer_size) + 
                ") has high utilization: " + std::to_string(pool_stat.utilization_ratio * 100) + "%");
        }
        
        if (pool_stat.available_buffers == 0 && pool_stat.total_buffers > 0) {
            result.pool_issues.push_back(
                "Pool (size=" + std::to_string(pool_stat.buffer_size) + 
                ") is completely exhausted");
        }
    }
    
    // Check performance
    auto perf_stats = utils::MemoryPerformanceMonitor::instance().get_all_stats();
    for (const auto& stat : perf_stats) {
        if (stat.average_time() > std::chrono::milliseconds(10)) {
            result.performance_issues.push_back(
                "Operation '" + stat.name + "' has slow average time: " +
                std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(stat.average_time()).count()) + "μs");
        }
    }
    
    // Overall health assessment
    result.overall_healthy = result.pool_issues.empty() && 
                           result.allocation_issues.empty() && 
                           result.performance_issues.empty() &&
                           result.memory_leaks == 0;
    
    auto end_time = std::chrono::steady_clock::now();
    result.check_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return Result<MemoryHealthCheckResult>(std::move(result));
}

// Self-tests
Result<MemoryTestResult> run_memory_self_tests() {
    auto start_time = std::chrono::steady_clock::now();
    
    MemoryTestResult result;
    
    if (!g_memory_initialized.load()) {
        result.all_tests_passed = false;
        result.failed_test_names.push_back("system_initialization");
        result.tests_run = 1;
        result.tests_failed = 1;
        
        auto end_time = std::chrono::steady_clock::now();
        result.total_test_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        return Result<MemoryTestResult>(std::move(result));
    }
    
    // Test buffer creation and basic operations
    try {
        auto buffer = create_buffer(1024);
        if (buffer && (*buffer)->capacity() >= 1024) {
            result.tests_passed++;
        } else {
            result.failed_test_names.push_back("buffer_creation");
            result.tests_failed++;
        }
        result.tests_run++;
    } catch (...) {
        result.failed_test_names.push_back("buffer_creation_exception");
        result.tests_failed++;
        result.tests_run++;
    }
    
    // Test pooled buffer creation
    try {
        auto pooled = create_pooled_buffer(512);
        if (pooled && pooled->is_valid() && pooled->buffer().capacity() >= 512) {
            result.tests_passed++;
        } else {
            result.failed_test_names.push_back("pooled_buffer_creation");
            result.tests_failed++;
        }
        result.tests_run++;
    } catch (...) {
        result.failed_test_names.push_back("pooled_buffer_creation_exception");
        result.tests_failed++;
        result.tests_run++;
    }
    
    // Test buffer operations
    try {
        ZeroCopyBuffer test_buffer(256);
        std::vector<std::byte> test_data(100, std::byte{0xAB});
        
        auto append_result = test_buffer.append(test_data.data(), test_data.size());
        if (append_result && test_buffer.size() == 100) {
            result.tests_passed++;
        } else {
            result.failed_test_names.push_back("buffer_append");
            result.tests_failed++;
        }
        result.tests_run++;
    } catch (...) {
        result.failed_test_names.push_back("buffer_operations_exception");
        result.tests_failed++;
        result.tests_run++;
    }
    
    // Test memory pool operations
    try {
        auto& pool_manager = GlobalPoolManager::instance();
        auto create_result = pool_manager.create_pool(128, 16);
        
        if (create_result) {
            auto& pool = pool_manager.get_pool(128);
            auto pool_buffer = pool.acquire();
            
            if (pool_buffer && pool_buffer->capacity() == 128) {
                result.tests_passed++;
                pool.release(std::move(pool_buffer));
            } else {
                result.failed_test_names.push_back("pool_buffer_acquisition");
                result.tests_failed++;
            }
        } else {
            result.failed_test_names.push_back("pool_creation");
            result.tests_failed++;
        }
        result.tests_run++;
    } catch (...) {
        result.failed_test_names.push_back("pool_operations_exception");
        result.tests_failed++;
        result.tests_run++;
    }
    
    // Test buffer views
    try {
        ZeroCopyBuffer test_buffer(64);
        test_buffer.resize(32);
        
        BufferView view(test_buffer);
        if (view.size() == 32) {
            result.tests_passed++;
        } else {
            result.failed_test_names.push_back("buffer_view");
            result.tests_failed++;
        }
        result.tests_run++;
    } catch (...) {
        result.failed_test_names.push_back("buffer_view_exception");
        result.tests_failed++;
        result.tests_run++;
    }
    
    result.all_tests_passed = (result.tests_failed == 0);
    
    auto end_time = std::chrono::steady_clock::now();
    result.total_test_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return Result<MemoryTestResult>(std::move(result));
}

// Optimization namespace implementation
namespace optimization {

size_t optimize_memory_pools() {
    auto& pool_manager = GlobalPoolManager::instance();
    auto pool_stats = pool_manager.get_all_statistics();
    
    size_t optimized_count = 0;
    
    for (const auto& stats : pool_stats) {
        // If utilization is very low, shrink the pool
        if (stats.utilization_ratio < 0.1 && stats.total_buffers > 4) {
            auto& pool = pool_manager.get_pool(stats.buffer_size);
            size_t target_size = std::max(static_cast<size_t>(4), stats.total_buffers / 2);
            
            auto shrink_result = pool.shrink_pool(target_size);
            if (shrink_result) {
                optimized_count++;
            }
        }
        // If utilization is very high, expand the pool
        else if (stats.utilization_ratio > 0.9 && stats.allocation_failures > 0) {
            auto& pool = pool_manager.get_pool(stats.buffer_size);
            size_t additional = std::max(static_cast<size_t>(4), stats.total_buffers / 4);
            
            auto expand_result = pool.expand_pool(additional);
            if (expand_result) {
                optimized_count++;
            }
        }
    }
    
    return optimized_count;
}

size_t compact_memory() {
    return utils::compact_memory_pools();
}

Result<void> preload_pools(const std::vector<std::pair<size_t, size_t>>& usage_hints) {
    auto& pool_manager = GlobalPoolManager::instance();
    
    for (const auto& [buffer_size, expected_count] : usage_hints) {
        if (buffer_size == 0 || expected_count == 0) {
            continue;
        }
        
        // Create or expand pool to expected size
        auto create_result = pool_manager.create_pool(buffer_size, expected_count);
        if (!create_result && create_result.error() != DTLSError::ALREADY_INITIALIZED) {
            return create_result;
        }
        
        // If pool already exists, expand it if needed
        if (create_result.error() == DTLSError::ALREADY_INITIALIZED) {
            auto& pool = pool_manager.get_pool(buffer_size);
            if (pool.total_buffers() < expected_count) {
                size_t additional = expected_count - pool.total_buffers();
                auto expand_result = pool.expand_pool(additional);
                if (!expand_result) {
                    return expand_result;
                }
            }
        }
    }
    
    return Result<void>();
}

size_t predict_memory_usage(std::chrono::minutes time_horizon) {
    // Simple prediction based on current usage trends
    auto memory_stats = utils::MemoryStatsCollector::instance().get_statistics();
    size_t current_usage = memory_stats.current_bytes_allocated;
    
    // Calculate usage rate (bytes per minute)
    auto uptime = std::chrono::steady_clock::now() - memory_stats.start_time;
    auto uptime_minutes = std::chrono::duration_cast<std::chrono::minutes>(uptime);
    
    if (uptime_minutes.count() == 0) {
        return current_usage; // No trend data available
    }
    
    double usage_rate = static_cast<double>(current_usage) / uptime_minutes.count();
    size_t predicted_usage = current_usage + static_cast<size_t>(usage_rate * time_horizon.count());
    
    return predicted_usage;
}

} // namespace optimization

// Debugging namespace implementation
namespace debugging {

void enable_debugging(bool enable_guards, bool enable_tracking, bool enable_validation) {
    utils::MemoryStatsCollector::instance().enable_tracking(enable_tracking);
    utils::MemoryDebugger::instance().enable_guard_patterns(enable_guards);
    utils::MemoryPerformanceMonitor::instance().enable_monitoring(true);
}

void disable_debugging() {
    utils::MemoryStatsCollector::instance().enable_tracking(false);
    utils::MemoryDebugger::instance().enable_guard_patterns(false);
    utils::MemoryPerformanceMonitor::instance().enable_monitoring(false);
}

std::string generate_memory_report(bool include_details) {
    std::stringstream report;
    
    report << "=== DTLS Memory System Report ===\n";
    
    auto status = get_memory_system_status();
    report << "System Status:\n";
    report << "  Initialized: " << (status.is_initialized ? "Yes" : "No") << "\n";
    report << "  Total Memory Usage: " << status.total_memory_usage << " bytes\n";
    report << "  Pool Memory Usage: " << status.pool_memory_usage << " bytes\n";
    report << "  Direct Memory Usage: " << status.direct_memory_usage << " bytes\n";
    report << "  Active Allocations: " << status.active_allocations << "\n";
    report << "  Peak Allocations: " << status.peak_allocations << "\n";
    report << "  Total Pools: " << status.total_pools << "\n";
    report << "  Average Pool Utilization: " << (status.average_pool_utilization * 100) << "%\n";
    
    if (include_details) {
        report << "\nPool Details:\n";
        auto& pool_manager = GlobalPoolManager::instance();
        auto pool_stats = pool_manager.get_all_statistics();
        
        for (const auto& stats : pool_stats) {
            report << "  Pool (size=" << stats.buffer_size << "):\n";
            report << "    Total Buffers: " << stats.total_buffers << "\n";
            report << "    Available Buffers: " << stats.available_buffers << "\n";
            report << "    Peak Usage: " << stats.peak_usage << "\n";
            report << "    Utilization: " << (stats.utilization_ratio * 100) << "%\n";
            report << "    Allocations: " << stats.total_allocations << "\n";
            report << "    Failures: " << stats.allocation_failures << "\n";
        }
        
        report << "\nPerformance Statistics:\n";
        auto perf_stats = utils::MemoryPerformanceMonitor::instance().get_all_stats();
        for (const auto& stat : perf_stats) {
            report << "  " << stat.name << ":\n";
            report << "    Count: " << stat.count << "\n";
            report << "    Average Time: " << 
                std::chrono::duration_cast<std::chrono::microseconds>(stat.average_time()).count() << "μs\n";
            report << "    Min Time: " << 
                std::chrono::duration_cast<std::chrono::microseconds>(stat.min_time).count() << "μs\n";
            report << "    Max Time: " << 
                std::chrono::duration_cast<std::chrono::microseconds>(stat.max_time).count() << "μs\n";
        }
    }
    
    report << "=== End Report ===\n";
    
    return report.str();
}

size_t validate_all_buffers() {
    // In a real implementation, this would validate all tracked buffers
    // For now, return 0 errors
    return 0;
}

void dump_memory_statistics(std::ostream& output) {
    output << generate_memory_report(true);
}

} // namespace debugging

// Factory functions
Result<PooledBuffer> create_pooled_buffer(size_t size) {
    try {
        PooledBuffer buffer(size);
        if (buffer.is_valid()) {
            return Result<PooledBuffer>(std::move(buffer));
        } else {
            return Result<PooledBuffer>(DTLSError::OUT_OF_MEMORY);
        }
    } catch (...) {
        return Result<PooledBuffer>(DTLSError::OUT_OF_MEMORY);
    }
}

Result<BufferPtr> create_buffer(size_t size) {
    try {
        auto buffer = make_buffer(size);
        if (buffer) {
            return Result<BufferPtr>(std::move(buffer));
        } else {
            return Result<BufferPtr>(DTLSError::OUT_OF_MEMORY);
        }
    } catch (...) {
        return Result<BufferPtr>(DTLSError::OUT_OF_MEMORY);
    }
}

Result<BufferPtr> create_aligned_buffer(size_t size, size_t alignment) {
    // For simplicity, create a regular buffer (alignment would be implemented in a real system)
    return create_buffer(utils::align_size(size, alignment));
}

// Buffer operation helpers
Result<BufferPtr> clone_buffer(const BufferView& source) {
    auto copy_result = utils::copy_buffer(source);
    if (!copy_result) {
        return Result<BufferPtr>(copy_result.error());
    }
    return Result<BufferPtr>(std::make_unique<ZeroCopyBuffer>(std::move(*copy_result)));
}

Result<BufferPtr> merge_buffers(const std::vector<BufferView>& buffers) {
    auto concat_result = utils::concat_buffers(buffers);
    if (!concat_result) {
        return Result<BufferPtr>(concat_result.error());
    }
    return Result<BufferPtr>(std::make_unique<ZeroCopyBuffer>(std::move(*concat_result)));
}

Result<std::vector<BufferPtr>> split_buffer(const BufferView& source, 
                                           const std::vector<size_t>& split_points) {
    std::vector<BufferPtr> result;
    
    if (split_points.empty()) {
        auto clone_result = clone_buffer(source);
        if (clone_result) {
            result.push_back(std::move(*clone_result));
        } else {
            return Result<std::vector<BufferPtr>>(clone_result.error());
        }
        return Result<std::vector<BufferPtr>>(std::move(result));
    }
    
    size_t offset = 0;
    for (size_t split_point : split_points) {
        if (split_point <= offset || split_point > source.size()) {
            return Result<std::vector<BufferPtr>>(DTLSError::INVALID_PARAMETER);
        }
        
        auto slice = source.slice(offset, split_point - offset);
        auto clone_result = clone_buffer(slice);
        if (!clone_result) {
            return Result<std::vector<BufferPtr>>(clone_result.error());
        }
        
        result.push_back(std::move(*clone_result));
        offset = split_point;
    }
    
    // Add remaining data
    if (offset < source.size()) {
        auto slice = source.slice(offset, source.size() - offset);
        auto clone_result = clone_buffer(slice);
        if (!clone_result) {
            return Result<std::vector<BufferPtr>>(clone_result.error());
        }
        result.push_back(std::move(*clone_result));
    }
    
    return Result<std::vector<BufferPtr>>(std::move(result));
}

// Security-focused operations
Result<BufferPtr> create_secure_buffer(size_t size) {
    auto buffer_result = create_buffer(size);
    if (buffer_result) {
        (*buffer_result)->secure_zero();
        return buffer_result;
    }
    return buffer_result;
}

void secure_clear_buffer(Buffer& buffer) {
    buffer.secure_zero();
}

bool compare_buffers_secure(const BufferView& a, const BufferView& b) {
    return utils::secure_compare(a.data(), b.data(), std::min(a.size(), b.size()));
}

// High-level operations
void trigger_garbage_collection() {
    utils::force_garbage_collection();
}

size_t get_total_memory_usage() {
    auto stats = utils::MemoryStatsCollector::instance().get_statistics();
    return stats.current_bytes_allocated;
}

size_t get_available_memory() {
    auto config = get_memory_system_config();
    size_t used = get_total_memory_usage();
    return (used < config.max_total_memory) ? (config.max_total_memory - used) : 0;
}

double get_memory_fragmentation_ratio() {
    auto health_result = utils::perform_memory_health_check();
    return health_result ? health_result->fragmentation_ratio : 0.0;
}

} // namespace memory
} // namespace v13
} // namespace dtls