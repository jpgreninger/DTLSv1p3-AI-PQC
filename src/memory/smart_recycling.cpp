#include <dtls/memory/smart_recycling.h>
#include <dtls/error.h>
#include <algorithm>
#include <thread>
#include <cmath>

namespace dtls {
namespace v13 {
namespace memory {

// BufferRecyclingManager implementation
BufferRecyclingManager::BufferRecyclingManager() {
    // Initialize with reasonable defaults
    recycling_stats_.last_optimization = std::chrono::steady_clock::now();
}

BufferRecyclingManager& BufferRecyclingManager::instance() {
    static BufferRecyclingManager instance;
    return instance;
}

void BufferRecyclingManager::track_buffer_usage(size_t buffer_size, 
                                               std::chrono::steady_clock::time_point access_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto& stats = usage_stats_[buffer_size];
    if (stats.buffer_size == 0) {
        stats.buffer_size = buffer_size;
        stats.last_access = access_time;
    }
    
    stats.total_accesses++;
    stats.recent_accesses++;
    
    // Calculate access frequency (accesses per minute)
    auto time_diff = access_time - stats.last_access;
    auto minutes_diff = std::chrono::duration_cast<std::chrono::minutes>(time_diff).count();
    if (minutes_diff > 0) {
        stats.access_frequency = static_cast<double>(stats.recent_accesses) / minutes_diff;
        stats.is_trending_up = stats.access_frequency > (stats.total_accesses / 
            std::max(1.0, static_cast<double>(std::chrono::duration_cast<std::chrono::minutes>(
            access_time.time_since_epoch()).count())));
    }
    
    stats.last_access = access_time;
    update_usage_stats(buffer_size);
}

void BufferRecyclingManager::register_buffer_death(size_t buffer_size, 
                                                  std::chrono::steady_clock::time_point death_time) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto it = usage_stats_.find(buffer_size);
    if (it != usage_stats_.end()) {
        auto& stats = it->second;
        auto lifetime = death_time - stats.last_access;
        auto lifetime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(lifetime);
        
        // Update average lifetime using exponential moving average
        if (stats.average_lifetime.count() == 0) {
            stats.average_lifetime = lifetime_ms;
        } else {
            auto alpha = 0.1; // Smoothing factor
            stats.average_lifetime = std::chrono::milliseconds(
                static_cast<long long>(alpha * lifetime_ms.count() + 
                (1.0 - alpha) * stats.average_lifetime.count()));
        }
        
        stats.utilization_score = calculate_utilization_score(stats);
    }
}

bool BufferRecyclingManager::should_recycle_buffer(size_t buffer_size) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto it = usage_stats_.find(buffer_size);
    if (it == usage_stats_.end()) {
        // No usage data, use conservative approach
        return buffer_size <= 4096; // Recycle buffers up to 4KB by default
    }
    
    const auto& stats = it->second;
    double threshold = recycling_threshold_.load();
    
    if (aggressive_recycling_.load()) {
        threshold *= 0.5; // Lower threshold for aggressive recycling
    }
    
    return stats.utilization_score > threshold;
}

size_t BufferRecyclingManager::get_optimal_pool_size(size_t buffer_size) const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    auto it = usage_stats_.find(buffer_size);
    if (it == usage_stats_.end()) {
        return 16; // Default pool size
    }
    
    const auto& stats = it->second;
    
    // Base pool size on recent access frequency and utilization score
    double base_size = std::max(4.0, stats.access_frequency * 2.0);
    double utilization_multiplier = 1.0 + stats.utilization_score;
    
    // Trending buffers get larger pools
    if (stats.is_trending_up) {
        utilization_multiplier *= 1.5;
    }
    
    size_t optimal_size = static_cast<size_t>(base_size * utilization_multiplier);
    
    // Clamp to reasonable bounds
    return std::clamp(optimal_size, static_cast<size_t>(4), static_cast<size_t>(128));
}

std::vector<BufferRecyclingManager::BufferUsageStats> 
BufferRecyclingManager::get_usage_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    std::vector<BufferUsageStats> stats;
    stats.reserve(usage_stats_.size());
    
    for (const auto& [size, usage_stats] : usage_stats_) {
        stats.push_back(usage_stats);
    }
    
    // Sort by utilization score in descending order
    std::sort(stats.begin(), stats.end(), 
              [](const BufferUsageStats& a, const BufferUsageStats& b) {
                  return a.utilization_score > b.utilization_score;
              });
    
    return stats;
}

void BufferRecyclingManager::optimize_pools_based_on_usage() {
    if (!should_optimize_pools()) {
        return;
    }
    
    auto& pool_manager = GlobalPoolManager::instance();
    size_t pools_optimized = 0;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    for (const auto& [buffer_size, stats] : usage_stats_) {
        if (should_recycle_buffer(buffer_size)) {
            size_t optimal_size = get_optimal_pool_size(buffer_size);
            
            // Check if pool exists and needs adjustment
            auto pool_result = pool_manager.create_pool(buffer_size, optimal_size);
            if (pool_result || pool_result.error() == DTLSError::ALREADY_INITIALIZED) {
                auto& pool = pool_manager.get_pool(buffer_size);
                
                // Adjust pool size based on utilization
                if (stats.utilization_score > 0.8 && pool.total_buffers() < optimal_size) {
                    pool.expand_pool(optimal_size - pool.total_buffers());
                    pools_optimized++;
                } else if (stats.utilization_score < 0.2 && pool.total_buffers() > 4) {
                    pool.shrink_pool(std::max(static_cast<size_t>(4), optimal_size));
                    pools_optimized++;
                }
            }
        }
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(recycling_stats_mutex_);
        recycling_stats_.pools_optimized += pools_optimized;
        recycling_stats_.last_optimization = std::chrono::steady_clock::now();
        
        // Calculate average utilization
        if (!usage_stats_.empty()) {
            double total_utilization = 0.0;
            for (const auto& [size, stats] : usage_stats_) {
                total_utilization += stats.utilization_score;
            }
            recycling_stats_.average_utilization = total_utilization / usage_stats_.size();
        }
    }
    
    // Cleanup old statistics
    cleanup_old_stats();
}

void BufferRecyclingManager::handle_memory_pressure() {
    enable_aggressive_recycling(true);
    
    // Optimize all pools immediately
    optimize_pools_based_on_usage();
    
    // Force cleanup of low-utilization pools
    auto& pool_manager = GlobalPoolManager::instance();
    auto pool_stats = pool_manager.get_all_statistics();
    
    size_t pools_cleaned = 0;
    for (const auto& stats : pool_stats) {
        if (stats.utilization_ratio < 0.1 && stats.available_buffers > 2) {
            auto& pool = pool_manager.get_pool(stats.buffer_size);
            pool.shrink_pool(2); // Keep minimal pool
            pools_cleaned++;
        }
    }
    
    std::lock_guard<std::mutex> lock(recycling_stats_mutex_);
    recycling_stats_.pools_optimized += pools_cleaned;
}

BufferRecyclingManager::RecyclingStats 
BufferRecyclingManager::get_recycling_statistics() const {
    std::lock_guard<std::mutex> lock(recycling_stats_mutex_);
    return recycling_stats_;
}

void BufferRecyclingManager::reset_statistics() {
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        usage_stats_.clear();
    }
    
    {
        std::lock_guard<std::mutex> lock(recycling_stats_mutex_);
        recycling_stats_ = RecyclingStats{};
        recycling_stats_.last_optimization = std::chrono::steady_clock::now();
    }
}

void BufferRecyclingManager::update_usage_stats(size_t buffer_size) {
    // This method is called with stats_mutex_ already locked
    auto it = usage_stats_.find(buffer_size);
    if (it != usage_stats_.end()) {
        auto& stats = it->second;
        stats.utilization_score = calculate_utilization_score(stats);
    }
}

double BufferRecyclingManager::calculate_utilization_score(const BufferUsageStats& stats) const {
    if (stats.total_accesses == 0) {
        return 0.0;
    }
    
    // Combine multiple factors into utilization score
    double frequency_score = std::min(1.0, stats.access_frequency / 10.0); // Normalize to [0,1]
    double recency_score = 1.0;
    
    auto now = std::chrono::steady_clock::now();
    auto time_since_access = now - stats.last_access;
    auto minutes_since = std::chrono::duration_cast<std::chrono::minutes>(time_since_access).count();
    
    if (minutes_since > 0) {
        // Exponential decay based on recency
        recency_score = std::exp(-minutes_since / 60.0); // Decay over 1 hour
    }
    
    double lifetime_score = 0.5; // Default
    if (stats.average_lifetime.count() > 0) {
        // Longer lived buffers are more valuable for pooling
        lifetime_score = std::min(1.0, stats.average_lifetime.count() / 60000.0); // Normalize to 1 minute
    }
    
    double trending_bonus = stats.is_trending_up ? 0.2 : 0.0;
    
    // Weighted combination
    return (0.4 * frequency_score + 0.3 * recency_score + 0.2 * lifetime_score + trending_bonus);
}

void BufferRecyclingManager::cleanup_old_stats() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - (usage_window_ * 2); // Keep stats for 2x the usage window
    
    auto it = usage_stats_.begin();
    while (it != usage_stats_.end()) {
        if (it->second.last_access < cutoff && it->second.total_accesses < 5) {
            // Remove infrequently used old stats
            it = usage_stats_.erase(it);
        } else {
            // Reset recent access counter for active stats
            it->second.recent_accesses = 0;
            ++it;
        }
    }
}

bool BufferRecyclingManager::should_optimize_pools() const {
    auto now = std::chrono::steady_clock::now();
    auto time_since_last = now - recycling_stats_.last_optimization;
    
    // Optimize every 5 minutes, or immediately under memory pressure
    return time_since_last > std::chrono::minutes(5) || aggressive_recycling_.load();
}

// SmartBufferFactory implementation
SmartBufferFactory& SmartBufferFactory::instance() {
    static SmartBufferFactory instance;
    return instance;
}

PooledBuffer SmartBufferFactory::create_smart_buffer(size_t size) {
    auto& recycling_manager = BufferRecyclingManager::instance();
    
    // Track buffer creation for recycling analysis
    recycling_manager.track_buffer_usage(size, std::chrono::steady_clock::now());
    
    // Optimize size if enabled
    size_t optimized_size = size;
    if (size_optimization_enabled_.load()) {
        optimized_size = optimize_buffer_size(size);
        
        if (optimized_size != size) {
            std::lock_guard<std::mutex> lock(factory_stats_mutex_);
            factory_stats_.optimizations_applied++;
            factory_stats_.memory_saved_by_optimization += (optimized_size - size);
        }
    }
    
    // Recommend buffer type
    BufferType recommended_type = recommend_buffer_type(optimized_size);
    
    PooledBuffer buffer(optimized_size);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(factory_stats_mutex_);
        if (recommended_type == BufferType::POOLED) {
            factory_stats_.pooled_buffers_created++;
        }
        
        // Calculate hit rate (successful pooled buffer creation)
        size_t total_created = factory_stats_.pooled_buffers_created + 
                              factory_stats_.direct_buffers_created + 
                              factory_stats_.shared_buffers_created;
        if (total_created > 0) {
            factory_stats_.hit_rate = static_cast<double>(factory_stats_.pooled_buffers_created) / total_created;
        }
    }
    
    return buffer;
}

std::unique_ptr<ZeroCopyBuffer> SmartBufferFactory::create_optimized_buffer(size_t size) {
    auto& recycling_manager = BufferRecyclingManager::instance();
    
    // Track buffer creation
    recycling_manager.track_buffer_usage(size, std::chrono::steady_clock::now());
    
    // Optimize size
    size_t optimized_size = optimize_buffer_size(size);
    
    // Check if we should use shared buffer
    bool use_shared = should_use_shared_buffer(optimized_size, false);
    
    std::unique_ptr<ZeroCopyBuffer> buffer;
    
    if (use_shared && recycling_manager.should_recycle_buffer(optimized_size)) {
        // Try to get from pool first
        auto& pool_manager = GlobalPoolManager::instance();
        auto& pool = pool_manager.get_pool(optimized_size);
        auto pooled_buffer = pool.acquire();
        
        if (pooled_buffer) {
            buffer = std::move(pooled_buffer);
            
            std::lock_guard<std::mutex> lock(factory_stats_mutex_);
            factory_stats_.shared_buffers_created++;
        }
    }
    
    if (!buffer) {
        // Fallback to direct allocation
        buffer = std::make_unique<ZeroCopyBuffer>(optimized_size);
        
        std::lock_guard<std::mutex> lock(factory_stats_mutex_);
        factory_stats_.direct_buffers_created++;
    }
    
    return buffer;
}

SmartBufferFactory::BufferType SmartBufferFactory::recommend_buffer_type(size_t size, bool likely_to_share) const {
    auto& recycling_manager = BufferRecyclingManager::instance();
    
    if (likely_to_share) {
        return BufferType::SHARED;
    }
    
    if (recycling_manager.should_recycle_buffer(size)) {
        return BufferType::POOLED;
    }
    
    // Large buffers or infrequently used sizes use direct allocation
    if (size > 16384) { // > 16KB
        return BufferType::DIRECT;
    }
    
    return analyze_usage_pattern(size);
}

size_t SmartBufferFactory::optimize_buffer_size(size_t requested_size) const {
    if (!size_optimization_enabled_.load()) {
        return requested_size;
    }
    
    // Round up to optimal sizes that align with common allocation patterns
    size_t optimized = round_to_optimal_size(requested_size);
    
    // Don't optimize if the increase is too large
    double increase_ratio = static_cast<double>(optimized - requested_size) / requested_size;
    if (increase_ratio > optimization_threshold_.load()) {
        return requested_size;
    }
    
    return optimized;
}

size_t SmartBufferFactory::predict_memory_usage(size_t connection_count, 
                                               std::chrono::minutes time_window) const {
    auto& recycling_manager = BufferRecyclingManager::instance();
    auto usage_stats = recycling_manager.get_usage_statistics();
    
    size_t predicted_usage = 0;
    
    for (const auto& stats : usage_stats) {
        // Estimate buffers per connection based on access frequency
        double buffers_per_connection = stats.access_frequency * time_window.count();
        size_t total_buffers = static_cast<size_t>(buffers_per_connection * connection_count);
        
        predicted_usage += total_buffers * stats.buffer_size;
    }
    
    return predicted_usage;
}

SmartBufferFactory::FactoryStats SmartBufferFactory::get_factory_statistics() const {
    std::lock_guard<std::mutex> lock(factory_stats_mutex_);
    return factory_stats_;
}

void SmartBufferFactory::reset_statistics() {
    std::lock_guard<std::mutex> lock(factory_stats_mutex_);
    factory_stats_ = FactoryStats{};
}

SmartBufferFactory::BufferType SmartBufferFactory::analyze_usage_pattern(size_t size) const {
    auto& recycling_manager = BufferRecyclingManager::instance();
    auto usage_stats = recycling_manager.get_usage_statistics();
    
    // Find stats for this buffer size
    for (const auto& stats : usage_stats) {
        if (stats.buffer_size == size) {
            if (stats.utilization_score > 0.7) {
                return BufferType::POOLED;
            } else if (stats.access_frequency > 5.0) { // > 5 accesses per minute
                return BufferType::SHARED;
            }
            break;
        }
    }
    
    return BufferType::DIRECT;
}

size_t SmartBufferFactory::round_to_optimal_size(size_t size) const {
    // Common optimal sizes for DTLS operations
    static const std::vector<size_t> optimal_sizes = {
        32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
    };
    
    // Find the smallest optimal size that's >= requested size
    auto it = std::lower_bound(optimal_sizes.begin(), optimal_sizes.end(), size);
    
    if (it != optimal_sizes.end()) {
        return *it;
    }
    
    // For very large sizes, round up to nearest multiple of 4KB
    return ((size + 4095) / 4096) * 4096;
}

bool SmartBufferFactory::should_use_shared_buffer(size_t size, bool likely_to_share) const {
    if (likely_to_share) {
        return true;
    }
    
    // Use shared buffers for medium-sized buffers that are frequently accessed
    auto& recycling_manager = BufferRecyclingManager::instance();
    auto usage_stats = recycling_manager.get_usage_statistics();
    
    for (const auto& stats : usage_stats) {
        if (stats.buffer_size == size) {
            return stats.access_frequency > 3.0 && size >= 256 && size <= 4096;
        }
    }
    
    return false;
}

// MemoryPressureDetector implementation
MemoryPressureDetector& MemoryPressureDetector::instance() {
    static MemoryPressureDetector instance;
    return instance;
}

MemoryPressureDetector::PressureLevel MemoryPressureDetector::detect_memory_pressure() const {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    return current_stats_.current_level;
}

void MemoryPressureDetector::update_memory_statistics(size_t current_usage, size_t available_memory) {
    double usage_ratio = 0.0;
    if (available_memory > 0) {
        usage_ratio = static_cast<double>(current_usage) / available_memory;
    }
    
    PressureLevel new_level = calculate_pressure_level(usage_ratio);
    
    {
        std::lock_guard<std::mutex> lock(pressure_mutex_);
        
        PressureLevel old_level = current_stats_.current_level;
        current_stats_.current_level = new_level;
        current_stats_.current_memory_usage = current_usage;
        current_stats_.available_memory = available_memory;
        current_stats_.usage_ratio = usage_ratio;
        
        if (new_level != PressureLevel::NONE && new_level != old_level) {
            current_stats_.pressure_events++;
            current_stats_.last_pressure_event = std::chrono::steady_clock::now();
            
            // Trigger callbacks outside of lock to avoid deadlocks
            trigger_pressure_callbacks(new_level);
        }
    }
}

void MemoryPressureDetector::register_pressure_callback(const std::string& name, PressureCallback callback) {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    pressure_callbacks_[name] = callback;
}

void MemoryPressureDetector::unregister_pressure_callback(const std::string& name) {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    pressure_callbacks_.erase(name);
}

void MemoryPressureDetector::set_pressure_thresholds(double low, double medium, double high, double critical) {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    thresholds_.low = std::clamp(low, 0.0, 1.0);
    thresholds_.medium = std::clamp(medium, 0.0, 1.0);
    thresholds_.high = std::clamp(high, 0.0, 1.0);
    thresholds_.critical = std::clamp(critical, 0.0, 1.0);
}

MemoryPressureDetector::PressureThresholds MemoryPressureDetector::get_pressure_thresholds() const {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    return thresholds_;
}

MemoryPressureDetector::PressureStats MemoryPressureDetector::get_pressure_statistics() const {
    std::lock_guard<std::mutex> lock(pressure_mutex_);
    return current_stats_;
}

void MemoryPressureDetector::trigger_pressure_callbacks(PressureLevel level) {
    // Create a copy of callbacks to avoid holding lock during callback execution
    std::unordered_map<std::string, PressureCallback> callbacks_copy;
    {
        std::lock_guard<std::mutex> lock(pressure_mutex_);
        callbacks_copy = pressure_callbacks_;
    }
    
    for (const auto& [name, callback] : callbacks_copy) {
        try {
            callback(level);
        } catch (...) {
            // Ignore callback exceptions to prevent cascade failures
        }
    }
}

MemoryPressureDetector::PressureLevel MemoryPressureDetector::calculate_pressure_level(double usage_ratio) const {
    if (usage_ratio >= thresholds_.critical) {
        return PressureLevel::CRITICAL;
    } else if (usage_ratio >= thresholds_.high) {
        return PressureLevel::HIGH;
    } else if (usage_ratio >= thresholds_.medium) {
        return PressureLevel::MEDIUM;
    } else if (usage_ratio >= thresholds_.low) {
        return PressureLevel::LOW;
    }
    
    return PressureLevel::NONE;
}

// Factory functions implementation
PooledBuffer make_smart_buffer(size_t size) {
    return SmartBufferFactory::instance().create_smart_buffer(size);
}

std::unique_ptr<ZeroCopyBuffer> make_optimized_buffer(size_t size) {
    return SmartBufferFactory::instance().create_optimized_buffer(size);
}

void configure_smart_pools() {
    // Configure default pools first
    configure_default_pools();
    
    // Set up smart recycling system
    auto& recycling_manager = BufferRecyclingManager::instance();
    recycling_manager.set_recycling_threshold(0.3);
    recycling_manager.set_usage_window(std::chrono::minutes(30));
    
    // Set up memory pressure detection
    auto& pressure_detector = MemoryPressureDetector::instance();
    pressure_detector.set_pressure_thresholds(0.7, 0.8, 0.9, 0.95);
    
    // Register pressure callback to trigger aggressive recycling
    pressure_detector.register_pressure_callback("recycling_manager", 
        [&recycling_manager](MemoryPressureDetector::PressureLevel level) {
            if (level >= MemoryPressureDetector::PressureLevel::MEDIUM) {
                recycling_manager.handle_memory_pressure();
            } else {
                recycling_manager.enable_aggressive_recycling(false);
            }
        });
}

void enable_smart_recycling(bool enabled) {
    auto& recycling_manager = BufferRecyclingManager::instance();
    if (enabled) {
        // Start optimization thread (simplified - in real implementation would be more sophisticated)
        recycling_manager.optimize_pools_based_on_usage();
    }
}

void optimize_all_pools() {
    BufferRecyclingManager::instance().optimize_pools_based_on_usage();
}

void enable_memory_pressure_monitoring(bool enabled) {
    auto& detector = MemoryPressureDetector::instance();
    detector.enable_auto_monitoring(enabled);
}

MemoryPressureDetector::PressureLevel get_current_memory_pressure() {
    return MemoryPressureDetector::instance().detect_memory_pressure();
}

void handle_memory_pressure() {
    BufferRecyclingManager::instance().handle_memory_pressure();
}

} // namespace memory
} // namespace v13
} // namespace dtls