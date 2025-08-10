#include <dtls/memory/connection_pools.h>
#include <dtls/memory/adaptive_pools.h>
#include <dtls/memory/leak_detection.h>
#include <dtls/error.h>
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace dtls {
namespace v13 {
namespace memory {

// ConnectionPool implementation
ConnectionPool::ConnectionPool(void* connection_id, const ConnectionCharacteristics& characteristics)
    : connection_id_(connection_id)
    , characteristics_(characteristics) {
    
    create_specialized_pools();
    
    // Initialize statistics
    current_stats_.buffers_in_use = 0;
    current_stats_.pool_hits = 0;
    current_stats_.pool_misses = 0;
    
    // Register with leak detection system
    if (is_leak_detection_enabled()) {
        LeakDetector::instance().track_resource(
            this, ResourceType::MEMORY_POOL, sizeof(*this),
            "ConnectionPool", "Per-connection memory pool");
    }
}

ConnectionPool::~ConnectionPool() {
    if (is_leak_detection_enabled()) {
        LeakDetector::instance().untrack_resource(this);
    }
}

std::unique_ptr<ZeroCopyBuffer> ConnectionPool::acquire_buffer(size_t size) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<ZeroCopyBuffer> buffer;
    
    // Try to get from size-specific pool first
    auto pool_it = size_specific_pools_.find(size);
    if (pool_it != size_specific_pools_.end()) {
        buffer = pool_it->second->acquire();
        if (buffer) {
            std::lock_guard<std::mutex> lock(usage_mutex_);
            current_stats_.pool_hits++;
        }
    }
    
    // If no buffer from pool, create new one
    if (!buffer) {
        // Check if we should create a dedicated pool for this size
        if (should_create_dedicated_pool(size)) {
            size_t pool_size = calculate_optimal_pool_size(size);
            auto new_pool = std::make_unique<BufferPool>(size, pool_size);
            buffer = new_pool->acquire();
            size_specific_pools_[size] = std::move(new_pool);
        } else {
            buffer = std::make_unique<ZeroCopyBuffer>(size);
        }
        
        std::lock_guard<std::mutex> lock(usage_mutex_);
        current_stats_.pool_misses++;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(usage_mutex_);
        current_stats_.total_buffers_allocated++;
        current_stats_.buffers_in_use++;
        current_memory_usage_ += size;
        
        allocation_times_.push_back(std::chrono::steady_clock::now());
        allocation_durations_.push_back(duration);
        
        // Calculate running average
        auto total_time = current_stats_.average_acquire_time.count() * (current_stats_.total_buffers_allocated - 1);
        current_stats_.average_acquire_time = std::chrono::nanoseconds(
            (total_time + duration.count()) / current_stats_.total_buffers_allocated);
        
        // Update hit rate
        size_t total_requests = current_stats_.pool_hits + current_stats_.pool_misses;
        current_stats_.hit_rate = total_requests > 0 ? 
            static_cast<double>(current_stats_.pool_hits) / total_requests : 0.0;
        
        // Cleanup old timing data
        if (allocation_times_.size() > 1000) {
            allocation_times_.erase(allocation_times_.begin(), allocation_times_.begin() + 500);
            allocation_durations_.erase(allocation_durations_.begin(), allocation_durations_.begin() + 500);
        }
    }
    
    return buffer;
}

void ConnectionPool::release_buffer(std::unique_ptr<ZeroCopyBuffer> buffer) {
    if (!buffer) {
        return;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    size_t buffer_size = buffer->capacity();
    
    // Try to return to appropriate pool
    auto pool_it = size_specific_pools_.find(buffer_size);
    if (pool_it != size_specific_pools_.end()) {
        pool_it->second->release(std::move(buffer));
    }
    // Otherwise, buffer will be destroyed automatically
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(usage_mutex_);
        current_stats_.buffers_in_use = std::max(static_cast<int>(current_stats_.buffers_in_use) - 1, 0);
        current_memory_usage_ -= buffer_size;
        
        release_durations_.push_back(duration);
        
        // Calculate running average release time
        if (!release_durations_.empty()) {
            auto total_time = std::accumulate(release_durations_.begin(), release_durations_.end(),
                                            std::chrono::nanoseconds{0});
            current_stats_.average_release_time = total_time / release_durations_.size();
        }
        
        // Cleanup old timing data
        if (release_durations_.size() > 1000) {
            release_durations_.erase(release_durations_.begin(), release_durations_.begin() + 500);
        }
    }
}

std::unique_ptr<ZeroCopyBuffer> ConnectionPool::acquire_message_buffer() {
    if (message_pool_) {
        auto buffer = message_pool_->acquire();
        if (buffer) {
            return buffer;
        }
    }
    
    // Fallback to general allocation
    size_t message_size = characteristics_.average_message_size > 0 ? 
                         characteristics_.average_message_size : 1024;
    return acquire_buffer(message_size);
}

std::unique_ptr<ZeroCopyBuffer> ConnectionPool::acquire_header_buffer() {
    if (header_pool_) {
        auto buffer = header_pool_->acquire();
        if (buffer) {
            return buffer;
        }
    }
    
    // DTLS header is typically ~25 bytes, round up to 32
    return acquire_buffer(32);
}

std::unique_ptr<ZeroCopyBuffer> ConnectionPool::acquire_payload_buffer() {
    if (payload_pool_) {
        auto buffer = payload_pool_->acquire();
        if (buffer) {
            return buffer;
        }
    }
    
    // Use common payload size or fallback
    return acquire_buffer(8192);
}

std::unique_ptr<ZeroCopyBuffer> ConnectionPool::acquire_crypto_buffer() {
    if (crypto_pool_) {
        auto buffer = crypto_pool_->acquire();
        if (buffer) {
            return buffer;
        }
    }
    
    // Crypto operations typically need smaller buffers
    return acquire_buffer(256);
}

void ConnectionPool::optimize_for_characteristics() {
    // Determine optimal pool configurations based on connection characteristics
    switch (characteristics_.type) {
        case ConnectionCharacteristics::ConnectionType::LOW_LATENCY:
            // Pre-allocate more buffers for low latency
            for (auto& [size, pool] : size_specific_pools_) {
                pool->expand_pool(pool->total_buffers() / 2);
            }
            break;
            
        case ConnectionCharacteristics::ConnectionType::HIGH_THROUGHPUT:
            // Optimize for bulk operations
            if (!preferred_buffer_sizes().empty()) {
                for (size_t size : characteristics_.preferred_buffer_sizes) {
                    if (size_specific_pools_.find(size) == size_specific_pools_.end()) {
                        size_specific_pools_[size] = std::make_unique<BufferPool>(size, 16);
                    }
                }
            }
            break;
            
        case ConnectionCharacteristics::ConnectionType::INTERACTIVE:
            // Balanced approach with moderate pre-allocation
            break;
            
        case ConnectionCharacteristics::ConnectionType::IOT_SENSOR:
            // Memory-constrained optimization
            memory_limit_ = 64 * 1024; // 64KB limit for IoT
            optimization_level_ = 1; // Minimal optimization
            break;
            
        default:
            break;
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(usage_mutex_);
        current_stats_.adaptations_performed++;
    }
}

void ConnectionPool::adapt_to_usage_pattern() {
    update_usage_statistics();
    
    // Analyze buffer size usage patterns
    if (!characteristics_.buffer_size_usage.empty()) {
        // Find most frequently used buffer sizes
        std::vector<std::pair<size_t, size_t>> usage_pairs;
        for (const auto& [size, count] : characteristics_.buffer_size_usage) {
            usage_pairs.emplace_back(count, size);
        }
        
        std::sort(usage_pairs.rbegin(), usage_pairs.rend()); // Sort by usage count descending
        
        // Create dedicated pools for top 5 most used sizes
        for (size_t i = 0; i < std::min(usage_pairs.size(), static_cast<size_t>(5)); ++i) {
            size_t buffer_size = usage_pairs[i].second;
            size_t usage_count = usage_pairs[i].first;
            
            if (size_specific_pools_.find(buffer_size) == size_specific_pools_.end()) {
                size_t pool_size = std::min(usage_count / 4, static_cast<size_t>(32)); // Quarter of usage, max 32
                pool_size = std::max(pool_size, static_cast<size_t>(2)); // Minimum 2
                
                size_specific_pools_[buffer_size] = std::make_unique<BufferPool>(buffer_size, pool_size);
            }
        }
    }
    
    // Cleanup unused pools
    cleanup_unused_pools();
    
    // Predictive pre-allocation
    if (predictive_enabled_.load()) {
        predict_and_preallocate();
    }
}

void ConnectionPool::prepare_for_burst_traffic() {
    // Pre-allocate buffers for expected burst
    size_t burst_size = static_cast<size_t>(characteristics_.peak_concurrent_buffers * 1.5);
    
    for (auto& [size, pool] : size_specific_pools_) {
        size_t current_size = pool->total_buffers();
        if (current_size < burst_size) {
            pool->expand_pool(burst_size - current_size);
        }
    }
    
    // Also prepare specialized pools
    if (message_pool_ && message_pool_->total_buffers() < burst_size / 2) {
        message_pool_->expand_pool(burst_size / 2);
    }
}

void ConnectionPool::scale_down_for_idle() {
    // Shrink pools during idle periods
    for (auto& [size, pool] : size_specific_pools_) {
        size_t current_size = pool->total_buffers();
        size_t target_size = std::max(current_size / 2, static_cast<size_t>(2)); // At least 2 buffers
        
        if (current_size > target_size) {
            auto shrink_result = pool->shrink_pool(target_size);
            (void)shrink_result; // Ignore result for now
        }
    }
}

ConnectionPool::PoolStats ConnectionPool::get_statistics() const {
    std::lock_guard<std::mutex> lock(usage_mutex_);
    
    PoolStats stats = current_stats_;
    stats.memory_footprint = current_memory_usage_.load();
    
    return stats;
}

void ConnectionPool::reset_statistics() {
    std::lock_guard<std::mutex> lock(usage_mutex_);
    
    current_stats_ = PoolStats{};
    allocation_times_.clear();
    allocation_durations_.clear();
    release_durations_.clear();
}

void ConnectionPool::set_optimization_level(int level) {
    optimization_level_ = std::clamp(level, 0, 5);
    
    // Apply optimization level
    switch (optimization_level_.load()) {
        case 0: // Minimal
            memory_limit_ = 32 * 1024;  // 32KB
            predictive_enabled_ = false;
            break;
        case 1: // Low
            memory_limit_ = 128 * 1024; // 128KB
            predictive_enabled_ = false;
            break;
        case 2: // Moderate
            memory_limit_ = 512 * 1024; // 512KB
            predictive_enabled_ = true;
            break;
        case 3: // Balanced (default)
            memory_limit_ = 1024 * 1024; // 1MB
            predictive_enabled_ = true;
            break;
        case 4: // High
            memory_limit_ = 2 * 1024 * 1024; // 2MB
            predictive_enabled_ = true;
            break;
        case 5: // Aggressive
            memory_limit_ = 4 * 1024 * 1024; // 4MB
            predictive_enabled_ = true;
            break;
    }
}

void ConnectionPool::create_specialized_pools() {
    // Create message pool based on average message size
    if (characteristics_.average_message_size > 0) {
        size_t pool_size = std::max(static_cast<size_t>(8), optimization_level_.load() * 2);
        message_pool_ = std::make_unique<BufferPool>(characteristics_.average_message_size, pool_size);
    } else {
        message_pool_ = std::make_unique<BufferPool>(1024, 8); // Default 1KB messages
    }
    
    // Create header pool (DTLS headers are ~25 bytes, use 32)
    header_pool_ = std::make_unique<BufferPool>(32, 16);
    
    // Create payload pool (common sizes: 1KB, 4KB, 8KB)
    size_t payload_size = 8192;
    if (!characteristics_.preferred_buffer_sizes.empty()) {
        auto it = std::max_element(characteristics_.preferred_buffer_sizes.begin(),
                                  characteristics_.preferred_buffer_sizes.end());
        if (it != characteristics_.preferred_buffer_sizes.end()) {
            payload_size = *it;
        }
    }
    payload_pool_ = std::make_unique<BufferPool>(payload_size, 4);
    
    // Create crypto pool (256 bytes is typical for crypto operations)
    crypto_pool_ = std::make_unique<BufferPool>(256, 8);
}

void ConnectionPool::update_usage_statistics() {
    // Calculate memory footprint
    size_t total_memory = 0;
    for (const auto& [size, pool] : size_specific_pools_) {
        total_memory += size * pool->total_buffers();
    }
    
    if (message_pool_) total_memory += characteristics_.average_message_size * message_pool_->total_buffers();
    if (header_pool_) total_memory += 32 * header_pool_->total_buffers();
    if (payload_pool_) total_memory += 8192 * payload_pool_->total_buffers();  
    if (crypto_pool_) total_memory += 256 * crypto_pool_->total_buffers();
    
    current_stats_.memory_footprint = total_memory;
}

size_t ConnectionPool::calculate_optimal_pool_size(size_t buffer_size) const {
    // Base pool size on optimization level and usage patterns
    size_t base_size = 2 + optimization_level_.load();
    
    // Check if we have usage data for this buffer size
    auto usage_it = characteristics_.buffer_size_usage.find(buffer_size);
    if (usage_it != characteristics_.buffer_size_usage.end()) {
        size_t usage_count = usage_it->second;
        // Size pool to handle quarter of peak usage
        size_t usage_based_size = std::max(usage_count / 4, static_cast<size_t>(1));
        base_size = std::max(base_size, usage_based_size);
    }
    
    // Consider connection type
    switch (characteristics_.type) {
        case ConnectionCharacteristics::ConnectionType::LOW_LATENCY:
            base_size *= 2; // More pre-allocation for low latency
            break;
        case ConnectionCharacteristics::ConnectionType::HIGH_THROUGHPUT:
            base_size *= 3; // Even more for high throughput
            break;
        case ConnectionCharacteristics::ConnectionType::IOT_SENSOR:
            base_size = std::min(base_size, static_cast<size_t>(2)); // Constrain for IoT
            break;
        default:
            break;
    }
    
    // Cap based on memory limits
    size_t max_buffers = memory_limit_.load() / buffer_size;
    return std::min(base_size, std::max(max_buffers, static_cast<size_t>(1)));
}

bool ConnectionPool::should_create_dedicated_pool(size_t buffer_size) const {
    // Don't create pools for very large buffers
    if (buffer_size > 64 * 1024) {
        return false;
    }
    
    // Don't create pools if we're at memory limit
    if (current_memory_usage_.load() > memory_limit_.load() * 0.8) {
        return false;
    }
    
    // Create pool if we've seen this size enough times
    auto usage_it = characteristics_.buffer_size_usage.find(buffer_size);
    if (usage_it != characteristics_.buffer_size_usage.end()) {
        return usage_it->second >= 5; // At least 5 allocations of this size
    }
    
    return false;
}

void ConnectionPool::cleanup_unused_pools() {
    auto now = std::chrono::steady_clock::now();
    const auto idle_threshold = std::chrono::minutes(10);
    
    for (auto it = size_specific_pools_.begin(); it != size_specific_pools_.end();) {
        // Check if pool has been unused (simplified - in real implementation would track usage)
        if (it->second->available_buffers() == it->second->total_buffers()) {
            // Pool is completely unused, consider removing it
            // For simplicity, we'll keep all pools but shrink them
            if (it->second->total_buffers() > 2) {
                it->second->shrink_pool(2);
            }
        }
        ++it;
    }
}

void ConnectionPool::predict_and_preallocate() {
    // Simple prediction based on recent allocation patterns
    if (allocation_times_.size() < 5) {
        return; // Not enough data
    }
    
    // Calculate allocation rate over last minute
    auto now = std::chrono::steady_clock::now();
    auto one_minute_ago = now - std::chrono::minutes(1);
    
    size_t recent_allocations = std::count_if(allocation_times_.begin(), allocation_times_.end(),
        [one_minute_ago](const auto& time) {
            return time >= one_minute_ago;
        });
    
    // If allocation rate is high, pre-allocate some buffers
    if (recent_allocations > 10) { // More than 10 allocations per minute
        // Pre-allocate in message pool
        if (message_pool_ && message_pool_->available_buffers() < 4) {
            message_pool_->expand_pool(2);
        }
    }
}

// ConnectionMemoryManager implementation
ConnectionMemoryManager& ConnectionMemoryManager::instance() {
    static ConnectionMemoryManager instance;
    return instance;
}

Result<void> ConnectionMemoryManager::create_connection_pool(
    void* connection_id, const ConnectionCharacteristics& characteristics) {
    
    if (!connection_id) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    if (connection_pools_.find(connection_id) != connection_pools_.end()) {
        return Result<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    // Check global limits
    if (connection_pools_.size() >= 10000) { // Limit to 10k connections
        return Result<void>(DTLSError::RESOURCE_EXHAUSTED);
    }
    
    try {
        auto pool = std::make_unique<ConnectionPool>(connection_id, characteristics);
        pool->optimize_for_characteristics();
        
        connection_pools_[connection_id] = std::move(pool);
        connection_characteristics_[connection_id] = characteristics;
        
        // Update system statistics
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            system_stats_.total_connections++;
            system_stats_.active_connections++;
        }
        
        return Result<void>();
        
    } catch (const std::exception&) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
}

void ConnectionMemoryManager::destroy_connection_pool(void* connection_id) {
    if (!connection_id) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto pool_it = connection_pools_.find(connection_id);
    if (pool_it != connection_pools_.end()) {
        // Update statistics before destroying
        auto pool_stats = pool_it->second->get_statistics();
        
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            system_stats_.active_connections--;
            system_stats_.total_memory_usage -= pool_stats.memory_footprint;
        }
        
        connection_pools_.erase(pool_it);
        connection_characteristics_.erase(connection_id);
    }
}

ConnectionPool* ConnectionMemoryManager::get_connection_pool(void* connection_id) {
    if (!connection_id) {
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = connection_pools_.find(connection_id);
    return (it != connection_pools_.end()) ? it->second.get() : nullptr;
}

std::unique_ptr<ZeroCopyBuffer> ConnectionMemoryManager::allocate_for_connection(
    void* connection_id, size_t size) {
    
    auto* pool = get_connection_pool(connection_id);
    if (pool) {
        return pool->acquire_buffer(size);
    }
    
    // Fallback to general allocation
    return std::make_unique<ZeroCopyBuffer>(size);
}

void ConnectionMemoryManager::deallocate_for_connection(
    void* connection_id, std::unique_ptr<ZeroCopyBuffer> buffer) {
    
    auto* pool = get_connection_pool(connection_id);
    if (pool) {
        pool->release_buffer(std::move(buffer));
    }
    // Otherwise buffer will be automatically destroyed
}

ConnectionMemoryManager::SystemStats ConnectionMemoryManager::get_system_statistics() const {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    std::lock_guard<std::mutex> connections_lock(connections_mutex_);
    
    SystemStats stats = system_stats_;
    
    // Calculate current statistics
    stats.total_connections = connection_pools_.size();
    stats.active_connections = stats.total_connections; // Simplified
    
    stats.total_memory_usage = 0;
    stats.total_buffers_allocated = 0;
    double total_hit_rate = 0.0;
    
    for (const auto& [id, pool] : connection_pools_) {
        auto pool_stats = pool->get_statistics();
        stats.total_memory_usage += pool_stats.memory_footprint;
        stats.total_buffers_allocated += pool_stats.total_buffers_allocated;
        total_hit_rate += pool_stats.hit_rate;
    }
    
    if (stats.total_connections > 0) {
        stats.average_hit_rate = total_hit_rate / stats.total_connections;
    }
    
    return stats;
}

void ConnectionMemoryManager::handle_memory_pressure() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    // Scale down all connection pools
    for (auto& [id, pool] : connection_pools_) {
        pool->scale_down_for_idle();
        pool->set_optimization_level(1); // Switch to low optimization
    }
    
    // Update global limits
    per_connection_limit_ = per_connection_limit_.load() / 2;
}

void ConnectionMemoryManager::handle_memory_relief() {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    // Restore optimization levels
    for (auto& [id, pool] : connection_pools_) {
        pool->set_optimization_level(3); // Back to balanced optimization
    }
    
    // Restore limits
    per_connection_limit_ = 1024 * 1024; // Back to 1MB per connection
}

// Factory functions implementation
Result<void> create_connection_memory_pool(void* connection_id, 
    const ConnectionCharacteristics& characteristics) {
    return ConnectionMemoryManager::instance().create_connection_pool(connection_id, characteristics);
}

void destroy_connection_memory_pool(void* connection_id) {
    ConnectionMemoryManager::instance().destroy_connection_pool(connection_id);
}

ConnectionBuffer allocate_connection_buffer(void* connection_id, size_t size) {
    auto buffer = ConnectionMemoryManager::instance().allocate_for_connection(connection_id, size);
    return ConnectionBuffer(connection_id, std::move(buffer));
}

ConnectionBuffer allocate_message_buffer(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        auto buffer = pool->acquire_message_buffer();
        return ConnectionBuffer(connection_id, std::move(buffer));
    }
    
    // Fallback
    return allocate_connection_buffer(connection_id, 1024);
}

ConnectionBuffer allocate_header_buffer(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        auto buffer = pool->acquire_header_buffer();
        return ConnectionBuffer(connection_id, std::move(buffer));
    }
    
    return allocate_connection_buffer(connection_id, 32);
}

ConnectionBuffer allocate_payload_buffer(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        auto buffer = pool->acquire_payload_buffer();
        return ConnectionBuffer(connection_id, std::move(buffer));
    }
    
    return allocate_connection_buffer(connection_id, 8192);
}

ConnectionBuffer allocate_crypto_buffer(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        auto buffer = pool->acquire_crypto_buffer();
        return ConnectionBuffer(connection_id, std::move(buffer));
    }
    
    return allocate_connection_buffer(connection_id, 256);
}

// ConnectionBuffer implementation
ConnectionBuffer::ConnectionBuffer(void* connection_id, std::unique_ptr<ZeroCopyBuffer> buffer)
    : connection_id_(connection_id)
    , buffer_(std::move(buffer)) {
}

ConnectionBuffer::~ConnectionBuffer() {
    if (buffer_ && connection_id_) {
        ConnectionMemoryManager::instance().deallocate_for_connection(connection_id_, std::move(buffer_));
    }
}

ConnectionBuffer::ConnectionBuffer(ConnectionBuffer&& other) noexcept
    : connection_id_(other.connection_id_)
    , buffer_(std::move(other.buffer_)) {
    other.connection_id_ = nullptr;
}

ConnectionBuffer& ConnectionBuffer::operator=(ConnectionBuffer&& other) noexcept {
    if (this != &other) {
        if (buffer_ && connection_id_) {
            ConnectionMemoryManager::instance().deallocate_for_connection(connection_id_, std::move(buffer_));
        }
        
        connection_id_ = other.connection_id_;
        buffer_ = std::move(other.buffer_);
        other.connection_id_ = nullptr;
    }
    return *this;
}

std::unique_ptr<ZeroCopyBuffer> ConnectionBuffer::release() {
    connection_id_ = nullptr;
    return std::move(buffer_);
}

// Connection lifecycle functions
void on_connection_established(void* connection_id, const ConnectionCharacteristics& characteristics) {
    create_connection_memory_pool(connection_id, characteristics);
    
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        pool->on_connection_established();
    }
}

void on_connection_handshake_complete(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        pool->on_handshake_completed();
        pool->optimize_for_characteristics();
    }
}

void on_connection_data_phase(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        pool->on_data_transfer_started();
        pool->prepare_for_burst_traffic();
    }
}

void on_connection_idle(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        pool->on_connection_idle();
        pool->scale_down_for_idle();
    }
}

void on_connection_closing(void* connection_id) {
    auto* pool = ConnectionMemoryManager::instance().get_connection_pool(connection_id);
    if (pool) {
        pool->on_connection_closing();
    }
    
    // Destroy the pool after a delay to handle any remaining cleanup
    destroy_connection_memory_pool(connection_id);
}

// Configuration presets
namespace connection_presets {

ConnectionCharacteristics low_latency_connection() {
    ConnectionCharacteristics chars;
    chars.type = ConnectionCharacteristics::ConnectionType::LOW_LATENCY;
    chars.qos_requirements.max_latency = std::chrono::milliseconds(10);
    chars.qos_requirements.requires_low_jitter = true;
    chars.average_message_size = 512;
    chars.preferred_buffer_sizes = {128, 256, 512, 1024};
    return chars;
}

ConnectionCharacteristics high_throughput_connection() {
    ConnectionCharacteristics chars;
    chars.type = ConnectionCharacteristics::ConnectionType::HIGH_THROUGHPUT;
    chars.qos_requirements.min_throughput = 10.0 * 1024 * 1024; // 10 MB/s
    chars.average_message_size = 8192;
    chars.preferred_buffer_sizes = {4096, 8192, 16384, 32768};
    return chars;
}

ConnectionCharacteristics interactive_connection() {
    ConnectionCharacteristics chars;
    chars.type = ConnectionCharacteristics::ConnectionType::INTERACTIVE;
    chars.qos_requirements.max_latency = std::chrono::milliseconds(100);
    chars.average_message_size = 1024;
    chars.preferred_buffer_sizes = {256, 512, 1024, 2048};
    return chars;
}

ConnectionCharacteristics streaming_connection() {
    ConnectionCharacteristics chars;
    chars.type = ConnectionCharacteristics::ConnectionType::STREAMING;
    chars.qos_requirements.min_throughput = 2.0 * 1024 * 1024; // 2 MB/s
    chars.qos_requirements.requires_low_jitter = true;
    chars.average_message_size = 4096;
    chars.preferred_buffer_sizes = {2048, 4096, 8192};
    return chars;
}

ConnectionCharacteristics iot_sensor_connection() {
    ConnectionCharacteristics chars;
    chars.type = ConnectionCharacteristics::ConnectionType::IOT_SENSOR;
    chars.qos_requirements.memory_constrained = true;
    chars.average_message_size = 128;
    chars.preferred_buffer_sizes = {64, 128, 256};
    return chars;
}

ConnectionCharacteristics memory_constrained_connection() {
    ConnectionCharacteristics chars;
    chars.qos_requirements.memory_constrained = true;
    chars.average_message_size = 256;
    chars.preferred_buffer_sizes = {128, 256, 512};
    return chars;
}

} // namespace connection_presets

} // namespace memory
} // namespace v13
} // namespace dtls