#include <dtls/memory/pool.h>
#include <dtls/error.h>
#include <algorithm>
#include <stdexcept>

namespace dtls {
namespace v13 {
namespace memory {

// BufferPool implementation
BufferPool::BufferPool(size_t buffer_size, size_t pool_size)
    : buffer_size_(buffer_size)
    , pool_size_(pool_size)
    , max_pool_size_(pool_size * 2) // Allow 2x expansion by default
    , peak_usage_(0)
    , total_allocations_(0)
    , total_deallocations_(0)
    , allocation_failures_(0) {
    
    if (buffer_size == 0) {
        throw std::invalid_argument("Buffer size cannot be zero");
    }
    
    // Pre-allocate initial buffers
    std::lock_guard<std::mutex> lock(pool_mutex_);
    for (size_t i = 0; i < pool_size; ++i) {
        auto buffer = create_buffer();
        if (buffer) {
            available_buffers_.push(std::move(buffer));
        }
    }
}

BufferPool::~BufferPool() {
    clear_pool();
}

std::unique_ptr<ZeroCopyBuffer> BufferPool::acquire() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    total_allocations_.fetch_add(1, std::memory_order_relaxed);
    
    if (!available_buffers_.empty()) {
        auto buffer = std::move(available_buffers_.front());
        available_buffers_.pop();
        
        // Update peak usage statistics
        size_t current_usage = pool_size_.load() - available_buffers_.size();
        size_t current_peak = peak_usage_.load();
        while (current_usage > current_peak && 
               !peak_usage_.compare_exchange_weak(current_peak, current_usage)) {
            // Retry if another thread updated peak_usage_
        }
        
        // Clear the buffer for reuse
        buffer->clear();
        return buffer;
    }
    
    // No buffers available, try to expand pool only if allowed
    if (pool_size_.load() < max_pool_size_.load()) {
        auto buffer = create_buffer();
        if (buffer) {
            pool_size_.fetch_add(1, std::memory_order_relaxed);
            return buffer;
        }
    }
    
    // Failed to allocate
    allocation_failures_.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
}

void BufferPool::release(std::unique_ptr<ZeroCopyBuffer> buffer) {
    if (!buffer) {
        return;
    }
    
    // Validate buffer belongs to this pool
    if (!is_valid_buffer(buffer.get())) {
        return; // Invalid buffer, don't add to pool
    }
    
    total_deallocations_.fetch_add(1, std::memory_order_relaxed);
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    // Check if pool is at capacity
    if (available_buffers_.size() >= max_pool_size_.load()) {
        // Pool is full, let buffer be destroyed
        return;
    }
    
    // Secure zero the buffer before returning to pool
    buffer->secure_zero();
    available_buffers_.push(std::move(buffer));
}

Result<void> BufferPool::expand_pool(size_t additional_buffers) {
    if (additional_buffers == 0) {
        return Result<void>();
    }
    
    size_t current_max = max_pool_size_.load();
    size_t new_max = current_max + additional_buffers;
    
    // Update max pool size first
    max_pool_size_.store(new_max, std::memory_order_relaxed);
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    size_t created = 0;
    for (size_t i = 0; i < additional_buffers; ++i) {
        auto buffer = create_buffer();
        if (buffer) {
            available_buffers_.push(std::move(buffer));
            created++;
        } else {
            // Failed to create buffer, break
            break;
        }
    }
    
    if (created > 0) {
        pool_size_.fetch_add(created, std::memory_order_relaxed);
        return Result<void>();
    }
    
    return Result<void>(DTLSError::OUT_OF_MEMORY);
}

Result<void> BufferPool::shrink_pool(size_t target_size) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    size_t current_total = pool_size_.load();
    size_t current_available = available_buffers_.size();
    size_t current_in_use = current_total - current_available;
    
    // Cannot shrink below the number of buffers currently in use
    if (target_size < current_in_use) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    // If already at or below target, nothing to do
    if (current_total <= target_size) {
        return Result<void>();
    }
    
    // Can only remove available buffers, not in-use ones
    size_t max_removable = current_available;
    size_t desired_removal = current_total - target_size;
    size_t actual_removal = std::min(desired_removal, max_removable);
    
    for (size_t i = 0; i < actual_removal && !available_buffers_.empty(); ++i) {
        available_buffers_.pop();
        pool_size_.fetch_sub(1, std::memory_order_relaxed);
    }
    
    return Result<void>();
}

void BufferPool::clear_pool() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    size_t cleared = available_buffers_.size();
    while (!available_buffers_.empty()) {
        available_buffers_.pop();
    }
    
    pool_size_.fetch_sub(cleared, std::memory_order_relaxed);
}

PoolStats BufferPool::get_statistics() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    
    PoolStats stats;
    stats.total_buffers = pool_size_.load();
    stats.available_buffers = available_buffers_.size();
    stats.peak_usage = peak_usage_.load();
    stats.total_allocations = total_allocations_.load();
    stats.total_deallocations = total_deallocations_.load();
    stats.allocation_failures = allocation_failures_.load();
    stats.buffer_size = buffer_size_;
    
    if (stats.total_buffers > 0) {
        stats.utilization_ratio = static_cast<double>(stats.total_buffers - stats.available_buffers) / 
                                 static_cast<double>(stats.total_buffers);
    } else {
        stats.utilization_ratio = 0.0;
    }
    
    return stats;
}

size_t BufferPool::available_buffers() const {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    return available_buffers_.size();
}

size_t BufferPool::total_buffers() const {
    return pool_size_.load();
}

double BufferPool::utilization_ratio() const {
    size_t total = pool_size_.load();
    if (total == 0) {
        return 0.0;
    }
    
    std::lock_guard<std::mutex> lock(pool_mutex_);
    size_t available = available_buffers_.size();
    return static_cast<double>(total - available) / static_cast<double>(total);
}

void BufferPool::set_max_pool_size(size_t max_size) {
    if (max_size < pool_size_.load()) {
        max_size = pool_size_.load(); // Can't be smaller than current size
    }
    max_pool_size_.store(max_size, std::memory_order_relaxed);
}

std::unique_ptr<ZeroCopyBuffer> BufferPool::create_buffer() {
    try {
        return std::make_unique<ZeroCopyBuffer>(buffer_size_);
    } catch (const std::bad_alloc&) {
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

bool BufferPool::is_valid_buffer(const ZeroCopyBuffer* buffer) const {
    if (!buffer) {
        return false;
    }
    
    // Check if buffer capacity matches pool buffer size
    return buffer->capacity() == buffer_size_;
}

// GlobalPoolManager implementation
GlobalPoolManager& GlobalPoolManager::instance() {
    static GlobalPoolManager instance;
    return instance;
}

BufferPool& GlobalPoolManager::get_pool(size_t buffer_size) {
    std::lock_guard<std::mutex> lock(pools_mutex_);
    
    auto it = pools_.find(buffer_size);
    if (it != pools_.end()) {
        return *it->second;
    }
    
    // Create new pool with default size
    auto pool = std::make_unique<BufferPool>(buffer_size, default_pool_size_);
    BufferPool& pool_ref = *pool;
    pools_[buffer_size] = std::move(pool);
    
    return pool_ref;
}

Result<void> GlobalPoolManager::create_pool(size_t buffer_size, size_t pool_size) {
    if (buffer_size == 0 || pool_size == 0) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    std::lock_guard<std::mutex> lock(pools_mutex_);
    
    if (pools_.find(buffer_size) != pools_.end()) {
        return Result<void>(DTLSError::ALREADY_INITIALIZED);
    }
    
    try {
        auto pool = std::make_unique<BufferPool>(buffer_size, pool_size);
        pools_[buffer_size] = std::move(pool);
        return Result<void>();
    } catch (const std::exception&) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
}

void GlobalPoolManager::remove_pool(size_t buffer_size) {
    std::lock_guard<std::mutex> lock(pools_mutex_);
    pools_.erase(buffer_size);
}

void GlobalPoolManager::clear_all_pools() {
    std::lock_guard<std::mutex> lock(pools_mutex_);
    pools_.clear();
}

std::vector<PoolStats> GlobalPoolManager::get_all_statistics() const {
    std::lock_guard<std::mutex> lock(pools_mutex_);
    
    std::vector<PoolStats> all_stats;
    all_stats.reserve(pools_.size());
    
    for (const auto& [buffer_size, pool] : pools_) {
        all_stats.push_back(pool->get_statistics());
    }
    
    return all_stats;
}

size_t GlobalPoolManager::total_memory_usage() const {
    std::lock_guard<std::mutex> lock(pools_mutex_);
    
    size_t total = 0;
    for (const auto& [buffer_size, pool] : pools_) {
        total += buffer_size * pool->total_buffers();
    }
    
    return total;
}

// PooledBuffer implementation
PooledBuffer::PooledBuffer(size_t buffer_size) 
    : pool_(&GlobalPoolManager::instance().get_pool(buffer_size)) {
    buffer_ = pool_->acquire();
}

PooledBuffer::PooledBuffer(std::unique_ptr<ZeroCopyBuffer> buffer, BufferPool* pool)
    : buffer_(std::move(buffer))
    , pool_(pool) {}

PooledBuffer::PooledBuffer(PooledBuffer&& other) noexcept
    : buffer_(std::move(other.buffer_))
    , pool_(other.pool_) {
    other.pool_ = nullptr;
}

PooledBuffer& PooledBuffer::operator=(PooledBuffer&& other) noexcept {
    if (this != &other) {
        // Return current buffer to pool if we have one
        if (buffer_ && pool_) {
            pool_->release(std::move(buffer_));
        }
        
        buffer_ = std::move(other.buffer_);
        pool_ = other.pool_;
        other.pool_ = nullptr;
    }
    return *this;
}

PooledBuffer::~PooledBuffer() {
    if (buffer_ && pool_) {
        pool_->release(std::move(buffer_));
    }
}

std::unique_ptr<ZeroCopyBuffer> PooledBuffer::release() {
    pool_ = nullptr; // Prevent destructor from returning to pool
    return std::move(buffer_);
}

// Factory functions
PooledBuffer make_pooled_buffer(size_t size) {
    return PooledBuffer(size);
}

std::unique_ptr<ZeroCopyBuffer> make_buffer(size_t size) {
    auto& pool = GlobalPoolManager::instance().get_pool(size);
    auto buffer = pool.acquire();
    
    if (!buffer) {
        // Fallback to direct allocation
        try {
            buffer = std::make_unique<ZeroCopyBuffer>(size);
        } catch (...) {
            return nullptr;
        }
    }
    
    return buffer;
}

// Pool configuration helpers
void configure_default_pools() {
    auto& manager = GlobalPoolManager::instance();
    
    // Create pools for common DTLS record sizes
    manager.create_pool(64, 16);      // Small messages
    manager.create_pool(256, 32);     // Handshake fragments
    manager.create_pool(1024, 16);    // Medium records
    manager.create_pool(4096, 8);     // Large records
    manager.create_pool(16384, 4);    // Maximum DTLS record size
    
    // Create pools for common crypto operations
    manager.create_pool(32, 32);      // Hash outputs, random values
    manager.create_pool(48, 16);      // SHA-384 outputs
    manager.create_pool(64, 16);      // SHA-512 outputs, key material
}

void cleanup_all_pools() {
    GlobalPoolManager::instance().clear_all_pools();
}

} // namespace memory
} // namespace v13
} // namespace dtls