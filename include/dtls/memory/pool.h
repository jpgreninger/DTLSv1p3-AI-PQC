#ifndef DTLS_MEMORY_POOL_H
#define DTLS_MEMORY_POOL_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <dtls/memory/buffer.h>
#include <memory>
#include <queue>
#include <mutex>
#include <atomic>
#include <vector>
#include <unordered_map>

namespace dtls {
namespace v13 {
namespace memory {

// Memory pool statistics
struct DTLS_API PoolStats {
    size_t total_buffers{0};
    size_t available_buffers{0};
    size_t peak_usage{0};
    size_t total_allocations{0};
    size_t total_deallocations{0};
    size_t allocation_failures{0};
    size_t buffer_size{0};
    double utilization_ratio{0.0};
};

// Buffer pool for high-frequency allocations
class DTLS_API BufferPool {
public:
    // Constructor
    explicit BufferPool(size_t buffer_size, size_t pool_size = 32);
    
    // Destructor
    ~BufferPool();
    
    // Non-copyable, non-movable
    BufferPool(const BufferPool&) = delete;
    BufferPool& operator=(const BufferPool&) = delete;
    BufferPool(BufferPool&&) = delete;
    BufferPool& operator=(BufferPool&&) = delete;
    
    // Buffer management
    std::unique_ptr<ZeroCopyBuffer> acquire();
    void release(std::unique_ptr<ZeroCopyBuffer> buffer);
    
    // Pool management
    Result<void> expand_pool(size_t additional_buffers);
    Result<void> shrink_pool(size_t target_size);
    void clear_pool();
    
    // Statistics
    PoolStats get_statistics() const;
    size_t available_buffers() const;
    size_t total_buffers() const;
    double utilization_ratio() const;
    
    // Configuration
    size_t buffer_size() const noexcept { return buffer_size_; }
    size_t pool_size() const noexcept { return pool_size_; }
    void set_max_pool_size(size_t max_size);
    
    // Thread safety
    bool is_thread_safe() const noexcept { return true; }

private:
    const size_t buffer_size_;
    std::atomic<size_t> pool_size_;
    std::atomic<size_t> max_pool_size_;
    
    mutable std::mutex pool_mutex_;
    std::queue<std::unique_ptr<ZeroCopyBuffer>> available_buffers_;
    
    // Statistics (atomic for thread-safety)
    std::atomic<size_t> peak_usage_;
    std::atomic<size_t> total_allocations_;
    std::atomic<size_t> total_deallocations_;
    std::atomic<size_t> allocation_failures_;
    
    // Helper functions
    std::unique_ptr<ZeroCopyBuffer> create_buffer();
    bool is_valid_buffer(const ZeroCopyBuffer* buffer) const;
};

// Global buffer pool manager
class DTLS_API GlobalPoolManager {
public:
    // Singleton access
    static GlobalPoolManager& instance();
    
    // Pool management
    BufferPool& get_pool(size_t buffer_size);
    Result<void> create_pool(size_t buffer_size, size_t pool_size);
    void remove_pool(size_t buffer_size);
    void clear_all_pools();
    
    // Statistics
    std::vector<PoolStats> get_all_statistics() const;
    size_t total_memory_usage() const;
    
    // Configuration
    void set_default_pool_size(size_t size) { default_pool_size_ = size; }
    size_t default_pool_size() const { return default_pool_size_; }
    
private:
    GlobalPoolManager() = default;
    ~GlobalPoolManager() = default;
    
    mutable std::mutex pools_mutex_;
    std::unordered_map<size_t, std::unique_ptr<BufferPool>> pools_;
    size_t default_pool_size_{32};
};

// RAII buffer holder with automatic pool return
class DTLS_API PooledBuffer {
public:
    // Constructors
    explicit PooledBuffer(size_t buffer_size);
    PooledBuffer(std::unique_ptr<ZeroCopyBuffer> buffer, BufferPool* pool);
    
    // Move semantics only
    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer& operator=(const PooledBuffer&) = delete;
    PooledBuffer(PooledBuffer&& other) noexcept;
    PooledBuffer& operator=(PooledBuffer&& other) noexcept;
    
    // Destructor - automatically returns buffer to pool
    ~PooledBuffer();
    
    // Buffer access
    ZeroCopyBuffer& buffer() { return *buffer_; }
    const ZeroCopyBuffer& buffer() const { return *buffer_; }
    ZeroCopyBuffer* operator->() { return buffer_.get(); }
    const ZeroCopyBuffer* operator->() const { return buffer_.get(); }
    ZeroCopyBuffer& operator*() { return *buffer_; }
    const ZeroCopyBuffer& operator*() const { return *buffer_; }
    
    // Release buffer from pool management
    std::unique_ptr<ZeroCopyBuffer> release();
    
    // Validity check
    bool is_valid() const noexcept { return buffer_ != nullptr; }
    explicit operator bool() const noexcept { return is_valid(); }
    
private:
    std::unique_ptr<ZeroCopyBuffer> buffer_;
    BufferPool* pool_;
};

// Memory allocator for STL containers using buffer pools
template<typename T>
class PoolAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    
    template<typename U>
    struct rebind {
        using other = PoolAllocator<U>;
    };
    
    PoolAllocator() noexcept = default;
    
    template<typename U>
    PoolAllocator(const PoolAllocator<U>&) noexcept {}
    
    pointer allocate(size_type n) {
        if (n == 0) return nullptr;
        
        size_t bytes = n * sizeof(T);
        auto& pool = GlobalPoolManager::instance().get_pool(
            next_power_of_two(bytes));
        
        auto buffer = pool.acquire();
        if (!buffer || buffer->capacity() < bytes) {
            throw std::bad_alloc();
        }
        
        // Store buffer pointer for deallocation
        void* ptr = buffer->mutable_data();
        buffer_map_[ptr] = std::move(buffer);
        
        return static_cast<pointer>(ptr);
    }
    
    void deallocate(pointer p, size_type n) noexcept {
        if (!p) return;
        
        auto it = buffer_map_.find(p);
        if (it != buffer_map_.end()) {
            size_t bytes = n * sizeof(T);
            auto& pool = GlobalPoolManager::instance().get_pool(
                next_power_of_two(bytes));
            pool.release(std::move(it->second));
            buffer_map_.erase(it);
        }
    }
    
    template<typename U>
    bool operator==(const PoolAllocator<U>&) const noexcept {
        return true;
    }
    
    template<typename U>
    bool operator!=(const PoolAllocator<U>&) const noexcept {
        return false;
    }

private:
    static size_t next_power_of_two(size_t n) {
        n--;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        if constexpr (sizeof(size_t) > 4) {
            n |= n >> 32;
        }
        return n + 1;
    }
    
    static thread_local std::unordered_map<void*, std::unique_ptr<ZeroCopyBuffer>> buffer_map_;
};

template<typename T>
thread_local std::unordered_map<void*, std::unique_ptr<ZeroCopyBuffer>> 
    PoolAllocator<T>::buffer_map_;

// Type aliases for pooled containers
template<typename T>
using PoolVector = std::vector<T, PoolAllocator<T>>;

// Factory functions for easy buffer creation
DTLS_API PooledBuffer make_pooled_buffer(size_t size);
DTLS_API std::unique_ptr<ZeroCopyBuffer> make_buffer(size_t size);

// Pool configuration helpers
DTLS_API void configure_default_pools();
DTLS_API void cleanup_all_pools();

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_POOL_H