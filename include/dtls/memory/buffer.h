#ifndef DTLS_MEMORY_BUFFER_H
#define DTLS_MEMORY_BUFFER_H

#include <dtls/config.h>
#include <dtls/result.h>
#include <memory>
#include <cstddef>
#include <cstring>
#include <atomic>

namespace dtls {
namespace v13 {
namespace memory {

// Forward declarations for optimized buffer sharing
class BufferSharedState;
class BufferRefCount;

// Shared buffer state for zero-copy buffer sharing
class DTLS_API BufferSharedState {
public:
    BufferSharedState(std::unique_ptr<std::byte[]> data, size_t capacity);
    ~BufferSharedState() = default;
    
    // Non-copyable, non-movable (managed by shared_ptr)
    BufferSharedState(const BufferSharedState&) = delete;
    BufferSharedState& operator=(const BufferSharedState&) = delete;
    BufferSharedState(BufferSharedState&&) = delete;
    BufferSharedState& operator=(BufferSharedState&&) = delete;
    
    const std::byte* data() const noexcept { return data_.get(); }
    std::byte* mutable_data() noexcept { return data_.get(); }
    size_t capacity() const noexcept { return capacity_; }
    
    // Reference counting
    std::atomic<size_t> ref_count{1};
    
    // Security
    void secure_zero() noexcept;
    
private:
    std::unique_ptr<std::byte[]> data_;
    size_t capacity_;
};

// Zero-copy buffer for efficient data handling with reference counting and buffer sharing
class DTLS_API ZeroCopyBuffer {
public:
    // Constructors
    explicit ZeroCopyBuffer(size_t capacity = 0);
    ZeroCopyBuffer(std::unique_ptr<std::byte[]> data, size_t size, size_t capacity);
    ZeroCopyBuffer(const std::byte* data, size_t size);
    
    // Shared buffer constructor for zero-copy sharing
    ZeroCopyBuffer(std::shared_ptr<BufferSharedState> shared_state, size_t offset = 0, size_t size = 0);
    
    // Copy semantics now allowed for reference-counted zero-copy sharing
    ZeroCopyBuffer(const ZeroCopyBuffer& other) noexcept;
    ZeroCopyBuffer& operator=(const ZeroCopyBuffer& other) noexcept;
    ZeroCopyBuffer(ZeroCopyBuffer&& other) noexcept;
    ZeroCopyBuffer& operator=(ZeroCopyBuffer&& other) noexcept;
    
    // Destructor
    ~ZeroCopyBuffer() = default;
    
    // Data access
    std::byte* mutable_data() noexcept { return get_mutable_data_ptr(); }
    const std::byte* data() const noexcept { return get_data_ptr(); }
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size_ == 0; }
    
    // Buffer operations
    Result<void> append(const std::byte* data, size_t length);
    Result<void> append(const ZeroCopyBuffer& other);
    Result<void> prepend(const std::byte* data, size_t length);
    Result<ZeroCopyBuffer> slice(size_t offset, size_t length) const;
    
    // Zero-copy operations
    ZeroCopyBuffer create_slice(size_t offset, size_t length) const noexcept;
    Result<ZeroCopyBuffer> share_buffer() const;
    bool is_shared() const noexcept;
    size_t reference_count() const noexcept;
    
    // Buffer sharing optimization
    Result<void> make_unique(); // Copy-on-write when shared
    bool can_modify() const noexcept; // Check if buffer can be modified without copying
    
    // Memory management
    Result<void> reserve(size_t new_capacity);
    Result<void> resize(size_t new_size);
    void clear() noexcept { size_ = 0; }
    void shrink_to_fit();
    
    // Utility functions
    void zero_memory() noexcept;
    size_t available_space() const noexcept { return capacity_ - size_; }
    
    // Iterator support
    std::byte* begin() noexcept { return get_mutable_data_ptr(); }
    std::byte* end() noexcept { return get_mutable_data_ptr() + size_; }
    const std::byte* begin() const noexcept { return get_data_ptr(); }
    const std::byte* end() const noexcept { return get_data_ptr() + size_; }
    const std::byte* cbegin() const noexcept { return get_data_ptr(); }
    const std::byte* cend() const noexcept { return get_data_ptr() + size_; }
    
    // Operators
    std::byte& operator[](size_t index) noexcept { return get_mutable_data_ptr()[index]; }
    const std::byte& operator[](size_t index) const noexcept { return get_data_ptr()[index]; }
    
    // Security
    void secure_zero() noexcept;
    
    // Buffer state queries
    bool is_owning() const noexcept;
    bool is_pooled() const noexcept;
    
    // Performance optimization hints
    void hint_sequential_access() noexcept;
    void hint_random_access() noexcept;
    void hint_read_only() noexcept;
    
private:
    std::unique_ptr<std::byte[]> data_;
    std::shared_ptr<BufferSharedState> shared_state_;
    size_t size_;
    size_t capacity_;
    size_t offset_; // Offset into shared buffer
    
    bool is_shared_buffer_{false};
    bool is_pooled_buffer_{false};
    
    Result<void> ensure_capacity(size_t required_capacity);
    void initialize_shared_state();
    void convert_to_shared(); // Convert owned buffer to shared state
    const std::byte* get_data_ptr() const noexcept;
    std::byte* get_mutable_data_ptr() noexcept;
};

// Buffer view for non-owning access to buffer data
class DTLS_API BufferView {
public:
    // Constructors
    BufferView() noexcept : data_(nullptr), size_(0) {}
    BufferView(const std::byte* data, size_t size) noexcept : data_(data), size_(size) {}
    BufferView(const ZeroCopyBuffer& buffer) noexcept : data_(buffer.data()), size_(buffer.size()) {}
    
    template<typename Container>
    BufferView(const Container& container) noexcept 
        : data_(reinterpret_cast<const std::byte*>(container.data())), 
          size_(container.size() * sizeof(typename Container::value_type)) {}
    
    // Access
    const std::byte* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    
    // Slicing
    BufferView slice(size_t offset, size_t length) const noexcept;
    BufferView subview(size_t offset) const noexcept;
    
    // Iterator support
    const std::byte* begin() const noexcept { return data_; }
    const std::byte* end() const noexcept { return data_ + size_; }
    const std::byte* cbegin() const noexcept { return data_; }
    const std::byte* cend() const noexcept { return data_ + size_; }
    
    // Operators
    const std::byte& operator[](size_t index) const noexcept { return data_[index]; }
    
    // Comparison
    bool operator==(const BufferView& other) const noexcept;
    bool operator!=(const BufferView& other) const noexcept { return !(*this == other); }
    
private:
    const std::byte* data_;
    size_t size_;
};

// Mutable buffer view
class DTLS_API MutableBufferView {
public:
    // Constructors
    MutableBufferView() noexcept : data_(nullptr), size_(0) {}
    MutableBufferView(std::byte* data, size_t size) noexcept : data_(data), size_(size) {}
    MutableBufferView(ZeroCopyBuffer& buffer) noexcept : data_(buffer.mutable_data()), size_(buffer.size()) {}
    
    // Access
    std::byte* data() noexcept { return data_; }
    const std::byte* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    
    // Slicing
    MutableBufferView slice(size_t offset, size_t length) noexcept;
    MutableBufferView subview(size_t offset) noexcept;
    
    // Iterator support
    std::byte* begin() noexcept { return data_; }
    std::byte* end() noexcept { return data_ + size_; }
    const std::byte* begin() const noexcept { return data_; }
    const std::byte* end() const noexcept { return data_ + size_; }
    const std::byte* cbegin() const noexcept { return data_; }
    const std::byte* cend() const noexcept { return data_ + size_; }
    
    // Operators
    std::byte& operator[](size_t index) noexcept { return data_[index]; }
    const std::byte& operator[](size_t index) const noexcept { return data_[index]; }
    
    // Conversion to immutable view
    operator BufferView() const noexcept { return BufferView(data_, size_); }
    
    // Fill operations
    void fill(std::byte value) noexcept;
    void zero() noexcept { fill(std::byte{0}); }
    
private:
    std::byte* data_;
    size_t size_;
};

// Utility functions for buffer operations
DTLS_API bool constant_time_compare(const BufferView& a, const BufferView& b) noexcept;
DTLS_API void secure_zero_memory(void* ptr, size_t size) noexcept;
DTLS_API size_t find_byte(const BufferView& buffer, std::byte value) noexcept;

// Buffer concatenation
DTLS_API Result<ZeroCopyBuffer> concatenate_buffers(
    const std::vector<BufferView>& buffers);

// Hex encoding/decoding for debugging
DTLS_API std::string to_hex_string(const BufferView& buffer);
DTLS_API Result<ZeroCopyBuffer> from_hex_string(const std::string& hex);

} // namespace memory
} // namespace v13
} // namespace dtls

#endif // DTLS_MEMORY_BUFFER_H