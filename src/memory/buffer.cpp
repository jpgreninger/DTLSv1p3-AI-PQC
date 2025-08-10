#include <dtls/memory/buffer.h>
#include <dtls/error.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <atomic>
#include <memory>

namespace dtls {
namespace v13 {
namespace memory {

// BufferSharedState implementation
BufferSharedState::BufferSharedState(std::unique_ptr<std::byte[]> data, size_t capacity)
    : data_(std::move(data)), capacity_(capacity) {}

void BufferSharedState::secure_zero() noexcept {
    if (data_ && capacity_ > 0) {
        secure_zero_memory(data_.get(), capacity_);
    }
}

// ZeroCopyBuffer implementation
ZeroCopyBuffer::ZeroCopyBuffer(size_t capacity)
    : data_(capacity > 0 ? std::make_unique<std::byte[]>(capacity) : nullptr)
    , size_(0)
    , capacity_(capacity)
    , offset_(0)
    , is_shared_buffer_(false)
    , is_pooled_buffer_(false) {}

ZeroCopyBuffer::ZeroCopyBuffer(std::unique_ptr<std::byte[]> data, size_t size, size_t capacity)
    : data_(std::move(data))
    , size_(size)
    , capacity_(capacity)
    , offset_(0)
    , is_shared_buffer_(false)
    , is_pooled_buffer_(false) {
    
    if (size > capacity) {
        size_ = capacity;
    }
}

ZeroCopyBuffer::ZeroCopyBuffer(const std::byte* data, size_t size)
    : data_(size > 0 ? std::make_unique<std::byte[]>(size) : nullptr)
    , size_(size)
    , capacity_(size)
    , offset_(0)
    , is_shared_buffer_(false)
    , is_pooled_buffer_(false) {
    
    if (data && size > 0) {
        std::memcpy(data_.get(), data, size);
    }
}

ZeroCopyBuffer::ZeroCopyBuffer(std::shared_ptr<BufferSharedState> shared_state, size_t offset, size_t size)
    : shared_state_(std::move(shared_state))
    , size_(size)
    , capacity_(size)
    , offset_(offset)
    , is_shared_buffer_(true)
    , is_pooled_buffer_(false) {
    
    if (!shared_state_) {
        size_ = 0;
        capacity_ = 0;
        offset_ = 0;
        is_shared_buffer_ = false;
    } else {
        // Ensure offset and size are within bounds
        size_t max_size = shared_state_->capacity();
        if (offset > max_size) {
            offset_ = max_size;
            size_ = 0;
        } else if (offset + size > max_size) {
            size_ = max_size - offset;
        }
        capacity_ = size_; // For shared buffers, capacity equals size
    }
}

// Copy constructor - implements zero-copy sharing for shared buffers
ZeroCopyBuffer::ZeroCopyBuffer(const ZeroCopyBuffer& other) noexcept
    : shared_state_(other.shared_state_)
    , size_(other.size_)
    , capacity_(other.capacity_)
    , offset_(other.offset_)
    , is_shared_buffer_(other.is_shared_buffer_)
    , is_pooled_buffer_(other.is_pooled_buffer_) {
    
    if (other.is_shared_buffer_) {
        // Zero-copy sharing - just increment reference count
        if (shared_state_) {
            shared_state_->ref_count.fetch_add(1, std::memory_order_relaxed);
        }
    } else {
        // Traditional copy for non-shared buffers
        if (other.data_ && other.size_ > 0) {
            data_ = std::make_unique<std::byte[]>(other.capacity_);
            std::memcpy(data_.get(), other.data_.get(), other.size_);
        }
    }
}

ZeroCopyBuffer::ZeroCopyBuffer(ZeroCopyBuffer&& other) noexcept
    : data_(std::move(other.data_))
    , shared_state_(std::move(other.shared_state_))
    , size_(other.size_)
    , capacity_(other.capacity_)
    , offset_(other.offset_)
    , is_shared_buffer_(other.is_shared_buffer_)
    , is_pooled_buffer_(other.is_pooled_buffer_) {
    
    other.size_ = 0;
    other.capacity_ = 0;
    other.offset_ = 0;
    other.is_shared_buffer_ = false;
    other.is_pooled_buffer_ = false;
}

// Assignment operator - implements zero-copy sharing for shared buffers
ZeroCopyBuffer& ZeroCopyBuffer::operator=(const ZeroCopyBuffer& other) noexcept {
    if (this != &other) {
        // Decrement reference count for current shared state
        if (is_shared_buffer_ && shared_state_) {
            if (shared_state_->ref_count.fetch_sub(1, std::memory_order_relaxed) == 1) {
                // Last reference, state will be destroyed automatically
            }
        }
        
        // Copy from other
        shared_state_ = other.shared_state_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        offset_ = other.offset_;
        is_shared_buffer_ = other.is_shared_buffer_;
        is_pooled_buffer_ = other.is_pooled_buffer_;
        
        if (other.is_shared_buffer_) {
            // Zero-copy sharing
            if (shared_state_) {
                shared_state_->ref_count.fetch_add(1, std::memory_order_relaxed);
            }
            data_.reset(); // Clear owned data
        } else {
            // Traditional copy for non-shared buffers
            shared_state_.reset();
            if (other.data_ && other.size_ > 0) {
                data_ = std::make_unique<std::byte[]>(other.capacity_);
                std::memcpy(data_.get(), other.data_.get(), other.size_);
            } else {
                data_.reset();
            }
        }
    }
    return *this;
}

ZeroCopyBuffer& ZeroCopyBuffer::operator=(ZeroCopyBuffer&& other) noexcept {
    if (this != &other) {
        // Decrement reference count for current shared state
        if (is_shared_buffer_ && shared_state_) {
            if (shared_state_->ref_count.fetch_sub(1, std::memory_order_relaxed) == 1) {
                // Last reference, state will be destroyed automatically
            }
        }
        
        data_ = std::move(other.data_);
        shared_state_ = std::move(other.shared_state_);
        size_ = other.size_;
        capacity_ = other.capacity_;
        offset_ = other.offset_;
        is_shared_buffer_ = other.is_shared_buffer_;
        is_pooled_buffer_ = other.is_pooled_buffer_;
        
        other.size_ = 0;
        other.capacity_ = 0;
        other.offset_ = 0;
        other.is_shared_buffer_ = false;
        other.is_pooled_buffer_ = false;
    }
    return *this;
}

Result<void> ZeroCopyBuffer::append(const std::byte* data, size_t length) {
    if (!data && length > 0) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    if (length == 0) {
        return Result<void>();
    }
    
    auto result = ensure_capacity(size_ + length);
    if (!result) {
        return result;
    }
    
    std::memcpy(data_.get() + size_, data, length);
    size_ += length;
    
    return Result<void>();
}

Result<void> ZeroCopyBuffer::append(const ZeroCopyBuffer& other) {
    return append(other.data(), other.size());
}

Result<void> ZeroCopyBuffer::prepend(const std::byte* data, size_t length) {
    if (!data && length > 0) {
        return Result<void>(DTLSError::INVALID_PARAMETER);
    }
    
    if (length == 0) {
        return Result<void>();
    }
    
    auto result = ensure_capacity(size_ + length);
    if (!result) {
        return result;
    }
    
    // Move existing data to make room
    if (size_ > 0) {
        std::memmove(data_.get() + length, data_.get(), size_);
    }
    
    // Copy new data to the beginning
    std::memcpy(data_.get(), data, length);
    size_ += length;
    
    return Result<void>();
}

Result<ZeroCopyBuffer> ZeroCopyBuffer::slice(size_t offset, size_t length) const {
    if (offset > size_) {
        return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
    }
    
    size_t actual_length = std::min(length, size_ - offset);
    
    if (actual_length == 0) {
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer());
    }
    
    return Result<ZeroCopyBuffer>(ZeroCopyBuffer(data_.get() + offset, actual_length));
}

Result<void> ZeroCopyBuffer::reserve(size_t new_capacity) {
    if (new_capacity <= capacity_) {
        return Result<void>();
    }
    
    auto new_data = std::make_unique<std::byte[]>(new_capacity);
    if (!new_data) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
    
    if (size_ > 0 && data_) {
        std::memcpy(new_data.get(), data_.get(), size_);
    }
    
    data_ = std::move(new_data);
    capacity_ = new_capacity;
    
    return Result<void>();
}

Result<void> ZeroCopyBuffer::resize(size_t new_size) {
    if (new_size > capacity_) {
        auto result = reserve(new_size);
        if (!result) {
            return result;
        }
    }
    
    if (new_size > size_) {
        // Zero new memory
        std::memset(data_.get() + size_, 0, new_size - size_);
    }
    
    size_ = new_size;
    return Result<void>();
}

void ZeroCopyBuffer::shrink_to_fit() {
    if (size_ == capacity_) {
        return;
    }
    
    if (size_ == 0) {
        data_.reset();
        capacity_ = 0;
        return;
    }
    
    auto new_data = std::make_unique<std::byte[]>(size_);
    if (new_data) {
        std::memcpy(new_data.get(), data_.get(), size_);
        data_ = std::move(new_data);
        capacity_ = size_;
    }
}

void ZeroCopyBuffer::zero_memory() noexcept {
    if (data_ && size_ > 0) {
        std::memset(data_.get(), 0, size_);
    }
}

void ZeroCopyBuffer::secure_zero() noexcept {
    if (data_ && capacity_ > 0) {
        secure_zero_memory(data_.get(), capacity_);
    }
}

Result<void> ZeroCopyBuffer::ensure_capacity(size_t required_capacity) {
    if (required_capacity <= capacity_) {
        return Result<void>();
    }
    
    // Grow by at least 50% to amortize allocations
    size_t new_capacity = std::max(required_capacity, capacity_ + capacity_ / 2);
    
    return reserve(new_capacity);
}

// Zero-copy operations
ZeroCopyBuffer ZeroCopyBuffer::create_slice(size_t offset, size_t length) const noexcept {
    if (offset >= size_ || length == 0) {
        return ZeroCopyBuffer(); // Empty buffer
    }
    
    // Ensure slice doesn't exceed buffer bounds
    size_t actual_length = std::min(length, size_ - offset);
    
    if (is_shared_buffer_ && shared_state_) {
        // Create a new slice sharing the same underlying data
        return ZeroCopyBuffer(shared_state_, offset_ + offset, actual_length);
    } else if (data_) {
        // Convert to shared buffer for efficient slicing
        auto shared_state = std::make_shared<BufferSharedState>(std::make_unique<std::byte[]>(capacity_), capacity_);
        std::memcpy(shared_state->mutable_data(), data_.get(), size_);
        return ZeroCopyBuffer(shared_state, offset, actual_length);
    }
    
    return ZeroCopyBuffer(); // Empty buffer
}

Result<ZeroCopyBuffer> ZeroCopyBuffer::share_buffer() const {
    if (is_shared_buffer_ && shared_state_) {
        // Already shared, create another reference
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer(shared_state_, offset_, size_));
    } else if (data_ && size_ > 0) {
        // Convert to shared buffer
        auto shared_state = std::make_shared<BufferSharedState>(std::make_unique<std::byte[]>(capacity_), capacity_);
        std::memcpy(shared_state->mutable_data(), data_.get(), size_);
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer(shared_state, 0, size_));
    }
    
    return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
}

bool ZeroCopyBuffer::is_shared() const noexcept {
    return is_shared_buffer_ && shared_state_ != nullptr;
}

size_t ZeroCopyBuffer::reference_count() const noexcept {
    if (is_shared_buffer_ && shared_state_) {
        return shared_state_->ref_count.load(std::memory_order_relaxed);
    }
    return 1; // Non-shared buffers have reference count of 1
}

Result<void> ZeroCopyBuffer::make_unique() {
    if (!is_shared_buffer_ || !shared_state_) {
        return Result<void>(); // Already unique
    }
    
    if (shared_state_->ref_count.load(std::memory_order_relaxed) == 1) {
        return Result<void>(); // Only reference, already unique
    }
    
    // Copy-on-write: create unique copy
    auto new_data = std::make_unique<std::byte[]>(size_);
    if (!new_data) {
        return Result<void>(DTLSError::OUT_OF_MEMORY);
    }
    
    std::memcpy(new_data.get(), get_data_ptr(), size_);
    
    // Decrement shared reference count
    shared_state_->ref_count.fetch_sub(1, std::memory_order_relaxed);
    
    // Switch to unique ownership
    data_ = std::move(new_data);
    shared_state_.reset();
    capacity_ = size_;
    offset_ = 0;
    is_shared_buffer_ = false;
    
    return Result<void>();
}

bool ZeroCopyBuffer::can_modify() const noexcept {
    if (!is_shared_buffer_) {
        return true; // Owned buffers can always be modified
    }
    
    return shared_state_ && shared_state_->ref_count.load(std::memory_order_relaxed) == 1;
}

bool ZeroCopyBuffer::is_owning() const noexcept {
    return !is_shared_buffer_ && data_ != nullptr;
}

bool ZeroCopyBuffer::is_pooled() const noexcept {
    return is_pooled_buffer_;
}

void ZeroCopyBuffer::hint_sequential_access() noexcept {
    // Hint for memory access patterns - could be used for prefetching
    // Implementation would be platform-specific
}

void ZeroCopyBuffer::hint_random_access() noexcept {
    // Hint for memory access patterns
}

void ZeroCopyBuffer::hint_read_only() noexcept {
    // Hint that buffer will only be read from
}

const std::byte* ZeroCopyBuffer::get_data_ptr() const noexcept {
    if (is_shared_buffer_ && shared_state_) {
        return shared_state_->data() + offset_;
    }
    return data_.get();
}

std::byte* ZeroCopyBuffer::get_mutable_data_ptr() noexcept {
    if (is_shared_buffer_ && shared_state_) {
        return shared_state_->mutable_data() + offset_;
    }
    return data_.get();
}

void ZeroCopyBuffer::initialize_shared_state() {
    if (!is_shared_buffer_ && data_) {
        shared_state_ = std::make_shared<BufferSharedState>(std::move(data_), capacity_);
        is_shared_buffer_ = true;
        offset_ = 0;
    }
}

// BufferView implementation
BufferView BufferView::slice(size_t offset, size_t length) const noexcept {
    if (offset >= size_) {
        return BufferView();
    }
    
    size_t actual_length = std::min(length, size_ - offset);
    return BufferView(data_ + offset, actual_length);
}

BufferView BufferView::subview(size_t offset) const noexcept {
    if (offset >= size_) {
        return BufferView();
    }
    
    return BufferView(data_ + offset, size_ - offset);
}

bool BufferView::operator==(const BufferView& other) const noexcept {
    if (size_ != other.size_) {
        return false;
    }
    
    return std::memcmp(data_, other.data_, size_) == 0;
}

// MutableBufferView implementation
MutableBufferView MutableBufferView::slice(size_t offset, size_t length) noexcept {
    if (offset >= size_) {
        return MutableBufferView();
    }
    
    size_t actual_length = std::min(length, size_ - offset);
    return MutableBufferView(data_ + offset, actual_length);
}

MutableBufferView MutableBufferView::subview(size_t offset) noexcept {
    if (offset >= size_) {
        return MutableBufferView();
    }
    
    return MutableBufferView(data_ + offset, size_ - offset);
}

void MutableBufferView::fill(std::byte value) noexcept {
    if (data_ && size_ > 0) {
        std::memset(data_, static_cast<int>(value), size_);
    }
}

// Utility functions
bool constant_time_compare(const BufferView& a, const BufferView& b) noexcept {
    // Always perform comparison, even if sizes differ
    // This prevents early exit timing attacks
    size_t min_size = (a.size() < b.size()) ? a.size() : b.size();
    size_t max_size = (a.size() > b.size()) ? a.size() : b.size();
    
    const std::byte* ptr_a = a.data();
    const std::byte* ptr_b = b.data();
    
    // Mark as volatile to prevent compiler optimizations
    volatile std::byte result{0};
    
    // Compare all bytes up to the minimum size
    for (size_t i = 0; i < min_size; ++i) {
        std::byte diff = (ptr_a[i] ^ ptr_b[i]);
        result = result | diff;
    }
    
    // If sizes differ, XOR remaining bytes with themselves
    // This maintains constant-time behavior regardless of size difference
    if (a.size() != b.size()) {
        result = result | std::byte{1}; // Set result to indicate size mismatch
        
        // Perform dummy operations to maintain constant timing
        const std::byte* longer_ptr = (a.size() > b.size()) ? ptr_a : ptr_b;
        for (size_t i = min_size; i < max_size; ++i) {
            volatile std::byte dummy = longer_ptr[i];
            (void)dummy; // Suppress unused variable warning
        }
    }
    
    return result == std::byte{0};
}

void secure_zero_memory(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) {
        return;
    }
    
    // Use volatile to prevent compiler optimization
    volatile std::byte* volatile_ptr = static_cast<volatile std::byte*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = std::byte{0};
    }
}

size_t find_byte(const BufferView& buffer, std::byte value) noexcept {
    const std::byte* data = buffer.data();
    size_t size = buffer.size();
    
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == value) {
            return i;
        }
    }
    
    return size; // Not found, return size as "end" indicator
}

Result<ZeroCopyBuffer> concatenate_buffers(const std::vector<BufferView>& buffers) {
    // Calculate total size
    size_t total_size = 0;
    for (const auto& buffer : buffers) {
        total_size += buffer.size();
        
        // Check for overflow
        if (total_size < buffer.size()) {
            return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
        }
    }
    
    if (total_size == 0) {
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer());
    }
    
    ZeroCopyBuffer result(total_size);
    auto resize_result = result.resize(total_size);
    if (!resize_result) {
        return Result<ZeroCopyBuffer>(resize_result.error());
    }
    
    size_t offset = 0;
    for (const auto& buffer : buffers) {
        if (buffer.size() > 0) {
            std::memcpy(result.mutable_data() + offset, buffer.data(), buffer.size());
            offset += buffer.size();
        }
    }
    
    return Result<ZeroCopyBuffer>(std::move(result));
}

std::string to_hex_string(const BufferView& buffer) {
    if (buffer.empty()) {
        return "";
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    const std::byte* data = buffer.data();
    for (size_t i = 0; i < buffer.size(); ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    
    return oss.str();
}

Result<ZeroCopyBuffer> from_hex_string(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
    }
    
    size_t buffer_size = hex.length() / 2;
    if (buffer_size == 0) {
        return Result<ZeroCopyBuffer>(ZeroCopyBuffer());
    }
    
    ZeroCopyBuffer buffer(buffer_size);
    auto resize_result = buffer.resize(buffer_size);
    if (!resize_result) {
        return Result<ZeroCopyBuffer>(resize_result.error());
    }
    
    std::byte* data = buffer.mutable_data();
    
    for (size_t i = 0; i < buffer_size; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        
        try {
            unsigned long byte_value = std::stoul(byte_str, nullptr, 16);
            if (byte_value > 255) {
                return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
            }
            data[i] = static_cast<std::byte>(byte_value);
        } catch (...) {
            return Result<ZeroCopyBuffer>(DTLSError::INVALID_PARAMETER);
        }
    }
    
    return Result<ZeroCopyBuffer>(std::move(buffer));
}

} // namespace memory
} // namespace v13
} // namespace dtls