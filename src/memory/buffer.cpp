#include <dtls/memory/buffer.h>
#include <dtls/error.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace dtls {
namespace v13 {
namespace memory {

// ZeroCopyBuffer implementation
ZeroCopyBuffer::ZeroCopyBuffer(size_t capacity)
    : data_(capacity > 0 ? std::make_unique<std::byte[]>(capacity) : nullptr)
    , size_(0)
    , capacity_(capacity) {}

ZeroCopyBuffer::ZeroCopyBuffer(std::unique_ptr<std::byte[]> data, size_t size, size_t capacity)
    : data_(std::move(data))
    , size_(size)
    , capacity_(capacity) {
    
    if (size > capacity) {
        size_ = capacity;
    }
}

ZeroCopyBuffer::ZeroCopyBuffer(const std::byte* data, size_t size)
    : data_(size > 0 ? std::make_unique<std::byte[]>(size) : nullptr)
    , size_(size)
    , capacity_(size) {
    
    if (data && size > 0) {
        std::memcpy(data_.get(), data, size);
    }
}

ZeroCopyBuffer::ZeroCopyBuffer(ZeroCopyBuffer&& other) noexcept
    : data_(std::move(other.data_))
    , size_(other.size_)
    , capacity_(other.capacity_) {
    
    other.size_ = 0;
    other.capacity_ = 0;
}

ZeroCopyBuffer& ZeroCopyBuffer::operator=(ZeroCopyBuffer&& other) noexcept {
    if (this != &other) {
        data_ = std::move(other.data_);
        size_ = other.size_;
        capacity_ = other.capacity_;
        
        other.size_ = 0;
        other.capacity_ = 0;
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
    if (a.size() != b.size()) {
        return false;
    }
    
    const std::byte* ptr_a = a.data();
    const std::byte* ptr_b = b.data();
    size_t size = a.size();
    
    std::byte result{0};
    for (size_t i = 0; i < size; ++i) {
        result |= (ptr_a[i] ^ ptr_b[i]);
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