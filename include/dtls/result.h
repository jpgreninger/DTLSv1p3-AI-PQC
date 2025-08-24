#ifndef DTLS_RESULT_H
#define DTLS_RESULT_H

#include <dtls/config.h>
#include <dtls/error.h>
#include <variant>
#include <functional>
#include <type_traits>

namespace dtls {
namespace v13 {

/** Forward declaration for Result template class. */
template<typename T>
class Result;

/**
 * Result type for operations that can fail.
 * 
 * A type that represents either a success value of type T or an error.
 * This provides a safe way to handle operations that might fail without
 * using exceptions, following the Rust-style Result pattern.
 * 
 * @tparam T The type of the success value
 */
template<typename T>
class DTLS_API Result {
public:
    /**
     * Constructs a successful Result with the given value.
     * @param value The success value
     */
    Result(T value) : data_(std::move(value)) {}
    
    /**
     * Constructs a failed Result with the given error.
     * @param error The error code
     */
    Result(DTLSError error) : data_(error) {}
    
    /** Copy constructor. */
    Result(const Result&) = default;
    
    /** Move constructor. */
    Result(Result&&) = default;
    
    /** Copy assignment operator. */
    Result& operator=(const Result&) = default;
    
    /** Move assignment operator. */
    Result& operator=(Result&&) = default;
    
    // Success/error checking
    bool is_success() const noexcept {
        return std::holds_alternative<T>(data_);
    }
    
    // Alias for is_success() for compatibility
    bool is_ok() const noexcept {
        return is_success();
    }
    
    bool is_error() const noexcept {
        return std::holds_alternative<DTLSError>(data_);
    }
    
    // Value access (throws if error)
    const T& value() const & {
        if (is_error()) {
            throw DTLSException(std::get<DTLSError>(data_));
        }
        return std::get<T>(data_);
    }
    
    T& value() & {
        if (is_error()) {
            throw DTLSException(std::get<DTLSError>(data_));
        }
        return std::get<T>(data_);
    }
    
    T value() && {
        if (is_error()) {
            throw DTLSException(std::get<DTLSError>(data_));
        }
        return std::move(std::get<T>(data_));
    }
    
    // Value access with default
    template<typename U>
    T value_or(U&& default_value) const & {
        if (is_success()) {
            return std::get<T>(data_);
        }
        return static_cast<T>(std::forward<U>(default_value));
    }
    
    template<typename U>
    T value_or(U&& default_value) && {
        if (is_success()) {
            return std::move(std::get<T>(data_));
        }
        return static_cast<T>(std::forward<U>(default_value));
    }
    
    // Error access
    DTLSError error() const {
        if (is_success()) {
            return DTLSError::SUCCESS;
        }
        return std::get<DTLSError>(data_);
    }
    
    // Operators
    explicit operator bool() const noexcept {
        return is_success();
    }
    
    const T& operator*() const & {
        return value();
    }
    
    T& operator*() & {
        return value();
    }
    
    T operator*() && {
        return std::move(*this).value();
    }
    
    const T* operator->() const {
        if (is_error()) {
            return nullptr;
        }
        return &std::get<T>(data_);
    }
    
    T* operator->() {
        if (is_error()) {
            return nullptr;
        }
        return &std::get<T>(data_);
    }
    
    // Monadic operations
    template<typename F>
    auto map(F&& func) const & -> Result<decltype(func(value()))> {
        using ReturnType = decltype(func(value()));
        if (is_error()) {
            return Result<ReturnType>(error());
        }
        return Result<ReturnType>(func(value()));
    }
    
    template<typename F>
    auto map(F&& func) && -> Result<decltype(func(std::move(*this).value()))> {
        using ReturnType = decltype(func(std::move(*this).value()));
        if (is_error()) {
            return Result<ReturnType>(error());
        }
        return Result<ReturnType>(func(std::move(*this).value()));
    }
    
    template<typename F>
    auto and_then(F&& func) const & -> decltype(func(value())) {
        if (is_error()) {
            using ReturnType = decltype(func(value()));
            return ReturnType(error());
        }
        return func(value());
    }
    
    template<typename F>
    auto and_then(F&& func) && -> decltype(func(std::move(*this).value())) {
        if (is_error()) {
            using ReturnType = decltype(func(std::move(*this).value()));
            return ReturnType(error());
        }
        return func(std::move(*this).value());
    }
    
    template<typename F>
    Result<T> or_else(F&& func) const & {
        if (is_success()) {
            return *this;
        }
        return func(error());
    }
    
    template<typename F>
    Result<T> or_else(F&& func) && {
        if (is_success()) {
            return std::move(*this);
        }
        return func(error());
    }
    
    // Transform error
    template<typename F>
    Result<T> map_error(F&& func) const & {
        if (is_success()) {
            return *this;
        }
        return Result<T>(func(error()));
    }
    
    template<typename F>
    Result<T> map_error(F&& func) && {
        if (is_success()) {
            return std::move(*this);
        }
        return Result<T>(func(error()));
    }

private:
    std::variant<T, DTLSError> data_;
};

// Specialization for void type
template<>
class DTLS_API Result<void> {
public:
    // Constructors
    Result() : error_(DTLSError::SUCCESS) {}
    Result(DTLSError error) : error_(error) {}
    
    // Copy and move
    Result(const Result&) = default;
    Result(Result&&) = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) = default;
    
    // Success/error checking
    bool is_success() const noexcept {
        return error_ == DTLSError::SUCCESS;
    }
    
    // Alias for is_success() for compatibility
    bool is_ok() const noexcept {
        return is_success();
    }
    
    bool is_error() const noexcept {
        return error_ != DTLSError::SUCCESS;
    }
    
    // Error access
    DTLSError error() const noexcept {
        return error_;
    }
    
    // Operators
    explicit operator bool() const noexcept {
        return is_success();
    }
    
    // Monadic operations
    template<typename F>
    auto and_then(F&& func) const -> decltype(func()) {
        if (is_error()) {
            using ReturnType = decltype(func());
            return ReturnType(error_);
        }
        return func();
    }
    
    template<typename F>
    Result<void> or_else(F&& func) const {
        if (is_success()) {
            return *this;
        }
        return func(error_);
    }
    
    // Transform error
    template<typename F>
    Result<void> map_error(F&& func) const {
        if (is_success()) {
            return *this;
        }
        return Result<void>(func(error_));
    }

private:
    DTLSError error_;
};

// Helper functions for creating Results
template<typename T>
Result<std::decay_t<T>> make_result(T&& value) {
    return Result<std::decay_t<T>>(std::forward<T>(value));
}

inline Result<void> make_result() {
    return Result<void>();
}

template<typename T>
Result<T> make_error(DTLSError error) {
    return Result<T>(error);
}

template<typename T>
Result<T> make_error(DTLSError error, const char* message) {
    // For now, ignore the message and just return the error
    // In a more sophisticated implementation, this could store the message
    (void)message; // Suppress unused parameter warning
    return Result<T>(error);
}

template<typename T>
Result<T> make_error(DTLSError error, const std::string& message) {
    // For now, ignore the message and just return the error
    // In a more sophisticated implementation, this could store the message
    (void)message; // Suppress unused parameter warning
    return Result<T>(error);
}

// Convenience macros
#define DTLS_TRY(expr) \
    ({ \
        auto _result = (expr); \
        if (_result.is_error()) { \
            return _result.error(); \
        } \
        std::move(_result).value(); \
    })

#define DTLS_TRY_VOID(expr) \
    do { \
        auto _result = (expr); \
        if (_result.is_error()) { \
            return _result.error(); \
        } \
    } while (0)

} // namespace v13
} // namespace dtls

#endif // DTLS_RESULT_H