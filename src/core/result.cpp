#include <dtls/result.h>

namespace dtls {
namespace v13 {

// Template specialization implementations for Result<void>
// Most of the Result implementation is in the header as templates,
// but we can provide some utility functions here.

// Helper function for creating success results
Result<void> make_success() {
    return Result<void>();
}

// Helper function for creating error results
Result<void> make_error_void(DTLSError error) {
    return Result<void>(error);
}

// Utility functions for working with Results
namespace result_utils {

// Check if an error code represents success
bool is_success(DTLSError error) {
    return error == DTLSError::SUCCESS;
}

// Check if an error code represents failure
bool is_error(DTLSError error) {
    return error != DTLSError::SUCCESS;
}

// Convert error code to string
std::string error_to_string(DTLSError error) {
    return error_message(error);
}

// Combine multiple Result<void> operations
Result<void> combine_results(const std::vector<Result<void>>& results) {
    for (const auto& result : results) {
        if (result.is_error()) {
            return result;
        }
    }
    return Result<void>();
}

// Execute a function and wrap any thrown DTLSException in a Result
template<typename F>
auto try_execute(F&& func) -> Result<decltype(func())> {
    try {
        if constexpr (std::is_void_v<decltype(func())>) {
            func();
            return Result<void>();
        } else {
            return Result<decltype(func())>(func());
        }
    } catch (const DTLSException& e) {
        return Result<decltype(func())>(e.dtls_error());
    } catch (const std::exception& e) {
        // Convert standard exceptions to internal error
        return Result<decltype(func())>(DTLSError::INTERNAL_ERROR);
    }
}

// Explicit template instantiations for common types
template Result<void> try_execute<std::function<void()>>(std::function<void()>&& func);
template Result<int> try_execute<std::function<int()>>(std::function<int()>&& func);
template Result<std::string> try_execute<std::function<std::string()>>(std::function<std::string()>&& func);
template Result<std::vector<uint8_t>> try_execute<std::function<std::vector<uint8_t>()>>(std::function<std::vector<uint8_t>()>&& func);

} // namespace result_utils

// Result composition utilities
namespace result_compose {

// Chain multiple operations that return Results
template<typename T, typename F>
auto and_then_chain(Result<T> initial, F&& func) -> decltype(func(std::move(initial).value())) {
    if (initial.is_error()) {
        using ReturnType = decltype(func(std::move(initial).value()));
        return ReturnType(initial.error());
    }
    return func(std::move(initial).value());
}

// Map over a Result value
template<typename T, typename F>
auto map_result(const Result<T>& result, F&& func) -> Result<decltype(func(result.value()))> {
    if (result.is_error()) {
        using ReturnType = decltype(func(result.value()));
        return Result<ReturnType>(result.error());
    }
    return Result<decltype(func(result.value()))>(func(result.value()));
}

// Apply a function to the error case
template<typename T, typename F>
Result<T> map_error_result(const Result<T>& result, F&& func) {
    if (result.is_success()) {
        return result;
    }
    return Result<T>(func(result.error()));
}

// Convert Result<T> to Result<U> using a conversion function
template<typename T, typename U, typename F>
Result<U> convert_result(const Result<T>& result, F&& converter) {
    if (result.is_error()) {
        return Result<U>(result.error());
    }
    try {
        return Result<U>(converter(result.value()));
    } catch (const DTLSException& e) {
        return Result<U>(e.dtls_error());
    } catch (...) {
        return Result<U>(DTLSError::INTERNAL_ERROR);
    }
}

} // namespace result_compose

// Result validation utilities
namespace result_validate {

// Validate that a Result contains an expected value
template<typename T>
Result<T> validate_result(const Result<T>& result, 
                         std::function<bool(const T&)> validator,
                         DTLSError validation_error = DTLSError::INVALID_PARAMETER) {
    if (result.is_error()) {
        return result;
    }
    
    if (!validator(result.value())) {
        return Result<T>(validation_error);
    }
    
    return result;
}

// Validate Result<void> with a predicate
Result<void> validate_void_result(const Result<void>& result,
                                 std::function<bool()> validator,
                                 DTLSError validation_error = DTLSError::INVALID_PARAMETER) {
    if (result.is_error()) {
        return result;
    }
    
    if (!validator()) {
        return Result<void>(validation_error);
    }
    
    return result;
}

// Ensure a Result meets minimum requirements
template<typename T>
Result<T> ensure_result(const Result<T>& result,
                       std::function<Result<void>(const T&)> requirement) {
    if (result.is_error()) {
        return result;
    }
    
    auto req_result = requirement(result.value());
    if (req_result.is_error()) {
        return Result<T>(req_result.error());
    }
    
    return result;
}

} // namespace result_validate

// Result timing and performance utilities
namespace result_perf {

// Measure execution time of a function that returns a Result
template<typename F>
auto timed_execute(F&& func) -> std::pair<decltype(func()), std::chrono::nanoseconds> {
    auto start = std::chrono::steady_clock::now();
    auto result = func();
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    return {std::move(result), duration};
}

// Execute with timeout
template<typename F>
auto execute_with_timeout(F&& func, std::chrono::milliseconds timeout) -> Result<decltype(func().value())> {
    // Note: This is a simplified version. A real implementation would need
    // proper timeout handling with threads or async operations.
    try {
        auto start = std::chrono::steady_clock::now();
        auto result = func();
        auto elapsed = std::chrono::steady_clock::now() - start;
        
        if (elapsed > timeout) {
            using ReturnType = decltype(func().value());
            return Result<ReturnType>(DTLSError::TIMEOUT);
        }
        
        return result;
    } catch (const DTLSException& e) {
        using ReturnType = decltype(func().value());
        return Result<ReturnType>(e.dtls_error());
    } catch (...) {
        using ReturnType = decltype(func().value());
        return Result<ReturnType>(DTLSError::INTERNAL_ERROR);
    }
}

} // namespace result_perf

} // namespace v13
} // namespace dtls