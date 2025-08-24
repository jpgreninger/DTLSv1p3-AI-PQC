#include <gtest/gtest.h>
#include <dtls/result.h>
#include <dtls/error.h>
#include <string>
#include <vector>
#include <memory>

using namespace dtls::v13;

class DTLSResultTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup common test data
    }

    void TearDown() override {
        // Cleanup
    }
};

// Test basic Result construction and state checking
TEST_F(DTLSResultTest, BasicConstruction) {
    // Test successful Result
    Result<int> success_result(42);
    EXPECT_TRUE(success_result.is_success());
    EXPECT_TRUE(success_result.is_ok()); // Alias for is_success
    EXPECT_FALSE(success_result.is_error());
    EXPECT_TRUE(success_result); // operator bool
    
    // Test error Result
    Result<int> error_result(DTLSError::INVALID_PARAMETER);
    EXPECT_FALSE(error_result.is_success());
    EXPECT_FALSE(error_result.is_ok());
    EXPECT_TRUE(error_result.is_error());
    EXPECT_FALSE(error_result); // operator bool
}

// Test Result value access
TEST_F(DTLSResultTest, ValueAccess) {
    Result<int> success_result(42);
    
    // Test value() methods
    EXPECT_EQ(success_result.value(), 42);
    EXPECT_EQ(std::as_const(success_result).value(), 42);
    
    // Test operator* methods
    EXPECT_EQ(*success_result, 42);
    EXPECT_EQ(*std::as_const(success_result), 42);
    
    // Test operator-> methods (with a type that has members)
    Result<std::string> string_result("hello");
    EXPECT_EQ(string_result->length(), 5);
    EXPECT_EQ(std::as_const(string_result)->length(), 5);
}

TEST_F(DTLSResultTest, ValueAccessFromError) {
    Result<int> error_result(DTLSError::INVALID_PARAMETER);
    
    // Accessing value from error should throw
    EXPECT_THROW(error_result.value(), DTLSException);
    EXPECT_THROW(*error_result, DTLSException);
    
    // operator-> should return nullptr for error
    EXPECT_EQ(error_result.operator->(), nullptr);
}

TEST_F(DTLSResultTest, MoveValueAccess) {
    Result<std::string> result("hello world");
    
    // Test move value access
    std::string moved_value = std::move(result).value();
    EXPECT_EQ(moved_value, "hello world");
    
    // Test move operator*
    Result<std::string> result2("test string");
    std::string moved_value2 = *std::move(result2);
    EXPECT_EQ(moved_value2, "test string");
}

// Test value_or functionality
TEST_F(DTLSResultTest, ValueOr) {
    Result<int> success_result(42);
    Result<int> error_result(DTLSError::TIMEOUT);
    
    // Test with success
    EXPECT_EQ(success_result.value_or(0), 42);
    EXPECT_EQ(std::as_const(success_result).value_or(0), 42);
    
    // Test with error
    EXPECT_EQ(error_result.value_or(99), 99);
    EXPECT_EQ(std::as_const(error_result).value_or(99), 99);
    
    // Test move version
    Result<std::string> string_success("success");
    Result<std::string> string_error(DTLSError::NETWORK_ERROR);
    
    EXPECT_EQ(std::move(string_success).value_or("default"), "success");
    EXPECT_EQ(std::move(string_error).value_or("default"), "default");
}

// Test error access
TEST_F(DTLSResultTest, ErrorAccess) {
    Result<int> success_result(42);
    Result<int> error_result(DTLSError::HANDSHAKE_FAILURE);
    
    // Test error() method
    EXPECT_EQ(success_result.error(), DTLSError::SUCCESS);
    EXPECT_EQ(error_result.error(), DTLSError::HANDSHAKE_FAILURE);
}

// Test copy and move semantics
TEST_F(DTLSResultTest, CopyAndMove) {
    Result<std::string> original("original value");
    
    // Test copy constructor
    Result<std::string> copied(original);
    EXPECT_TRUE(original.is_success());
    EXPECT_TRUE(copied.is_success());
    EXPECT_EQ(original.value(), "original value");
    EXPECT_EQ(copied.value(), "original value");
    
    // Test copy assignment
    Result<std::string> copy_assigned(DTLSError::TIMEOUT);
    copy_assigned = original;
    EXPECT_TRUE(copy_assigned.is_success());
    EXPECT_EQ(copy_assigned.value(), "original value");
    
    // Test move constructor
    Result<std::string> moved(std::move(original));
    EXPECT_TRUE(moved.is_success());
    EXPECT_EQ(moved.value(), "original value");
    
    // Test move assignment
    Result<std::string> move_assigned(DTLSError::NETWORK_ERROR);
    move_assigned = std::move(copied);
    EXPECT_TRUE(move_assigned.is_success());
    EXPECT_EQ(move_assigned.value(), "original value");
}

// Test monadic operations - map
TEST_F(DTLSResultTest, MapOperation) {
    Result<int> success_result(5);
    Result<int> error_result(DTLSError::DECRYPT_ERROR);
    
    // Test map on success
    auto mapped_success = success_result.map([](int x) { return x * 2; });
    EXPECT_TRUE(mapped_success.is_success());
    EXPECT_EQ(mapped_success.value(), 10);
    
    // Test map on error - should propagate error
    auto mapped_error = error_result.map([](int x) { return x * 2; });
    EXPECT_TRUE(mapped_error.is_error());
    EXPECT_EQ(mapped_error.error(), DTLSError::DECRYPT_ERROR);
    
    // Test map changing type
    auto string_mapped = success_result.map([](int x) { return std::to_string(x); });
    EXPECT_TRUE(string_mapped.is_success());
    EXPECT_EQ(string_mapped.value(), "5");
    
    // Test move version of map
    Result<std::string> move_source("hello");
    auto move_mapped = std::move(move_source).map([](std::string s) { return s + " world"; });
    EXPECT_TRUE(move_mapped.is_success());
    EXPECT_EQ(move_mapped.value(), "hello world");
}

// Test monadic operations - and_then
TEST_F(DTLSResultTest, AndThenOperation) {
    Result<int> success_result(5);
    Result<int> error_result(DTLSError::CERTIFICATE_VERIFY_FAILED);
    
    // Test and_then on success
    auto chained_success = success_result.and_then([](int x) -> Result<int> {
        if (x > 0) {
            return Result<int>(x * 2);
        }
        return Result<int>(DTLSError::INVALID_PARAMETER);
    });
    EXPECT_TRUE(chained_success.is_success());
    EXPECT_EQ(chained_success.value(), 10);
    
    // Test and_then returning error
    auto chained_error = success_result.and_then([](int x) -> Result<int> {
        return Result<int>(DTLSError::TIMEOUT);
    });
    EXPECT_TRUE(chained_error.is_error());
    EXPECT_EQ(chained_error.error(), DTLSError::TIMEOUT);
    
    // Test and_then on error - should propagate error
    auto error_chained = error_result.and_then([](int x) -> Result<int> {
        return Result<int>(x * 2);
    });
    EXPECT_TRUE(error_chained.is_error());
    EXPECT_EQ(error_chained.error(), DTLSError::CERTIFICATE_VERIFY_FAILED);
    
    // Test and_then changing type
    auto type_changed = success_result.and_then([](int x) -> Result<std::string> {
        return Result<std::string>(std::to_string(x * 3));
    });
    EXPECT_TRUE(type_changed.is_success());
    EXPECT_EQ(type_changed.value(), "15");
    
    // Test move version
    Result<std::string> move_source("42");
    auto move_chained = std::move(move_source).and_then([](std::string s) -> Result<int> {
        return Result<int>(std::stoi(s));
    });
    EXPECT_TRUE(move_chained.is_success());
    EXPECT_EQ(move_chained.value(), 42);
}

// Test monadic operations - or_else
TEST_F(DTLSResultTest, OrElseOperation) {
    Result<int> success_result(42);
    Result<int> error_result(DTLSError::NETWORK_ERROR);
    
    // Test or_else on success - should return original
    auto success_or_else = success_result.or_else([](DTLSError error) -> Result<int> {
        return Result<int>(999); // Should not be called
    });
    EXPECT_TRUE(success_or_else.is_success());
    EXPECT_EQ(success_or_else.value(), 42);
    
    // Test or_else on error - should call fallback
    auto error_or_else = error_result.or_else([](DTLSError error) -> Result<int> {
        EXPECT_EQ(error, DTLSError::NETWORK_ERROR);
        return Result<int>(100);
    });
    EXPECT_TRUE(error_or_else.is_success());
    EXPECT_EQ(error_or_else.value(), 100);
    
    // Test or_else returning another error
    auto error_or_else_error = error_result.or_else([](DTLSError error) -> Result<int> {
        return Result<int>(DTLSError::TIMEOUT);
    });
    EXPECT_TRUE(error_or_else_error.is_error());
    EXPECT_EQ(error_or_else_error.error(), DTLSError::TIMEOUT);
    
    // Test move version
    Result<std::string> move_error(DTLSError::INVALID_PARAMETER);
    auto move_or_else = std::move(move_error).or_else([](DTLSError error) -> Result<std::string> {
        return Result<std::string>("fallback");
    });
    EXPECT_TRUE(move_or_else.is_success());
    EXPECT_EQ(move_or_else.value(), "fallback");
}

// Test monadic operations - map_error
TEST_F(DTLSResultTest, MapErrorOperation) {
    Result<int> success_result(42);
    Result<int> error_result(DTLSError::HANDSHAKE_FAILURE);
    
    // Test map_error on success - should return original
    auto success_mapped_error = success_result.map_error([](DTLSError error) {
        return DTLSError::TIMEOUT; // Should not be called
    });
    EXPECT_TRUE(success_mapped_error.is_success());
    EXPECT_EQ(success_mapped_error.value(), 42);
    
    // Test map_error on error - should transform error
    auto error_mapped = error_result.map_error([](DTLSError error) {
        EXPECT_EQ(error, DTLSError::HANDSHAKE_FAILURE);
        return DTLSError::INTERNAL_ERROR;
    });
    EXPECT_TRUE(error_mapped.is_error());
    EXPECT_EQ(error_mapped.error(), DTLSError::INTERNAL_ERROR);
    
    // Test move version
    Result<std::string> move_error(DTLSError::DECRYPT_ERROR);
    auto move_mapped_error = std::move(move_error).map_error([](DTLSError error) {
        return DTLSError::CRYPTO_PROVIDER_ERROR;
    });
    EXPECT_TRUE(move_mapped_error.is_error());
    EXPECT_EQ(move_mapped_error.error(), DTLSError::CRYPTO_PROVIDER_ERROR);
}

// Test Result<void> specialization
TEST_F(DTLSResultTest, VoidSpecialization) {
    // Test successful void Result
    Result<void> success_void;
    EXPECT_TRUE(success_void.is_success());
    EXPECT_TRUE(success_void.is_ok());
    EXPECT_FALSE(success_void.is_error());
    EXPECT_TRUE(success_void); // operator bool
    EXPECT_EQ(success_void.error(), DTLSError::SUCCESS);
    
    // Test error void Result
    Result<void> error_void(DTLSError::CONNECTION_TIMEOUT);
    EXPECT_FALSE(error_void.is_success());
    EXPECT_FALSE(error_void.is_ok());
    EXPECT_TRUE(error_void.is_error());
    EXPECT_FALSE(error_void); // operator bool
    EXPECT_EQ(error_void.error(), DTLSError::CONNECTION_TIMEOUT);
}

TEST_F(DTLSResultTest, VoidSpecializationMonadicOps) {
    Result<void> success_void;
    Result<void> error_void(DTLSError::SOCKET_ERROR);
    
    // Test and_then on void
    auto void_and_then_success = success_void.and_then([]() -> Result<int> {
        return Result<int>(123);
    });
    EXPECT_TRUE(void_and_then_success.is_success());
    EXPECT_EQ(void_and_then_success.value(), 123);
    
    auto void_and_then_error = error_void.and_then([]() -> Result<int> {
        return Result<int>(456); // Should not be called
    });
    EXPECT_TRUE(void_and_then_error.is_error());
    EXPECT_EQ(void_and_then_error.error(), DTLSError::SOCKET_ERROR);
    
    // Test or_else on void
    auto void_or_else_success = success_void.or_else([](DTLSError error) -> Result<void> {
        return Result<void>(DTLSError::TIMEOUT); // Should not be called
    });
    EXPECT_TRUE(void_or_else_success.is_success());
    
    auto void_or_else_error = error_void.or_else([](DTLSError error) -> Result<void> {
        EXPECT_EQ(error, DTLSError::SOCKET_ERROR);
        return Result<void>(); // Success
    });
    EXPECT_TRUE(void_or_else_error.is_success());
    
    // Test map_error on void
    auto void_map_error_success = success_void.map_error([](DTLSError error) {
        return DTLSError::TIMEOUT; // Should not be called
    });
    EXPECT_TRUE(void_map_error_success.is_success());
    
    auto void_map_error_error = error_void.map_error([](DTLSError error) {
        EXPECT_EQ(error, DTLSError::SOCKET_ERROR);
        return DTLSError::NETWORK_ERROR;
    });
    EXPECT_TRUE(void_map_error_error.is_error());
    EXPECT_EQ(void_map_error_error.error(), DTLSError::NETWORK_ERROR);
}

// Test helper functions
TEST_F(DTLSResultTest, HelperFunctions) {
    // Test make_result with value
    auto int_result = make_result(42);
    EXPECT_TRUE(int_result.is_success());
    EXPECT_EQ(int_result.value(), 42);
    
    auto string_result = make_result(std::string("test"));
    EXPECT_TRUE(string_result.is_success());
    EXPECT_EQ(string_result.value(), "test");
    
    // Test make_result void
    auto void_result = make_result();
    EXPECT_TRUE(void_result.is_success());
    
    // Test make_error
    auto error_result = make_error<int>(DTLSError::HANDSHAKE_FAILURE);
    EXPECT_TRUE(error_result.is_error());
    EXPECT_EQ(error_result.error(), DTLSError::HANDSHAKE_FAILURE);
    
    // Test make_error with message (message is ignored in current implementation)
    auto error_with_message = make_error<std::string>(DTLSError::DECRYPT_ERROR, "test message");
    EXPECT_TRUE(error_with_message.is_error());
    EXPECT_EQ(error_with_message.error(), DTLSError::DECRYPT_ERROR);
    
    auto error_with_c_message = make_error<int>(DTLSError::TIMEOUT, "c-style message");
    EXPECT_TRUE(error_with_c_message.is_error());
    EXPECT_EQ(error_with_c_message.error(), DTLSError::TIMEOUT);
}

// Test complex types in Result
TEST_F(DTLSResultTest, ComplexTypes) {
    // Test with vector
    std::vector<int> test_vector = {1, 2, 3, 4, 5};
    Result<std::vector<int>> vector_result(test_vector);
    EXPECT_TRUE(vector_result.is_success());
    EXPECT_EQ(vector_result.value().size(), 5);
    EXPECT_EQ(vector_result.value()[0], 1);
    
    // Test with unique_ptr
    auto unique_ptr = std::make_unique<int>(42);
    Result<std::unique_ptr<int>> ptr_result(std::move(unique_ptr));
    EXPECT_TRUE(ptr_result.is_success());
    EXPECT_EQ(*ptr_result.value(), 42);
    
    // Test with custom struct
    struct TestStruct {
        int x;
        std::string y;
        bool operator==(const TestStruct& other) const {
            return x == other.x && y == other.y;
        }
    };
    
    TestStruct test_struct{42, "hello"};
    Result<TestStruct> struct_result(test_struct);
    EXPECT_TRUE(struct_result.is_success());
    EXPECT_EQ(struct_result.value().x, 42);
    EXPECT_EQ(struct_result.value().y, "hello");
}

// Test chaining multiple operations
TEST_F(DTLSResultTest, OperationChaining) {
    Result<int> initial(10);
    
    // Chain multiple operations
    auto result = initial
        .map([](int x) { return x * 2; })           // 20
        .and_then([](int x) -> Result<int> {        // 40
            return Result<int>(x * 2);
        })
        .map([](int x) { return x + 5; })           // 45
        .and_then([](int x) -> Result<std::string> { // "45"
            return Result<std::string>(std::to_string(x));
        });
    
    EXPECT_TRUE(result.is_success());
    EXPECT_EQ(result.value(), "45");
    
    // Test chaining with error in the middle
    Result<int> error_chain(5);
    auto error_result = error_chain
        .map([](int x) { return x * 2; })           // 10
        .and_then([](int x) -> Result<int> {        // Error here
            return Result<int>(DTLSError::TIMEOUT);
        })
        .map([](int x) { return x + 100; })         // Should not execute
        .and_then([](int x) -> Result<std::string> { // Should not execute
            return Result<std::string>("should not reach");
        });
    
    EXPECT_TRUE(error_result.is_error());
    EXPECT_EQ(error_result.error(), DTLSError::TIMEOUT);
}

// Test error propagation through complex chains
TEST_F(DTLSResultTest, ErrorPropagation) {
    // Test that errors propagate correctly through long chains
    Result<int> start_error(DTLSError::INVALID_PARAMETER);
    
    bool map_called = false;
    bool and_then_called = false;
    
    auto propagated = start_error
        .map([&map_called](int x) -> int { 
            map_called = true; 
            return x * 2; 
        })
        .and_then([&and_then_called](int x) -> Result<std::string> { 
            and_then_called = true; 
            return Result<std::string>("test"); 
        });
    
    EXPECT_TRUE(propagated.is_error());
    EXPECT_EQ(propagated.error(), DTLSError::INVALID_PARAMETER);
    EXPECT_FALSE(map_called);
    EXPECT_FALSE(and_then_called);
}

// Test edge cases and corner conditions
TEST_F(DTLSResultTest, EdgeCases) {
    // Test with empty string
    Result<std::string> empty_string("");
    EXPECT_TRUE(empty_string.is_success());
    EXPECT_EQ(empty_string.value(), "");
    
    // Test with zero
    Result<int> zero_result(0);
    EXPECT_TRUE(zero_result.is_success());
    EXPECT_EQ(zero_result.value(), 0);
    
    // Test with nullptr (if using pointer types)
    Result<int*> null_ptr_result(nullptr);
    EXPECT_TRUE(null_ptr_result.is_success());
    EXPECT_EQ(null_ptr_result.value(), nullptr);
    
    // Test operator-> with null result - it should return a pointer to the stored value
    EXPECT_NE(null_ptr_result.operator->(), nullptr); // operator-> returns &value, not value
    EXPECT_EQ(*null_ptr_result.operator->(), nullptr); // the stored value should be nullptr
}

// Test macros (basic functionality)
TEST_F(DTLSResultTest, MacroBasics) {
    // Note: Full macro testing would require a function context
    // These are basic compile-time tests
    
    // Test that macros are defined
    #ifdef DTLS_TRY
    EXPECT_TRUE(true); // Macro is defined
    #else
    FAIL() << "DTLS_TRY macro not defined";
    #endif
    
    #ifdef DTLS_TRY_VOID
    EXPECT_TRUE(true); // Macro is defined
    #else
    FAIL() << "DTLS_TRY_VOID macro not defined";
    #endif
}