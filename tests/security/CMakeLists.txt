# Security Validation Suite CMake Configuration
cmake_minimum_required(VERSION 3.16)

# Security test sources
set(SECURITY_TEST_SOURCES
    dtls_security_test.cpp
    test_dos_protection.cpp
    test_rate_limiter.cpp
    test_attack_resilience.cpp
    security_validation_suite.cpp
    comprehensive_security_tests.cpp
    security_assessment_report_generator.cpp
)

# Security test headers
set(SECURITY_TEST_HEADERS
    security_validation_suite.h
)

# Create security test executable
add_executable(dtls_security_tests ${SECURITY_TEST_SOURCES})

# Create dedicated rate limiter test executable
add_executable(dtls_rate_limiter_tests test_rate_limiter.cpp)

# Create dedicated attack resilience test executable
add_executable(dtls_attack_resilience_tests test_attack_resilience.cpp)

# Link required libraries
target_link_libraries(dtls_security_tests
    PRIVATE
        dtlsv13
        gtest
        gtest_main
        ${CMAKE_THREAD_LIBS_INIT}
)

# Link required libraries for rate limiter tests
target_link_libraries(dtls_rate_limiter_tests
    PRIVATE
        dtlsv13
        gtest
        gtest_main
        ${CMAKE_THREAD_LIBS_INIT}
)

# Link required libraries for attack resilience tests
target_link_libraries(dtls_attack_resilience_tests
    PRIVATE
        dtlsv13
        gtest
        gtest_main
        ${CMAKE_THREAD_LIBS_INIT}
)

# Include directories
target_include_directories(dtls_security_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests/test_infrastructure
)

# Include directories for rate limiter tests
target_include_directories(dtls_rate_limiter_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests/test_infrastructure
)

# Include directories for attack resilience tests
target_include_directories(dtls_attack_resilience_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests/test_infrastructure
)

# Compiler flags for security testing
target_compile_options(dtls_security_tests
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -pedantic
        -O2
        -g
        -fsanitize=address
        -fsanitize=undefined
        -fstack-protector-strong
)

# Compiler flags for rate limiter testing
target_compile_options(dtls_rate_limiter_tests
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -pedantic
        -O2
        -g
        -fsanitize=address
        -fsanitize=undefined
        -fstack-protector-strong
)

# Compiler flags for attack resilience testing
target_compile_options(dtls_attack_resilience_tests
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -pedantic
        -O2
        -g
        -fsanitize=address
        -fsanitize=undefined
        -fstack-protector-strong
)

# Linker flags for security testing
target_link_options(dtls_security_tests
    PRIVATE
        -fsanitize=address
        -fsanitize=undefined
)

# Linker flags for rate limiter testing
target_link_options(dtls_rate_limiter_tests
    PRIVATE
        -fsanitize=address
        -fsanitize=undefined
)

# Linker flags for attack resilience testing
target_link_options(dtls_attack_resilience_tests
    PRIVATE
        -fsanitize=address
        -fsanitize=undefined
)

# Create comprehensive security validation test
add_executable(comprehensive_security_validation comprehensive_security_tests.cpp security_validation_suite.cpp security_assessment_report_generator.cpp)

target_link_libraries(comprehensive_security_validation
    PRIVATE
        dtlsv13
        gtest
        gtest_main
        ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(comprehensive_security_validation
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests/test_infrastructure
)

target_compile_options(comprehensive_security_validation
    PRIVATE
        -Wall
        -Wextra
        -Werror
        -pedantic
        -O2
        -g
        -fsanitize=address
        -fsanitize=undefined
        -fstack-protector-strong
)

target_link_options(comprehensive_security_validation
    PRIVATE
        -fsanitize=address
        -fsanitize=undefined
)

# Security report generator executable
add_executable(security_report_generator security_assessment_report_generator.cpp security_validation_suite.cpp)

target_link_libraries(security_report_generator
    PRIVATE
        dtlsv13
        ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(security_report_generator
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)

# Test discovery
include(GoogleTest)
gtest_discover_tests(dtls_security_tests)
gtest_discover_tests(dtls_rate_limiter_tests)
gtest_discover_tests(dtls_attack_resilience_tests)
gtest_discover_tests(comprehensive_security_validation)

# Custom test targets for different security test types
add_custom_target(security_tests_basic
    COMMAND dtls_security_tests
    COMMENT "Running basic security tests"
    VERBATIM
)

add_custom_target(rate_limiter_tests
    COMMAND dtls_rate_limiter_tests
    COMMENT "Running rate limiter tests"
    VERBATIM
)

add_custom_target(attack_resilience_tests
    COMMAND dtls_attack_resilience_tests
    COMMENT "Running comprehensive DoS attack resilience tests"
    VERBATIM
)

add_custom_target(security_tests_comprehensive
    COMMAND comprehensive_security_validation
    COMMENT "Running comprehensive security validation suite"
    VERBATIM
)

add_custom_target(security_tests_quick
    COMMAND dtls_security_tests --gtest_filter="*Quick*"
    COMMENT "Running quick security tests"
    VERBATIM
)

add_custom_target(security_tests_attack_simulation
    COMMAND comprehensive_security_validation --gtest_filter="*AttackSimulation*"
    COMMENT "Running attack simulation tests"
    VERBATIM
)

add_custom_target(security_tests_fuzzing
    COMMAND comprehensive_security_validation --gtest_filter="*Fuzzing*"
    COMMENT "Running fuzzing tests"
    VERBATIM
)

add_custom_target(security_tests_timing
    COMMAND comprehensive_security_validation --gtest_filter="*Timing*"
    COMMENT "Running timing attack resistance tests"
    VERBATIM
)

add_custom_target(security_tests_memory
    COMMAND comprehensive_security_validation --gtest_filter="*Memory*"
    COMMENT "Running memory safety tests"
    VERBATIM
)

add_custom_target(security_tests_crypto
    COMMAND comprehensive_security_validation --gtest_filter="*Crypto*"
    COMMENT "Running cryptographic compliance tests"
    VERBATIM
)

add_custom_target(security_assessment_report
    COMMAND comprehensive_security_validation --gtest_also_run_disabled_tests
    COMMAND security_report_generator
    COMMENT "Generating comprehensive security assessment report"
    VERBATIM
)

# Configure security test output directory
set(SECURITY_REPORT_DIR "${CMAKE_BINARY_DIR}/security_reports")
file(MAKE_DIRECTORY ${SECURITY_REPORT_DIR})

# Add compile definitions for report output directory
target_compile_definitions(dtls_security_tests
    PRIVATE
        SECURITY_REPORT_DIR="${SECURITY_REPORT_DIR}"
)

target_compile_definitions(comprehensive_security_validation
    PRIVATE
        SECURITY_REPORT_DIR="${SECURITY_REPORT_DIR}"
)

target_compile_definitions(security_report_generator
    PRIVATE
        SECURITY_REPORT_DIR="${SECURITY_REPORT_DIR}"
)

# Enable testing
enable_testing()

# Add tests to CTest
add_test(NAME SecurityTests_Basic COMMAND dtls_security_tests)
add_test(NAME RateLimiterTests COMMAND dtls_rate_limiter_tests)
add_test(NAME AttackResilienceTests COMMAND dtls_attack_resilience_tests)
add_test(NAME SecurityTests_Comprehensive COMMAND comprehensive_security_validation)

# Set test properties
set_tests_properties(SecurityTests_Basic PROPERTIES
    TIMEOUT 600  # 10 minutes
    LABELS "security;basic"
)

set_tests_properties(RateLimiterTests PROPERTIES
    TIMEOUT 300  # 5 minutes
    LABELS "security;rate_limiting"
)

set_tests_properties(AttackResilienceTests PROPERTIES
    TIMEOUT 3600  # 60 minutes (extended time for comprehensive attack simulation)
    LABELS "security;attack_resilience;dos_protection"
)

set_tests_properties(SecurityTests_Comprehensive PROPERTIES
    TIMEOUT 1800  # 30 minutes
    LABELS "security;comprehensive"
)

# Install security test executables and reports
install(TARGETS dtls_security_tests dtls_rate_limiter_tests dtls_attack_resilience_tests comprehensive_security_validation security_report_generator
    RUNTIME DESTINATION bin/security_tests
)

install(DIRECTORY ${SECURITY_REPORT_DIR}
    DESTINATION share/dtls_v13/security_reports
    OPTIONAL
)

# Documentation
install(FILES README_SECURITY_TESTS.md
    DESTINATION share/dtls_v13/docs
    OPTIONAL
)

message(STATUS "Security validation suite configured")
message(STATUS "Security report output directory: ${SECURITY_REPORT_DIR}")
message(STATUS "Available security test targets:")
message(STATUS "  - security_tests_basic: Basic security tests")
message(STATUS "  - rate_limiter_tests: Dedicated rate limiter tests")
message(STATUS "  - attack_resilience_tests: Comprehensive DoS attack resilience tests")
message(STATUS "  - security_tests_comprehensive: Full security validation")
message(STATUS "  - security_tests_quick: Quick security checks")
message(STATUS "  - security_tests_attack_simulation: Attack simulation tests")
message(STATUS "  - security_tests_fuzzing: Fuzzing and malformed input tests")
message(STATUS "  - security_tests_timing: Timing attack resistance tests")
message(STATUS "  - security_tests_memory: Memory safety validation")
message(STATUS "  - security_tests_crypto: Cryptographic compliance tests")
message(STATUS "  - security_assessment_report: Generate comprehensive security report")