# DTLS v1.3 Interoperability Testing CMake Configuration
# Task 9: External library integration and compatibility testing

cmake_minimum_required(VERSION 3.20)

# Find external DTLS implementations for interoperability testing
find_package(PkgConfig QUIET)

# OpenSSL Detection (should already be available)
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND AND OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0.0")
    set(DTLS_INTEROP_OPENSSL_AVAILABLE TRUE)
    message(STATUS "OpenSSL ${OPENSSL_VERSION} found - DTLS v1.3 support available")
else()
    set(DTLS_INTEROP_OPENSSL_AVAILABLE FALSE)
    message(WARNING "OpenSSL 3.0+ required for DTLS v1.3 interoperability tests")
endif()

# WolfSSL Detection
find_path(WOLFSSL_INCLUDE_DIR 
    NAMES wolfssl/ssl.h
    HINTS /usr/local/include /opt/wolfssl/include
)
find_library(WOLFSSL_LIBRARY 
    NAMES wolfssl
    HINTS /usr/local/lib /opt/wolfssl/lib
)

if(WOLFSSL_INCLUDE_DIR AND WOLFSSL_LIBRARY)
    set(DTLS_INTEROP_WOLFSSL_AVAILABLE TRUE)
    message(STATUS "WolfSSL found at ${WOLFSSL_LIBRARY}")
else()
    set(DTLS_INTEROP_WOLFSSL_AVAILABLE FALSE)
    message(STATUS "WolfSSL not found - installing via Docker for interoperability tests")
endif()

# GnuTLS Detection
if(PkgConfig_FOUND)
    pkg_check_modules(GNUTLS gnutls>=3.7.0)
    if(GNUTLS_FOUND)
        set(DTLS_INTEROP_GNUTLS_AVAILABLE TRUE)
        message(STATUS "GnuTLS ${GNUTLS_VERSION} found")
    else()
        set(DTLS_INTEROP_GNUTLS_AVAILABLE FALSE)
        message(STATUS "GnuTLS 3.7+ not found")
    endif()
else()
    set(DTLS_INTEROP_GNUTLS_AVAILABLE FALSE)
endif()

# Docker Detection for isolated testing
find_program(DOCKER_EXECUTABLE docker)
if(DOCKER_EXECUTABLE)
    set(DTLS_INTEROP_DOCKER_AVAILABLE TRUE)
    message(STATUS "Docker found - isolated interoperability testing enabled")
else()
    set(DTLS_INTEROP_DOCKER_AVAILABLE FALSE)
    message(WARNING "Docker not found - external implementation tests will be limited")
endif()

# Configure interoperability test capabilities
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/interop_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/interop_config.h"
    @ONLY
)

# Core interoperability test library
add_library(dtls_interop_framework STATIC
    interop_test_framework.cpp
    interop_test_harness.cpp
    external_implementation_runner.cpp
    rfc_compliance_validator.cpp
    interop_result_reporter.cpp
)

target_include_directories(dtls_interop_framework PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../include
    ../test_infrastructure
)

target_link_libraries(dtls_interop_framework PRIVATE
    dtls_protocol
    dtls_crypto
    dtls_test_infrastructure
    OpenSSL::SSL
    OpenSSL::Crypto
    gtest
)

# Add WolfSSL if available
if(DTLS_INTEROP_WOLFSSL_AVAILABLE)
    target_include_directories(dtls_interop_framework PRIVATE ${WOLFSSL_INCLUDE_DIR})
    target_link_libraries(dtls_interop_framework PRIVATE ${WOLFSSL_LIBRARY})
endif()

# Add GnuTLS if available
if(DTLS_INTEROP_GNUTLS_AVAILABLE)
    target_include_directories(dtls_interop_framework PRIVATE ${GNUTLS_INCLUDE_DIRS})
    target_link_libraries(dtls_interop_framework PRIVATE ${GNUTLS_LIBRARIES})
    target_compile_options(dtls_interop_framework PRIVATE ${GNUTLS_CFLAGS_OTHER})
endif()

# Main interoperability test executable
add_executable(dtls_interop_tests
    dtls_interop_test_suite.cpp
    openssl_interop_tests.cpp
    wolfssl_interop_tests.cpp
    gnutls_interop_tests.cpp
    rfc_compliance_tests.cpp
)

target_include_directories(dtls_interop_tests PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../include
    ../test_infrastructure
)

target_link_libraries(dtls_interop_tests PRIVATE
    dtls_interop_framework
    dtls_protocol
    dtls_crypto
    dtls_test_infrastructure
    gtest
    gtest_main
)

# Copy Docker configurations for external implementations
if(DTLS_INTEROP_DOCKER_AVAILABLE)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/docker/openssl_server.dockerfile"
        "${CMAKE_CURRENT_BINARY_DIR}/docker/openssl_server.dockerfile"
        COPYONLY
    )
    
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/docker/wolfssl_server.dockerfile"
        "${CMAKE_CURRENT_BINARY_DIR}/docker/wolfssl_server.dockerfile"
        COPYONLY
    )
    
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/docker/gnutls_server.dockerfile"
        "${CMAKE_CURRENT_BINARY_DIR}/docker/gnutls_server.dockerfile"
        COPYONLY
    )
    
    # Copy Docker compose file for orchestrated testing
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/docker/docker-compose.interop.yml"
        "${CMAKE_CURRENT_BINARY_DIR}/docker/docker-compose.interop.yml"
        COPYONLY
    )
endif()

# Test discovery and registration
gtest_discover_tests(dtls_interop_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    PROPERTIES
        LABELS "interoperability"
        TIMEOUT 300
)

# Custom test targets
add_custom_target(interop_quick
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dtls_interop_tests --gtest_filter="*Quick*"
    DEPENDS dtls_interop_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running quick interoperability tests"
)

add_custom_target(interop_full
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dtls_interop_tests
    DEPENDS dtls_interop_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running full interoperability test suite"
)

if(DTLS_INTEROP_DOCKER_AVAILABLE)
    add_custom_target(interop_docker
        COMMAND docker-compose -f docker/docker-compose.interop.yml up --build --abort-on-container-exit
        DEPENDS dtls_interop_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running Docker-based interoperability tests"
    )
endif()

# Performance regression testing
add_custom_target(interop_perf
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dtls_interop_tests --gtest_filter="*Performance*"
    DEPENDS dtls_interop_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running interoperability performance regression tests"
)

# Generate interoperability test report
add_custom_target(interop_report
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/dtls_interop_tests --gtest_output=xml:interop_results.xml
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_interop_report.py interop_results.xml
    DEPENDS dtls_interop_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating interoperability test report"
)