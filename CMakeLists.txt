cmake_minimum_required(VERSION 3.20)

project(DTLSv13
    VERSION 1.0.0
    DESCRIPTION "DTLS v1.3 Implementation (RFC 9147)"
    LANGUAGES CXX
)

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(DTLS_BUILD_TESTS "Build unit tests" ON)
option(DTLS_BUILD_EXAMPLES "Build example applications" ON)
option(DTLS_BUILD_SYSTEMC "Build SystemC model" OFF)
option(DTLS_ENABLE_HARDWARE_ACCEL "Enable hardware acceleration" ON)
option(DTLS_BUILD_SHARED "Build shared libraries" ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -fsanitize=address")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native")

# Find required dependencies
find_package(Threads REQUIRED)

# OpenSSL (required) - Use custom OpenSSL from /home/jgreninger/Work/openssl
if(EXISTS "/home/jgreninger/Work/openssl")
    set(OPENSSL_ROOT_DIR "/home/jgreninger/Work/openssl")
    set(OPENSSL_INCLUDE_DIR "/home/jgreninger/Work/openssl/include")
    set(OPENSSL_CRYPTO_LIBRARY "/home/jgreninger/Work/openssl/libcrypto.a")
    set(OPENSSL_SSL_LIBRARY "/home/jgreninger/Work/openssl/libssl.a")
    message(STATUS "Using custom OpenSSL at ${OPENSSL_ROOT_DIR}")

    # Create OpenSSL targets manually for custom installation
    add_library(OpenSSL::Crypto STATIC IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")

    add_library(OpenSSL::SSL STATIC IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES
        IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "OpenSSL::Crypto")

    set(OPENSSL_FOUND TRUE)
    set(OPENSSL_VERSION "3.6.0")
else()
    find_package(OpenSSL REQUIRED)
endif()

if(OpenSSL_FOUND OR OPENSSL_FOUND)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
endif()

# Botan (optional)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(BOTAN botan-3)
    if(BOTAN_FOUND)
        message(STATUS "Found Botan ${BOTAN_VERSION}")
        set(DTLS_HAS_BOTAN ON)
    else()
        message(STATUS "Botan not found, using OpenSSL only")
        set(DTLS_HAS_BOTAN OFF)
    endif()
endif()

# SystemC (optional)
if(DTLS_BUILD_SYSTEMC)
    find_package(SystemCLanguage QUIET)
    if(SystemCLanguage_FOUND)
        message(STATUS "Found SystemC ${SystemCLanguage_VERSION}")
        set(DTLS_HAS_SYSTEMC ON)
    else()
        message(WARNING "SystemC not found, disabling SystemC build")
        set(DTLS_BUILD_SYSTEMC OFF)
        set(DTLS_HAS_SYSTEMC OFF)
    endif()
endif()

# Google Test (for testing)
if(DTLS_BUILD_TESTS)
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
            DOWNLOAD_EXTRACT_TIMESTAMP true
        )
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set configuration variables for config.h
# Debug: Print the current value of DTLS_BUILD_SHARED
message(STATUS "DTLS_BUILD_SHARED before configure_file: ${DTLS_BUILD_SHARED}")

# Detect platform for config.h
if(WIN32)
    set(DTLS_PLATFORM_WINDOWS 1)
endif()

# Generate configuration header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/dtls/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/dtls/config.h
)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

# Add subdirectories
add_subdirectory(src)

if(DTLS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(DTLS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(DTLS_BUILD_SYSTEMC AND DTLS_HAS_SYSTEMC)
    add_subdirectory(systemc)
endif()

# Installation
include(GNUInstallDirs)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/dtls/config.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dtls
)

# Package configuration
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DTLSv13Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSv13Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DTLSv13
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSv13ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSv13Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSv13ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DTLSv13
)

# CPack configuration
set(CPACK_PACKAGE_NAME "DTLSv13")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_VENDOR "DTLS v1.3 Implementation Project")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

include(CPack)

# Print configuration summary
message(STATUS "")
message(STATUS "DTLSv13 Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build tests: ${DTLS_BUILD_TESTS}")
message(STATUS "  Build examples: ${DTLS_BUILD_EXAMPLES}")
message(STATUS "  Build SystemC: ${DTLS_BUILD_SYSTEMC}")
message(STATUS "  Hardware acceleration: ${DTLS_ENABLE_HARDWARE_ACCEL}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
if(DTLS_HAS_BOTAN)
    message(STATUS "  Botan: ${BOTAN_VERSION}")
else()
    message(STATUS "  Botan: Not found")
endif()
if(DTLS_HAS_SYSTEMC)
    message(STATUS "  SystemC: ${SystemCLanguage_VERSION}")
else()
    message(STATUS "  SystemC: Not found")
endif()
message(STATUS "")
