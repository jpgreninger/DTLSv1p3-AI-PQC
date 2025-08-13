# Hardware Acceleration Detection and Configuration for DTLS v1.3
# This file handles detection of hardware acceleration capabilities and 
# configures build options accordingly.

include(CheckCXXCompilerFlag)
include(CheckIncludeFiles)
include(CheckFunctionExists)

# Function to detect hardware acceleration capabilities
function(detect_hardware_acceleration)
    message(STATUS "Detecting hardware acceleration capabilities...")
    
    # Check for x86_64 SIMD support
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i686)")
        message(STATUS "Detected x86_64 architecture - checking SIMD support")
        
        # Check for SSE2 support
        check_cxx_compiler_flag("-msse2" DTLS_COMPILER_SUPPORTS_SSE2)
        if(DTLS_COMPILER_SUPPORTS_SSE2)
            message(STATUS "SSE2 support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_SSE2)
        endif()
        
        # Check for SSE4.1 support
        check_cxx_compiler_flag("-msse4.1" DTLS_COMPILER_SUPPORTS_SSE41)
        if(DTLS_COMPILER_SUPPORTS_SSE41)
            message(STATUS "SSE4.1 support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_SSE41)
        endif()
        
        # Check for AES-NI support
        check_cxx_compiler_flag("-maes" DTLS_COMPILER_SUPPORTS_AES_NI)
        if(DTLS_COMPILER_SUPPORTS_AES_NI)
            message(STATUS "AES-NI support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_AES_NI)
            target_compile_options(dtls_v13 PRIVATE -maes)
        endif()
        
        # Check for PCLMUL support
        check_cxx_compiler_flag("-mpclmul" DTLS_COMPILER_SUPPORTS_PCLMUL)
        if(DTLS_COMPILER_SUPPORTS_PCLMUL)
            message(STATUS "PCLMUL support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_PCLMUL)
            target_compile_options(dtls_v13 PRIVATE -mpclmul)
        endif()
        
        # Check for AVX support
        check_cxx_compiler_flag("-mavx" DTLS_COMPILER_SUPPORTS_AVX)
        if(DTLS_COMPILER_SUPPORTS_AVX)
            message(STATUS "AVX support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_AVX)
            target_compile_options(dtls_v13 PRIVATE -mavx)
        endif()
        
        # Check for AVX2 support
        check_cxx_compiler_flag("-mavx2" DTLS_COMPILER_SUPPORTS_AVX2)
        if(DTLS_COMPILER_SUPPORTS_AVX2)
            message(STATUS "AVX2 support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_AVX2)
            target_compile_options(dtls_v13 PRIVATE -mavx2)
        endif()
        
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64|arm64|armv8)")
        message(STATUS "Detected ARM64 architecture - checking crypto extensions")
        
        # Check for ARM crypto extensions
        check_cxx_compiler_flag("-march=armv8-a+crypto" DTLS_COMPILER_SUPPORTS_ARM_CRYPTO)
        if(DTLS_COMPILER_SUPPORTS_ARM_CRYPTO)
            message(STATUS "ARM crypto extensions detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_ARM_CRYPTO)
            target_compile_options(dtls_v13 PRIVATE -march=armv8-a+crypto)
        endif()
        
        # Check for NEON support
        check_cxx_compiler_flag("-mfpu=neon" DTLS_COMPILER_SUPPORTS_ARM_NEON)
        if(DTLS_COMPILER_SUPPORTS_ARM_NEON)
            message(STATUS "ARM NEON support detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_ARM_NEON)
        endif()
        
    else()
        message(STATUS "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
    
    # Check for hardware random number generator support
    if(UNIX AND NOT APPLE)
        # Check for /dev/hwrng
        if(EXISTS "/dev/hwrng")
            message(STATUS "Hardware RNG detected at /dev/hwrng")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_HARDWARE_RNG)
        endif()
        
        # Check for RDRAND on x86_64
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
            check_cxx_compiler_flag("-mrdrnd" DTLS_COMPILER_SUPPORTS_RDRAND)
            if(DTLS_COMPILER_SUPPORTS_RDRAND)
                message(STATUS "RDRAND support detected")
                target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_RDRAND)
                target_compile_options(dtls_v13 PRIVATE -mrdrnd)
            endif()
        endif()
    endif()
    
    # Check for TPM support on Linux
    if(UNIX AND NOT APPLE)
        if(EXISTS "/dev/tpm0" OR EXISTS "/dev/tpmrm0")
            message(STATUS "TPM device detected")
            target_compile_definitions(dtls_v13 PRIVATE DTLS_HAS_TPM)
        endif()
    endif()
endfunction()

# Function to configure crypto provider hardware acceleration
function(configure_crypto_hardware_acceleration)
    message(STATUS "Configuring crypto provider hardware acceleration...")
    
    # OpenSSL hardware acceleration
    if(DTLS_USE_OPENSSL)
        message(STATUS "Configuring OpenSSL hardware acceleration")
        
        # OpenSSL automatically detects and uses hardware acceleration
        # We just need to ensure the right compile flags are set
        if(DTLS_COMPILER_SUPPORTS_AES_NI)
            message(STATUS "Enabling OpenSSL AES-NI support")
        endif()
        
        if(DTLS_COMPILER_SUPPORTS_AVX2)
            message(STATUS "Enabling OpenSSL AVX2 support")
        endif()
    endif()
    
    # Botan hardware acceleration
    if(DTLS_USE_BOTAN)
        message(STATUS "Configuring Botan hardware acceleration")
        
        # Botan has more limited hardware acceleration
        if(DTLS_COMPILER_SUPPORTS_AES_NI)
            message(STATUS "Botan AES-NI support available")
        endif()
    endif()
endfunction()

# Function to add hardware acceleration sources
function(add_hardware_acceleration_sources target_name)
    target_sources(${target_name} PRIVATE
        src/crypto/hardware_acceleration.cpp
        src/crypto/hardware_accelerated_provider.cpp
        src/crypto/hardware_zero_copy.cpp
        src/protocol/hardware_accelerated_record_layer.cpp
    )
    
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/dtls/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/include/dtls/protocol
    )
endfunction()

# Function to add hardware acceleration tests
function(add_hardware_acceleration_tests)
    if(DTLS_BUILD_TESTS)
        add_executable(test_hardware_acceleration
            tests/crypto/test_hardware_acceleration.cpp
        )
        
        target_link_libraries(test_hardware_acceleration
            dtls_v13
            ${GTEST_LIBRARIES}
            ${CMAKE_THREAD_LIBS_INIT}
        )
        
        target_include_directories(test_hardware_acceleration PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${GTEST_INCLUDE_DIRS}
        )
        
        # Add compile definitions for hardware acceleration tests
        if(DTLS_HAS_AES_NI)
            target_compile_definitions(test_hardware_acceleration PRIVATE DTLS_TEST_AES_NI)
        endif()
        
        if(DTLS_HAS_AVX2)
            target_compile_definitions(test_hardware_acceleration PRIVATE DTLS_TEST_AVX2)
        endif()
        
        if(DTLS_HAS_ARM_CRYPTO)
            target_compile_definitions(test_hardware_acceleration PRIVATE DTLS_TEST_ARM_CRYPTO)
        endif()
        
        add_test(NAME HardwareAccelerationTest COMMAND test_hardware_acceleration)
        
        # Set test properties for hardware-specific tests
        set_tests_properties(HardwareAccelerationTest PROPERTIES
            TIMEOUT 60
            LABELS "crypto;hardware;performance"
        )
    endif()
endfunction()

# Function to create hardware acceleration benchmark
function(add_hardware_acceleration_benchmarks)
    if(DTLS_BUILD_BENCHMARKS)
        add_executable(benchmark_hardware_acceleration
            benchmarks/crypto/benchmark_hardware_acceleration.cpp
        )
        
        target_link_libraries(benchmark_hardware_acceleration
            dtls_v13
            ${BENCHMARK_LIBRARIES}
            ${CMAKE_THREAD_LIBS_INIT}
        )
        
        target_include_directories(benchmark_hardware_acceleration PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${BENCHMARK_INCLUDE_DIRS}
        )
        
        # Add to benchmark suite
        add_custom_target(run_hardware_benchmarks
            COMMAND benchmark_hardware_acceleration
            DEPENDS benchmark_hardware_acceleration
            COMMENT "Running hardware acceleration benchmarks"
        )
    endif()
endfunction()

# Function to print hardware acceleration summary
function(print_hardware_acceleration_summary)
    message(STATUS "")
    message(STATUS "=== Hardware Acceleration Summary ===")
    
    if(DTLS_COMPILER_SUPPORTS_AES_NI OR DTLS_HAS_AES_NI)
        message(STATUS "AES-NI: ENABLED")
    else()
        message(STATUS "AES-NI: Not available")
    endif()
    
    if(DTLS_COMPILER_SUPPORTS_AVX2 OR DTLS_HAS_AVX2)
        message(STATUS "AVX2: ENABLED")
    elseif(DTLS_COMPILER_SUPPORTS_AVX OR DTLS_HAS_AVX)
        message(STATUS "AVX: ENABLED")
    else()
        message(STATUS "AVX/AVX2: Not available")
    endif()
    
    if(DTLS_COMPILER_SUPPORTS_ARM_CRYPTO OR DTLS_HAS_ARM_CRYPTO)
        message(STATUS "ARM Crypto: ENABLED")
    else()
        message(STATUS "ARM Crypto: Not available")
    endif()
    
    if(DTLS_HAS_HARDWARE_RNG)
        message(STATUS "Hardware RNG: ENABLED")
    else()
        message(STATUS "Hardware RNG: Not available")
    endif()
    
    if(DTLS_HAS_TPM)
        message(STATUS "TPM: DETECTED")
    else()
        message(STATUS "TPM: Not detected")
    endif()
    
    message(STATUS "=====================================")
    message(STATUS "")
endfunction()

# Main hardware acceleration configuration function
function(configure_hardware_acceleration target_name)
    option(DTLS_ENABLE_HARDWARE_ACCEL "Enable hardware acceleration support" ON)
    
    if(DTLS_ENABLE_HARDWARE_ACCEL)
        message(STATUS "Hardware acceleration support: ENABLED")
        
        # Detect hardware capabilities
        detect_hardware_acceleration()
        
        # Configure crypto providers
        configure_crypto_hardware_acceleration()
        
        # Add hardware acceleration sources
        add_hardware_acceleration_sources(${target_name})
        
        # Add compile definition to enable hardware acceleration
        target_compile_definitions(${target_name} PRIVATE DTLS_HARDWARE_ACCELERATION_ENABLED)
        
        # Add tests and benchmarks
        add_hardware_acceleration_tests()
        add_hardware_acceleration_benchmarks()
        
        # Print summary
        print_hardware_acceleration_summary()
        
    else()
        message(STATUS "Hardware acceleration support: DISABLED")
        target_compile_definitions(${target_name} PRIVATE DTLS_HARDWARE_ACCELERATION_DISABLED)
    endif()
endfunction()

# Export configuration for use in other CMake files
set(DTLS_HARDWARE_ACCELERATION_CONFIGURED TRUE CACHE INTERNAL "Hardware acceleration configured")