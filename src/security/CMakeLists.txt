# DTLS v1.3 Security Components CMakeLists.txt

# Security library sources
set(SECURITY_SOURCES
    rate_limiter.cpp
    resource_manager.cpp
    dos_protection.cpp
)

# Security library headers
set(SECURITY_HEADERS
    ${CMAKE_SOURCE_DIR}/include/dtls/security/rate_limiter.h
    ${CMAKE_SOURCE_DIR}/include/dtls/security/resource_manager.h
    ${CMAKE_SOURCE_DIR}/include/dtls/security/dos_protection.h
    ${CMAKE_SOURCE_DIR}/include/dtls/security/secure_connection_manager.h
)

# Create security library
add_library(dtls_security STATIC ${SECURITY_SOURCES})

# Set target properties
set_target_properties(dtls_security PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Include directories
target_include_directories(dtls_security
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link dependencies
target_link_libraries(dtls_security
    PUBLIC
        dtls_core
        dtls_crypto
        dtls_protocol
    PRIVATE
        ${CMAKE_THREAD_LIBS_INIT}
)

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dtls_security PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wno-unused-parameter
        -fstack-protector-strong
    )
    
    # Additional security flags for DoS protection
    target_compile_options(dtls_security PRIVATE
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(dtls_security PRIVATE
            -O2
            -DNDEBUG
        )
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(dtls_security PRIVATE
        /W4
        /WX
        /permissive-
        /GS  # Buffer security check
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(dtls_security PRIVATE
            /O2
            /DNDEBUG
        )
    endif()
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(dtls_security PRIVATE
        psapi    # For CPU monitoring
        ws2_32   # For network operations
    )
elseif(UNIX)
    target_link_libraries(dtls_security PRIVATE
        pthread  # For threading
    )
endif()

# Install targets
install(TARGETS dtls_security
    EXPORT DTLSSecurityTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(FILES ${SECURITY_HEADERS}
    DESTINATION include/dtls/security
)

# Export configuration
install(EXPORT DTLSSecurityTargets
    FILE DTLSSecurityTargets.cmake
    NAMESPACE DTLS::
    DESTINATION lib/cmake/DTLS
)

# Generate config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/DTLSSecurityConfigVersion.cmake"
    VERSION ${DTLS_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/DTLSSecurityConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/DTLSSecurityConfig.cmake"
    INSTALL_DESTINATION lib/cmake/DTLS
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/DTLSSecurityConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/DTLSSecurityConfigVersion.cmake"
    DESTINATION lib/cmake/DTLS
)

# Add security tests if testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Documentation
if(BUILD_DOCUMENTATION)
    # Add security components to documentation
    set(DOXYGEN_SECURITY_SOURCES
        ${SECURITY_HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    )
    
    # Add to main documentation target
    list(APPEND DOXYGEN_INPUT_DIRS ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Performance benchmarks (optional)
if(BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()