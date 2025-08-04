# DTLS v1.3 Library Source

# Core library sources
set(DTLS_CORE_SOURCES
    core/types.cpp
    core/error.cpp
    core/result.cpp
    memory/buffer.cpp
    memory/pool.cpp
    memory/memory_utils.cpp
    memory/memory_system.cpp
)

# Protocol layer sources
set(DTLS_PROTOCOL_SOURCES
    protocol/protocol.cpp
    protocol/record.cpp
    protocol/dtls_records.cpp
    protocol/record_layer.cpp
    protocol/handshake.cpp
    protocol/handshake_manager.cpp
    protocol/cookie.cpp
    protocol/message_layer.cpp
    protocol/early_data.cpp
)

# Crypto layer sources  
set(DTLS_CRYPTO_SOURCES
    crypto/provider_factory.cpp
    crypto/crypto_utils.cpp
    crypto/crypto_system.cpp
    crypto/openssl_provider.cpp
    # crypto/advanced_cipher_suites.cpp  # Has compilation issues - TBD
    # crypto/key_manager.cpp  # TBD
)

# Transport layer sources
set(DTLS_TRANSPORT_SOURCES
    transport/udp_transport.cpp
)

# Connection layer sources
set(DTLS_CONNECTION_SOURCES
    connection/connection.cpp
    # connection/advanced_connection_manager.cpp  # Has compilation issues - TBD
)

# Optional Botan provider
if(DTLS_HAS_BOTAN)
    list(APPEND DTLS_CRYPTO_SOURCES crypto/botan_provider.cpp)
else()
    # Always include Botan provider for testing (simulation mode)
    list(APPEND DTLS_CRYPTO_SOURCES crypto/botan_provider.cpp)
    add_definitions(-DDTLS_ENABLE_BOTAN_SIMULATION)
endif()

# Additional modules - temporarily disabled due to compilation issues
# set(DTLS_MONITORING_SOURCES
#     monitoring/metrics_system.cpp
# )

# set(DTLS_SECURITY_SOURCES
#     security/dos_protection.cpp
#     security/rate_limiter.cpp
#     security/resource_manager.cpp
# )

# set(DTLS_COMPATIBILITY_SOURCES
#     compatibility/dtls12_compat.cpp
# )

# All sources
set(DTLS_ALL_SOURCES
    ${DTLS_CORE_SOURCES}
    ${DTLS_PROTOCOL_SOURCES}
    ${DTLS_CRYPTO_SOURCES}
    ${DTLS_TRANSPORT_SOURCES}
    ${DTLS_CONNECTION_SOURCES}
    # ${DTLS_MONITORING_SOURCES}      # Temporarily disabled
    # ${DTLS_SECURITY_SOURCES}        # Temporarily disabled
    # ${DTLS_COMPATIBILITY_SOURCES}   # Temporarily disabled
)

# Create library
if(DTLS_BUILD_SHARED)
    add_library(dtlsv13 SHARED ${DTLS_ALL_SOURCES})
    target_compile_definitions(dtlsv13 PRIVATE DTLS_BUILDING_DLL)
else()
    add_library(dtlsv13 STATIC ${DTLS_ALL_SOURCES})
endif()

# Create alias for backward compatibility
add_library(dtls_core ALIAS dtlsv13)

# Set library properties
set_target_properties(dtlsv13 PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME dtlsv13
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

# Link libraries
target_link_libraries(dtlsv13
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(DTLS_HAS_BOTAN)
    target_link_libraries(dtlsv13 PRIVATE ${BOTAN_LIBRARIES})
    target_include_directories(dtlsv13 PRIVATE ${BOTAN_INCLUDE_DIRS})
endif()

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Only hide symbols for static builds - shared builds need visibility control
    if(NOT DTLS_BUILD_SHARED)
        target_compile_options(dtlsv13 PRIVATE
            -fvisibility=hidden
            -fvisibility-inlines-hidden
        )
    endif()
    
    if(DTLS_ENABLE_HARDWARE_ACCEL)
        target_compile_options(dtlsv13 PRIVATE
            -maes -msse4.2 -mavx2
        )
    endif()
endif()

# Installation
install(TARGETS dtlsv13
    EXPORT DTLSv13Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(EXPORT DTLSv13Targets
    FILE DTLSv13Targets.cmake
    NAMESPACE DTLSv13::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DTLSv13
)