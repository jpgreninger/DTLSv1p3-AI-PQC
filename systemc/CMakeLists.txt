# CMakeLists.txt for DTLS v1.3 SystemC TLM Models
cmake_minimum_required(VERSION 3.16)

project(DTLS_SystemC_TLM 
    VERSION 1.0.0 
    DESCRIPTION "DTLS v1.3 SystemC Transaction Level Models"
    LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(DTLS_SYSTEMC_BUILD_TESTS "Build SystemC testbenches" OFF)
option(DTLS_SYSTEMC_BUILD_EXAMPLES "Build SystemC examples" ON)
option(DTLS_SYSTEMC_ENABLE_COVERAGE "Enable code coverage" OFF)
option(DTLS_SYSTEMC_ENABLE_PROFILING "Enable performance profiling" OFF)

# Set SystemC installation path
set(SYSTEMC_ROOT "/home/jgreninger/Work/systemc")

# SystemC library and include paths
set(SYSTEMC_INCLUDE_DIRS "${SYSTEMC_ROOT}/include")
set(SYSTEMC_LIBRARY_DIRS "${SYSTEMC_ROOT}/lib-linux64")
set(SYSTEMC_LIBRARIES "systemc")

# Add SystemC library directory to search path
link_directories(${SYSTEMC_LIBRARY_DIRS})

# Find required packages
find_package(Threads REQUIRED)

# Create SystemC imported target manually since find_package failed
add_library(SystemC::systemc SHARED IMPORTED)
set_target_properties(SystemC::systemc PROPERTIES
    IMPORTED_LOCATION "${SYSTEMC_LIBRARY_DIRS}/libsystemc.so"
    INTERFACE_INCLUDE_DIRECTORIES "${SYSTEMC_INCLUDE_DIRS}"
)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include  # Main DTLS headers
    ${SYSTEMC_ROOT}/include  # SystemC headers
)

# SystemC TLM source files
set(DTLS_SYSTEMC_SOURCES
    src/dtls_systemc_utils.cpp
    src/crypto_provider_tlm.cpp
    src/record_layer_tlm.cpp
    src/message_layer_tlm.cpp
    src/dtls_channels.cpp
    src/dtls_protocol_stack.cpp
    src/dtls_timing_models.cpp
    src/dtls_protocol_modules.cpp
)

# SystemC TLM header files
set(DTLS_SYSTEMC_HEADERS
    include/dtls_systemc_types.h
    include/crypto_provider_tlm.h
    include/record_layer_tlm.h
    include/message_layer_tlm.h
    include/dtls_channels.h
    include/dtls_testbench.h
    include/dtls_protocol_stack.h
    include/dtls_timing_models.h
    include/dtls_tlm_extensions.h
    include/dtls_protocol_modules.h
)

# Create SystemC TLM library
add_library(dtls_systemc_tlm STATIC
    ${DTLS_SYSTEMC_SOURCES}
    ${DTLS_SYSTEMC_HEADERS}
)

# Link with SystemC
target_link_libraries(dtls_systemc_tlm
    PUBLIC
        SystemC::systemc
        Threads::Threads
    PRIVATE
        dtls_core  # Main DTLS library
)

# Set target properties
set_target_properties(dtls_systemc_tlm PROPERTIES
    OUTPUT_NAME "dtls_systemc_tlm"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${DTLS_SYSTEMC_HEADERS}"
)

# Compiler-specific options
target_compile_options(dtls_systemc_tlm PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

# Enable code coverage if requested
if(DTLS_SYSTEMC_ENABLE_COVERAGE)
    target_compile_options(dtls_systemc_tlm PRIVATE --coverage)
    target_link_libraries(dtls_systemc_tlm PRIVATE --coverage)
endif()

# Enable profiling if requested
if(DTLS_SYSTEMC_ENABLE_PROFILING)
    target_compile_options(dtls_systemc_tlm PRIVATE -pg)
    target_link_libraries(dtls_systemc_tlm PRIVATE -pg)
endif()

# Build tests if enabled
if(DTLS_SYSTEMC_BUILD_TESTS)
    enable_testing()
    
    # Test executables
    set(SYSTEMC_TESTS
        basic_crypto_test
        record_layer_test
        message_layer_test
        integration_test
        performance_test
        security_test
        functional_validation_test
        timing_validation_test
        co_simulation_test
    )
    
    foreach(test_name ${SYSTEMC_TESTS})
        add_executable(${test_name}
            tests/${test_name}.cpp
            src/dtls_testbench.cpp  # Testbench implementation
        )
        
        target_link_libraries(${test_name}
            PRIVATE
                dtls_systemc_tlm
                SystemC::systemc
        )
        
        # Add to CTest
        add_test(NAME ${test_name} COMMAND ${test_name})
        
        # Set test timeout (SystemC tests can be long-running)
        set_tests_properties(${test_name} PROPERTIES TIMEOUT 300)
    endforeach()
    
    # Comprehensive system test
    add_executable(dtls_system_test
        tests/dtls_system_test.cpp
        src/dtls_testbench.cpp
    )
    
    target_link_libraries(dtls_system_test
        PRIVATE
            dtls_systemc_tlm
            SystemC::systemc
    )
    
    add_test(NAME dtls_system_test COMMAND dtls_system_test)
    set_tests_properties(dtls_system_test PROPERTIES TIMEOUT 600)
endif()

# Build examples if enabled
if(DTLS_SYSTEMC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Install targets
install(TARGETS dtls_systemc_tlm
    EXPORT DTLSSystemCTLMTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/dtls/systemc
)

# Install export targets
install(EXPORT DTLSSystemCTLMTargets
    FILE DTLSSystemCTLMTargets.cmake
    NAMESPACE DTLS::
    DESTINATION lib/cmake/DTLSSystemCTLM
)

# Create and install config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    DTLSSystemCTLMConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    cmake/DTLSSystemCTLMConfig.cmake.in
    DTLSSystemCTLMConfig.cmake
    INSTALL_DESTINATION lib/cmake/DTLSSystemCTLM
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSSystemCTLMConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/DTLSSystemCTLMConfigVersion.cmake
    DESTINATION lib/cmake/DTLSSystemCTLM
)

# Create pkgconfig file
configure_file(
    cmake/dtls_systemc_tlm.pc.in
    dtls_systemc_tlm.pc
    @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dtls_systemc_tlm.pc
    DESTINATION lib/pkgconfig
)

# Documentation (if Doxygen is available)
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    
    add_custom_target(systemc_docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating SystemC TLM API documentation with Doxygen"
        VERBATIM
    )
    
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/html
        DESTINATION share/doc/dtls_systemc_tlm
        OPTIONAL
    )
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "DTLS SystemC TLM Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  SystemC path: ${SystemC_DIR}")
message(STATUS "  Build tests: ${DTLS_SYSTEMC_BUILD_TESTS}")
message(STATUS "  Build examples: ${DTLS_SYSTEMC_BUILD_EXAMPLES}")
message(STATUS "  Enable coverage: ${DTLS_SYSTEMC_ENABLE_COVERAGE}")
message(STATUS "  Enable profiling: ${DTLS_SYSTEMC_ENABLE_PROFILING}")
message(STATUS "")

# Add custom targets for common operations
add_custom_target(systemc-clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target clean
    COMMENT "Cleaning SystemC TLM build artifacts"
)

add_custom_target(systemc-test
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${SYSTEMC_TESTS} dtls_system_test
    COMMENT "Running all SystemC TLM tests"
)

add_custom_target(systemc-coverage
    COMMAND lcov --capture --directory . --output-file coverage.info
    COMMAND lcov --remove coverage.info '/usr/*' --output-file coverage.info
    COMMAND lcov --list coverage.info
    COMMAND genhtml coverage.info --output-directory coverage_html
    DEPENDS systemc-test
    COMMENT "Generating SystemC TLM code coverage report"
)

# Packaging
set(CPACK_PACKAGE_NAME "dtls-systemc-tlm")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "DTLS v1.3 SystemC Transaction Level Models")
set(CPACK_PACKAGE_VENDOR "DTLS v1.3 Project")
set(CPACK_PACKAGE_CONTACT "dtls-dev@example.com")

set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set(CPACK_SOURCE_IGNORE_FILES
    "${CMAKE_BINARY_DIR}"
    "\\.git"
    "\\.gitignore"
    "\\.DS_Store"
    ".*~$"
)

include(CPack)