# CMakeLists.txt for DTLS v1.3 Example Applications
# Week 14, Stream A: Example Applications

# Define example applications
set(DTLS_EXAMPLES
    # Basic examples
    transport_example
    dtls_client_example
    dtls_server_example
    
    # Advanced examples (Week 14)
    dtls_connection_migration_example
    dtls_early_data_example
    dtls_multi_connection_server_example
)

# Example source files with descriptions
set(EXAMPLE_DESCRIPTIONS
    "transport_example;UDP Transport Layer demonstration"
    "dtls_client_example;Simple DTLS v1.3 client application"
    "dtls_server_example;Simple DTLS v1.3 server application"
    "dtls_connection_migration_example;Connection migration using Connection IDs"
    "dtls_early_data_example;Early data (0-RTT) functionality demonstration"
    "dtls_multi_connection_server_example;High-performance multi-connection server"
)

# Common compile definitions for examples
set(EXAMPLE_COMPILE_DEFINITIONS
    DTLS_EXAMPLE_BUILD
    $<$<CONFIG:Debug>:DTLS_DEBUG_ENABLED>
)

# Common libraries for all examples
set(EXAMPLE_LIBRARIES
    dtls_core                # Main DTLS library
    Threads::Threads         # Threading support
    ${CMAKE_DL_LIBS}        # Dynamic loading (if needed)
)

# Check if the main DTLS library target exists
if(NOT TARGET dtls_core)
    message(FATAL_ERROR "dtls_core library target not found. Make sure src/CMakeLists.txt is processed first.")
endif()

# Create example executables
foreach(example_name ${DTLS_EXAMPLES})
    # Check if source file exists
    set(source_file "${CMAKE_CURRENT_SOURCE_DIR}/${example_name}.cpp")
    if(EXISTS ${source_file})
        # Create executable
        add_executable(${example_name} ${source_file})
        
        # Set target properties
        set_target_properties(${example_name} PROPERTIES
            OUTPUT_NAME ${example_name}
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
        
        # Link libraries
        target_link_libraries(${example_name} PRIVATE ${EXAMPLE_LIBRARIES})
        
        # Add compile definitions
        target_compile_definitions(${example_name} PRIVATE ${EXAMPLE_COMPILE_DEFINITIONS})
        
        # Compiler-specific options for better performance and debugging
        target_compile_options(${example_name} PRIVATE
            $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
            $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
            $<$<CXX_COMPILER_ID:MSVC>:/W4>
        )
        
        # Enable optimizations for release builds
        target_compile_options(${example_name} PRIVATE
            $<$<CONFIG:Release>:-O3 -march=native>
            $<$<CONFIG:Debug>:-O0 -g -fsanitize=address>
        )
        
        # Link address sanitizer for debug builds
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            target_link_options(${example_name} PRIVATE -fsanitize=address)
        endif()
        
        message(STATUS "Added example: ${example_name}")
        
    else()
        message(WARNING "Source file not found for example: ${example_name} (${source_file})")
    endif()
endforeach()

# Create convenience targets for running examples

# Basic examples group
add_custom_target(run_basic_examples
    COMMENT "Running basic DTLS examples"
)

if(TARGET transport_example)
    add_custom_target(run_transport_example
        COMMAND $<TARGET_FILE:transport_example>
        DEPENDS transport_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running UDP transport layer example"
    )
    add_dependencies(run_basic_examples run_transport_example)
endif()

# Client-server example pair
if(TARGET dtls_client_example AND TARGET dtls_server_example)
    add_custom_target(run_client_server_demo
        COMMENT "Running client-server demo (requires manual coordination)"
    )
    
    add_custom_target(run_dtls_server
        COMMAND $<TARGET_FILE:dtls_server_example>
        DEPENDS dtls_server_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running DTLS server (bind to 0.0.0.0:4433)"
    )
    
    add_custom_target(run_dtls_client_interactive
        COMMAND $<TARGET_FILE:dtls_client_example> --interactive
        DEPENDS dtls_client_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running DTLS client in interactive mode"
    )
    
    add_custom_target(run_dtls_client_auto
        COMMAND $<TARGET_FILE:dtls_client_example>
        DEPENDS dtls_client_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running DTLS client in automated mode"
    )
endif()

# Advanced examples group
add_custom_target(run_advanced_examples
    COMMENT "Running advanced DTLS examples"
)

if(TARGET dtls_connection_migration_example)
    add_custom_target(run_migration_demo
        COMMAND $<TARGET_FILE:dtls_connection_migration_example>
        DEPENDS dtls_connection_migration_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running connection migration demonstration"
    )
    add_dependencies(run_advanced_examples run_migration_demo)
endif()

if(TARGET dtls_early_data_example)
    add_custom_target(run_early_data_demo
        COMMAND $<TARGET_FILE:dtls_early_data_example>
        DEPENDS dtls_early_data_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running early data (0-RTT) demonstration"
    )
    add_dependencies(run_advanced_examples run_early_data_demo)
endif()

if(TARGET dtls_multi_connection_server_example)
    add_custom_target(run_multi_server
        COMMAND $<TARGET_FILE:dtls_multi_connection_server_example>
        DEPENDS dtls_multi_connection_server_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running multi-connection server example"
    )
    
    # Variant with custom parameters
    add_custom_target(run_multi_server_custom
        COMMAND $<TARGET_FILE:dtls_multi_connection_server_example> 0.0.0.0 4433 8
        DEPENDS dtls_multi_connection_server_example
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running multi-connection server with 8 worker threads"
    )
    
    add_dependencies(run_advanced_examples run_multi_server)
endif()

# Master target to run all examples
add_custom_target(run_all_examples
    DEPENDS run_basic_examples run_advanced_examples
    COMMENT "Running all DTLS example applications"
)

# Installation of example binaries (optional)
install(TARGETS ${DTLS_EXAMPLES}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples
    COMPONENT examples
    OPTIONAL
)

# Install example source files for reference
install(FILES
    transport_example.cpp
    dtls_client_example.cpp
    dtls_server_example.cpp
    dtls_connection_migration_example.cpp
    dtls_early_data_example.cpp
    dtls_multi_connection_server_example.cpp
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
    COMPONENT examples-src
    OPTIONAL
)

# Create examples documentation
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/examples_README.md
"# DTLS v1.3 Example Applications

This directory contains example applications demonstrating DTLS v1.3 functionality.

## Basic Examples

### transport_example
Demonstrates UDP transport layer functionality without DTLS encryption.
Usage: `./transport_example`

### dtls_client_example  
Simple DTLS client with interactive and automated modes.
Usage: 
- Interactive: `./dtls_client_example --interactive`
- Automated: `./dtls_client_example`

### dtls_server_example
Simple DTLS server supporting multiple concurrent connections.
Usage: `./dtls_server_example [bind_address] [bind_port]`
Default: `./dtls_server_example 0.0.0.0 4433`

## Advanced Examples (Week 14)

### dtls_connection_migration_example
Demonstrates connection migration using Connection IDs.
- Shows seamless connection migration during address changes
- Validates Connection ID functionality
Usage: `./dtls_connection_migration_example`

### dtls_early_data_example
Demonstrates early data (0-RTT) functionality for reduced latency.
- Session resumption with Pre-Shared Keys
- 0-RTT data transmission
- Performance comparison with full handshake
Usage: `./dtls_early_data_example`

### dtls_multi_connection_server_example
High-performance server handling multiple concurrent connections.
- Multi-threaded architecture with worker threads
- Load balancing and performance monitoring
- Real-time statistics and connection management
Usage: `./dtls_multi_connection_server_example [bind_address] [bind_port] [num_workers]`
Default: `./dtls_multi_connection_server_example 0.0.0.0 4433 4`

## Build Instructions

Examples are built automatically when DTLS_BUILD_EXAMPLES=ON:

```bash
mkdir build && cd build
cmake -DDTLS_BUILD_EXAMPLES=ON ..
make
```

## Running Examples

Use the provided CMake targets:

```bash
# Basic examples
make run_basic_examples

# Client-server demo (requires coordination)
make run_dtls_server     # Terminal 1
make run_dtls_client_auto # Terminal 2

# Advanced examples  
make run_advanced_examples

# Individual examples
make run_migration_demo
make run_early_data_demo
make run_multi_server

# All examples
make run_all_examples
```

## Testing Client-Server Communication

1. Start the server:
   ```bash
   ./dtls_server_example 0.0.0.0 4433
   ```

2. In another terminal, run the client:
   ```bash
   ./dtls_client_example --interactive
   ```

3. For automated testing:
   ```bash
   ./dtls_client_example
   ```

## Performance Testing

The multi-connection server can be tested with multiple clients:

```bash
# Terminal 1: Start high-performance server
./dtls_multi_connection_server_example 0.0.0.0 4433 8

# Terminals 2-N: Start multiple clients
./dtls_client_example &
./dtls_client_example &
# ... repeat for desired load
```

## Requirements

- OpenSSL (required for cryptographic operations)
- Botan (optional, for alternative crypto provider)
- Threads (required for multi-threaded examples)
- C++20 compiler with full standard library support

All examples include comprehensive error handling and demonstrate best practices for DTLS v1.3 usage.
")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/examples_README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
    COMPONENT examples-doc
)

# Print summary of built examples
message(STATUS "")
message(STATUS "DTLS Examples Configuration:")
message(STATUS "  Examples to build: ${DTLS_EXAMPLES}")
message(STATUS "  Install examples: ${CMAKE_INSTALL_BINDIR}/examples")
message(STATUS "  Install sources: ${CMAKE_INSTALL_DOCDIR}/examples")

# Add convenience target for development
add_custom_target(examples_help
    COMMAND ${CMAKE_COMMAND} -E echo "Available example targets:"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_basic_examples - Run transport and basic client/server examples"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_advanced_examples - Run connection migration, early data, and multi-server examples"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_all_examples - Run all example applications"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_transport_example - UDP transport demonstration"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_dtls_server - Start DTLS server"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_dtls_client_auto - Run automated DTLS client"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_dtls_client_interactive - Run interactive DTLS client"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_migration_demo - Connection migration demonstration"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_early_data_demo - Early data (0-RTT) demonstration"
    COMMAND ${CMAKE_COMMAND} -E echo "  run_multi_server - Multi-connection server example"
    COMMENT "Available DTLS example targets"
)