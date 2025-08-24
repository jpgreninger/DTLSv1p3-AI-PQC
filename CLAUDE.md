# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive DTLS (Datagram Transport Layer Security) v1.3 implementation following RFC 9147, providing both a production C++ library and a SystemC TLM model for hardware/software co-design.

## Build System

**IMPORTANT**: Always build in `~/Work/DTLSv1p3/build` directory. Never build in the source root.

### Main Build Commands
```bash
# REQUIRED: Always use build directory for out-of-source builds
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Or use the provided build script (RECOMMENDED)
./build.sh                      # Release build
./build.sh --debug              # Debug build
./build.sh --clean --verbose    # Clean verbose build

# Build with SystemC support (requires SystemC installation)
cd build
cmake .. -DDTLS_BUILD_SYSTEMC=ON -DSYSTEMC_ROOT=/path/to/systemc
make -j$(nproc)

# Build options (always run from build/ directory)
cd build
cmake .. \
  -DDTLS_BUILD_TESTS=ON \          # Build test suite (default: ON)
  -DDTLS_BUILD_EXAMPLES=ON \       # Build examples (default: ON)
  -DDTLS_BUILD_SYSTEMC=OFF \       # Build SystemC model (default: OFF)
  -DDTLS_ENABLE_HARDWARE_ACCEL=ON  # Hardware acceleration (default: ON)
```

### SystemC TLM Build
```bash
cd systemc && mkdir -p build && cd build
cmake .. -DSYSTEMC_ROOT=/home/jgreninger/Work/systemc
make -j$(nproc)
```

### Test Execution
```bash
# REQUIRED: Always run tests from build directory or use test script
cd build

# Run all tests
make test
# or
ctest --output-on-failure

# Or use the provided test script (RECOMMENDED)
./test.sh                       # Run all tests
./test.sh security              # Run security tests only
./test.sh single dtls_crypto_test  # Run specific test
./test.sh ctest -R "crypto" -V  # Custom ctest command

# Run specific test categories (from build directory)
make run_integration_tests      # Integration tests
make run_performance_tests      # Performance benchmarks
make run_security_tests         # Security validation
make run_interop_tests         # Interoperability tests

# Performance benchmarking (Task 10 implementation)
make run_performance_benchmarks  # Comprehensive benchmarks
make run_prd_validation          # PRD compliance validation
make run_performance_regression  # Regression testing

# SystemC tests (if enabled)
cd systemc/build && make systemc-test
```

### Build Script Usage
```bash
# Available build options
./build.sh -h                   # Show help
./build.sh --clean              # Clean build
./build.sh --debug              # Debug build
./build.sh --release            # Release build (default)
./build.sh --verbose --jobs 8   # Verbose build with 8 jobs
```

### Test Script Usage
```bash
# Available test options
./test.sh -h                    # Show help
./test.sh all                   # All tests (default)
./test.sh performance          # Performance tests
./test.sh security             # Security tests
./test.sh single <test_name>    # Single test executable
./test.sh --verbose             # Verbose output
```

## Code Architecture

### Core Library Structure (`src/`)
- **Core Types**: `src/core/` - Basic protocol types, errors, results
- **Crypto System**: `src/crypto/` - Multi-provider crypto (OpenSSL, Botan)
- **Protocol Layer**: `src/protocol/` - DTLS v1.3 protocol implementation
- **Record Layer**: DTLSPlaintext/DTLSCiphertext with sequence number encryption
- **Memory Management**: `src/memory/` - Efficient buffer and pool management
- **Security**: `src/security/` - DoS protection, rate limiting, resource management
- **Transport**: `src/transport/` - UDP transport abstraction

### SystemC TLM Model (`systemc/`)
- **TLM Extensions**: `systemc/include/dtls_tlm_extensions.h` - Custom TLM extensions
- **Protocol Stack**: `systemc/include/dtls_protocol_stack.h` - Complete protocol modeling
- **Timing Models**: `systemc/include/dtls_timing_models.h` - Accurate timing simulation
- **Channels**: `systemc/include/dtls_channels.h` - SystemC communication channels

### Key Design Patterns
- **Provider Pattern**: Crypto operations abstracted through `CryptoProvider` interface
- **Factory Pattern**: `ProviderFactory` for crypto provider management
- **Result Type**: `Result<T>` for error handling (no exceptions)
- **RAII**: `ProviderManager` for automatic resource management
- **State Machine**: Connection states in `ConnectionState` enum

### Header Organization
- **Public API**: `include/dtls/` - Public interfaces
- **Types**: `include/dtls/types.h` - Core protocol types and enums
- **Crypto**: `include/dtls/crypto/` - Cryptographic interfaces
- **Protocol**: `include/dtls/protocol/` - Protocol message structures

## Development Workflows

## ⚠️ CRITICAL DEVELOPMENT REQUIREMENTS ⚠️

**ABSOLUTELY MANDATORY**: Use the following subagents for ALL development work:

- **cpp-pro**: ALWAYS use for implementing new C++ code
- **debugger**: ALWAYS use for debugging compile errors and runtime bugs  
- **qa-engineer**: ALWAYS use after each step to review against PRD/RFC 9147, update TASKS.md
- **test-writer-fixer**: ALWAYS use to write tests and integrate into regression suite

**FAILURE TO USE THESE SUBAGENTS WILL RESULT IN INCOMPLETE/NON-COMPLIANT IMPLEMENTATIONS**

### Required Subagent Usage
**CRITICAL**: Always use these specialized subagents for development tasks:

- **cpp-pro**: **ALWAYS** use for implementing new C++ code. Use PROACTIVELY for C++ refactoring, performance optimization, or complex .NET solutions.
- **debugger**: **ALWAYS** use for debugging compile errors, runtime bugs, and build issues. Use proactively when encountering any compilation or runtime issues.
- **qa-engineer**: **ALWAYS** use after each development step to review code against PRD and RFC 9147 requirements, update TASKS.md with missing features. Use proactively to ensure compliance and code quality.
- **test-writer-fixer**: **ALWAYS** use to write comprehensive tests for each implementation step and integrate into overall regression test suite. Use proactively after code modifications to ensure comprehensive test coverage and suite health.

**MANDATORY WORKFLOW**: 
1. Use `cpp-pro` for all code implementation
2. Use `debugger` immediately when compilation errors or bugs occur
3. Use `qa-engineer` after each implementation step for compliance review
4. Use `test-writer-fixer` to create/update tests and integrate into regression suite

### Adding New Features
**MANDATORY STEP-BY-STEP WORKFLOW:**
1. **Planning**: Use `qa-engineer` to review requirements against PRD/RFC 9147
2. **Headers**: Update relevant headers in `include/dtls/` using `cpp-pro`
3. **Implementation**: Implement in corresponding `src/` subdirectory using `cpp-pro`
4. **Debug Issues**: Use `debugger` for any compilation errors or runtime issues
5. **Code Review**: Use `qa-engineer` to review implementation against PRD/RFC 9147, update TASKS.md
6. **Unit Testing**: Add comprehensive unit tests in `tests/` using `test-writer-fixer`
7. **SystemC**: Update SystemC model if applicable (`systemc/`) using `cpp-pro`
8. **Integration Testing**: Add integration tests and examples using `test-writer-fixer`
9. **Final Validation**: Use `qa-engineer` to verify complete compliance and test coverage
10. **Regression Integration**: Use `test-writer-fixer` to ensure all tests are integrated into regression suite

**IMPORTANT**: Never proceed to next step without using the required subagent for current step.

### Crypto Provider Development
```cpp
// Extend CryptoProvider interface
class MyProvider : public CryptoProvider {
    // Implement required methods
};

// Register with factory
ProviderFactory::instance().register_provider(
    "myprovider", "Description", 
    []() { return std::make_unique<MyProvider>(); }
);
```

### SystemC Model Development
- Extend `systemc/include/` headers for new TLM interfaces
- Implement timing models in `systemc/src/dtls_timing_models.cpp`
- Add testbenches in `systemc/tests/`

## Testing Strategy

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component interactions
- **Performance Tests**: Benchmarking and regression testing
- **Security Tests**: Vulnerability and attack simulation
- **Interoperability Tests**: OpenSSL, WolfSSL, GnuTLS compatibility
- **SystemC Tests**: Hardware/software co-simulation

### Coverage Requirements
- Minimum 95% code coverage for new features
- All public APIs must have unit tests
- Security-critical code requires additional validation

### Coverage Analysis and Reporting
**IMPORTANT**: Always filter coverage reports to exclude system dependencies and build artifacts.

```bash
# Generate filtered coverage report (ALWAYS USE THIS APPROACH)
cd build

# Run tests with coverage instrumentation
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage -g -O0" -DCMAKE_C_FLAGS="--coverage -g -O0"
make -j$(nproc)
make dtls_coverage  # or run individual test suites

# Filter out system includes, build artifacts, and third-party code
lcov --remove total_coverage.info '*/build/*' '*/usr/include/*' '*/openssl/include/*' '*/_deps/*' --output-file filtered_source_coverage.info

# Generate clean HTML report (project source only)
genhtml --output-directory clean_coverage_html filtered_source_coverage.info

# View filtered coverage summary
lcov --summary filtered_source_coverage.info
```

**Why Filter Coverage?**
- System headers and third-party code pollute coverage metrics
- Build artifacts and generated files create noise in reports
- Project-only coverage provides accurate implementation assessment
- Filtered reports show true coverage of DTLS v1.3 source code

**Coverage Report Locations:**
- **Clean Report**: `clean_coverage_html/index.html` (project files only - USE THIS)
- **Complete Report**: `latest_coverage_html/index.html` (includes all files)
- **Filtered Data**: `filtered_source_coverage.info` (project-only coverage)
- **Complete Data**: `total_coverage.info` (all files including system)

## Implementation Status

**Current Status**: IMPLEMENTATION COMPLETE - Full RFC 9147 compliance achieved

All 12 critical tasks completed:
- ✅ DTLSPlaintext/DTLSCiphertext structures
- ✅ Sequence number encryption
- ✅ HelloRetryRequest implementation  
- ✅ Cookie exchange mechanism
- ✅ Complete DoS protection
- ✅ HKDF-Expand-Label compliance
- ✅ Key update mechanisms
- ✅ Record layer integration
- ✅ Interoperability testing
- ✅ Performance benchmarking
- ✅ 0-RTT early data support
- ✅ Security validation suite

## Common Development Tasks

### Running Linters/Formatters
The project uses standard C++ compiler warnings. Enable with:
```bash
cmake .. -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic"
```

### Dependencies
- **Required**: OpenSSL 1.1.1+ or 3.0+, CMake 3.20+, C++20 compiler
- **Optional**: Botan 3.0+, SystemC 2.3.3+, Google Test, Google Benchmark
- **Testing**: Docker (for interoperability tests)

### Performance Requirements
- <5% overhead vs plain UDP
- <10ms handshake time on LAN  
- >90% UDP throughput
- <64KB memory per connection
- >10,000 concurrent connections

## Key Files to Understand

- `include/dtls/types.h` - Core protocol definitions
- `include/dtls/crypto/provider_factory.h` - Crypto abstraction
- `include/dtls/protocol/handshake.h` - Handshake message structures
- `src/protocol/record_layer.cpp` - Record layer implementation
- `systemc/include/dtls_protocol_stack.h` - SystemC modeling
- `tests/CMakeLists.txt` - Test infrastructure