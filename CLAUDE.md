# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive DTLS (Datagram Transport Layer Security) v1.3 implementation following RFC 9147, providing both a production C++ library and a SystemC TLM model for hardware/software co-design.

## Build System

### Main Build Commands
```bash
# Configure and build main library
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Build with SystemC support (requires SystemC installation)
cmake .. -DDTLS_BUILD_SYSTEMC=ON -DSYSTEMC_ROOT=/path/to/systemc

# Build options
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
# Run all tests
make test
# or
ctest --output-on-failure

# Run specific test categories
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

### Adding New Features
1. Update relevant headers in `include/dtls/`
2. Implement in corresponding `src/` subdirectory
3. Add unit tests in `tests/`
4. Update SystemC model if applicable (`systemc/`)
5. Add integration tests and examples

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