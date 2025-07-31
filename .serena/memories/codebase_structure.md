# Codebase Structure

## Directory Layout
```
├── include/dtls/              # Public API headers
│   ├── crypto/               # Cryptographic interfaces
│   ├── protocol/             # Protocol layer interfaces  
│   ├── memory/               # Memory management interfaces
│   ├── error.h              # Error handling types
│   ├── types.h              # Core DTLS types
│   ├── result.h             # Result<T> error handling
│   └── *.h                  # Main API headers
├── src/                      # Implementation source
│   ├── core/                # Core utilities and types
│   ├── crypto/              # Cryptographic implementations
│   ├── memory/              # Memory management system
│   └── protocol/            # Protocol layer implementations
├── cmake/                    # CMake configuration files
├── examples/                 # Usage examples (TBD)
├── tests/                    # Test suites (empty - TBD)
├── systemc/                  # SystemC TLM models (TBD)
└── docs/                     # Documentation files
```

## Key Components

### Core Layer (`src/core/`, `include/dtls/`)
- **types.cpp/.h**: Protocol enums and basic types
- **error.cpp/.h**: Error handling system
- **result.cpp/.h**: Result<T> monadic error handling

### Cryptographic Layer (`src/crypto/`, `include/dtls/crypto/`)
- **provider.h**: Abstract crypto provider interface
- **openssl_provider.cpp/.h**: OpenSSL implementation
- **botan_provider.cpp/.h**: Botan implementation
- **provider_factory.cpp/.h**: Provider selection and registration
- **crypto_utils.cpp/.h**: DTLS-specific crypto utilities
- **hardware_acceleration.h**: Hardware crypto detection

### Protocol Layer (`src/protocol/`, `include/dtls/protocol/`)
- **record.cpp/.h**: DTLS record structures
- **handshake.cpp/.h**: Handshake message types
- **message_layer.cpp/.h**: Message fragmentation/reassembly
- **record_layer.cpp/.h**: Record layer processing
- **protocol.cpp/.h**: Protocol validation utilities

### Memory System (`src/memory/`, `include/dtls/memory/`)
- **buffer.cpp/.h**: Zero-copy buffer management
- **pool.cpp/.h**: Memory pool allocators
- **memory_utils.cpp/.h**: Memory utilities and debugging
- **memory_system.cpp/.h**: Global memory management

## Implementation Status
- ✅ **Core Types**: Complete implementation
- ✅ **Crypto System**: OpenSSL + Botan providers implemented
- ✅ **Record Layer**: DTLS record processing complete
- ✅ **Handshake Layer**: Message types and processing complete
- ✅ **Memory System**: Comprehensive memory management
- 🚧 **SystemC Models**: Planned for Phase 4
- ⏳ **Testing**: Planned for Phase 5
- ⏳ **Examples**: Planned for Phase 5