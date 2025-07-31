# Code Style and Conventions

## Formatting
- **Style Base**: Google C++ Style Guide
- **Indentation**: 4 spaces (no tabs)
- **Column Limit**: 100 characters
- **Braces**: Attach style (`{` on same line)

## Naming Conventions
- **Variables**: snake_case (`buffer_size`, `connection_id_`)
- **Functions**: snake_case (`create_random`, `is_valid`)
- **Classes**: PascalCase (`ClientHello`, `RecordLayer`)
- **Constants**: UPPER_CASE (`MAX_RECORD_SIZE`, `DTLS_V13`)
- **Namespaces**: snake_case (`dtls::v13::protocol`)
- **Private Members**: trailing underscore (`data_`, `header_`)

## Code Organization
- **Namespace Structure**: `dtls::v13::<module>` (e.g., `dtls::v13::crypto`)
- **Header Guards**: Use pragma once
- **Include Order**: DTLS headers first, then third-party (OpenSSL/Botan), then standard library
- **File Extensions**: `.h` for headers, `.cpp` for implementation

## Documentation
- **API Documentation**: Doxygen-style comments for public interfaces
- **Descriptive Names**: Self-documenting code preferred over comments
- **Error Handling**: Result<T> pattern for error propagation
- **Thread Safety**: Explicitly documented where applicable

## Memory Management
- **RAII**: Resource Acquisition Is Initialization pattern
- **Smart Pointers**: Prefer unique_ptr and shared_ptr over raw pointers
- **Buffer Management**: ZeroCopyBuffer class for efficient memory handling
- **Secure Cleanup**: Explicit secure zeroing of sensitive data

## Architecture Patterns
- **Interface Segregation**: Clean interfaces for crypto providers, record layers
- **Factory Pattern**: Provider factory for crypto backend selection
- **PIMPL**: Private implementation idiom for stable ABI
- **Template Specialization**: For performance-critical crypto operations