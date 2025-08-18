# DTLS v1.3 Documentation

## API Documentation

Complete documentation for the DTLS v1.3 implementation, covering both C++ and SystemC APIs.

### Main Documentation

| Document | Description | Target Audience |
|----------|-------------|----------------|
| [API Documentation](API_DOCUMENTATION.md) | Complete C++ API reference with examples | Developers integrating DTLS |
| [API Quick Reference](API_QUICK_REFERENCE.md) | Essential patterns and quick lookup | Daily development reference |
| [SystemC API Documentation](SYSTEMC_API_DOCUMENTATION.md) | SystemC TLM modeling interface | Hardware/software co-design |

### Specialized Documentation

| Document | Description |
|----------|-------------|
| [Security Assessment Report](SECURITY_ASSESSMENT_REPORT.md) | Security analysis and validation |
| [Early Data Implementation](EARLY_DATA_IMPLEMENTATION.md) | 0-RTT implementation details |
| [Error Handling](ERROR_HANDLING.md) | Error management and recovery |
| [ACK State Machine Integration](ACK_STATE_MACHINE_INTEGRATION.md) | ACK mechanism implementation |
| [Security Validation Suite](SECURITY_VALIDATION_SUITE.md) | Security testing framework |

### Getting Started

#### For Application Developers (C++ API)

1. **Start with**: [API Quick Reference](API_QUICK_REFERENCE.md) for essential patterns
2. **Deep dive**: [API Documentation](API_DOCUMENTATION.md) for complete reference
3. **Examples**: See examples in the main API documentation

#### For SystemC Developers (Hardware/Software Co-design)

1. **Start with**: [SystemC API Documentation](SYSTEMC_API_DOCUMENTATION.md)
2. **Focus on**: TLM interfaces and timing models
3. **Examples**: SystemC testbenches and performance analysis

#### For Security Engineers

1. **Start with**: [Security Assessment Report](SECURITY_ASSESSMENT_REPORT.md)
2. **Testing**: [Security Validation Suite](SECURITY_VALIDATION_SUITE.md)
3. **Implementation**: Security-specific sections in main API docs

## Documentation Generation

### Doxygen Documentation

Generate comprehensive HTML documentation from source code:

```bash
# Generate API documentation
doxygen Doxyfile
# Output: docs/api/html/index.html

# Or use the build system target
make docs
```

**Features of Generated Documentation:**
- Complete API reference with class diagrams
- Function signatures with detailed parameter descriptions  
- Code examples and usage patterns
- Cross-references and inheritance diagrams
- Search functionality and alphabetical index
- RFC 9147 compliance notes and security annotations

### API Coverage

The documentation covers:

- ✅ **Core API**: Connection management, configuration, lifecycle
- ✅ **Cryptographic Interface**: Provider system, operations, key management
- ✅ **Protocol Layer**: Record layer, handshake management, message processing
- ✅ **Memory Management**: Buffers, pools, zero-copy operations
- ✅ **Error Handling**: Result types, error codes, recovery mechanisms
- ✅ **Security Features**: DoS protection, certificate handling, validation
- ✅ **Performance Monitoring**: Metrics collection, statistics, analysis
- ✅ **SystemC TLM**: Transaction-level modeling, timing, verification
- ✅ **Examples**: Complete working examples for common use cases
- ✅ **Best Practices**: Recommendations and common patterns

## Quick Navigation

### By Use Case

| Use Case | Primary Documentation |
|----------|----------------------|
| Basic client connection | [API Quick Reference - Client Connection](API_QUICK_REFERENCE.md#client-connection) |
| Server setup | [API Quick Reference - Server Setup](API_QUICK_REFERENCE.md#server-setup) |
| Error handling | [Error Handling](ERROR_HANDLING.md) + [API Documentation - Error Handling](API_DOCUMENTATION.md#error-handling) |
| Performance optimization | [API Documentation - Performance Monitoring](API_DOCUMENTATION.md#performance-monitoring) |
| Security configuration | [Security Assessment Report](SECURITY_ASSESSMENT_REPORT.md) |
| Early data (0-RTT) | [Early Data Implementation](EARLY_DATA_IMPLEMENTATION.md) |
| Hardware modeling | [SystemC API Documentation](SYSTEMC_API_DOCUMENTATION.md) |

### By Component

| Component | Primary Documentation |
|-----------|----------------------|
| Connection class | [API Documentation - Connection Management](API_DOCUMENTATION.md#connection-management) |
| Crypto providers | [API Documentation - Cryptographic Interface](API_DOCUMENTATION.md#cryptographic-interface) |
| Record layer | [API Documentation - Protocol Layer](API_DOCUMENTATION.md#protocol-layer) |
| Memory buffers | [API Documentation - Memory Management](API_DOCUMENTATION.md#memory-management) |
| SystemC protocol stack | [SystemC API - Protocol Stack Model](SYSTEMC_API_DOCUMENTATION.md#protocol-stack-model) |

## Documentation Standards

### Code Examples

All code examples in the documentation:
- ✅ Use realistic, compilable C++ code
- ✅ Include proper error handling with Result<T>
- ✅ Follow project coding standards
- ✅ Include necessary #include statements
- ✅ Demonstrate best practices

### API Reference

All public APIs documented with:
- ✅ Function signatures and parameters
- ✅ Return value descriptions
- ✅ Usage examples
- ✅ Error conditions
- ✅ Performance considerations
- ✅ Thread safety information

### SystemC TLM

SystemC documentation includes:
- ✅ TLM-2.0 compliance details
- ✅ Custom extensions for DTLS
- ✅ Timing model configurations
- ✅ Testbench examples
- ✅ Performance analysis tools

## Contribution Guidelines

When updating documentation:

1. **Maintain consistency** with existing style and structure
2. **Include examples** for new API additions
3. **Update quick reference** for commonly used features  
4. **Test code examples** to ensure they compile and work
5. **Update this index** when adding new documentation files

## Version Information

- **Documentation Version**: 1.0
- **API Version**: DTLS v1.3 (RFC 9147 compliant)
- **Last Updated**: August 17, 2025
- **SystemC Version**: Compatible with SystemC 2.3.3+