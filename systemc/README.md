# DTLS v1.3 SystemC Transaction Level Models

This directory contains SystemC Transaction Level Models (TLM) for the DTLS v1.3 implementation, providing hardware/software co-design verification and performance analysis capabilities.

## Overview

The SystemC TLM models enable:
- **Hardware/Software Co-Design**: Model both software and hardware implementations
- **Performance Analysis**: Detailed timing and throughput analysis
- **Architecture Exploration**: Evaluate different implementation architectures
- **Verification**: Comprehensive functional and security verification
- **System Integration**: Model complete DTLS systems with network conditions

## Architecture

### Component Hierarchy

```
DTLS SystemC TLM System
├── Crypto Provider TLM Models
│   ├── CryptoProviderTLM - Basic crypto operations
│   ├── HardwareAcceleratedCryptoTLM - Hardware acceleration
│   └── CryptoManagerTLM - Multi-provider management
│
├── Record Layer TLM Models
│   ├── AntiReplayWindowTLM - Replay attack protection
│   ├── SequenceNumberManagerTLM - Sequence number management
│   ├── EpochManagerTLM - DTLS epoch handling
│   └── RecordLayerTLM - Complete record layer
│
├── Message Layer TLM Models
│   ├── MessageReassemblerTLM - Fragment reassembly
│   ├── MessageFragmenterTLM - Message fragmentation
│   ├── FlightManagerTLM - Handshake flight management
│   └── MessageLayerTLM - Complete message layer
│
├── Communication Channels
│   ├── CryptoOperationChannel - Crypto operation routing
│   ├── RecordOperationChannel - Record layer communications
│   ├── MessageOperationChannel - Message layer communications
│   ├── TransportChannel - Network transport simulation
│   └── DTLSInterconnectBus - System interconnect
│
└── Verification Infrastructure
    ├── DTLSSystemTestbench - Comprehensive system tests
    ├── DTLSPerformanceBenchmark - Performance characterization
    └── DTLSSecurityValidator - Security verification
```

## Key Features

### Transaction Level Modeling
- **TLM-2.0 Compliant**: Standard SystemC TLM interfaces
- **Blocking/Non-blocking**: Support for both transport modes
- **Timing Accurate**: Configurable timing models
- **Protocol Specific**: Custom transaction types for DTLS operations

### Performance Modeling
- **Configurable Timing**: Hardware-specific timing parameters
- **Throughput Analysis**: Operations per second measurements
- **Latency Modeling**: End-to-end delay calculations
- **Resource Utilization**: Memory and processing load tracking

### Security Modeling
- **Attack Simulation**: Replay attacks, timing attacks
- **Security Validation**: Protocol compliance verification
- **Vulnerability Testing**: Systematic security testing
- **Side-Channel Resistance**: Timing attack resistance

### Network Simulation
- **Packet Loss**: Configurable loss probability
- **Network Delay**: Latency and jitter simulation
- **Bandwidth Modeling**: Throughput limitations
- **Congestion Control**: Network condition adaptation

## Building

### Prerequisites
- SystemC 2.3.3 or later
- C++17 compatible compiler
- CMake 3.16 or later
- Main DTLS v1.3 library

### Build Instructions

```bash
# Create build directory
mkdir build && cd build

# Configure build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DDTLS_SYSTEMC_BUILD_TESTS=ON \
      -DDTLS_SYSTEMC_BUILD_EXAMPLES=ON \
      ..

# Build
make -j$(nproc)

# Run tests
make systemc-test

# Generate documentation (if Doxygen available)
make systemc_docs
```

### Build Options
- `DTLS_SYSTEMC_BUILD_TESTS`: Build test executables (default: ON)
- `DTLS_SYSTEMC_BUILD_EXAMPLES`: Build example applications (default: ON)  
- `DTLS_SYSTEMC_ENABLE_COVERAGE`: Enable code coverage (default: OFF)
- `DTLS_SYSTEMC_ENABLE_PROFILING`: Enable performance profiling (default: OFF)

## Usage

### Basic Crypto Provider Test

```cpp
#include "crypto_provider_tlm.h"

// Create crypto provider with hardware acceleration
CryptoProviderTLM crypto_provider("crypto_provider", true);

// Create test transaction
crypto_transaction trans(crypto_transaction::ENCRYPT);
trans.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
trans.input_data = test_data;
trans.key_material = encryption_key;

// Perform operation via TLM
tlm::tlm_generic_payload payload;
payload.set_data_ptr(reinterpret_cast<unsigned char*>(&trans));
sc_time delay = SC_ZERO_TIME;

crypto_provider.target_socket->b_transport(payload, delay);
```

### System Integration Test

```cpp
#include "dtls_testbench.h"

// Create comprehensive system testbench
DTLSSystemTestbench testbench("system_testbench");

// Run all test scenarios
testbench.run_all_tests();

// Get results
auto results = testbench.get_test_results();
testbench.print_test_summary();
```

### Performance Benchmarking

```cpp
#include "dtls_testbench.h"

// Create performance benchmark
DTLSPerformanceBenchmark::BenchmarkConfig config;
config.enable_hardware_acceleration = true;
config.enable_network_simulation = true;

DTLSPerformanceBenchmark benchmark("perf_benchmark", config);

// Run benchmark suite
benchmark.run_benchmark();
auto results = benchmark.get_benchmark_results();
```

## Test Scenarios

### Functional Tests
1. **Basic Crypto Operations**: Encryption, signing, key derivation
2. **Record Layer Protection**: Record encryption/decryption with anti-replay
3. **Message Fragmentation**: Large message fragmentation and reassembly
4. **Flight Management**: Handshake flight reliability and retransmission
5. **Full DTLS Handshake**: Complete handshake protocol execution

### Performance Tests  
6. **Stress Testing**: High-load operation validation
7. **Network Conditions**: Packet loss and delay tolerance
8. **Scalability**: Multi-connection concurrent processing

### Security Tests
9. **Security Validation**: Comprehensive security compliance
10. **Attack Simulation**: Replay attacks, timing attacks
11. **Vulnerability Testing**: Systematic security verification

## Configuration

### Timing Configuration

```cpp
// Global timing configuration
dtls_timing_config timing;
timing.aes_encryption_time = sc_time(10, SC_NS);
timing.ecdsa_sign_time = sc_time(1, SC_US);
timing.network_latency = sc_time(50, SC_MS);
```

### Network Simulation

```cpp
// Network condition configuration
TransportChannel::NetworkConditions conditions;
conditions.packet_loss_probability = 0.01; // 1% packet loss
conditions.base_latency = sc_time(100, SC_MS);
conditions.bandwidth_mbps = 100.0;
```

### Hardware Acceleration

```cpp
// Enable hardware acceleration
CryptoProviderTLM crypto("crypto", true); // Hardware accelerated
crypto.set_hardware_acceleration(true);
```

## Performance Characteristics

### Typical Performance (Hardware Accelerated)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| AES-128-GCM Encrypt | 10 ns | 1 GB/s |
| ECDSA P-256 Sign | 1 μs | 1M ops/s |
| HKDF Derive | 500 ns | 2M ops/s |
| Record Protection | 50 ns | 500 MB/s |
| Message Fragmentation | 25 ns | 40M msgs/s |

### Memory Usage
- **Crypto Provider**: ~64 KB per instance
- **Record Layer**: ~128 KB per connection
- **Message Layer**: ~256 KB per connection
- **System Interconnect**: ~512 KB total

## Verification Coverage

### Functional Coverage
- ✅ All crypto operations (AES, ECDSA, HKDF, SHA)
- ✅ Record layer protection/unprotection
- ✅ Anti-replay window management
- ✅ Message fragmentation/reassembly
- ✅ Handshake flight management
- ✅ Network transport simulation

### Security Coverage
- ✅ Replay attack protection
- ✅ Timing attack resistance
- ✅ Epoch security management
- ✅ Connection ID security
- ✅ Protocol compliance (RFC 9147)

### Performance Coverage
- ✅ Throughput characterization
- ✅ Latency analysis
- ✅ Resource utilization
- ✅ Scalability testing
- ✅ Network condition tolerance

## Directory Structure

```
systemc/
├── include/           # Header files
│   ├── dtls_systemc_types.h
│   ├── crypto_provider_tlm.h
│   ├── record_layer_tlm.h
│   ├── message_layer_tlm.h
│   ├── dtls_channels.h
│   └── dtls_testbench.h
├── src/              # Implementation files  
│   ├── crypto_provider_tlm.cpp
│   ├── record_layer_tlm.cpp
│   ├── message_layer_tlm.cpp
│   ├── dtls_channels.cpp
│   └── dtls_testbench.cpp
├── tests/            # Test executables
│   ├── basic_crypto_test.cpp
│   ├── record_layer_test.cpp
│   ├── message_layer_test.cpp
│   ├── integration_test.cpp
│   ├── performance_test.cpp
│   └── security_test.cpp
├── examples/         # Example applications
├── docs/            # Documentation
└── CMakeLists.txt   # Build configuration
```

## Contributing

### Adding New Components
1. Inherit from appropriate base TLM class
2. Implement required TLM interface methods
3. Add timing and performance modeling
4. Include comprehensive statistics
5. Add unit tests and integration tests

### Performance Optimization
1. Profile critical paths with `--enable-profiling`
2. Optimize hot spots in transaction processing
3. Validate timing models against hardware
4. Update performance benchmarks

### Security Enhancement
1. Add new attack simulation scenarios
2. Implement additional security validations
3. Verify protocol compliance
4. Update security test suite

## Troubleshooting

### Common Issues

**Build Errors**
- Ensure SystemC is properly installed and configured
- Check C++17 compiler compatibility
- Verify all dependencies are available

**Runtime Issues**
- Check timing configuration parameters
- Verify transaction data structures
- Enable debug tracing with `--trace`

**Performance Issues**
- Profile with built-in performance counters
- Check for resource contention
- Validate timing model assumptions

### Debug Tracing

```bash
# Enable VCD tracing
./basic_crypto_test --trace

# View with waveform viewer
gtkwave basic_crypto_test.vcd
```

### Logging

```cpp
// Enable detailed logging
SC_REPORT_INFO("DTLS_TLM", "Crypto operation completed");
SC_REPORT_WARNING("DTLS_TLM", "Performance threshold exceeded");
```

## References

- [SystemC TLM-2.0 User Manual](https://www.accellera.org/images/downloads/standards/systemc/TLM_2_0_User_Manual.pdf)
- [DTLS v1.3 RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html)
- [SystemC Modeling Guidelines](https://www.accellera.org/images/downloads/standards/systemc/SystemC_2011_New_Features.pdf)

## License

This SystemC TLM implementation follows the same license as the main DTLS v1.3 project.