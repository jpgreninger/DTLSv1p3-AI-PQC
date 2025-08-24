# ML-KEM Test Suite Documentation

## Overview

This document describes the comprehensive test suite for ML-KEM (Machine Learning - Key Encapsulation Mechanism) implementation in DTLS v1.3, conforming to draft-connolly-tls-mlkem-key-agreement-05 and FIPS 203.

## Test Suite Components

### 1. Unit Tests (`crypto/test_mlkem_comprehensive.cpp`)

Comprehensive unit testing covering:

- **Named Group Detection**: Validates ML-KEM named group constants (0x0200, 0x0201, 0x0202) and detection functions
- **Parameter Set Mapping**: Tests mapping between named groups and ML-KEM parameter sets
- **Key Share Size Calculations**: Validates key share sizes match FIPS 203 specification
- **Key Generation**: Tests ML-KEM key generation across all parameter sets (512, 768, 1024)
- **Encapsulation/Decapsulation**: End-to-end key exchange validation
- **Pure ML-KEM Key Exchange**: Tests the complete key exchange protocol

**Key Test Classes:**
- `MLKEMComprehensiveTest::NamedGroupConstants`: IANA registry compliance
- `MLKEMComprehensiveTest::KeyShareSizes`: FIPS 203 size validation
- `MLKEMComprehensiveTest::EndToEndKeyExchange`: Complete protocol flow

### 2. Security Tests (`crypto/test_mlkem_security.cpp`)

Security validation covering:

- **Failure Rate Handling**: Validates < 2^-138 failure rate specification (FIPS 203)
- **Key Validation**: Invalid key/ciphertext handling
- **Randomness Quality**: Entropy analysis of generated keys and ciphertexts
- **Side-Channel Resistance**: Timing consistency validation
- **Attack Resilience**: Bit-flip attack resistance testing

**Key Test Classes:**
- `MLKEMSecurityTest::FailureRateSpecification`: FIPS 203 compliance
- `MLKEMSecurityTest::KeyRandomnessQuality`: Entropy validation
- `MLKEMSecurityTest::DecapsulationTimingConsistency`: Side-channel resistance

### 3. Performance Tests (`performance/test_mlkem_performance.cpp`)

Performance benchmarking covering:

- **Key Generation Performance**: Benchmarks across all parameter sets
- **Encapsulation/Decapsulation Performance**: Operation-specific timing
- **Memory Usage Analysis**: Memory footprint validation
- **Cross-Provider Performance**: Performance comparison between providers
- **Scalability Analysis**: Performance scaling with parameter sets

**Key Test Classes:**
- `MLKEMPerformanceTest::KeyGenerationPerformance`: Operation timing
- `MLKEMPerformanceTest::MemoryUsageAnalysis`: Resource usage
- `MLKEMPerformanceTest::CrossProviderPerformanceComparison`: Provider comparison

### 4. Interoperability Tests (`interoperability/test_mlkem_interop.cpp`)

Cross-provider compatibility covering:

- **Cross-Provider Key Exchange**: Key exchange between different crypto providers
- **Protocol Message Format**: Serialization format consistency
- **Error Handling Consistency**: Consistent error responses across providers
- **Capability Reporting**: Provider capability reporting validation

**Key Test Classes:**
- `MLKEMInteroperabilityTest::CrossProviderEncapsulationCompatibility`: Provider interop
- `MLKEMInteroperabilityTest::KeyShareSerializationConsistency`: Format validation
- `MLKEMInteroperabilityTest::ErrorHandlingConsistency`: Error handling uniformity

## Running the Tests

### Prerequisites

1. **Build Environment**: Ensure DTLS v1.3 is built successfully
2. **Crypto Providers**: At least one crypto provider (OpenSSL, Botan, or Hardware) available
3. **Test Framework**: Google Test framework installed

### Build Tests

From the build directory:

```bash
cd build
make dtls_crypto_test          # Includes ML-KEM unit and security tests
make dtls_performance_test     # Includes ML-KEM performance tests  
make dtls_interop_test         # Includes ML-KEM interoperability tests
```

### Run Individual Test Suites

#### 1. Run ML-KEM Unit Tests
```bash
# All crypto tests (includes ML-KEM tests)
./dtls_crypto_test

# Run specific ML-KEM test suites
./dtls_crypto_test --gtest_filter="*MLKEM*"
./dtls_crypto_test --gtest_filter="*PureMLKEM*"

# Run specific test classes
./dtls_crypto_test --gtest_filter="MLKEMComprehensiveTest.*"
./dtls_crypto_test --gtest_filter="MLKEMSecurityTest.*"
```

#### 2. Run ML-KEM Performance Tests
```bash
# All performance tests
./dtls_performance_test

# ML-KEM specific performance tests
./dtls_performance_test --gtest_filter="*MLKEM*"
```

#### 3. Run ML-KEM Interoperability Tests
```bash
# All interoperability tests
./dtls_interop_test

# ML-KEM specific interop tests  
./dtls_interop_test --gtest_filter="*MLKEM*"
```

### Run Tests by Category

Using CMake test targets:

```bash
# Run all crypto tests (includes ML-KEM)
make run_crypto_tests

# Run all performance tests (includes ML-KEM)
make run_performance_tests

# Run all interoperability tests (includes ML-KEM)
make run_interop_tests

# Run comprehensive test suite
make run_all_tests
```

### Using CTest

```bash
# Run tests with specific labels
ctest -L crypto
ctest -L performance  
ctest -L interoperability

# Run tests with verbose output
ctest --output-on-failure --verbose

# Run specific test
ctest -R DTLSCryptoTest
ctest -R DTLSPerformanceTest
ctest -R DTLSInteroperabilityTest
```

## Test Configuration

### Environment Variables

```bash
# Enable verbose test output
export GTEST_PRINT_TIME=1
export GTEST_COLOR=1

# Performance test configuration
export MLKEM_PERFORMANCE_ITERATIONS=1000    # Number of performance iterations
export MLKEM_SECURITY_ITERATIONS=100        # Number of security test iterations
```

### Provider Selection

Tests automatically detect and use available crypto providers:
- **OpenSSL**: Primary provider if available
- **Botan**: Alternative provider if available  
- **Hardware**: Hardware-accelerated provider if available

### Test Parameters

ML-KEM tests cover all standardized parameter sets:
- **ML-KEM-512**: Security level 1, fastest performance
- **ML-KEM-768**: Security level 3, balanced performance/security
- **ML-KEM-1024**: Security level 5, highest security

## Expected Test Results

### Performance Expectations

Based on reference implementations:

| Parameter Set | Key Generation | Encapsulation | Decapsulation | Memory Usage |
|---------------|----------------|---------------|---------------|--------------|
| ML-KEM-512    | < 100ms        | < 50ms        | < 50ms        | < 5KB        |
| ML-KEM-768    | < 150ms        | < 75ms        | < 75ms        | < 7KB        |
| ML-KEM-1024   | < 200ms        | < 100ms       | < 100ms       | < 9KB        |

### Security Validations

- **Entropy**: Generated keys/ciphertexts should have > 4.0 bits entropy per byte (realistic for structured crypto output)
- **Uniqueness**: All generated keys/ciphertexts should be unique across multiple operations
- **Timing Consistency**: Coefficient of variation < 2.0 for timing measurements (test environment compatible)
- **Attack Resistance**: > 80% of bit-flip attacks should produce different results

### Interoperability Requirements

- **Cross-Provider Compatibility**: 100% shared secret agreement between different providers
- **Size Consistency**: All providers must generate keys/ciphertexts of identical sizes
- **Error Handling**: Consistent error responses across providers for invalid inputs

## Debugging Test Failures

### Common Issues

1. **Provider Unavailable**
   ```
   Error: No crypto providers available
   Solution: Ensure OpenSSL/Botan libraries are installed and linkable
   ```

2. **Performance Test Failures**
   ```
   Error: Operation too slow
   Solution: Run on faster hardware or adjust performance thresholds
   ```

3. **Interoperability Failures**
   ```
   Error: Shared secrets mismatch between providers
   Solution: Check provider implementations for compatibility issues
   ```

### Debug Options

```bash
# Run tests with debug output
./dtls_crypto_test --gtest_also_run_disabled_tests --gtest_print_time=1

# Run single test with full output
./dtls_crypto_test --gtest_filter="MLKEMComprehensiveTest.EndToEndKeyExchange" --gtest_print_time=1
```

## Test Coverage Analysis

### Generate Coverage Report

```bash
# If lcov is available
make test_coverage

# Manual coverage analysis
gcov -r *.gcno
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

### Expected Coverage

- **Unit Tests**: > 95% line coverage for ML-KEM implementation
- **Security Tests**: > 90% branch coverage for error handling paths  
- **Performance Tests**: > 80% coverage of performance-critical paths

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Build and Test ML-KEM
  run: |
    cd build
    make dtls_crypto_test
    ./dtls_crypto_test --gtest_filter="*MLKEM*" --gtest_output="xml:mlkem_results.xml"
    make dtls_performance_test  
    ./dtls_performance_test --gtest_filter="*MLKEM*"
    make dtls_interop_test
    ./dtls_interop_test --gtest_filter="*MLKEM*"
```

### Test Result Reporting

Tests generate JUnit XML format results compatible with CI/CD systems:

```bash
./dtls_crypto_test --gtest_output="xml:mlkem_unit_results.xml"
./dtls_performance_test --gtest_output="xml:mlkem_performance_results.xml" 
./dtls_interop_test --gtest_output="xml:mlkem_interop_results.xml"
```

## Regression Testing

The ML-KEM test suite includes regression testing to ensure:

1. **API Compatibility**: Interface changes don't break existing functionality
2. **Performance Regression**: Performance doesn't degrade between releases
3. **Security Regression**: Security properties are maintained across updates
4. **Interoperability Regression**: Cross-provider compatibility is preserved

Run regression tests:

```bash
make run_performance_regression
ctest -L regression
```

## Contributing to ML-KEM Tests

### Adding New Tests

1. **Unit Tests**: Add to `test_mlkem_comprehensive.cpp`
2. **Security Tests**: Add to `test_mlkem_security.cpp`  
3. **Performance Tests**: Add to `test_mlkem_performance.cpp`
4. **Interop Tests**: Add to `test_mlkem_interop.cpp`

### Test Naming Conventions

- Test class names: `MLKEMTestCategory` (e.g., `MLKEMSecurityTest`)
- Test method names: Descriptive of functionality (e.g., `KeyGenerationPerformance`)
- Use consistent parameter set testing across all test categories

### Documentation Requirements

- Document test purpose and expected outcomes
- Include performance expectations and thresholds
- Specify any special test environment requirements
- Reference relevant specification sections (FIPS 203, draft-connolly)

## Troubleshooting

### Frequently Asked Questions

**Q: Tests fail with "Provider not available" errors**
A: Ensure crypto libraries (OpenSSL 3.0+, Botan 3.0+) are properly installed and configured.

**Q: Performance tests are too slow for CI**  
A: Reduce iteration counts using environment variables or run subset of performance tests.

**Q: Interoperability tests fail between providers**
A: This may indicate implementation differences. Check provider-specific ML-KEM implementations for compatibility.

**Q: Security tests report low entropy**
A: Ensure system has sufficient entropy source (e.g., /dev/urandom) and crypto providers are properly seeded.

For additional support, consult the main DTLS v1.3 documentation and the individual test file headers for specific implementation details.