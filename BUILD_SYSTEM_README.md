# DTLS v1.3 Build System

This document explains the build system configuration and enforced practices for the DTLS v1.3 project.

## Build Directory Policy

**IMPORTANT**: This project enforces out-of-source builds. All builds MUST happen in `~/Work/DTLSv1p3/build`.

### Why Out-of-Source Builds?

1. **Prevents contamination** of the source tree with build artifacts
2. **Enables clean rebuilds** by simply deleting the build directory
3. **Avoids conflicts** between different build configurations
4. **Simplifies version control** by keeping generated files separate
5. **Ensures consistency** across all development environments

## Quick Start

### Using Build Scripts (Recommended)

```bash
# Build the project
./build.sh                    # Release build
./build.sh --debug            # Debug build  
./build.sh --clean --verbose  # Clean verbose build

# Run tests
./test.sh                     # All tests
./test.sh security            # Security tests only
./test.sh single dtls_crypto_test  # Specific test
```

### Manual Build

```bash
# Create and enter build directory
mkdir -p build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build with make
make -j$(nproc)

# Run tests
make test
# or
ctest --output-on-failure
```

## Build Scripts

### build.sh

Main build script that ensures consistent builds in the build directory.

**Options:**
- `-d, --debug`: Debug build
- `-r, --release`: Release build (default)
- `-c, --clean`: Clean build directory first
- `-v, --verbose`: Verbose build output
- `-j, --jobs N`: Use N parallel jobs
- `-h, --help`: Show help

### test.sh  

Test runner that ensures all tests run from the correct build directory.

**Test Types:**
- `all`: Run all tests (default)
- `protocol`: Protocol unit tests
- `crypto`: Cryptographic tests
- `connection`: Connection tests
- `integration`: Integration tests
- `performance`: Performance tests
- `security`: Security validation tests
- `reliability`: Reliability tests
- `interop`: Interoperability tests
- `single <name>`: Run specific test executable
- `ctest [args]`: Run ctest directly with args

**Options:**
- `-v, --verbose`: Verbose test output
- `-s, --serial`: Run tests serially
- `-j, --jobs N`: Use N parallel jobs
- `-h, --help`: Show help

### check-build-dir.sh

Verification script that prevents in-source builds and guides users to the correct build directory.

## Directory Structure

```
~/Work/DTLSv1p3/
├── build/                 # All build artifacts (REQUIRED)
│   ├── CMakeCache.txt
│   ├── Makefile
│   ├── src/               # Built libraries
│   ├── tests/             # Test executables
│   ├── examples/          # Example executables
│   └── ...
├── src/                   # Source code (read-only during build)
├── tests/                 # Test source code
├── examples/              # Example source code
├── build.sh               # Build script
├── test.sh                # Test script
├── check-build-dir.sh     # Build directory verification
└── CLAUDE.md              # Updated project instructions
```

## Build Targets

### Main Targets
- `all`: Build everything (default)
- `dtlsv13`: Build main library
- `test`: Run all tests via CTest

### Test Targets
- `run_all_tests`: Run comprehensive test suite
- `run_protocol_tests`: Protocol unit tests
- `run_crypto_tests`: Crypto unit tests
- `run_connection_tests`: Connection unit tests
- `run_integration_tests`: Integration tests
- `run_performance_tests`: Performance benchmarks
- `run_security_tests`: Security validation
- `run_reliability_tests`: Reliability tests
- `run_interop_tests`: Interoperability tests

### Performance Targets
- `run_performance_benchmarks`: Comprehensive benchmarks
- `run_prd_validation`: PRD compliance validation
- `run_performance_regression`: Regression testing

## GoogleTest Integration

GoogleTest is automatically downloaded and built via CMake's FetchContent when needed. All test executables are built in `build/tests/` and properly linked against GoogleTest.

## Common Issues and Solutions

### Issue: "You are trying to build in the source directory!"
**Solution**: Use the build scripts or manually create the build directory:
```bash
./build.sh
# or
mkdir -p build && cd build && cmake .. && make
```

### Issue: "Build directory not found or not configured"
**Solution**: Run the build script to configure:
```bash
./build.sh
```

### Issue: Test executables not found
**Solution**: Tests are in `build/tests/`. Use the test script or run from build directory:
```bash
./test.sh single dtls_crypto_test
# or
cd build && ./tests/dtls_crypto_test
```

### Issue: CMake configuration errors
**Solution**: Clean build directory and reconfigure:
```bash
./build.sh --clean
```

## Regression Testing

The build system supports regression testing for:
- **Performance regressions**: `./test.sh regression`
- **Single test execution**: `./test.sh single <test_name>`
- **GoogleTest integration**: All tests use GoogleTest framework

## CI/CD Integration

For automated builds, use:
```bash
# CI Build
./build.sh --clean --verbose

# CI Testing  
./test.sh all --verbose

# Performance Validation
./test.sh prd --verbose
```

## Migration from In-Source Builds

If you previously built in the source directory:

1. Clean up source directory:
   ```bash
   rm -rf CMakeFiles CMakeCache.txt Makefile _deps *.cmake
   ```

2. Use the new build system:
   ```bash
   ./build.sh
   ```

## Troubleshooting

1. **Check build directory**: `./check-build-dir.sh`
2. **Clean rebuild**: `./build.sh --clean`
3. **Verbose output**: `./build.sh --verbose`
4. **Test specific issues**: `./test.sh single <test_name> --verbose`

For more help, see the main project documentation in CLAUDE.md.