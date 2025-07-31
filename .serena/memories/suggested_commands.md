# Suggested Development Commands

## Build Commands
```bash
# Configure build (Release)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

# Configure build (Debug with sanitizers)
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Build project
cmake --build . -j$(nproc)

# Install project
cmake --build . --target install
```

## Build Options
```bash
# Enable/disable optional components
cmake -DDTLS_BUILD_TESTS=ON \
      -DDTLS_BUILD_EXAMPLES=ON \
      -DDTLS_BUILD_SYSTEMC=OFF \
      -DDTLS_ENABLE_HARDWARE_ACCEL=ON \
      -DDTLS_BUILD_SHARED=ON \
      ..
```

## Testing Commands
```bash
# Run all tests (when test suite exists)
ctest --output-on-failure

# Run tests in parallel
ctest -j$(nproc)

# Run specific test
ctest -R "crypto_test"
```

## Development Tools
```bash
# Format code
find . -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Static analysis
clang-tidy src/**/*.cpp -- -Iinclude

# Build with sanitizers (Debug mode)
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address" ..
```

## Package Management
```bash
# Create distribution package
cmake --build . --target package

# Create source package
cmake --build . --target package_source
```

## System Commands (Linux)
- **Git**: Standard git workflow
- **Find**: `find . -name "*.h" -o -name "*.cpp"` for source files
- **Grep**: `grep -r "pattern" src/` for code search
- **Build Dependencies**: Handled automatically by CMake's find_package