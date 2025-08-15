#!/bin/bash

# DTLS v1.3 Build Script
# Ensures consistent builds in ~/Work/DTLSv1p3/build directory

set -e  # Exit on any error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

echo "DTLS v1.3 Build System"
echo "======================"
echo "Project root: $PROJECT_ROOT"
echo "Build directory: $BUILD_DIR"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Change to build directory
cd "$BUILD_DIR"

# Parse command line arguments
BUILD_TYPE="Release"
CLEAN_BUILD=false
VERBOSE=false
JOBS=$(nproc)

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -r|--release)
            BUILD_TYPE="Release"
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -d, --debug      Build in Debug mode (default: Release)"
            echo "  -r, --release    Build in Release mode"
            echo "  -c, --clean      Clean build directory first"
            echo "  -v, --verbose    Verbose build output"
            echo "  -j, --jobs N     Use N parallel jobs (default: $(nproc))"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Clean build if requested
if [ "$CLEAN_BUILD" = true ]; then
    echo "Cleaning build directory..."
    rm -rf CMakeFiles CMakeCache.txt *.cmake Makefile _deps
fi

# Configure with CMake
echo "Configuring build (Type: $BUILD_TYPE)..."
CMAKE_ARGS=(
    ..
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
    -DDTLS_BUILD_TESTS=ON
    -DDTLS_BUILD_EXAMPLES=ON
    -DDTLS_BUILD_SYSTEMC=OFF
    -DDTLS_ENABLE_HARDWARE_ACCEL=ON
)

if [ "$VERBOSE" = true ]; then
    CMAKE_ARGS+=(-DCMAKE_VERBOSE_MAKEFILE=ON)
fi

cmake "${CMAKE_ARGS[@]}"

# Build
echo "Building with $JOBS parallel jobs..."
if [ "$VERBOSE" = true ]; then
    make -j"$JOBS" VERBOSE=1
else
    make -j"$JOBS"
fi

echo ""
echo "Build completed successfully!"
echo "Built executables are in: $BUILD_DIR"
echo ""
echo "Available targets:"
echo "  make test                       - Run all tests"
echo "  make run_all_tests             - Run comprehensive test suite"
echo "  make run_performance_tests     - Run performance benchmarks"
echo "  make run_security_tests        - Run security validation"
echo "  make run_interop_tests         - Run interoperability tests"
echo ""