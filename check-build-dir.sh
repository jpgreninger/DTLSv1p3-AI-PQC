#!/bin/bash

# DTLS v1.3 Build Directory Verification Script
# Prevents in-source builds and enforces out-of-source builds in ~/Work/DTLSv1p3/build

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
CURRENT_DIR="$(pwd)"

echo "DTLS v1.3 Build Directory Check"
echo "==============================="
echo "Project root: $PROJECT_ROOT"
echo "Required build directory: $BUILD_DIR"
echo "Current directory: $CURRENT_DIR"

# Check if we're in the project root
if [ "$CURRENT_DIR" = "$PROJECT_ROOT" ]; then
    echo ""
    echo "❌ ERROR: You are trying to build in the source directory!"
    echo ""
    echo "This project requires out-of-source builds to prevent conflicts."
    echo ""
    echo "Please use one of these approaches:"
    echo ""
    echo "1. Use the build script (RECOMMENDED):"
    echo "   ./build.sh"
    echo ""
    echo "2. Manual out-of-source build:"
    echo "   mkdir -p build && cd build"
    echo "   cmake .. -DCMAKE_BUILD_TYPE=Release"
    echo "   make -j$(nproc)"
    echo ""
    echo "3. Run tests with the test script:"
    echo "   ./test.sh"
    echo ""
    exit 1
fi

# Check if we're in the correct build directory
if [ "$CURRENT_DIR" = "$BUILD_DIR" ]; then
    echo ""
    echo "✅ BUILD DIRECTORY CORRECT"
    echo "You are in the correct build directory."
    echo ""
    exit 0
fi

# Check if we're in a subdirectory of the build directory
if [[ "$CURRENT_DIR" == "$BUILD_DIR"* ]]; then
    echo ""
    echo "✅ BUILD SUBDIRECTORY CORRECT"
    echo "You are in a subdirectory of the build directory."
    echo ""
    exit 0
fi

# Check if build directory exists and is configured
if [ ! -d "$BUILD_DIR" ] || [ ! -f "$BUILD_DIR/Makefile" ]; then
    echo ""
    echo "⚠️  WARNING: Build directory not found or not configured."
    echo ""
    echo "Please run the build script to configure the build:"
    echo "   ./build.sh"
    echo ""
    exit 1
fi

# We're somewhere else
echo ""
echo "⚠️  WARNING: You are not in the recommended build directory."
echo ""
echo "For consistent builds, please change to the build directory:"
echo "   cd $BUILD_DIR"
echo ""
echo "Or use the provided scripts:"
echo "   ./build.sh    # To build"
echo "   ./test.sh     # To run tests"
echo ""
exit 1