#!/bin/bash

# DTLS v1.3 Test Runner Script
# Ensures all tests run from the correct build directory

set -e  # Exit on any error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

echo "DTLS v1.3 Test Runner"
echo "====================="
echo "Project root: $PROJECT_ROOT"
echo "Build directory: $BUILD_DIR"

# Check if build directory exists and has been configured
if [ ! -d "$BUILD_DIR" ] || [ ! -f "$BUILD_DIR/Makefile" ]; then
    echo "Build directory not found or not configured."
    echo "Please run ./build.sh first to configure the build."
    exit 1
fi

# Change to build directory
cd "$BUILD_DIR"

# Parse command line arguments
TEST_TARGET=""
VERBOSE=false
PARALLEL=true
JOBS=$(nproc)

while [[ $# -gt 0 ]]; do
    case $1 in
        all|run_all_tests)
            TEST_TARGET="run_all_tests"
            shift
            ;;
        protocol|run_protocol_tests)
            TEST_TARGET="run_protocol_tests"
            shift
            ;;
        crypto|run_crypto_tests)
            TEST_TARGET="run_crypto_tests"
            shift
            ;;
        connection|run_connection_tests)
            TEST_TARGET="run_connection_tests"
            shift
            ;;
        integration|run_integration_tests)
            TEST_TARGET="run_integration_tests"
            shift
            ;;
        performance|run_performance_tests)
            TEST_TARGET="run_performance_tests"
            shift
            ;;
        security|run_security_tests)
            TEST_TARGET="run_security_tests"
            shift
            ;;
        reliability|run_reliability_tests)
            TEST_TARGET="run_reliability_tests"
            shift
            ;;
        interop|run_interop_tests)
            TEST_TARGET="run_interop_tests"
            shift
            ;;
        benchmarks|run_performance_benchmarks)
            TEST_TARGET="run_performance_benchmarks"
            shift
            ;;
        regression|run_performance_regression)
            TEST_TARGET="run_performance_regression"
            shift
            ;;
        prd|run_prd_validation)
            TEST_TARGET="run_prd_validation"
            shift
            ;;
        single)
            if [ -z "$2" ]; then
                echo "Error: single test requires test name"
                echo "Usage: $0 single <test_name>"
                exit 1
            fi
            TEST_TARGET="$2"
            shift 2
            ;;
        ctest)
            # Direct ctest execution
            shift
            echo "Running CTest directly..."
            ctest --output-on-failure "$@"
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--serial)
            PARALLEL=false
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [test_type] [options]"
            echo ""
            echo "Test Types:"
            echo "  all           Run all tests (default)"
            echo "  protocol      Run protocol unit tests"
            echo "  crypto        Run cryptographic tests"
            echo "  connection    Run connection tests"
            echo "  integration   Run integration tests"
            echo "  performance   Run performance tests"
            echo "  security      Run security validation tests"
            echo "  reliability   Run reliability tests"
            echo "  interop       Run interoperability tests"
            echo "  benchmarks    Run performance benchmarks"
            echo "  regression    Run performance regression tests"
            echo "  prd           Run PRD compliance validation"
            echo "  single <name> Run specific test executable"
            echo "  ctest [args]  Run ctest directly with args"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Verbose test output"
            echo "  -s, --serial     Run tests serially (not parallel)"
            echo "  -j, --jobs N     Use N parallel jobs (default: $(nproc))"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 all              # Run all tests"
            echo "  $0 security         # Run security tests only"
            echo "  $0 single dtls_crypto_test  # Run specific test"
            echo "  $0 ctest -R \"crypto\" -V    # Run crypto tests with ctest"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Default to all tests if no target specified
if [ -z "$TEST_TARGET" ]; then
    TEST_TARGET="run_all_tests"
fi

# Check if the target is a direct test executable
if [ -f "$TEST_TARGET" ]; then
    echo "Running single test: $TEST_TARGET"
    if [ "$VERBOSE" = true ]; then
        "./$TEST_TARGET" --gtest_output=xml:test_results.xml --verbose
    else
        "./$TEST_TARGET"
    fi
    exit 0
fi

# Run the specified test target
echo "Running test target: $TEST_TARGET"

if [ "$VERBOSE" = true ]; then
    if [ "$PARALLEL" = true ]; then
        make "$TEST_TARGET" -j"$JOBS" VERBOSE=1
    else
        make "$TEST_TARGET" VERBOSE=1
    fi
else
    if [ "$PARALLEL" = true ]; then
        make "$TEST_TARGET" -j"$JOBS"
    else
        make "$TEST_TARGET"
    fi
fi

echo ""
echo "Test execution completed!"
echo "Check above output for test results."