#!/bin/bash
# Comprehensive coverage test runner script
# This script runs all available tests to maximize code coverage

set -e

BUILD_DIR="./build"
COVERAGE_DIR="$BUILD_DIR/coverage_reports"

echo "=== DTLS v1.3 Comprehensive Coverage Analysis ==="
echo "Date: $(date)"
echo "Target: >95% code coverage"
echo ""

# Ensure we're in the right directory
if [[ ! -f "CMakeLists.txt" ]]; then
    echo "Error: Must be run from project root directory"
    exit 1
fi

# Clean any existing coverage data
echo "Cleaning previous coverage data..."
cd "$BUILD_DIR"
lcov --directory . --zerocounters >/dev/null 2>&1 || true

# Create coverage reports directory
mkdir -p "$COVERAGE_DIR"

echo "Running comprehensive test suite for maximum coverage..."
echo ""

# Track which tests pass/fail but continue running
declare -a TESTS=()
declare -a TEST_STATUS=()

# Function to run test and track status
run_test() {
    local test_name="$1"
    local test_executable="$2"
    
    echo "Running $test_name..."
    TESTS+=("$test_name")
    
    if timeout 300 "$test_executable" >/dev/null 2>&1; then
        echo "  ✓ $test_name PASSED"
        TEST_STATUS+=("PASS")
    else
        echo "  ✗ $test_name FAILED (continuing for coverage)"
        TEST_STATUS+=("FAIL")
    fi
}

# Run all available tests
echo "=== Core Protocol Tests ==="
run_test "Protocol Tests" "./tests/dtls_protocol_test"
run_test "Core Protocol Tests" "./tests/dtls_core_protocol_test"

echo ""
echo "=== Crypto Tests ==="
run_test "Crypto Tests" "./tests/dtls_crypto_test"

echo ""
echo "=== Connection Tests ==="
run_test "Connection Tests" "./tests/dtls_connection_test"

echo ""
echo "=== Integration Tests ==="
run_test "Integration Tests" "./tests/dtls_integration_test"

echo ""
echo "=== Security Tests ==="
run_test "Security Tests" "./tests/dtls_security_test"

echo ""
echo "=== Performance Tests ==="
run_test "Performance Tests" "./tests/dtls_performance_test"

echo ""
echo "=== Reliability Tests ==="
run_test "Reliability Tests" "./tests/dtls_reliability_test"

echo ""
echo "=== Interoperability Tests ==="
run_test "Interoperability Tests" "./tests/dtls_interop_test"

echo ""
echo "=== Generating Coverage Report ==="

# Capture coverage data
echo "Capturing coverage data..."
lcov --directory . --capture --output-file "$COVERAGE_DIR/full_coverage.info" --ignore-errors mismatch >/dev/null 2>&1

# Filter out unwanted files
echo "Filtering coverage data..."
lcov --remove "$COVERAGE_DIR/full_coverage.info" \
    '/usr/*' \
    '*/tests/*' \
    '*/build/*' \
    '*/googletest/*' \
    '*/googlemock/*' \
    '*/_deps/*' \
    '*/systemc-src/*' \
    --output-file "$COVERAGE_DIR/filtered_coverage.info" \
    --ignore-errors unused >/dev/null 2>&1

# Generate HTML report
echo "Generating HTML coverage report..."
genhtml "$COVERAGE_DIR/filtered_coverage.info" \
    --output-directory "$COVERAGE_DIR/html" \
    --title "DTLS v1.3 Code Coverage Report" \
    --num-spaces 4 \
    --sort \
    --demangle-cpp \
    --function-coverage \
    --branch-coverage \
    --legend >/dev/null 2>&1

# Validate coverage with our script
echo "Validating coverage against 95% target..."
cd ..  # Go back to source root
VALIDATION_RESULT=0
if python3 scripts/validate_coverage.py "$COVERAGE_DIR/filtered_coverage.info" 95; then
    COVERAGE_STATUS="✓ SUCCESS"
else
    COVERAGE_STATUS="✗ NEEDS IMPROVEMENT" 
    VALIDATION_RESULT=1
fi

echo ""
echo "=== COVERAGE ANALYSIS SUMMARY ==="
echo "HTML Report: file://$PWD/$COVERAGE_DIR/html/index.html"
echo "Coverage Data: $COVERAGE_DIR/filtered_coverage.info"
echo ""

echo "Test Execution Summary:"
for i in "${!TESTS[@]}"; do
    status_symbol="✓"
    if [[ "${TEST_STATUS[i]}" == "FAIL" ]]; then
        status_symbol="✗"
    fi
    printf "  %s %s: %s\n" "$status_symbol" "${TESTS[i]}" "${TEST_STATUS[i]}"
done

echo ""
echo "Coverage Status: $COVERAGE_STATUS"
echo ""

if [[ $VALIDATION_RESULT -eq 0 ]]; then
    echo "🎉 CONGRATULATIONS! Code coverage target achieved!"
else
    echo "📊 Coverage analysis complete. Review report for improvement opportunities."
fi

echo ""
echo "Next steps:"
echo "1. Open HTML report: file://$PWD/$COVERAGE_DIR/html/index.html"
echo "2. Review uncovered code areas"
echo "3. Add tests for critical uncovered paths"
echo "4. Re-run this script to validate improvements"

exit $VALIDATION_RESULT