#!/usr/bin/env python3
"""
DTLS v1.3 Code Coverage Validation Script

This script validates that the project achieves the target code coverage percentage
(>95% as specified in the requirements).

Usage: validate_coverage.py <coverage_info_file> <minimum_coverage_percent>
"""

import sys
import re
import json
import subprocess
from pathlib import Path

def parse_lcov_info(info_file):
    """Parse LCOV info file and extract coverage statistics."""
    if not Path(info_file).exists():
        print(f"Error: Coverage info file not found: {info_file}")
        return None
    
    try:
        # Use lcov to generate summary
        result = subprocess.run(
            ['lcov', '--summary', info_file],
            capture_output=True,
            text=True,
            check=True
        )
        
        summary = result.stdout
        
        # Parse line coverage
        line_match = re.search(r'lines......: (\d+\.\d+)% \((\d+) of (\d+) lines\)', summary)
        function_match = re.search(r'functions..: (\d+\.\d+)% \((\d+) of (\d+) functions\)', summary)
        branch_match = re.search(r'branches...: (\d+\.\d+)% \((\d+) of (\d+) branches\)', summary)
        
        coverage_data = {
            'line_coverage': {
                'percentage': float(line_match.group(1)) if line_match else 0.0,
                'covered': int(line_match.group(2)) if line_match else 0,
                'total': int(line_match.group(3)) if line_match else 0,
            },
            'function_coverage': {
                'percentage': float(function_match.group(1)) if function_match else 0.0,
                'covered': int(function_match.group(2)) if function_match else 0,
                'total': int(function_match.group(3)) if function_match else 0,
            },
            'branch_coverage': {
                'percentage': float(branch_match.group(1)) if branch_match else 0.0,
                'covered': int(branch_match.group(2)) if branch_match else 0,
                'total': int(branch_match.group(3)) if branch_match else 0,
            }
        }
        
        return coverage_data
        
    except subprocess.CalledProcessError as e:
        print(f"Error running lcov: {e}")
        return None

def validate_coverage(coverage_data, minimum_percent):
    """Validate that coverage meets the minimum threshold."""
    if not coverage_data:
        return False, "No coverage data available"
    
    line_coverage = coverage_data['line_coverage']['percentage']
    function_coverage = coverage_data['function_coverage']['percentage']
    branch_coverage = coverage_data['branch_coverage']['percentage']
    
    # Calculate overall coverage (weighted average)
    # Line coverage is most important, function and branch are secondary
    overall_coverage = (line_coverage * 0.6 + 
                       function_coverage * 0.25 + 
                       branch_coverage * 0.15)
    
    print("=" * 60)
    print("DTLS v1.3 Code Coverage Report")
    print("=" * 60)
    print(f"Line Coverage:     {line_coverage:6.2f}% ({coverage_data['line_coverage']['covered']}/{coverage_data['line_coverage']['total']})")
    print(f"Function Coverage: {function_coverage:6.2f}% ({coverage_data['function_coverage']['covered']}/{coverage_data['function_coverage']['total']})")
    print(f"Branch Coverage:   {branch_coverage:6.2f}% ({coverage_data['branch_coverage']['covered']}/{coverage_data['branch_coverage']['total']})")
    print(f"Overall Coverage:  {overall_coverage:6.2f}%")
    print(f"Target Coverage:   {minimum_percent:6.2f}%")
    print("=" * 60)
    
    # Check if each metric meets the minimum
    line_pass = line_coverage >= minimum_percent
    function_pass = function_coverage >= minimum_percent * 0.9  # Allow 10% tolerance for functions
    branch_pass = branch_coverage >= minimum_percent * 0.8     # Allow 20% tolerance for branches
    overall_pass = overall_coverage >= minimum_percent
    
    print("Coverage Status:")
    print(f"  Line Coverage:     {'PASS' if line_pass else 'FAIL'}")
    print(f"  Function Coverage: {'PASS' if function_pass else 'FAIL'}")
    print(f"  Branch Coverage:   {'PASS' if branch_pass else 'FAIL'}")
    print(f"  Overall Coverage:  {'PASS' if overall_pass else 'FAIL'}")
    print("=" * 60)
    
    if overall_pass and line_pass:
        print("✅ SUCCESS: Code coverage target achieved!")
        return True, "Coverage target met"
    else:
        print("❌ FAILURE: Code coverage below target!")
        gaps = []
        if not line_pass:
            gap = minimum_percent - line_coverage
            gaps.append(f"Line coverage needs {gap:.2f}% improvement")
        if not overall_pass:
            gap = minimum_percent - overall_coverage
            gaps.append(f"Overall coverage needs {gap:.2f}% improvement")
        
        return False, "; ".join(gaps)

def generate_coverage_suggestions(coverage_data, info_file):
    """Generate suggestions for improving coverage."""
    print("\nCoverage Improvement Suggestions:")
    print("-" * 40)
    
    # Extract file-level coverage from lcov info
    try:
        with open(info_file, 'r') as f:
            content = f.read()
        
        # Find files with low coverage
        files = re.findall(r'SF:(.+)', content)
        line_data = re.findall(r'LH:(\d+)', content)
        line_found = re.findall(r'LF:(\d+)', content)
        
        low_coverage_files = []
        for i, file_path in enumerate(files):
            if i < len(line_data) and i < len(line_found):
                covered = int(line_data[i])
                total = int(line_found[i])
                if total > 0:
                    coverage = (covered / total) * 100
                    if coverage < 90:  # Files with <90% coverage
                        low_coverage_files.append((file_path, coverage, covered, total))
        
        if low_coverage_files:
            print("Files needing attention (< 90% line coverage):")
            for file_path, coverage, covered, total in sorted(low_coverage_files, key=lambda x: x[1]):
                relative_path = file_path.split('DTLSv1p3/')[-1] if 'DTLSv1p3/' in file_path else file_path
                print(f"  {relative_path}: {coverage:5.1f}% ({covered}/{total})")
        else:
            print("All files have good coverage (>90%)")
            
    except Exception as e:
        print(f"Could not analyze file-level coverage: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: validate_coverage.py <coverage_info_file> <minimum_coverage_percent>")
        print("Example: validate_coverage.py coverage.info 95")
        sys.exit(1)
    
    info_file = sys.argv[1]
    try:
        minimum_percent = float(sys.argv[2])
    except ValueError:
        print("Error: Minimum coverage percent must be a number")
        sys.exit(1)
    
    # Parse coverage data
    coverage_data = parse_lcov_info(info_file)
    if not coverage_data:
        print("Failed to parse coverage data")
        sys.exit(1)
    
    # Validate coverage
    success, message = validate_coverage(coverage_data, minimum_percent)
    
    # Generate suggestions if coverage is insufficient
    if not success:
        generate_coverage_suggestions(coverage_data, info_file)
    
    # Save coverage report as JSON
    report_file = Path(info_file).parent / "coverage_report.json"
    with open(report_file, 'w') as f:
        json.dump({
            'coverage_data': coverage_data,
            'minimum_percent': minimum_percent,
            'success': success,
            'message': message
        }, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()