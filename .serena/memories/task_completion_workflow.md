# Task Completion Workflow

## When a Task is Completed

### 1. Code Quality Checks
```bash
# Format code with clang-format
find . -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Run static analysis (if available)
clang-tidy src/**/*.cpp -- -Iinclude
```

### 2. Build Verification
```bash
# Clean build to verify everything compiles
rm -rf build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)
```

### 3. Testing (When Available)
```bash
# Run test suite (currently no tests exist)
ctest --output-on-failure

# Manual testing of crypto providers
./crypto_provider_test  # if available
```

### 4. Documentation Updates
- Update relevant header documentation
- Update implementation workflow if phase completed
- Document any API changes

### 5. Git Workflow
```bash
# Stage changes
git add .

# Commit with descriptive message following existing pattern
git commit -m "Complete [Feature/Phase]: [Description]"

# Example pattern from history:
# "Complete Week X: DTLS v1.3 [Component] Implementation"
```

## Quality Gates
- ✅ Code compiles without warnings
- ✅ Follows clang-format style guide
- ✅ No static analysis violations
- ✅ All tests pass (when test suite exists)
- ✅ Documentation updated
- ✅ Commit message follows project conventions

## Current Limitations
- **No Test Suite**: Tests directory is empty, manual verification required
- **No CI/CD**: Manual quality checks required
- **No Linting**: Manual clang-tidy execution required

## Next Steps for Testing Infrastructure
According to workflow, Phase 5 (Weeks 10-14) will implement comprehensive testing including:
- Unit tests with Google Test
- Integration tests
- Performance benchmarks
- Security validation
- Cross-platform compatibility tests