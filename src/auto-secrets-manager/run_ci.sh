#!/bin/bash
set -e

# Auto Secrets Manager - Comprehensive Test Runner and Validation Script
# This script runs all tests, validates installation, and checks code quality

echo "🧪 Auto Secrets Manager - Test Runner & Validation"
echo "=================================================="

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
SRC_DIR="$ROOT_DIR/src"
REPORTS_DIR="$ROOT_DIR/.test_reports"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
RUN_UNIT_TESTS=true
RUN_INTEGRATION_TESTS=false
RUN_SHELL_TESTS=true
RUN_LINT_CHECKS=true
RUN_TYPE_CHECKS=true
RUN_SECURITY_CHECKS=true
GENERATE_COVERAGE=true
VERBOSE=false
CI_MODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
  --unit-only)
    RUN_INTEGRATION_TESTS=false
    RUN_SHELL_TESTS=false
    shift
    ;;
  --no-lint)
    RUN_LINT_CHECKS=false
    shift
    ;;
  --no-coverage)
    GENERATE_COVERAGE=false
    shift
    ;;
  --verbose | -v)
    VERBOSE=true
    shift
    ;;
  --ci)
    CI_MODE=true
    VERBOSE=true
    shift
    ;;
  --help | -h)
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --unit-only     Run only unit tests (skip integration and shell tests)"
    echo "  --no-lint       Skip linting and code quality checks"
    echo "  --no-coverage   Skip coverage report generation"
    echo "  --verbose, -v   Enable verbose output"
    echo "  --ci            Enable CI mode (verbose + strict)"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all tests and checks"
    echo "  $0 --unit-only       # Run only unit tests"
    echo "  $0 --ci              # Run in CI mode"
    exit 0
    ;;
  *)
    echo "❌ Unknown option: $1"
    echo "Use --help for usage information"
    exit 1
    ;;
  esac
done

# Utility functions
print_step() {
  echo -e "\n${BLUE}📋 $1${NC}"
}

print_success() {
  echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
  echo -e "${RED}❌ $1${NC}"
}

print_info() {
  if [[ "$VERBOSE" == "true" ]]; then
    echo -e "${BLUE}ℹ️  $1${NC}"
  fi
}

# Check if command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Initialize test environment
initialize_environment() {
  print_step "Initializing test environment"

  # Create reports directory
  mkdir -p "$REPORTS_DIR"

  # Set up Python environment
  cd "$ROOT_DIR"

  # Check Python version
  if ! command_exists python3; then
    print_error "Python 3 is required but not found"
    exit 1
  fi

  python_version=$(python3 --version | cut -d' ' -f2)
  print_info "Python version: $python_version"

  # Check if we're in a virtual environment (recommended)
  if [[ -z "$VIRTUAL_ENV" ]] && [[ "$CI_MODE" == "false" ]]; then
    print_warning "Not running in virtual environment. Consider using 'python3 -m venv venv && source venv/bin/activate'"
  fi

  # Install/upgrade pip and dependencies
  print_info "Installing Python dependencies..."
  cd "$SRC_DIR"

  if [[ "$CI_MODE" == "true" ]]; then
    pip3 install --quiet --upgrade pip
    # CI: Test the actual installation users will get if its working
    pip3 install .
    # Verify installation
    if ! python3 -c "import auto_secrets" 2>/dev/null; then
      print_error "Failed to import auto_secrets package - non editable build"
      exit 1
    fi
    # Then delete build directory
    rm -rf "$SRC_DIR/build" "$SRC_DIR/auto_secrets_manager.egg-info"
  fi

  # Development: Use editable with dev dependencies
  pip3 install --upgrade pip
  pip3 install -e ".[dev]"

  # Verify installation
  if ! python3 -c "import auto_secrets" 2>/dev/null; then
    print_error "Failed to import auto_secrets package - editable build"
    exit 1
  fi

  print_success "Environment initialized"
}

# Run Python unit tests
run_unit_tests() {
  if [[ "$RUN_UNIT_TESTS" != "true" ]]; then
    print_info "Skipping unit tests"
    return 0
  fi

  print_step "Running Python unit tests"

  cd "$SRC_DIR"

  # Prepare pytest arguments
  pytest_args=(
    "--tb=short"
    "--strict-markers"
    "--disable-warnings"
    "-m" "not (integration or shell or network)"
  )

  if [[ "$VERBOSE" == "true" ]]; then
    pytest_args+=("--verbose")
  else
    pytest_args+=("--quiet")
  fi

  if [[ "$GENERATE_COVERAGE" == "true" ]]; then
    pytest_args+=(
      "--cov=auto_secrets"
      "--cov-report=term-missing"
      "--cov-report=html:../.test_reports/htmlcov"
      "--cov-report=xml:../.test_reports/coverage.xml"
      "--cov-branch"
    )

    if [[ "$CI_MODE" == "true" ]]; then
      pytest_args+=("--cov-fail-under=70") # Relaxed for CI
    fi
  fi

  # Add JUnit XML for CI
  if [[ "$CI_MODE" == "true" ]]; then
    pytest_args+=("--junitxml=../.test_reports/junit.xml")
  fi

  # Run tests
  if pytest "${pytest_args[@]}" tests/; then
    print_success "Unit tests passed"
    return 0
  else
    print_error "Unit tests failed"
    return 1
  fi
}

# Run integration tests
run_integration_tests() {
  if [[ "$RUN_INTEGRATION_TESTS" != "true" ]]; then
    print_info "Skipping integration tests"
    return 0
  fi

  print_step "Running integration tests"

  cd "$SRC_DIR"

  # Set up test environment variables
  export AUTO_SECRETS_DEBUG=true
  export AUTO_SECRETS_CACHE_DIR="/tmp/auto-secrets-test-$$"
  export AUTO_SECRETS_LOG_LEVEL=DEBUG

  # Prepare pytest arguments for integration tests
  pytest_args=(
    "--tb=short"
    "--strict-markers"
    "-m" "integration"
  )

  if [[ "$VERBOSE" == "true" ]]; then
    pytest_args+=("--verbose")
  else
    pytest_args+=("--quiet")
  fi

  # Run integration tests
  if pytest "${pytest_args[@]}" tests/; then
    print_success "Integration tests passed"
    return 0
  else
    print_error "Integration tests failed"
    return 1
  fi
}

# Test shell integration
test_shell_integration() {
  if [[ "$RUN_SHELL_TESTS" != "true" ]]; then
    print_info "Skipping shell integration tests"
    return 0
  fi

  print_step "Testing shell integration"

  local errors=0

  # Test shell script syntax
  print_info "Checking shell script syntax..."

  for script in "$SRC_DIR"/shell/*.sh; do
    if [[ -f "$script" ]]; then
      if bash -n "$script"; then
        print_info "✓ $(basename "$script") - syntax OK"
      else
        print_error "✗ $(basename "$script") - syntax error"
        ((errors++))
      fi
    fi
  done

  # Test that shell scripts can be sourced
  print_info "Testing shell script sourcing..."

  # Create temporary test environment
  temp_dir=$(mktemp -d)
  export AUTO_SECRETS_FEATURE_DIR="$SRC_DIR/shell"
  export AUTO_SECRETS_ENABLE=false # Disable actual functionality for testing

  # Test bash integration
  if [[ -f "$SRC_DIR/shell/bash-integration.sh" ]]; then
    if (
      cd "$temp_dir"
      # shellcheck disable=SC2030
      export SHELL=bash
      # shellcheck disable=SC1091
      source "$SRC_DIR/shell/bash-integration.sh" 2>/dev/null
    ); then
      print_info "✓ Bash integration loads successfully"
    else
      print_error "✗ Bash integration failed to load"
      ((errors++))
    fi
  fi

  # Test zsh integration (if zsh is available)
  if command_exists zsh && [[ -f "$SRC_DIR/shell/zsh-integration.sh" ]]; then
    if (
      cd "$temp_dir"
      # shellcheck disable=SC2031
      export SHELL=zsh
      # shellcheck disable=SC1091
      zsh -c "source '$SRC_DIR/shell/zsh-integration.sh'" 2>/dev/null
    ); then
      print_info "✓ Zsh integration loads successfully"
    else
      print_error "✗ Zsh integration failed to load"
      ((errors++))
    fi
  fi

  # Test branch detection script
  if [[ -f "$SRC_DIR/shell/branch-detection.sh" ]]; then
    if (
      cd "$temp_dir"
      # shellcheck disable=SC1091
      source "$SRC_DIR/shell/branch-detection.sh"
      # Test that key functions are defined
      type _auto_secrets_check_branch_change >/dev/null 2>&1
    ); then
      print_info "✓ Branch detection script loads successfully"
    else
      print_error "✗ Branch detection script failed to load"
      ((errors++))
    fi
  fi

  # Cleanup
  rm -rf "$temp_dir"

  if [[ $errors -eq 0 ]]; then
    print_success "Shell integration tests passed"
    return 0
  else
    print_error "Shell integration tests failed ($errors errors)"
    return 1
  fi
}

# Run linting and code quality checks
run_lint_checks() {
  if [[ "$RUN_LINT_CHECKS" != "true" ]]; then
    print_info "Skipping lint checks"
    return 0
  fi

  print_step "Running code quality checks"

  cd "$SRC_DIR"
  local errors=0

  # Use Ruff for Python linting and formatting
  if command_exists ruff; then
    print_info "Running Ruff linting..."
    if ruff check . 2>/dev/null; then
      print_info "✓ Ruff linting passed"
    else
      print_warning "✗ Ruff linting issues found (run 'ruff check --fix .' to fix)"
      ((errors++))
    fi

    print_info "Checking Python code formatting with Ruff..."
    if ruff format --check . 2>/dev/null; then
      print_info "✓ Ruff formatting check passed"
    else
      print_warning "✗ Code formatting issues found (run 'ruff format .' to fix)"
      ((errors++))
    fi
  else
    print_warning "ruff not found, skipping Python linting and formatting"
  fi

  # Shell script linting (shellcheck)
  if command_exists shellcheck; then
    print_info "Running shellcheck on shell scripts..."
    local shell_errors=0

    for script in "$ROOT_DIR"/src/shell/*.sh "$ROOT_DIR"/*.sh; do
      if [[ -f "$script" ]]; then
        if shellcheck "$script" 2>/dev/null; then
          print_info "✓ $(basename "$script") - shellcheck passed"
        else
          print_warning "✗ $(basename "$script") - shellcheck issues found"
          ((shell_errors++))
        fi
      fi
    done

    if [[ $shell_errors -eq 0 ]]; then
      print_info "✓ All shell scripts passed shellcheck"
    else
      print_warning "✗ $shell_errors shell script(s) have shellcheck issues"
      ((errors++))
    fi
  else
    print_warning "shellcheck not found, skipping shell script linting"
  fi

  if [[ $errors -eq 0 ]]; then
    print_success "Code quality checks passed"
    return 0
  else
    print_warning "Code quality checks completed with $errors issues"
    return 0 # Don't fail on linting issues, just warn
  fi
}

# Run type checking
run_type_checks() {
  if [[ "$RUN_TYPE_CHECKS" != "true" ]]; then
    print_info "Skipping type checks"
    return 0
  fi

  print_step "Running type checking"

  cd "$SRC_DIR"

  if command_exists mypy; then
    print_info "Running mypy type checking..."
    if mypy . 2>/dev/null; then
      print_success "Type checking passed"
      return 0
    else
      print_warning "Type checking issues found"
      return 0 # Don't fail on type issues, just warn
    fi
  else
    print_warning "mypy not found, skipping type checking"
    return 0
  fi
}

# Run security checks
run_security_checks() {
  if [[ "$RUN_SECURITY_CHECKS" != "true" ]]; then
    print_info "Skipping security checks"
    return 0
  fi

  print_step "Running security checks"

  cd "$SRC_DIR"

  # Basic security checks
  print_info "Checking for common security issues..."

  local issues=0

  # Check for hardcoded secrets or tokens (excluding tests directory)
  if grep -r -i -E "(password|secret|token|key)\s*=\s*['\"][^'\"]{8,}" . --exclude-dir=__pycache__ --exclude-dir=tests 2>/dev/null; then
    print_warning "Potential hardcoded secrets found"
    ((issues++))
  fi

  # Check for SQL injection patterns (excluding tests directory)
  if grep -r -i -E "execute\s*\(\s*['\"].*%.*['\"]" . --exclude-dir=__pycache__ --exclude-dir=tests 2>/dev/null; then
    print_warning "Potential SQL injection vulnerability found"
    ((issues++))
  fi

  # Check file permissions in created files (excluding tests directory)
  if grep -r -E "chmod\s+[0-9]{3}" . --exclude-dir=__pycache__ --exclude-dir=tests 2>/dev/null | grep -v "0o600\|0o700"; then
    print_warning "Potentially insecure file permissions found"
    ((issues++))
  fi

  if [[ $issues -eq 0 ]]; then
    print_success "Security checks passed"
    return 0
  else
    print_warning "Security checks completed with $issues potential issues"
    return 0 # Don't fail on security warnings, just warn
  fi
}

# Validate installation
validate_installation() {
  print_step "Validating installation"

  cd "$SRC_DIR"
  local errors=0

  # Test Python package import
  print_info "Testing Python package import..."
  if python3 -c "import auto_secrets; print('✓ Package import successful')" 2>/dev/null; then
    print_info "✓ Python package import successful"
  else
    print_error "✗ Python package import failed"
    ((errors++))
  fi

  # Test CLI command
  print_info "Testing CLI command..."
  if python3 -m auto_secrets.cli --help >/dev/null 2>&1; then
    print_info "✓ CLI command working"
  else
    print_error "✗ CLI command failed"
    ((errors++))
  fi

  # Test configuration loading
  print_info "Testing configuration loading..."
  export AUTO_SECRETS_SECRET_MANAGER=infisical
  export AUTO_SECRETS_SHELLS=both
  export AUTO_SECRETS_BRANCH_MAPPINGS='{"main":"production","default":"development"}'
  export AUTO_SECRETS_CACHE_DIR="/dev/shm/auto-secrets"
  export AUTO_SECRETS_LOG_DIR="/var/log/auto-secrets"
  export AUTO_SECRETS_LOG_LEVEL="INFO"
  export AUTO_SECRETS_CACHE_CONFIG='{"refresh_interval":"15m","cleanup_interval":"7d"}'
  export AUTO_SECRETS_FEATURE_DIR="/usr/local/share/auto-secrets"
  export AUTO_SECRETS_ALL_SM_PATHS='["/"]'

  # Test import core modules
  local modules=("common_utils" "crypto_utils" "key_retriever" "process_utils" "singleton")
  for module in "${modules[@]}"; do
    if python3 -c "from auto_secrets.core import $module; print('✓ Module $module import successful')" 2>/dev/null; then
      print_info "✓ Module $module import successful"
    else
      print_error "✗ Module $module import failed"
      ((errors++))
    fi
  done

  # Test import managers modules
  local modules=("app_manager" "branch_manager" "cache_manager" "common_config" "log_manager")
  for module in "${modules[@]}"; do
    if python3 -c "from auto_secrets.managers import $module; print('✓ Module $module import successful')" 2>/dev/null; then
      print_info "✓ Module $module import successful"
    else
      print_error "✗ Module $module import failed"
      ((errors++))
    fi
  done

  # Test import SM modules
  local modules=("base" "factory" "infisical")
  for module in "${modules[@]}"; do
    if python3 -c "from auto_secrets.secret_managers import $module; print('✓ Module $module import successful')" 2>/dev/null; then
      print_info "✓ Module $module import successful"
    else
      print_error "✗ Module $module import failed"
      ((errors++))
    fi
  done

  if [[ $errors -eq 0 ]]; then
    print_success "Installation validation passed"
    return 0
  else
    print_error "Installation validation failed ($errors errors)"
    return 1
  fi
}

# Generate test report
generate_report() {
  print_step "Generating test report"

  local report_file="$REPORTS_DIR/test_report.txt"

  cat >"$report_file" <<EOF
Auto Secrets Manager - Test Report
==================================
Generated: $(date)
Environment: $(uname -a)
Python: $(python3 --version)

Test Configuration:
- Unit Tests: $RUN_UNIT_TESTS
- Integration Tests: $RUN_INTEGRATION_TESTS
- Shell Tests: $RUN_SHELL_TESTS
- Lint Checks: $RUN_LINT_CHECKS
- Type Checks: $RUN_TYPE_CHECKS
- Security Checks: $RUN_SECURITY_CHECKS
- Coverage: $GENERATE_COVERAGE
- CI Mode: $CI_MODE

Reports Generated:
EOF

  if [[ -f "$REPORTS_DIR/coverage.xml" ]]; then
    echo "- Coverage XML: $REPORTS_DIR/coverage.xml" >>"$report_file"
  fi

  if [[ -d "$REPORTS_DIR/htmlcov" ]]; then
    echo "- Coverage HTML: $REPORTS_DIR/htmlcov/index.html" >>"$report_file"
  fi

  if [[ -f "$REPORTS_DIR/junit.xml" ]]; then
    echo "- JUnit XML: $REPORTS_DIR/junit.xml" >>"$report_file"
  fi

  print_success "Test report generated: $report_file"
}

# Main execution
main() {
  local exit_code=0
  local start_time
  start_time=$(date +%s)

  echo "Starting test run at $(date)"
  echo ""

  # Initialize
  if ! initialize_environment; then
    exit_code=1
  fi

  # Run validation first
  if ! validate_installation; then
    exit_code=1
  fi

  # Run tests
  if ! run_unit_tests; then
    exit_code=1
  fi

  if ! run_integration_tests; then
    exit_code=1
  fi

  if ! test_shell_integration; then
    exit_code=1
  fi

  # Run quality checks (don't fail on these)
  run_lint_checks
  run_type_checks
  run_security_checks

  # Generate reports
  generate_report

  # Summary
  local end_time
  end_time=$(date +%s)
  local duration
  duration=$((end_time - start_time))

  echo ""
  echo "=================================================="

  if [[ $exit_code -eq 0 ]]; then
    print_success "All tests passed! 🎉"
    echo -e "${GREEN}Test run completed successfully in ${duration}s${NC}"

    if [[ -d "$REPORTS_DIR/htmlcov" ]]; then
      echo -e "${BLUE}📊 Coverage report: file://$REPORTS_DIR/htmlcov/index.html${NC}"
    fi
  else
    print_error "Some tests failed! 💥"
    echo -e "${RED}Test run completed with failures in ${duration}s${NC}"

    if [[ "$CI_MODE" == "true" ]]; then
      echo ""
      echo "Check the logs above for detailed error information."
      echo "In CI mode, any test failure will cause the build to fail."
    fi
  fi

  echo -e "${BLUE}📁 Reports directory: $REPORTS_DIR${NC}"
  echo ""

  exit $exit_code
}

# Run main function
main "$@"
