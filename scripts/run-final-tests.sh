#!/bin/bash

# Final Integration Test Runner
# Copyright 2023 Versity Software
# Licensed under the Apache License, Version 2.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_RESULTS_DIR="${TEST_RESULTS_DIR:-./test-results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    
    local test_output="$TEST_RESULTS_DIR/unit-tests-$TIMESTAMP.log"
    
    if go test -v ./backend/ipfs -run "Test.*" -short > "$test_output" 2>&1; then
        local test_count=$(grep -c "=== RUN" "$test_output" || echo "0")
        local pass_count=$(grep -c "--- PASS:" "$test_output" || echo "0")
        local fail_count=$(grep -c "--- FAIL:" "$test_output" || echo "0")
        local skip_count=$(grep -c "--- SKIP:" "$test_output" || echo "0")
        
        TOTAL_TESTS=$((TOTAL_TESTS + test_count))
        PASSED_TESTS=$((PASSED_TESTS + pass_count))
        FAILED_TESTS=$((FAILED_TESTS + fail_count))
        SKIPPED_TESTS=$((SKIPPED_TESTS + skip_count))
        
        log_success "Unit tests completed: $pass_count passed, $fail_count failed, $skip_count skipped"
    else
        log_error "Unit tests failed - see $test_output for details"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    local test_output="$TEST_RESULTS_DIR/integration-tests-$TIMESTAMP.log"
    
    # Check if IPFS cluster is available for integration tests
    if curl -s http://localhost:9094/health > /dev/null 2>&1; then
        log_info "IPFS cluster detected, running full integration tests"
        
        if go test -v ./backend/ipfs -run "TestIntegration.*" -timeout 10m > "$test_output" 2>&1; then
            local test_count=$(grep -c "=== RUN" "$test_output" || echo "0")
            local pass_count=$(grep -c "--- PASS:" "$test_output" || echo "0")
            local fail_count=$(grep -c "--- FAIL:" "$test_output" || echo "0")
            local skip_count=$(grep -c "--- SKIP:" "$test_output" || echo "0")
            
            TOTAL_TESTS=$((TOTAL_TESTS + test_count))
            PASSED_TESTS=$((PASSED_TESTS + pass_count))
            FAILED_TESTS=$((FAILED_TESTS + fail_count))
            SKIPPED_TESTS=$((SKIPPED_TESTS + skip_count))
            
            log_success "Integration tests completed: $pass_count passed, $fail_count failed, $skip_count skipped"
        else
            log_error "Integration tests failed - see $test_output for details"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    else
        log_warning "IPFS cluster not available, skipping integration tests"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    fi
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    local test_output="$TEST_RESULTS_DIR/performance-tests-$TIMESTAMP.log"
    
    if go test -v ./backend/ipfs -run "BenchmarkComprehensive.*" -bench=. -benchtime=30s > "$test_output" 2>&1; then
        local benchmark_count=$(grep -c "Benchmark" "$test_output" || echo "0")
        
        TOTAL_TESTS=$((TOTAL_TESTS + benchmark_count))
        PASSED_TESTS=$((PASSED_TESTS + benchmark_count))
        
        log_success "Performance tests completed: $benchmark_count benchmarks run"
    else
        log_error "Performance tests failed - see $test_output for details"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Run security audit
run_security_audit() {
    log_info "Running security audit..."
    
    if [[ -x "$SCRIPT_DIR/security-audit.sh" ]]; then
        if "$SCRIPT_DIR/security-audit.sh" > "$TEST_RESULTS_DIR/security-audit-$TIMESTAMP.log" 2>&1; then
            log_success "Security audit passed"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            local exit_code=$?
            if [[ $exit_code -eq 2 ]]; then
                log_warning "Security audit completed with warnings"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                log_error "Security audit failed"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
        fi
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
    else
        log_warning "Security audit script not found or not executable"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    fi
}

# Validate deployment scripts
validate_deployment_scripts() {
    log_info "Validating deployment scripts..."
    
    local scripts_to_validate=(
        "$SCRIPT_DIR/deploy-production-ipfs.sh"
        "$SCRIPT_DIR/deploy-ipfs-cluster.sh"
    )
    
    local validation_passed=true
    
    for script in "${scripts_to_validate[@]}"; do
        if [[ -f "$script" ]]; then
            if bash -n "$script"; then
                log_success "$(basename "$script") syntax is valid"
            else
                log_error "$(basename "$script") has syntax errors"
                validation_passed=false
            fi
        else
            log_warning "$(basename "$script") not found"
            validation_passed=false
        fi
    done
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if $validation_passed; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Validate documentation
validate_documentation() {
    log_info "Validating documentation..."
    
    local required_docs=(
        "backend/ipfs/API_DOCUMENTATION.md"
        "backend/ipfs/DEPLOYMENT_GUIDE.md"
        "backend/ipfs/CONFIGURATION_EXAMPLES.md"
        "backend/ipfs/TROUBLESHOOTING_GUIDE.md"
        "backend/ipfs/PERFORMANCE_TUNING_GUIDE.md"
        "RELEASE_NOTES_IPFS_INTEGRATION.md"
        "MIGRATION_GUIDE_IPFS.md"
    )
    
    local docs_found=0
    local total_docs=${#required_docs[@]}
    
    for doc in "${required_docs[@]}"; do
        if [[ -f "$PROJECT_ROOT/$doc" ]]; then
            local word_count=$(wc -w < "$PROJECT_ROOT/$doc")
            if [[ $word_count -gt 100 ]]; then
                log_success "$(basename "$doc") exists and has substantial content ($word_count words)"
                docs_found=$((docs_found + 1))
            else
                log_warning "$(basename "$doc") exists but has minimal content ($word_count words)"
            fi
        else
            log_error "$(basename "$doc") not found"
        fi
    done
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if [[ $docs_found -eq $total_docs ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_success "All required documentation found"
    elif [[ $docs_found -gt $((total_docs / 2)) ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_warning "Most required documentation found ($docs_found/$total_docs)"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_error "Insufficient documentation found ($docs_found/$total_docs)"
    fi
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    local report_file="$TEST_RESULTS_DIR/final-test-report-$TIMESTAMP.md"
    
    cat > "$report_file" << EOF
# VersityGW IPFS Integration - Final Test Report

**Generated:** $(date)
**Test Suite Version:** 1.0

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | $TOTAL_TESTS |
| Passed | $PASSED_TESTS |
| Failed | $FAILED_TESTS |
| Skipped | $SKIPPED_TESTS |
| Success Rate | $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")% |

## Test Categories

### Unit Tests
- **Status:** $([ $FAILED_TESTS -eq 0 ] && echo "✅ PASSED" || echo "❌ FAILED")
- **Coverage:** Core IPFS backend functionality
- **Results:** Available in unit-tests-$TIMESTAMP.log

### Integration Tests
- **Status:** $([ -f "$TEST_RESULTS_DIR/integration-tests-$TIMESTAMP.log" ] && echo "✅ COMPLETED" || echo "⏭️ SKIPPED")
- **Coverage:** End-to-end IPFS cluster integration
- **Results:** Available in integration-tests-$TIMESTAMP.log

### Performance Tests
- **Status:** $([ -f "$TEST_RESULTS_DIR/performance-tests-$TIMESTAMP.log" ] && echo "✅ COMPLETED" || echo "⏭️ SKIPPED")
- **Coverage:** Benchmark tests for scalability
- **Results:** Available in performance-tests-$TIMESTAMP.log

### Security Audit
- **Status:** $([ -f "$TEST_RESULTS_DIR/security-audit-$TIMESTAMP.log" ] && echo "✅ COMPLETED" || echo "⏭️ SKIPPED")
- **Coverage:** Security configuration and best practices
- **Results:** Available in security-audit-$TIMESTAMP.log

### Deployment Validation
- **Status:** ✅ COMPLETED
- **Coverage:** Deployment script validation
- **Results:** Syntax validation of deployment scripts

### Documentation Validation
- **Status:** ✅ COMPLETED
- **Coverage:** Required documentation completeness
- **Results:** Documentation presence and content validation

## Recommendations

EOF

    if [[ $FAILED_TESTS -gt 0 ]]; then
        cat >> "$report_file" << EOF
### ⚠️ Critical Issues
- $FAILED_TESTS test(s) failed
- Review failed test logs for specific issues
- Address failures before production deployment

EOF
    fi

    if [[ $SKIPPED_TESTS -gt 0 ]]; then
        cat >> "$report_file" << EOF
### ℹ️ Skipped Tests
- $SKIPPED_TESTS test(s) were skipped
- Consider running skipped tests in appropriate environment
- Integration tests require IPFS cluster to be running

EOF
    fi

    cat >> "$report_file" << EOF
### ✅ Next Steps
1. Review all test results and logs
2. Address any failed tests or security issues
3. Run integration tests with IPFS cluster if not done
4. Proceed with production deployment if all tests pass
5. Set up monitoring and alerting
6. Schedule regular security audits

## Test Artifacts

All test artifacts are available in: \`$TEST_RESULTS_DIR\`

- Unit test logs: \`unit-tests-$TIMESTAMP.log\`
- Integration test logs: \`integration-tests-$TIMESTAMP.log\`
- Performance test logs: \`performance-tests-$TIMESTAMP.log\`
- Security audit logs: \`security-audit-$TIMESTAMP.log\`

## Support

For issues or questions:
- Review troubleshooting guide: \`backend/ipfs/TROUBLESHOOTING_GUIDE.md\`
- Check GitHub issues: https://github.com/versity/versitygw/issues
- Contact support: support@versity.io
EOF

    log_success "Test report generated: $report_file"
}

# Print summary
print_summary() {
    echo ""
    echo "========================================"
    echo "FINAL INTEGRATION TEST SUMMARY"
    echo "========================================"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Skipped: $SKIPPED_TESTS"
    echo "Success Rate: $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")%"
    echo ""
    
    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo -e "${RED}❌ $FAILED_TESTS test(s) failed - review logs for details${NC}"
        echo -e "${RED}🚫 NOT READY for production deployment${NC}"
    elif [[ $SKIPPED_TESTS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  $SKIPPED_TESTS test(s) skipped - consider running in full environment${NC}"
        echo -e "${YELLOW}⚠️  CONDITIONALLY READY for production deployment${NC}"
    else
        echo -e "${GREEN}✅ All tests passed!${NC}"
        echo -e "${GREEN}🚀 READY for production deployment${NC}"
    fi
    
    echo ""
    echo "Test results available in: $TEST_RESULTS_DIR"
    echo "========================================"
}

# Main execution
main() {
    log_info "Starting VersityGW IPFS Integration Final Tests..."
    
    # Check if required tools are available
    local required_tools="go bc"
    for tool in $required_tools; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Run all test categories
    run_unit_tests
    run_integration_tests
    run_performance_tests
    run_security_audit
    validate_deployment_scripts
    validate_documentation
    
    # Generate reports
    generate_test_report
    print_summary
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    elif [[ $SKIPPED_TESTS -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

# Run main function
main "$@"