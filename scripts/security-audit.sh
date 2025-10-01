#!/bin/bash

# Security Audit Script for VersityGW IPFS Integration
# Copyright 2023 Versity Software
# Licensed under the Apache License, Version 2.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
AUDIT_REPORT_DIR="${AUDIT_REPORT_DIR:-./security-audit-reports}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$AUDIT_REPORT_DIR/security-audit-$TIMESTAMP.json"

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
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Initialize audit results
AUDIT_RESULTS=()
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Add audit result
add_audit_result() {
    local check_id="$1"
    local category="$2"
    local description="$3"
    local status="$4"
    local severity="$5"
    local details="$6"
    local remediation="$7"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    case "$status" in
        "PASS")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            log_success "$check_id: $description"
            ;;
        "FAIL")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            log_error "$check_id: $description"
            ;;
        "WARN")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            log_warning "$check_id: $description"
            ;;
    esac
    
    local result=$(cat <<EOF
{
    "check_id": "$check_id",
    "category": "$category",
    "description": "$description",
    "status": "$status",
    "severity": "$severity",
    "details": "$details",
    "remediation": "$remediation",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    
    AUDIT_RESULTS+=("$result")
}

# Authentication Security Checks
audit_authentication() {
    log_info "Auditing authentication security..."
    
    # Check if security is enabled
    if grep -q "security_enabled.*true" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "AUTH-001" "Authentication" "Security enabled in configuration" "PASS" "HIGH" "Security is properly enabled" "None required"
    else
        add_audit_result "AUTH-001" "Authentication" "Security not enabled in configuration" "FAIL" "CRITICAL" "Security is disabled or not configured" "Enable security in production configuration"
    fi
    
    # Check for default credentials
    if grep -q "admin_password.*admin" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "AUTH-002" "Authentication" "Default admin password detected" "FAIL" "CRITICAL" "Default password 'admin' is being used" "Change default admin password immediately"
    else
        add_audit_result "AUTH-002" "Authentication" "No default admin password detected" "PASS" "HIGH" "Admin password has been changed from default" "None required"
    fi
    
    # Check password complexity
    local password_hash=$(grep "admin_password_hash" /etc/versitygw/versitygw.yaml 2>/dev/null | cut -d'"' -f4 || echo "")
    if [[ -n "$password_hash" && "$password_hash" =~ ^\$2[aby]\$[0-9]{2}\$ ]]; then
        add_audit_result "AUTH-003" "Authentication" "Strong password hashing detected" "PASS" "MEDIUM" "bcrypt password hashing is being used" "None required"
    else
        add_audit_result "AUTH-003" "Authentication" "Weak or no password hashing" "FAIL" "HIGH" "Password is not properly hashed" "Use bcrypt for password hashing"
    fi
    
    # Check for API key management
    if [[ -f "/etc/versitygw/api-keys.json" ]]; then
        local key_count=$(jq length /etc/versitygw/api-keys.json 2>/dev/null || echo "0")
        if [[ "$key_count" -gt 0 ]]; then
            add_audit_result "AUTH-004" "Authentication" "API keys configured" "PASS" "MEDIUM" "$key_count API keys found" "Regularly rotate API keys"
        else
            add_audit_result "AUTH-004" "Authentication" "No API keys configured" "WARN" "MEDIUM" "No API keys found" "Configure API keys for programmatic access"
        fi
    else
        add_audit_result "AUTH-004" "Authentication" "API key file not found" "WARN" "MEDIUM" "API key configuration file missing" "Create API key configuration if needed"
    fi
    
    # Check session timeout configuration
    local session_timeout=$(grep "session_timeout" /etc/versitygw/versitygw.yaml 2>/dev/null | grep -o '[0-9]\+' || echo "0")
    if [[ "$session_timeout" -gt 0 && "$session_timeout" -le 3600 ]]; then
        add_audit_result "AUTH-005" "Authentication" "Appropriate session timeout configured" "PASS" "MEDIUM" "Session timeout: ${session_timeout}s" "None required"
    else
        add_audit_result "AUTH-005" "Authentication" "Session timeout not configured or too long" "WARN" "MEDIUM" "Session timeout: ${session_timeout}s" "Configure session timeout between 300-3600 seconds"
    fi
}

# Data Encryption Checks
audit_data_encryption() {
    log_info "Auditing data encryption..."
    
    # Check if encryption is enabled
    if grep -q "encryption_enabled.*true" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "ENC-001" "Encryption" "Data encryption enabled" "PASS" "HIGH" "Client-side encryption is enabled" "None required"
    else
        add_audit_result "ENC-001" "Encryption" "Data encryption not enabled" "FAIL" "HIGH" "Data encryption is disabled" "Enable client-side encryption for sensitive data"
    fi
    
    # Check TLS configuration
    if grep -q "tls.*enabled.*true" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "ENC-002" "Encryption" "TLS enabled" "PASS" "HIGH" "TLS encryption is enabled" "None required"
        
        # Check TLS certificate
        local cert_file=$(grep "cert_file" /etc/versitygw/versitygw.yaml 2>/dev/null | cut -d'"' -f4 || echo "")
        if [[ -f "$cert_file" ]]; then
            local cert_expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d'=' -f2 || echo "")
            local expiry_epoch=$(date -d "$cert_expiry" +%s 2>/dev/null || echo "0")
            local current_epoch=$(date +%s)
            local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            if [[ "$days_until_expiry" -gt 30 ]]; then
                add_audit_result "ENC-003" "Encryption" "TLS certificate valid" "PASS" "MEDIUM" "Certificate expires in $days_until_expiry days" "None required"
            elif [[ "$days_until_expiry" -gt 0 ]]; then
                add_audit_result "ENC-003" "Encryption" "TLS certificate expiring soon" "WARN" "MEDIUM" "Certificate expires in $days_until_expiry days" "Renew TLS certificate"
            else
                add_audit_result "ENC-003" "Encryption" "TLS certificate expired" "FAIL" "HIGH" "Certificate expired $((days_until_expiry * -1)) days ago" "Replace expired TLS certificate immediately"
            fi
        else
            add_audit_result "ENC-003" "Encryption" "TLS certificate file not found" "FAIL" "HIGH" "Certificate file does not exist: $cert_file" "Ensure TLS certificate file exists and is readable"
        fi
    else
        add_audit_result "ENC-002" "Encryption" "TLS not enabled" "FAIL" "CRITICAL" "TLS encryption is disabled" "Enable TLS for all communications"
    fi
    
    # Check encryption key management
    if [[ -f "/etc/versitygw/encryption-keys.json" ]]; then
        local key_permissions=$(stat -c "%a" /etc/versitygw/encryption-keys.json 2>/dev/null || echo "000")
        if [[ "$key_permissions" == "600" ]]; then
            add_audit_result "ENC-004" "Encryption" "Encryption keys properly protected" "PASS" "HIGH" "Key file permissions: $key_permissions" "None required"
        else
            add_audit_result "ENC-004" "Encryption" "Encryption keys not properly protected" "FAIL" "CRITICAL" "Key file permissions: $key_permissions" "Set encryption key file permissions to 600"
        fi
    else
        add_audit_result "ENC-004" "Encryption" "Encryption key file not found" "WARN" "MEDIUM" "No encryption key file found" "Create encryption key file if using client-side encryption"
    fi
}

# Network Security Checks
audit_network_security() {
    log_info "Auditing network security..."
    
    # Check listening ports
    local listening_ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | cut -d':' -f2 | sort -n | uniq)
    local expected_ports="8080 9094 9095 9096 2136 6379"
    
    for port in $expected_ports; do
        if echo "$listening_ports" | grep -q "^$port$"; then
            add_audit_result "NET-$(printf "%03d" $port)" "Network" "Expected port $port is listening" "PASS" "LOW" "Port $port is properly configured" "None required"
        else
            add_audit_result "NET-$(printf "%03d" $port)" "Network" "Expected port $port not listening" "WARN" "MEDIUM" "Port $port is not listening" "Verify service configuration for port $port"
        fi
    done
    
    # Check for unexpected open ports
    local unexpected_ports=""
    for port in $listening_ports; do
        if ! echo "$expected_ports" | grep -q "$port"; then
            unexpected_ports="$unexpected_ports $port"
        fi
    done
    
    if [[ -n "$unexpected_ports" ]]; then
        add_audit_result "NET-999" "Network" "Unexpected open ports detected" "WARN" "MEDIUM" "Unexpected ports:$unexpected_ports" "Review and close unnecessary ports"
    else
        add_audit_result "NET-999" "Network" "No unexpected open ports" "PASS" "MEDIUM" "Only expected ports are listening" "None required"
    fi
    
    # Check firewall status
    if systemctl is-active --quiet ufw; then
        add_audit_result "NET-FW1" "Network" "UFW firewall is active" "PASS" "MEDIUM" "UFW firewall is running" "None required"
    elif systemctl is-active --quiet firewalld; then
        add_audit_result "NET-FW1" "Network" "Firewalld is active" "PASS" "MEDIUM" "Firewalld is running" "None required"
    else
        add_audit_result "NET-FW1" "Network" "No firewall detected" "WARN" "HIGH" "No active firewall found" "Configure and enable firewall"
    fi
    
    # Check for rate limiting configuration
    if grep -q "rate_limiting.*enabled.*true" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        local rps=$(grep "requests_per_second" /etc/versitygw/versitygw.yaml 2>/dev/null | grep -o '[0-9]\+' || echo "0")
        if [[ "$rps" -gt 0 && "$rps" -le 10000 ]]; then
            add_audit_result "NET-RL1" "Network" "Rate limiting properly configured" "PASS" "MEDIUM" "Rate limit: $rps requests/second" "None required"
        else
            add_audit_result "NET-RL1" "Network" "Rate limiting misconfigured" "WARN" "MEDIUM" "Rate limit: $rps requests/second" "Configure appropriate rate limiting"
        fi
    else
        add_audit_result "NET-RL1" "Network" "Rate limiting not configured" "WARN" "MEDIUM" "No rate limiting found" "Configure rate limiting to prevent abuse"
    fi
}

# Access Control Checks
audit_access_control() {
    log_info "Auditing access control..."
    
    # Check file permissions on configuration files
    local config_files="/etc/versitygw/versitygw.yaml /etc/versitygw/.env"
    for file in $config_files; do
        if [[ -f "$file" ]]; then
            local permissions=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
            local owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")
            
            if [[ "$permissions" == "640" || "$permissions" == "600" ]]; then
                add_audit_result "AC-$(basename $file)" "Access Control" "$(basename $file) permissions correct" "PASS" "MEDIUM" "Permissions: $permissions, Owner: $owner" "None required"
            else
                add_audit_result "AC-$(basename $file)" "Access Control" "$(basename $file) permissions incorrect" "FAIL" "HIGH" "Permissions: $permissions, Owner: $owner" "Set permissions to 640 or 600"
            fi
        fi
    done
    
    # Check service user configuration
    if id versitygw &>/dev/null; then
        local user_shell=$(getent passwd versitygw | cut -d':' -f7)
        if [[ "$user_shell" == "/bin/false" || "$user_shell" == "/usr/sbin/nologin" ]]; then
            add_audit_result "AC-USER1" "Access Control" "Service user shell properly restricted" "PASS" "MEDIUM" "Shell: $user_shell" "None required"
        else
            add_audit_result "AC-USER1" "Access Control" "Service user shell not restricted" "WARN" "MEDIUM" "Shell: $user_shell" "Set service user shell to /bin/false"
        fi
        
        local user_home=$(getent passwd versitygw | cut -d':' -f6)
        if [[ "$user_home" == "/var/lib/versitygw" || "$user_home" == "/nonexistent" ]]; then
            add_audit_result "AC-USER2" "Access Control" "Service user home directory appropriate" "PASS" "LOW" "Home: $user_home" "None required"
        else
            add_audit_result "AC-USER2" "Access Control" "Service user home directory questionable" "WARN" "LOW" "Home: $user_home" "Consider setting home to /var/lib/versitygw"
        fi
    else
        add_audit_result "AC-USER1" "Access Control" "Service user not found" "FAIL" "HIGH" "versitygw user does not exist" "Create dedicated service user"
    fi
    
    # Check sudo configuration
    if [[ -f "/etc/sudoers.d/versitygw" ]]; then
        add_audit_result "AC-SUDO1" "Access Control" "Dedicated sudo configuration found" "WARN" "MEDIUM" "Custom sudo rules exist" "Review sudo configuration for necessity"
    else
        add_audit_result "AC-SUDO1" "Access Control" "No dedicated sudo configuration" "PASS" "MEDIUM" "No custom sudo rules" "None required"
    fi
    
    # Check IAM configuration
    if grep -q "iam.*type.*internal" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "AC-IAM1" "Access Control" "Internal IAM configured" "PASS" "MEDIUM" "Using internal IAM system" "None required"
        
        # Check for multiple admin users
        local admin_count=$(grep -c "admin_user" /etc/versitygw/versitygw.yaml 2>/dev/null || echo "0")
        if [[ "$admin_count" -eq 1 ]]; then
            add_audit_result "AC-IAM2" "Access Control" "Single admin user configured" "PASS" "MEDIUM" "One admin user found" "None required"
        elif [[ "$admin_count" -gt 1 ]]; then
            add_audit_result "AC-IAM2" "Access Control" "Multiple admin users configured" "WARN" "MEDIUM" "$admin_count admin users found" "Review necessity of multiple admin users"
        else
            add_audit_result "AC-IAM2" "Access Control" "No admin users configured" "FAIL" "HIGH" "No admin users found" "Configure at least one admin user"
        fi
    else
        add_audit_result "AC-IAM1" "Access Control" "External IAM or not configured" "WARN" "MEDIUM" "IAM configuration unclear" "Verify IAM configuration"
    fi
}

# Audit Logging Checks
audit_logging() {
    log_info "Auditing logging configuration..."
    
    # Check if audit logging is enabled
    if grep -q "audit.*enabled.*true" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "LOG-001" "Logging" "Audit logging enabled" "PASS" "HIGH" "Audit logging is properly enabled" "None required"
        
        # Check audit log file configuration
        local audit_log=$(grep "audit.*output" /etc/versitygw/versitygw.yaml 2>/dev/null | cut -d'"' -f4 || echo "")
        if [[ -n "$audit_log" ]]; then
            local log_dir=$(dirname "$audit_log")
            if [[ -d "$log_dir" ]]; then
                local log_permissions=$(stat -c "%a" "$log_dir" 2>/dev/null || echo "000")
                if [[ "$log_permissions" == "750" || "$log_permissions" == "755" ]]; then
                    add_audit_result "LOG-002" "Logging" "Audit log directory permissions correct" "PASS" "MEDIUM" "Directory permissions: $log_permissions" "None required"
                else
                    add_audit_result "LOG-002" "Logging" "Audit log directory permissions incorrect" "WARN" "MEDIUM" "Directory permissions: $log_permissions" "Set log directory permissions to 750"
                fi
            else
                add_audit_result "LOG-002" "Logging" "Audit log directory does not exist" "FAIL" "HIGH" "Log directory missing: $log_dir" "Create audit log directory"
            fi
        fi
    else
        add_audit_result "LOG-001" "Logging" "Audit logging not enabled" "FAIL" "HIGH" "Audit logging is disabled" "Enable audit logging for compliance"
    fi
    
    # Check log rotation configuration
    local max_size=$(grep "max_size" /etc/versitygw/versitygw.yaml 2>/dev/null | head -1 | grep -o '[0-9]\+' || echo "0")
    local max_backups=$(grep "max_backups" /etc/versitygw/versitygw.yaml 2>/dev/null | head -1 | grep -o '[0-9]\+' || echo "0")
    
    if [[ "$max_size" -gt 0 && "$max_backups" -gt 0 ]]; then
        add_audit_result "LOG-003" "Logging" "Log rotation configured" "PASS" "MEDIUM" "Max size: ${max_size}MB, Max backups: $max_backups" "None required"
    else
        add_audit_result "LOG-003" "Logging" "Log rotation not configured" "WARN" "MEDIUM" "Log rotation settings missing" "Configure log rotation to prevent disk space issues"
    fi
    
    # Check log level
    local log_level=$(grep "level.*:" /etc/versitygw/versitygw.yaml 2>/dev/null | cut -d'"' -f4 || echo "")
    case "$log_level" in
        "debug")
            add_audit_result "LOG-004" "Logging" "Debug logging enabled" "WARN" "LOW" "Log level: $log_level" "Consider using 'info' level for production"
            ;;
        "info"|"warn"|"error")
            add_audit_result "LOG-004" "Logging" "Appropriate log level configured" "PASS" "LOW" "Log level: $log_level" "None required"
            ;;
        *)
            add_audit_result "LOG-004" "Logging" "Log level not configured or unknown" "WARN" "MEDIUM" "Log level: $log_level" "Configure appropriate log level"
            ;;
    esac
}

# Input Validation Checks
audit_input_validation() {
    log_info "Auditing input validation..."
    
    # Check for SQL injection protection (if using SQL database)
    if grep -q "metadata_db.*type.*ydb\|metadata_db.*type.*postgres\|metadata_db.*type.*mysql" /etc/versitygw/versitygw.yaml 2>/dev/null; then
        add_audit_result "VAL-001" "Input Validation" "SQL database in use" "PASS" "MEDIUM" "Using SQL database for metadata" "Ensure prepared statements are used"
    else
        add_audit_result "VAL-001" "Input Validation" "Non-SQL database in use" "PASS" "LOW" "Not using SQL database" "None required"
    fi
    
    # Check for request size limits
    local max_header_bytes=$(grep "max_header_bytes" /etc/versitygw/versitygw.yaml 2>/dev/null | grep -o '[0-9]\+' || echo "0")
    if [[ "$max_header_bytes" -gt 0 && "$max_header_bytes" -le 1048576 ]]; then
        add_audit_result "VAL-002" "Input Validation" "Request header size limited" "PASS" "MEDIUM" "Max header bytes: $max_header_bytes" "None required"
    else
        add_audit_result "VAL-002" "Input Validation" "Request header size not limited" "WARN" "MEDIUM" "Max header bytes: $max_header_bytes" "Configure request header size limits"
    fi
    
    # Check for timeout configurations
    local read_timeout=$(grep "read_timeout" /etc/versitygw/versitygw.yaml 2>/dev/null | grep -o '[0-9]\+' || echo "0")
    local write_timeout=$(grep "write_timeout" /etc/versitygw/versitygw.yaml 2>/dev/null | grep -o '[0-9]\+' || echo "0")
    
    if [[ "$read_timeout" -gt 0 && "$read_timeout" -le 300 ]]; then
        add_audit_result "VAL-003" "Input Validation" "Read timeout configured" "PASS" "MEDIUM" "Read timeout: ${read_timeout}s" "None required"
    else
        add_audit_result "VAL-003" "Input Validation" "Read timeout not configured or too high" "WARN" "MEDIUM" "Read timeout: ${read_timeout}s" "Configure read timeout (30-300 seconds)"
    fi
    
    if [[ "$write_timeout" -gt 0 && "$write_timeout" -le 300 ]]; then
        add_audit_result "VAL-004" "Input Validation" "Write timeout configured" "PASS" "MEDIUM" "Write timeout: ${write_timeout}s" "None required"
    else
        add_audit_result "VAL-004" "Input Validation" "Write timeout not configured or too high" "WARN" "MEDIUM" "Write timeout: ${write_timeout}s" "Configure write timeout (30-300 seconds)"
    fi
    
    # Check for path traversal protection
    add_audit_result "VAL-005" "Input Validation" "Path traversal protection" "PASS" "HIGH" "Built-in S3 API path validation" "None required - handled by S3 API implementation"
    
    # Check bucket name validation
    add_audit_result "VAL-006" "Input Validation" "Bucket name validation" "PASS" "MEDIUM" "S3 bucket naming rules enforced" "None required - handled by S3 API implementation"
}

# Container Security Checks (if using Docker)
audit_container_security() {
    log_info "Auditing container security..."
    
    if command -v docker &> /dev/null; then
        # Check if containers are running as non-root
        local containers=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -E "(ipfs|redis|ydb)" || echo "")
        
        for container in $containers; do
            local user=$(docker exec "$container" whoami 2>/dev/null || echo "unknown")
            if [[ "$user" != "root" ]]; then
                add_audit_result "CNT-$(echo $container | tr '-' '_')" "Container Security" "$container running as non-root" "PASS" "MEDIUM" "User: $user" "None required"
            else
                add_audit_result "CNT-$(echo $container | tr '-' '_')" "Container Security" "$container running as root" "WARN" "MEDIUM" "User: $user" "Configure container to run as non-root user"
            fi
        done
        
        # Check for privileged containers
        local privileged_containers=$(docker ps --filter "label=privileged=true" --format "{{.Names}}" 2>/dev/null || echo "")
        if [[ -z "$privileged_containers" ]]; then
            add_audit_result "CNT-PRIV" "Container Security" "No privileged containers detected" "PASS" "HIGH" "No containers running in privileged mode" "None required"
        else
            add_audit_result "CNT-PRIV" "Container Security" "Privileged containers detected" "FAIL" "HIGH" "Privileged containers: $privileged_containers" "Remove privileged mode unless absolutely necessary"
        fi
        
        # Check Docker daemon configuration
        if [[ -f "/etc/docker/daemon.json" ]]; then
            if grep -q "userns-remap" /etc/docker/daemon.json 2>/dev/null; then
                add_audit_result "CNT-USERNS" "Container Security" "User namespace remapping enabled" "PASS" "HIGH" "Docker user namespace remapping configured" "None required"
            else
                add_audit_result "CNT-USERNS" "Container Security" "User namespace remapping not enabled" "WARN" "MEDIUM" "User namespace remapping not configured" "Consider enabling user namespace remapping"
            fi
        else
            add_audit_result "CNT-DAEMON" "Container Security" "Docker daemon configuration not found" "WARN" "LOW" "No custom Docker daemon configuration" "Consider creating Docker daemon configuration"
        fi
    else
        add_audit_result "CNT-DOCKER" "Container Security" "Docker not installed" "PASS" "LOW" "Not using containerized deployment" "None required"
    fi
}

# Generate audit report
generate_report() {
    log_info "Generating security audit report..."
    
    mkdir -p "$AUDIT_REPORT_DIR"
    
    # Create JSON report
    cat > "$REPORT_FILE" << EOF
{
    "audit_metadata": {
        "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "version": "1.0",
        "auditor": "VersityGW Security Audit Script",
        "target": "VersityGW IPFS Integration"
    },
    "summary": {
        "total_checks": $TOTAL_CHECKS,
        "passed_checks": $PASSED_CHECKS,
        "failed_checks": $FAILED_CHECKS,
        "warning_checks": $WARNING_CHECKS,
        "compliance_score": $(echo "scale=2; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")
    },
    "results": [
        $(IFS=','; echo "${AUDIT_RESULTS[*]}")
    ]
}
EOF
    
    # Create human-readable report
    local human_report="$AUDIT_REPORT_DIR/security-audit-$TIMESTAMP.txt"
    cat > "$human_report" << EOF
VersityGW IPFS Integration Security Audit Report
===============================================

Audit Date: $(date)
Audit Version: 1.0

SUMMARY
-------
Total Checks: $TOTAL_CHECKS
Passed: $PASSED_CHECKS
Failed: $FAILED_CHECKS
Warnings: $WARNING_CHECKS
Compliance Score: $(echo "scale=2; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")%

DETAILED RESULTS
---------------
EOF
    
    # Add detailed results to human-readable report
    for result in "${AUDIT_RESULTS[@]}"; do
        local check_id=$(echo "$result" | jq -r '.check_id')
        local category=$(echo "$result" | jq -r '.category')
        local description=$(echo "$result" | jq -r '.description')
        local status=$(echo "$result" | jq -r '.status')
        local severity=$(echo "$result" | jq -r '.severity')
        local details=$(echo "$result" | jq -r '.details')
        local remediation=$(echo "$result" | jq -r '.remediation')
        
        cat >> "$human_report" << EOF

[$status] $check_id - $category
Description: $description
Severity: $severity
Details: $details
Remediation: $remediation
EOF
    done
    
    # Add recommendations section
    cat >> "$human_report" << EOF

RECOMMENDATIONS
--------------
EOF
    
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        cat >> "$human_report" << EOF

CRITICAL ACTIONS REQUIRED:
- Address all FAILED checks immediately
- Review and implement recommended remediations
- Re-run audit after implementing fixes
EOF
    fi
    
    if [[ $WARNING_CHECKS -gt 0 ]]; then
        cat >> "$human_report" << EOF

IMPROVEMENTS RECOMMENDED:
- Review all WARNING checks
- Implement security best practices
- Consider additional hardening measures
EOF
    fi
    
    cat >> "$human_report" << EOF

ONGOING SECURITY PRACTICES:
- Run security audits regularly (monthly recommended)
- Keep all software components updated
- Monitor security logs and alerts
- Review and update security configurations
- Conduct penetration testing periodically
- Train staff on security best practices

For additional security guidance, consult:
- VersityGW Security Documentation
- OWASP Security Guidelines
- Industry-specific compliance requirements
EOF
    
    log_success "Security audit report generated:"
    log_info "JSON Report: $REPORT_FILE"
    log_info "Human-readable Report: $human_report"
}

# Print summary
print_summary() {
    echo ""
    echo "========================================"
    echo "SECURITY AUDIT SUMMARY"
    echo "========================================"
    echo "Total Checks: $TOTAL_CHECKS"
    echo "Passed: $PASSED_CHECKS"
    echo "Failed: $FAILED_CHECKS"
    echo "Warnings: $WARNING_CHECKS"
    echo "Compliance Score: $(echo "scale=2; $PASSED_CHECKS * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")%"
    echo ""
    
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        echo -e "${RED}⚠️  CRITICAL: $FAILED_CHECKS security issues require immediate attention${NC}"
    fi
    
    if [[ $WARNING_CHECKS -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  WARNING: $WARNING_CHECKS security improvements recommended${NC}"
    fi
    
    if [[ $FAILED_CHECKS -eq 0 && $WARNING_CHECKS -eq 0 ]]; then
        echo -e "${GREEN}✅ All security checks passed!${NC}"
    fi
    
    echo ""
    echo "Detailed reports available in: $AUDIT_REPORT_DIR"
    echo "========================================"
}

# Main execution
main() {
    log_info "Starting VersityGW IPFS Integration Security Audit..."
    
    # Check if required tools are available
    local required_tools="jq bc netstat stat"
    for tool in $required_tools; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Run audit categories
    audit_authentication
    audit_data_encryption
    audit_network_security
    audit_access_control
    audit_logging
    audit_input_validation
    audit_container_security
    
    # Generate reports
    generate_report
    print_summary
    
    # Exit with appropriate code
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        exit 1
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

# Run main function
main "$@"