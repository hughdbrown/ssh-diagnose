# SSH Diagnostic Tool

A comprehensive Python tool for diagnosing SSH connectivity issues on Linux/Ubuntu systems.

## Overview

This tool systematically tests SSH connectivity issues in logical order, from most fundamental (hardware/network) to most specific (external dependencies). It performs 59 different tests across 7 levels to identify why inbound SSH connections on port 22 might not work.

## Features

- **Comprehensive Testing**: 59 tests covering all major SSH connectivity issues
- **Logical Progression**: Tests organized from hardware to external dependencies
- **Color-coded Output**: Visual indicators for pass/fail/warn/skip status
- **Detailed Remediation**: Specific fix instructions for each failed test
- **Verbose Mode**: Detailed diagnostic information
- **Cross-platform**: Designed for Linux/Ubuntu but works on other systems

## Test Levels

### Level 1: Hardware & Network Foundation
- Network interface status and configuration
- Basic connectivity (localhost and external)
- Routing table validation
- DNS resolution testing
- Physical connection status

### Level 2: System Resources & Health
- Memory availability and usage
- Disk space (root and /var partitions)
- File descriptor limits
- System load and process count
- Time synchronization

### Level 3: SSH Service & Configuration
- SSH daemon status and enablement
- Configuration file validation and syntax
- File permissions for SSH directory and keys
- Port binding and local connectivity
- Host key availability and permissions

### Level 4: Network Services & Security
- UFW firewall status and rules
- iptables firewall configuration
- TCP wrappers (hosts.allow/hosts.deny)
- Port conflicts detection
- fail2ban intrusion prevention

### Level 5: Authentication & Access Control
- Authentication methods configuration
- SSH key setup and permissions
- PAM configuration for SSH
- User account status and restrictions
- LDAP/Kerberos external authentication

### Level 6: Advanced Security & Isolation
- SELinux mandatory access control
- AppArmor application confinement
- Container isolation (Docker)
- Network namespace separation
- System hardening parameters

### Level 7: External Dependencies
- Cloud provider metadata (AWS/GCP/Azure)
- NAT and port forwarding detection
- External reachability testing
- Geographic restrictions analysis
- Network infrastructure assessment

## Usage

### Basic Usage
```bash
python3 ssh_diagnose.py
```

### Verbose Mode
```bash
python3 ssh_diagnose.py --verbose
```

### Make Executable
```bash
chmod +x ssh_diagnose.py
./ssh_diagnose.py
```

## Sample Output

```
Starting SSH Diagnostic Tool...
Testing SSH connectivity issues in logical order...

Level 1: Hardware & Network Foundation
----------------------------------------
✅ PASS: Network Interfaces - Active interfaces found: eth0
✅ PASS: Localhost Connectivity - Localhost is reachable
✅ PASS: External Connectivity - External connectivity working
✅ PASS: Default Route - Default route is configured
⚠️  WARN: Reverse DNS - No reverse DNS for 192.168.1.100

Level 2: System Resources & Health
----------------------------------------
✅ PASS: Memory Availability - Memory OK: 2048MB available (25.0% used)
✅ PASS: Root Disk Space - Disk space OK: 45% used, 25G available
❌ FAIL: SSH Daemon Status - SSH daemon is not running
     Fix: Start SSH: sudo systemctl start ssh

================================================================================
SSH DIAGNOSTIC SUMMARY
================================================================================
Total Tests: 59
Passed: 25, Failed: 6, Warnings: 14, Skipped: 14

CRITICAL ISSUES:
  ❌ SSH Daemon Status: SSH daemon is not running
     Fix: Start SSH: sudo systemctl start ssh (or sshd)
  ❌ SSH Host Keys: No SSH host keys found
     Fix: Generate keys: sudo ssh-keygen -A

WARNINGS:
  ⚠️  Time Synchronization: No time synchronization service running
     Fix: Enable NTP: sudo systemctl enable --now systemd-timesyncd
```

## Common Issues Detected

### Critical Issues
- SSH daemon not running or not installed
- SSH configuration syntax errors
- Missing SSH host keys
- Firewall blocking SSH port
- Incorrect file permissions

### Common Warnings
- High system resource usage
- Insecure SSH configuration
- Missing security hardening
- Network configuration issues
- Authentication problems

## Requirements

- Python 3.6+
- Linux/Ubuntu system (some tests are Linux-specific)
- Standard system utilities (ip, ping, netstat/ss, etc.)
- Optional: nmap, fail2ban, ufw for enhanced testing

## Dependencies

The tool uses only Python standard library modules:
- `subprocess` - For running system commands
- `socket` - For network connectivity testing
- `pathlib` - For file system operations
- `json` - For parsing configuration data
- `os` - For system information
- `sys` - For command line arguments
- `time` - For timing operations

## Design Principles

1. **Progressive Diagnosis**: Start with fundamental issues before advanced ones
2. **Actionable Results**: Every failure includes specific remediation steps
3. **Safe Operation**: Read-only operations, no system modifications
4. **Graceful Degradation**: Continue testing even if some tools are unavailable
5. **Clear Output**: Color-coded results with detailed explanations

## Exit Codes

- `0`: Diagnostic completed successfully
- `1`: Interrupted by user or error occurred

## Limitations

- Some tests require sudo privileges for full functionality
- Cloud-specific tests only work on cloud instances
- External connectivity tests depend on internet access
- Some security tools may not be available on all systems

## Contributing

This tool was designed to be easily extensible. To add new tests:

1. Create a new test method following the naming pattern `test_*`
2. Use `self.log_result()` to record test results
3. Add the test to the appropriate level method
4. Include remediation steps for failures

## Security Considerations

This tool performs read-only diagnostic operations and does not:
- Modify system configuration
- Install or remove software
- Change permissions or ownership
- Create or delete files
- Expose sensitive information in output

However, it may reveal system configuration details that could be useful for security assessment.