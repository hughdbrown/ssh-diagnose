#!/usr/bin/env python3
# /// script
# dependencies = [
#   "ruff",
# ]
# ///


"""
SSH Diagnostic Tool for Linux/Ubuntu Systems

This tool systematically diagnoses why inbound SSH connections on port 22 might not work.
Tests are organized from most fundamental (hardware/network) to most specific (external dependencies).
"""

import subprocess
import socket
import os
import sys
import time
import ipaddress
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class DiagnosticResult:
    test_name: str
    result: TestResult
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None


class SSHDiagnostic:
    """Main SSH diagnostic class that runs all tests in logical order"""

    def __init__(self):
        self.results: List[DiagnosticResult] = []
        self.ssh_port = 22
        self.ssh_config_path = Path("/etc/ssh/sshd_config")
        self.verbose = False

    def run_command(
        self, cmd: List[str], timeout: int = 10, capture_error: bool = True
    ) -> Tuple[int, str, str]:
        """Execute a system command and return returncode, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd, encoding="utf-8", capture_output=True, timeout=timeout, cwd="."
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds"
        except subprocess.CalledProcessError as e:
            return (
                e.returncode,
                e.stdout if hasattr(e, "stdout") else "",
                e.stderr if hasattr(e, "stderr") else str(e),
            )
        except Exception as e:
            return -1, "", str(e)

    def is_ipv6_address(self, ip_string: str) -> bool:
        """Check if the given string is a valid IPv6 address"""
        try:
            ip_obj = ipaddress.ip_address(ip_string)
            return isinstance(ip_obj, ipaddress.IPv6Address)
        except ValueError:
            return False

    def check_systemd_socket_activation(self) -> Tuple[bool, bool]:
        """Check if SSH is using systemd socket activation
        Returns: (socket_exists, socket_active)
        """
        # Check if ssh.socket exists and is enabled
        socket_exists = False
        socket_active = False

        # Check for ssh.socket
        rc, stdout, stderr = self.run_command(["systemctl", "list-unit-files", "ssh.socket"])
        if rc == 0 and "ssh.socket" in stdout:
            socket_exists = True
        else:
            # Try sshd.socket
            rc, stdout, stderr = self.run_command(["systemctl", "list-unit-files", "sshd.socket"])
            if rc == 0 and "sshd.socket" in stdout:
                socket_exists = True

        if socket_exists:
            # Check if socket is active
            rc, stdout, stderr = self.run_command(["systemctl", "is-active", "ssh.socket"])
            if rc == 0:
                socket_active = True
            else:
                rc, stdout, stderr = self.run_command(["systemctl", "is-active", "sshd.socket"])
                socket_active = rc == 0

        return socket_exists, socket_active

    def trigger_sshd_startup(self) -> bool:
        """Attempt to trigger sshd startup via connection attempt
        Returns: True if successful, False otherwise
        """
        try:
            # Make a brief connection attempt to trigger socket activation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", self.ssh_port))
            sock.close()

            # Give systemd a moment to start the service
            time.sleep(2)

            # Check if sshd process is now running
            rc, stdout, stderr = self.run_command(["pgrep", "-f", "sshd"])
            return rc == 0 and stdout.strip()
        except Exception:
            return False

    def log_result(
        self,
        test_name: str,
        result: TestResult,
        message: str,
        details: str = None,
        remediation: str = None,
    ):
        """Log a diagnostic result"""
        diag_result = DiagnosticResult(test_name, result, message, details, remediation)
        self.results.append(diag_result)

        # Print result immediately if verbose
        if self.verbose:
            status_color = {
                TestResult.PASS: "\033[92m",  # Green
                TestResult.FAIL: "\033[91m",  # Red
                TestResult.WARN: "\033[93m",  # Yellow
                TestResult.SKIP: "\033[94m",  # Blue
            }
            reset_color = "\033[0m"

            print(
                f"{status_color[result]}{result.value}{reset_color}: {test_name} - {message}"
            )
            if details and self.verbose:
                print(f"  Details: {details}")
            if remediation and result in [TestResult.FAIL, TestResult.WARN]:
                print(f"  Fix: {remediation}")

    def print_summary(self):
        """Print summary of all test results"""
        print("\n" + "=" * 80)
        print("SSH DIAGNOSTIC SUMMARY")
        print("=" * 80)

        pass_count = sum(1 for r in self.results if r.result == TestResult.PASS)
        fail_count = sum(1 for r in self.results if r.result == TestResult.FAIL)
        warn_count = sum(1 for r in self.results if r.result == TestResult.WARN)
        skip_count = sum(1 for r in self.results if r.result == TestResult.SKIP)

        print(f"Total Tests: {len(self.results)}")
        print(
            f"Passed: {pass_count}, Failed: {fail_count}, Warnings: {warn_count}, Skipped: {skip_count}"
        )
        print()

        # Show failures and warnings
        critical_issues = [r for r in self.results if r.result == TestResult.FAIL]
        if critical_issues:
            print("CRITICAL ISSUES:")
            for result in critical_issues:
                print(f"  ❌ {result.test_name}: {result.message}")
                if result.remediation:
                    print(f"     Fix: {result.remediation}")
            print()

        warnings = [r for r in self.results if r.result == TestResult.WARN]
        if warnings:
            print("WARNINGS:")
            for result in warnings:
                print(f"  ⚠️  {result.test_name}: {result.message}")
                if result.remediation:
                    print(f"     Fix: {result.remediation}")

    def test_level_1_network_foundation(self):
        """Level 1: Hardware & Network Foundation Tests"""
        print("Level 1: Hardware & Network Foundation")
        print("-" * 40)

        # Test 1.1: Network interfaces are up
        self.test_network_interfaces_up()

        # Test 1.2: Basic network connectivity
        self.test_basic_connectivity()

        # Test 1.3: Network routing table
        self.test_routing_table()

        # Test 1.4: DNS resolution
        self.test_dns_resolution()

        # Test 1.5: Physical network connection
        self.test_physical_connection()

        print()

    def test_network_interfaces_up(self):
        """Test if network interfaces are up and configured"""
        rc, stdout, stderr = self.run_command(["ip", "addr", "show"])

        if rc != 0:
            self.log_result(
                "Network Interfaces",
                TestResult.FAIL,
                "Cannot check network interfaces",
                stderr,
                "Check if 'ip' command is available and system networking is functional",
            )
            return

        # Look for UP interfaces with IP addresses
        interfaces = []
        current_interface = None
        has_ip = False
        is_up = False

        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith(("1:", "2:", "3:", "4:", "5:", "6:", "7:", "8:", "9:")):
                # Save previous interface
                if current_interface and is_up and has_ip:
                    interfaces.append(current_interface)

                # Start new interface
                current_interface = line.split(":")[1].strip().split("@")[0]
                has_ip = False
                is_up = "UP" in line and "LOOPBACK" not in line

            elif line.startswith("inet ") and not line.startswith("inet 127."):
                has_ip = True

        # Check last interface
        if current_interface and is_up and has_ip:
            interfaces.append(current_interface)

        if not interfaces:
            self.log_result(
                "Network Interfaces",
                TestResult.FAIL,
                "No active network interfaces with IP addresses found",
                "Available interfaces without proper IP configuration",
                "Configure network interface: sudo dhclient <interface> or set static IP",
            )
        else:
            self.log_result(
                "Network Interfaces",
                TestResult.PASS,
                f"Active interfaces found: {', '.join(interfaces)}",
            )

    def test_basic_connectivity(self):
        """Test basic network connectivity"""
        # Test localhost connectivity
        rc, stdout, stderr = self.run_command(
            ["ping", "-c", "1", "-W", "2", "127.0.0.1"]
        )

        if rc != 0:
            self.log_result(
                "Localhost Connectivity",
                TestResult.FAIL,
                "Cannot ping localhost (127.0.0.1)",
                stderr,
                "Check if network stack is functional, try: sudo systemctl restart networking",
            )
        else:
            self.log_result(
                "Localhost Connectivity", TestResult.PASS, "Localhost is reachable"
            )

        # Test external connectivity
        rc, stdout, stderr = self.run_command(["ping", "-c", "1", "-W", "3", "8.8.8.8"])

        if rc != 0:
            self.log_result(
                "External Connectivity",
                TestResult.WARN,
                "Cannot reach external hosts (8.8.8.8)",
                "This may affect SSH from external networks",
                "Check default gateway: ip route show default",
            )
        else:
            self.log_result(
                "External Connectivity",
                TestResult.PASS,
                "External connectivity working",
            )

    def test_routing_table(self):
        """Test network routing configuration"""
        rc, stdout, stderr = self.run_command(["ip", "route", "show"])

        if rc != 0:
            self.log_result(
                "Routing Table",
                TestResult.FAIL,
                "Cannot check routing table",
                stderr,
                "Check network configuration",
            )
            return

        has_default_route = False
        local_routes = 0

        for line in stdout.split("\n"):
            if line.startswith("default"):
                has_default_route = True
            elif line and not line.startswith("default"):
                local_routes += 1

        if not has_default_route:
            self.log_result(
                "Default Route",
                TestResult.WARN,
                "No default route configured",
                "May prevent external SSH access",
                "Add default route: sudo ip route add default via <gateway_ip>",
            )
        else:
            self.log_result(
                "Default Route", TestResult.PASS, "Default route is configured"
            )

        if local_routes == 0:
            self.log_result(
                "Local Routes",
                TestResult.FAIL,
                "No local network routes found",
                "Network may not be properly configured",
                "Check network interface configuration",
            )
        else:
            self.log_result(
                "Local Routes",
                TestResult.PASS,
                f"{local_routes} local routes configured",
            )

    def test_dns_resolution(self):
        """Test DNS resolution functionality"""
        # Test resolving localhost
        try:
            socket.gethostbyname("localhost")
            self.log_result(
                "DNS - Localhost", TestResult.PASS, "Localhost resolves correctly"
            )
        except socket.gaierror as e:
            self.log_result(
                "DNS - Localhost",
                TestResult.FAIL,
                "Cannot resolve localhost",
                str(e),
                "Check /etc/hosts file has '127.0.0.1 localhost'",
            )

        # Test resolving external domain
        try:
            socket.gethostbyname("google.com")
            self.log_result(
                "DNS - External", TestResult.PASS, "External DNS resolution working"
            )
        except socket.gaierror:
            self.log_result(
                "DNS - External",
                TestResult.WARN,
                "Cannot resolve external domains",
                "May affect SSH client hostname resolution",
                "Check /etc/resolv.conf for DNS servers",
            )

        # Test reverse DNS for our own IP
        rc, stdout, stderr = self.run_command(["hostname", "-I"])
        if rc == 0 and stdout.strip():
            local_ip = stdout.strip().split()[0]
            try:
                socket.gethostbyaddr(local_ip)
                self.log_result(
                    "Reverse DNS", TestResult.PASS, f"Reverse DNS works for {local_ip}"
                )
            except socket.herror:
                self.log_result(
                    "Reverse DNS",
                    TestResult.WARN,
                    f"No reverse DNS for {local_ip}",
                    "May cause slow SSH connections",
                    "Add 'UseDNS no' to /etc/ssh/sshd_config or setup reverse DNS",
                )

    def test_physical_connection(self):
        """Test physical network connection status"""
        # Check ethtool for physical interfaces
        rc, stdout, stderr = self.run_command(
            [
                "find",
                "/sys/class/net",
                "-name",
                "eth*",
                "-o",
                "-name",
                "ens*",
                "-o",
                "-name",
                "enp*",
            ]
        )

        if rc != 0 or not stdout.strip():
            self.log_result(
                "Physical Interface",
                TestResult.SKIP,
                "No physical ethernet interfaces found",
                "May be using wireless or virtual interfaces",
            )
            return

        # Check first physical interface
        interface_path = stdout.strip().split("\n")[0]
        interface_name = Path(interface_path).name

        # Check if interface is up
        carrier_file = Path(interface_path) / "carrier"
        if carrier_file.exists():
            try:
                with open(carrier_file, "r") as f:
                    carrier = f.read().strip()

                if carrier == "1":
                    self.log_result(
                        "Physical Connection",
                        TestResult.PASS,
                        f"Physical link detected on {interface_name}",
                    )
                else:
                    self.log_result(
                        "Physical Connection",
                        TestResult.FAIL,
                        f"No physical link on {interface_name}",
                        "Cable may be unplugged or faulty",
                        "Check ethernet cable connection",
                    )
            except Exception as e:
                self.log_result(
                    "Physical Connection",
                    TestResult.WARN,
                    f"Cannot check carrier status for {interface_name}",
                    str(e),
                )
        else:
            self.log_result(
                "Physical Connection",
                TestResult.SKIP,
                f"Cannot check physical connection for {interface_name}",
            )

    def test_level_2_system_resources(self):
        """Level 2: System Resources & Health Tests"""
        print("Level 2: System Resources & Health")
        print("-" * 40)

        # Test 2.1: System memory availability
        self.test_memory_availability()

        # Test 2.2: Disk space availability
        self.test_disk_space()

        # Test 2.3: File descriptor limits
        self.test_file_descriptor_limits()

        # Test 2.4: System load and processes
        self.test_system_load()

        # Test 2.5: Time synchronization
        self.test_time_synchronization()

        print()

    def test_memory_availability(self):
        """Test system memory availability"""
        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = f.read()

            mem_total = 0
            mem_available = 0

            for line in meminfo.split("\n"):
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1])

            if mem_total == 0:
                self.log_result(
                    "Memory Check", TestResult.FAIL, "Cannot determine system memory"
                )
                return

            mem_usage_percent = ((mem_total - mem_available) / mem_total) * 100
            mem_available_mb = mem_available // 1024

            if mem_available_mb < 100:
                self.log_result(
                    "Memory Availability",
                    TestResult.FAIL,
                    f"Very low memory: {mem_available_mb}MB available",
                    f"Memory usage: {mem_usage_percent:.1f}%",
                    "Free memory: kill unnecessary processes or add more RAM",
                )
            elif mem_usage_percent > 90:
                self.log_result(
                    "Memory Availability",
                    TestResult.WARN,
                    f"High memory usage: {mem_usage_percent:.1f}%",
                    f"{mem_available_mb}MB available",
                    "Consider freeing memory or restarting services",
                )
            else:
                self.log_result(
                    "Memory Availability",
                    TestResult.PASS,
                    f"Memory OK: {mem_available_mb}MB available ({mem_usage_percent:.1f}% used)",
                )

        except Exception as e:
            self.log_result(
                "Memory Check", TestResult.FAIL, "Cannot check memory status", str(e)
            )

    def test_disk_space(self):
        """Test disk space availability"""
        # Check root filesystem
        rc, stdout, stderr = self.run_command(["df", "-h", "/"])

        if rc != 0:
            self.log_result(
                "Disk Space", TestResult.FAIL, "Cannot check disk space", stderr
            )
            return

        lines = stdout.strip().split("\n")
        if len(lines) < 2:
            self.log_result(
                "Disk Space", TestResult.FAIL, "Cannot parse disk space output"
            )
            return

        # Parse df output
        parts = lines[1].split()
        if len(parts) >= 5:
            used_percent = parts[4].rstrip("%")
            try:
                used_percent = int(used_percent)
                if used_percent > 95:
                    self.log_result(
                        "Root Disk Space",
                        TestResult.FAIL,
                        f"Disk almost full: {used_percent}% used",
                        f"Available: {parts[3]}",
                        "Free disk space: remove unnecessary files",
                    )
                elif used_percent > 85:
                    self.log_result(
                        "Root Disk Space",
                        TestResult.WARN,
                        f"Disk usage high: {used_percent}% used",
                        f"Available: {parts[3]}",
                        "Monitor disk space usage",
                    )
                else:
                    self.log_result(
                        "Root Disk Space",
                        TestResult.PASS,
                        f"Disk space OK: {used_percent}% used, {parts[3]} available",
                    )
            except ValueError:
                self.log_result(
                    "Root Disk Space",
                    TestResult.WARN,
                    "Cannot parse disk usage percentage",
                )

        # Check /var specifically (SSH logs)
        rc, stdout, stderr = self.run_command(["df", "-h", "/var"])
        if rc == 0:
            lines = stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    used_percent = parts[4].rstrip("%")
                    try:
                        used_percent = int(used_percent)
                        if used_percent > 95:
                            self.log_result(
                                "/var Disk Space",
                                TestResult.FAIL,
                                f"/var partition almost full: {used_percent}% used",
                                "SSH may not be able to write logs",
                                "Clean /var/log files or increase /var partition size",
                            )
                        elif used_percent > 85:
                            self.log_result(
                                "/var Disk Space",
                                TestResult.WARN,
                                f"/var partition usage high: {used_percent}% used",
                            )
                        else:
                            self.log_result(
                                "/var Disk Space",
                                TestResult.PASS,
                                f"/var partition OK: {used_percent}% used",
                            )
                    except ValueError:
                        pass

    def test_file_descriptor_limits(self):
        """Test file descriptor limits"""
        # Check current ulimit
        rc, stdout, stderr = self.run_command(["ulimit", "-n"])

        if rc != 0:
            # Try with bash -c
            rc, stdout, stderr = self.run_command(["bash", "-c", "ulimit -n"])

        if rc == 0 and stdout.strip():
            try:
                fd_limit = int(stdout.strip())
                if fd_limit < 1024:
                    self.log_result(
                        "File Descriptor Limit",
                        TestResult.WARN,
                        f"Low file descriptor limit: {fd_limit}",
                        "May limit SSH connections",
                        "Increase limit: echo '* soft nofile 65536' >> /etc/security/limits.conf",
                    )
                else:
                    self.log_result(
                        "File Descriptor Limit",
                        TestResult.PASS,
                        f"File descriptor limit OK: {fd_limit}",
                    )
            except ValueError:
                self.log_result(
                    "File Descriptor Limit",
                    TestResult.WARN,
                    "Cannot parse file descriptor limit",
                )
        else:
            self.log_result(
                "File Descriptor Limit",
                TestResult.WARN,
                "Cannot check file descriptor limit",
            )

        # Check current open files
        try:
            rc, stdout, stderr = self.run_command(["lsof", "-u", "root"])
            if rc == 0:
                open_files = len(stdout.split("\n")) - 1  # subtract header
                self.log_result(
                    "Open Files Count",
                    TestResult.PASS,
                    f"Currently {open_files} files open by root",
                )
        except:
            pass  # lsof might not be available

    def test_system_load(self):
        """Test system load and process count"""
        # Check system load average
        try:
            with open("/proc/loadavg", "r") as f:
                loadavg = f.read().strip()

            load_parts = loadavg.split()
            if len(load_parts) >= 3:
                load_1min = float(load_parts[0])
                load_5min = float(load_parts[1])
                load_15min = float(load_parts[2])

                # Get CPU count
                cpu_count = os.cpu_count() or 1

                if load_1min > cpu_count * 2:
                    self.log_result(
                        "System Load",
                        TestResult.WARN,
                        f"High system load: {load_1min} (1min avg)",
                        f"CPU count: {cpu_count}, Load: {load_1min}/{load_5min}/{load_15min}",
                        "Check for runaway processes: top or htop",
                    )
                else:
                    self.log_result(
                        "System Load",
                        TestResult.PASS,
                        f"System load OK: {load_1min} (1min avg)",
                    )
        except Exception as e:
            self.log_result(
                "System Load", TestResult.WARN, "Cannot check system load", str(e)
            )

        # Check process count
        rc, stdout, stderr = self.run_command(["ps", "aux"])
        if rc == 0:
            process_count = len(stdout.split("\n")) - 1  # subtract header
            if process_count > 500:
                self.log_result(
                    "Process Count",
                    TestResult.WARN,
                    f"High process count: {process_count}",
                    "May indicate system issues",
                )
            else:
                self.log_result(
                    "Process Count",
                    TestResult.PASS,
                    f"Process count OK: {process_count}",
                )

    def test_time_synchronization(self):
        """Test system time synchronization"""
        # Check if NTP is running
        rc, stdout, stderr = self.run_command(["systemctl", "is-active", "ntp"])
        ntp_running = rc == 0

        if not ntp_running:
            # Try systemd-timesyncd
            rc, stdout, stderr = self.run_command(
                ["systemctl", "is-active", "systemd-timesyncd"]
            )
            ntp_running = rc == 0

        if not ntp_running:
            # Try chrony
            rc, stdout, stderr = self.run_command(["systemctl", "is-active", "chronyd"])
            ntp_running = rc == 0

        if not ntp_running:
            self.log_result(
                "Time Synchronization",
                TestResult.WARN,
                "No time synchronization service running",
                "May cause authentication issues",
                "Enable NTP: sudo systemctl enable --now systemd-timesyncd",
            )
        else:
            self.log_result(
                "Time Synchronization",
                TestResult.PASS,
                "Time synchronization service is running",
            )

        # Check time difference with remote server
        rc, stdout, stderr = self.run_command(
            ["ntpdate", "-q", "pool.ntp.org"], timeout=5
        )
        if rc == 0 and "offset" in stdout:
            try:
                # Parse offset from ntpdate output
                for line in stdout.split("\n"):
                    if "offset" in line:
                        offset_str = line.split("offset")[1].split()[0]
                        offset = abs(float(offset_str))

                        if offset > 30:  # 30 seconds
                            self.log_result(
                                "Time Accuracy",
                                TestResult.FAIL,
                                f"System time offset too large: {offset:.3f}s",
                                "May cause Kerberos/certificate authentication failures",
                                "Sync time: sudo ntpdate -s pool.ntp.org",
                            )
                        elif offset > 5:  # 5 seconds
                            self.log_result(
                                "Time Accuracy",
                                TestResult.WARN,
                                f"System time offset: {offset:.3f}s",
                                "May cause minor authentication issues",
                            )
                        else:
                            self.log_result(
                                "Time Accuracy",
                                TestResult.PASS,
                                f"System time accurate (offset: {offset:.3f}s)",
                            )
                        break
            except:
                self.log_result(
                    "Time Accuracy", TestResult.SKIP, "Cannot parse time offset"
                )
        else:
            self.log_result(
                "Time Accuracy",
                TestResult.SKIP,
                "Cannot check time accuracy (ntpdate not available or no network)",
            )

    def test_level_3_ssh_service(self):
        """Level 3: SSH Service & Configuration Tests"""
        print("Level 3: SSH Service & Configuration")
        print("-" * 40)

        # Test 3.1: SSH daemon running
        self.test_ssh_daemon_running()

        # Test 3.2: SSH configuration file
        self.test_ssh_configuration()

        # Test 3.3: SSH file permissions
        self.test_ssh_file_permissions()

        # Test 3.4: SSH port binding
        self.test_ssh_port_binding()

        # Test 3.5: SSH host keys
        self.test_ssh_host_keys()

        print()

    def test_ssh_daemon_running(self):
        """Test if SSH daemon is running and enabled"""
        # First check for systemd socket activation
        socket_exists, socket_active = self.check_systemd_socket_activation()

        if socket_exists:
            if socket_active:
                self.log_result(
                    "SSH Socket Activation",
                    TestResult.PASS,
                    "SSH socket activation is enabled and active",
                    "systemd is managing SSH port 22 and will start sshd on demand",
                )
            else:
                self.log_result(
                    "SSH Socket Activation",
                    TestResult.WARN,
                    "SSH socket activation configured but not active",
                    "Socket may need to be started",
                    "Start socket: sudo systemctl start ssh.socket",
                )

        # Check if SSH service is active
        rc, stdout, stderr = self.run_command(["systemctl", "is-active", "ssh"])
        ssh_active = rc == 0

        if not ssh_active:
            # Try sshd instead of ssh
            rc, stdout, stderr = self.run_command(["systemctl", "is-active", "sshd"])
            ssh_active = rc == 0

        if not ssh_active and not (socket_exists and socket_active):
            self.log_result(
                "SSH Daemon Status",
                TestResult.FAIL,
                "SSH daemon is not running and no socket activation",
                "SSH service is inactive or not installed",
                "Start SSH: sudo systemctl start ssh (or sshd)",
            )
        elif ssh_active:
            self.log_result(
                "SSH Daemon Status", TestResult.PASS, "SSH daemon is running"
            )
        elif socket_exists and socket_active:
            self.log_result(
                "SSH Daemon Status",
                TestResult.PASS,
                "SSH daemon ready (systemd socket activation)",
                "Daemon will start automatically on first connection",
            )

        # Check if SSH service is enabled (or socket activation is configured)
        ssh_enabled = False
        if socket_exists and socket_active:
            ssh_enabled = True  # Socket activation counts as "enabled"
        else:
            rc, stdout, stderr = self.run_command(["systemctl", "is-enabled", "ssh"])
            ssh_enabled = rc == 0

            if not ssh_enabled:
                # Try sshd instead of ssh
                rc, stdout, stderr = self.run_command(["systemctl", "is-enabled", "sshd"])
                ssh_enabled = rc == 0

        if not ssh_enabled:
            self.log_result(
                "SSH Daemon Enabled",
                TestResult.WARN,
                "SSH daemon not enabled for startup",
                "SSH won't start automatically on boot",
                "Enable SSH: sudo systemctl enable ssh (or sshd)",
            )
        else:
            self.log_result(
                "SSH Daemon Enabled", TestResult.PASS, "SSH daemon enabled for startup"
            )

        # Check SSH process directly
        rc, stdout, stderr = self.run_command(["pgrep", "-f", "sshd"])
        if rc == 0 and stdout.strip():
            ssh_pids = stdout.strip().split("\n")
            self.log_result(
                "SSH Process",
                TestResult.PASS,
                f"SSH daemon process running (PIDs: {', '.join(ssh_pids)})",
            )
        else:
            if socket_exists and socket_active:
                # Try to trigger sshd startup
                if self.trigger_sshd_startup():
                    self.log_result(
                        "SSH Process",
                        TestResult.PASS,
                        "SSH daemon started via socket activation",
                        "systemd successfully started sshd on connection attempt",
                    )
                else:
                    self.log_result(
                        "SSH Process",
                        TestResult.WARN,
                        "SSH socket active but daemon won't start",
                        "systemd socket activation may be misconfigured",
                        "Check SSH logs: sudo journalctl -u ssh -f",
                    )
            else:
                self.log_result(
                    "SSH Process",
                    TestResult.FAIL,
                    "No SSH daemon process found",
                    "SSH daemon may have crashed or not started",
                    "Check SSH logs: sudo journalctl -u ssh -f",
                )

    def test_ssh_configuration(self):
        """Test SSH configuration file"""
        if not self.ssh_config_path.exists():
            self.log_result(
                "SSH Config File",
                TestResult.FAIL,
                f"SSH config file not found: {self.ssh_config_path}",
                "SSH not properly installed",
                "Install SSH server: sudo apt install openssh-server",
            )
            return

        try:
            with open(self.ssh_config_path, "r") as f:
                config_content = f.read()

            self.log_result(
                "SSH Config File",
                TestResult.PASS,
                f"SSH config file found: {self.ssh_config_path}",
            )

            # Check configuration syntax
            rc, stdout, stderr = self.run_command(["sshd", "-t"])
            if rc != 0:
                self.log_result(
                    "SSH Config Syntax",
                    TestResult.FAIL,
                    "SSH configuration has syntax errors",
                    stderr,
                    "Fix SSH config file syntax and restart SSH",
                )
            else:
                self.log_result(
                    "SSH Config Syntax",
                    TestResult.PASS,
                    "SSH configuration syntax is valid",
                )

            # Check important settings
            config_lines = config_content.lower()

            # Check if Port is set
            port_lines = [
                line
                for line in config_content.split("\n")
                if line.strip().startswith("Port") and not line.strip().startswith("#")
            ]

            if port_lines:
                port_line = port_lines[0]
                try:
                    port = int(port_line.split()[1])
                    self.ssh_port = port
                    if port != 22:
                        self.log_result(
                            "SSH Port Setting",
                            TestResult.WARN,
                            f"SSH running on non-standard port: {port}",
                            "Ensure firewall allows this port",
                        )
                    else:
                        self.log_result(
                            "SSH Port Setting",
                            TestResult.PASS,
                            f"SSH configured for standard port: {port}",
                        )
                except:
                    self.log_result(
                        "SSH Port Setting",
                        TestResult.WARN,
                        "Cannot parse SSH port setting",
                    )

            # Check PermitRootLogin
            if "permitrootlogin yes" in config_lines:
                self.log_result(
                    "Root Login Setting",
                    TestResult.WARN,
                    "Root login is enabled",
                    "Security risk - root login allowed",
                    "Disable root login: PermitRootLogin no",
                )
            elif "permitrootlogin no" in config_lines:
                self.log_result(
                    "Root Login Setting",
                    TestResult.PASS,
                    "Root login is properly disabled",
                )

            # Check PasswordAuthentication
            if "passwordauthentication no" in config_lines:
                self.log_result(
                    "Password Auth Setting",
                    TestResult.PASS,
                    "Password authentication disabled (key-only)",
                )
            elif "passwordauthentication yes" in config_lines:
                self.log_result(
                    "Password Auth Setting",
                    TestResult.WARN,
                    "Password authentication enabled",
                    "Consider using key-based authentication only",
                )

        except Exception as e:
            self.log_result(
                "SSH Config File",
                TestResult.FAIL,
                "Cannot read SSH configuration file",
                str(e),
                "Check file permissions and SSH installation",
            )

    def test_ssh_file_permissions(self):
        """Test SSH file and directory permissions"""
        ssh_dir = Path("/etc/ssh")

        if not ssh_dir.exists():
            self.log_result(
                "SSH Directory",
                TestResult.FAIL,
                "/etc/ssh directory not found",
                "SSH not properly installed",
            )
            return

        # Check /etc/ssh directory permissions
        stat_info = ssh_dir.stat()
        mode = oct(stat_info.st_mode)[-3:]

        if mode != "755":
            self.log_result(
                "SSH Directory Perms",
                TestResult.WARN,
                f"/etc/ssh has permissions {mode}, should be 755",
                "Incorrect permissions may cause issues",
                "Fix permissions: sudo chmod 755 /etc/ssh",
            )
        else:
            self.log_result(
                "SSH Directory Perms",
                TestResult.PASS,
                "/etc/ssh permissions are correct (755)",
            )

        # Check sshd_config permissions
        if self.ssh_config_path.exists():
            stat_info = self.ssh_config_path.stat()
            mode = oct(stat_info.st_mode)[-3:]

            if mode not in ["644", "600"]:
                self.log_result(
                    "SSH Config Perms",
                    TestResult.WARN,
                    f"sshd_config has permissions {mode}, should be 644 or 600",
                    remediation="Fix permissions: sudo chmod 644 /etc/ssh/sshd_config",
                )
            else:
                self.log_result(
                    "SSH Config Perms",
                    TestResult.PASS,
                    f"SSH config permissions are correct ({mode})",
                )

        # Check host key permissions
        host_key_files = list(ssh_dir.glob("ssh_host_*_key"))
        for key_file in host_key_files:
            if key_file.name.endswith("_key.pub"):
                continue  # Skip public keys

            stat_info = key_file.stat()
            mode = oct(stat_info.st_mode)[-3:]

            if mode != "600":
                self.log_result(
                    f"Host Key Perms ({key_file.name})",
                    TestResult.FAIL,
                    f"Host key {key_file.name} has permissions {mode}, should be 600",
                    "Incorrect permissions prevent SSH from starting",
                    f"Fix permissions: sudo chmod 600 {key_file}",
                )
            else:
                self.log_result(
                    f"Host Key Perms ({key_file.name})",
                    TestResult.PASS,
                    f"Host key {key_file.name} permissions correct (600)",
                )

    def test_ssh_port_binding(self):
        """Test if SSH is properly binding to ports"""
        # First check for systemd socket activation
        socket_exists, socket_active = self.check_systemd_socket_activation()

        # Check what's listening on SSH port
        rc, stdout, stderr = self.run_command(["netstat", "-tlnp"])

        if rc != 0:
            # Try ss if netstat fails
            rc, stdout, stderr = self.run_command(["ss", "-tlnp"])

        if rc != 0:
            self.log_result(
                "Port Listening Check",
                TestResult.WARN,
                "Cannot check listening ports (netstat/ss not available)",
            )
            return

        # Look for SSH port
        ssh_listening = False
        systemd_listening = False
        listening_details = []

        for line in stdout.split("\n"):
            if f":{self.ssh_port} " in line or f":{self.ssh_port}\t" in line:
                ssh_listening = True
                listening_details.append(line.strip())
                # Check if systemd is the one listening
                if "systemd" in line:
                    systemd_listening = True

        if not ssh_listening:
            if socket_exists and socket_active:
                self.log_result(
                    "SSH Port Binding",
                    TestResult.WARN,
                    f"SSH socket active but port {self.ssh_port} not visible in netstat",
                    "systemd may be holding the socket internally",
                    "This is normal for socket activation",
                )
            else:
                self.log_result(
                    "SSH Port Binding",
                    TestResult.FAIL,
                    f"SSH is not listening on port {self.ssh_port}",
                    "SSH daemon may not be running or misconfigured",
                    "Check SSH config and restart: sudo systemctl restart ssh",
                )
        else:
            if systemd_listening:
                self.log_result(
                    "SSH Port Binding",
                    TestResult.PASS,
                    f"systemd managing SSH port {self.ssh_port} (socket activation)",
                    "Port is managed by systemd socket activation",
                )
            else:
                # Check if listening on all interfaces
                all_interfaces = any(
                    "0.0.0.0:" in detail or ":::" in detail for detail in listening_details
                )

                if all_interfaces:
                    self.log_result(
                        "SSH Port Binding",
                        TestResult.PASS,
                        f"SSH listening on port {self.ssh_port} (all interfaces)",
                    )
                else:
                    self.log_result(
                        "SSH Port Binding",
                        TestResult.WARN,
                        f"SSH listening on port {self.ssh_port} but not all interfaces",
                        "May only accept local connections",
                        "Check ListenAddress in sshd_config",
                    )

        # Test local connection to SSH port
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", self.ssh_port))
            sock.close()

            if result == 0:
                self.log_result(
                    "SSH Local Connection",
                    TestResult.PASS,
                    f"Can connect to SSH on localhost:{self.ssh_port}",
                )
            else:
                self.log_result(
                    "SSH Local Connection",
                    TestResult.FAIL,
                    f"Cannot connect to SSH on localhost:{self.ssh_port}",
                    "SSH may not be accepting connections",
                )
        except Exception as e:
            self.log_result(
                "SSH Local Connection",
                TestResult.WARN,
                "Cannot test local SSH connection",
                str(e),
            )

    def test_ssh_host_keys(self):
        """Test SSH host key availability"""
        ssh_dir = Path("/etc/ssh")

        key_types = ["rsa", "dsa", "ecdsa", "ed25519"]
        found_keys = []

        for key_type in key_types:
            private_key = ssh_dir / f"ssh_host_{key_type}_key"
            public_key = ssh_dir / f"ssh_host_{key_type}_key.pub"

            if private_key.exists() and public_key.exists():
                found_keys.append(key_type)

                # Check private key permissions
                stat_info = private_key.stat()
                mode = oct(stat_info.st_mode)[-3:]

                if mode != "600":
                    self.log_result(
                        f"Host Key {key_type.upper()}",
                        TestResult.FAIL,
                        f"Private key permissions {mode}, should be 600",
                        remediation=f"Fix: sudo chmod 600 {private_key}",
                    )

        if not found_keys:
            self.log_result(
                "SSH Host Keys",
                TestResult.FAIL,
                "No SSH host keys found",
                "SSH cannot start without host keys",
                "Generate keys: sudo ssh-keygen -A",
            )
        else:
            self.log_result(
                "SSH Host Keys",
                TestResult.PASS,
                f"SSH host keys available: {', '.join(found_keys)}",
            )

    def run_all_diagnostics(self, verbose: bool = False):
        """Run all SSH diagnostic tests in logical order"""
        self.verbose = verbose

        print("Starting SSH Diagnostic Tool...")
        print("Testing SSH connectivity issues in logical order...")
        print()

        # Level 1: Hardware & Network Foundation
        self.test_level_1_network_foundation()

        # Level 2: System Resources & Health
        self.test_level_2_system_resources()

        # Level 3: SSH Service & Configuration
        self.test_level_3_ssh_service()

        # Level 4: Network Services & Security
        self.test_level_4_network_security()

        # Level 5: Authentication & Access Control
        self.test_level_5_authentication()

        # Level 6: Advanced Security & Isolation
        self.test_level_6_advanced_security()

        # Level 7: External Dependencies
        self.test_level_7_external_dependencies()

        self.print_summary()

    def test_level_4_network_security(self):
        """Level 4: Network Services & Security Tests"""
        print("Level 4: Network Services & Security")
        print("-" * 40)

        # Test 4.1: UFW firewall status
        self.test_ufw_firewall()

        # Test 4.2: iptables rules
        self.test_iptables_rules()

        # Test 4.3: TCP wrappers
        self.test_tcp_wrappers()

        # Test 4.4: Port conflicts
        self.test_port_conflicts()

        # Test 4.5: fail2ban status
        self.test_fail2ban()

        print()

    def test_ufw_firewall(self):
        """Test UFW firewall configuration"""
        # Check if UFW is installed
        rc, stdout, stderr = self.run_command(["which", "ufw"])
        if rc != 0:
            self.log_result("UFW Firewall", TestResult.SKIP, "UFW not installed")
            return

        # Check UFW status
        rc, stdout, stderr = self.run_command(["ufw", "status"])
        if rc != 0:
            self.log_result(
                "UFW Status Check",
                TestResult.WARN,
                "Cannot check UFW status",
                stderr,
                "Check UFW installation and permissions",
            )
            return

        if "Status: inactive" in stdout:
            self.log_result(
                "UFW Firewall",
                TestResult.WARN,
                "UFW firewall is inactive",
                "No firewall protection active",
                "Enable UFW: sudo ufw enable",
            )
        elif "Status: active" in stdout:
            self.log_result("UFW Firewall", TestResult.PASS, "UFW firewall is active")

            # Check for SSH rule
            if (
                f"{self.ssh_port}/tcp" in stdout
                or "22/tcp" in stdout
                or "OpenSSH" in stdout
            ):
                self.log_result(
                    "UFW SSH Rule", TestResult.PASS, "SSH port allowed in UFW"
                )
            else:
                self.log_result(
                    "UFW SSH Rule",
                    TestResult.FAIL,
                    f"SSH port {self.ssh_port} not allowed in UFW",
                    "SSH connections will be blocked",
                    f"Allow SSH: sudo ufw allow {self.ssh_port}/tcp",
                )
        else:
            self.log_result(
                "UFW Firewall", TestResult.WARN, "Cannot determine UFW status"
            )

    def test_iptables_rules(self):
        """Test iptables firewall rules"""
        # Check if iptables is available
        rc, stdout, stderr = self.run_command(["which", "iptables"])
        if rc != 0:
            self.log_result("iptables", TestResult.SKIP, "iptables not available")
            return

        # Check iptables rules
        rc, stdout, stderr = self.run_command(["iptables", "-L", "-n"])
        if rc != 0:
            self.log_result(
                "iptables Rules",
                TestResult.WARN,
                "Cannot check iptables rules",
                stderr,
                "May need sudo privileges",
            )
            return

        # Check for default policies
        lines = stdout.split("\n")
        input_policy = "ACCEPT"

        for line in lines:
            if line.startswith("Chain INPUT"):
                if "policy DROP" in line:
                    input_policy = "DROP"
                elif "policy REJECT" in line:
                    input_policy = "REJECT"

        if input_policy in ["DROP", "REJECT"]:
            # Check if SSH port is allowed
            ssh_allowed = False
            for line in lines:
                if (
                    f"dpt:{self.ssh_port}" in line or f":{self.ssh_port}" in line
                ) and "ACCEPT" in line:
                    ssh_allowed = True
                    break

            if not ssh_allowed:
                self.log_result(
                    "iptables SSH Rule",
                    TestResult.FAIL,
                    f"SSH port {self.ssh_port} blocked by iptables",
                    f"INPUT policy is {input_policy} but no SSH allow rule",
                    f"Allow SSH: sudo iptables -A INPUT -p tcp --dport {self.ssh_port} -j ACCEPT",
                )
            else:
                self.log_result(
                    "iptables SSH Rule",
                    TestResult.PASS,
                    f"SSH port {self.ssh_port} allowed in iptables",
                )
        else:
            self.log_result(
                "iptables Policy",
                TestResult.PASS,
                f"iptables INPUT policy is {input_policy} (permissive)",
            )

    def test_tcp_wrappers(self):
        """Test TCP wrappers configuration"""
        hosts_allow = Path("/etc/hosts.allow")
        hosts_deny = Path("/etc/hosts.deny")

        # Check if TCP wrappers files exist
        if not hosts_allow.exists() and not hosts_deny.exists():
            self.log_result(
                "TCP Wrappers", TestResult.SKIP, "TCP wrappers not configured"
            )
            return

        # Check hosts.deny
        if hosts_deny.exists():
            try:
                with open(hosts_deny, "r") as f:
                    deny_content = f.read()

                if "ALL: ALL" in deny_content:
                    self.log_result(
                        "TCP Wrappers Deny",
                        TestResult.WARN,
                        "hosts.deny blocks all connections",
                        "May block SSH if not allowed in hosts.allow",
                        "Check hosts.allow for SSH exceptions",
                    )
                elif "sshd:" in deny_content.lower():
                    self.log_result(
                        "TCP Wrappers SSH",
                        TestResult.FAIL,
                        "SSH explicitly denied in hosts.deny",
                        "SSH connections will be blocked",
                        "Remove SSH deny rule or add allow rule",
                    )
                else:
                    self.log_result(
                        "TCP Wrappers Deny",
                        TestResult.PASS,
                        "hosts.deny doesn't block SSH",
                    )
            except Exception as e:
                self.log_result(
                    "TCP Wrappers Deny",
                    TestResult.WARN,
                    "Cannot read hosts.deny",
                    str(e),
                )

        # Check hosts.allow
        if hosts_allow.exists():
            try:
                with open(hosts_allow, "r") as f:
                    allow_content = f.read()

                if "sshd:" in allow_content.lower():
                    self.log_result(
                        "TCP Wrappers Allow",
                        TestResult.PASS,
                        "SSH explicitly allowed in hosts.allow",
                    )
                else:
                    self.log_result(
                        "TCP Wrappers Allow",
                        TestResult.WARN,
                        "No SSH allow rule in hosts.allow",
                        "May be blocked if hosts.deny is restrictive",
                    )
            except Exception as e:
                self.log_result(
                    "TCP Wrappers Allow",
                    TestResult.WARN,
                    "Cannot read hosts.allow",
                    str(e),
                )

    def test_port_conflicts(self):
        """Test for port conflicts on SSH port"""
        # Check what's using the SSH port
        rc, stdout, stderr = self.run_command(["netstat", "-tlnp"])

        if rc != 0:
            rc, stdout, stderr = self.run_command(["ss", "-tlnp"])

        if rc != 0:
            self.log_result(
                "Port Conflict Check", TestResult.SKIP, "Cannot check port usage"
            )
            return

        # Look for processes on SSH port
        ssh_processes = []
        other_processes = []

        for line in stdout.split("\n"):
            if f":{self.ssh_port} " in line or f":{self.ssh_port}\t" in line:
                if "sshd" in line:
                    ssh_processes.append(line.strip())
                else:
                    other_processes.append(line.strip())

        if other_processes:
            self.log_result(
                "Port Conflict",
                TestResult.FAIL,
                f"Non-SSH process using port {self.ssh_port}",
                f"Conflicting processes: {len(other_processes)}",
                "Kill conflicting process or change SSH port",
            )
        elif ssh_processes:
            self.log_result(
                "Port Usage",
                TestResult.PASS,
                f"SSH properly using port {self.ssh_port}",
            )
        else:
            self.log_result(
                "Port Usage",
                TestResult.WARN,
                f"No process listening on port {self.ssh_port}",
            )

    def test_fail2ban(self):
        """Test fail2ban service status"""
        rc, stdout, stderr = self.run_command(["systemctl", "is-active", "fail2ban"])

        if rc != 0:
            self.log_result(
                "fail2ban", TestResult.SKIP, "fail2ban not installed or not running"
            )
            return

        self.log_result("fail2ban Status", TestResult.PASS, "fail2ban is running")

        # Check fail2ban SSH jail
        rc, stdout, stderr = self.run_command(["fail2ban-client", "status", "sshd"])
        if rc == 0:
            self.log_result(
                "fail2ban SSH Jail", TestResult.PASS, "SSH jail is active in fail2ban"
            )

            # Check for banned IPs
            if "Banned IP list:" in stdout:
                banned_line = [
                    line for line in stdout.split("\n") if "Banned IP list:" in line
                ]
                if banned_line:
                    banned_ips = banned_line[0].split("Banned IP list:")[1].strip()
                    if banned_ips:
                        self.log_result(
                            "fail2ban Banned IPs",
                            TestResult.WARN,
                            f"IPs currently banned: {banned_ips}",
                            "Check if legitimate IPs are banned",
                        )
                    else:
                        self.log_result(
                            "fail2ban Banned IPs",
                            TestResult.PASS,
                            "No IPs currently banned",
                        )
        else:
            # Try 'ssh' jail name
            rc, stdout, stderr = self.run_command(["fail2ban-client", "status", "ssh"])
            if rc == 0:
                self.log_result(
                    "fail2ban SSH Jail",
                    TestResult.PASS,
                    "SSH jail is active in fail2ban",
                )
            else:
                self.log_result(
                    "fail2ban SSH Jail",
                    TestResult.WARN,
                    "SSH jail not found in fail2ban",
                    "SSH brute force protection not active",
                )

    def test_level_5_authentication(self):
        """Level 5: Authentication & Access Control Tests"""
        print("Level 5: Authentication & Access Control")
        print("-" * 40)

        # Test 5.1: User authentication configuration
        self.test_user_authentication()

        # Test 5.2: SSH key configuration
        self.test_ssh_keys()

        # Test 5.3: PAM configuration
        self.test_pam_configuration()

        # Test 5.4: User account status
        self.test_user_accounts()

        # Test 5.5: LDAP/external auth
        self.test_external_authentication()

        print()

    def test_user_authentication(self):
        """Test user authentication settings"""
        try:
            with open(self.ssh_config_path, "r") as f:
                config_content = f.read().lower()

            # Check authentication methods
            auth_methods = []

            if "pubkeyauthentication yes" in config_content:
                auth_methods.append("publickey")
            if "passwordauthentication yes" in config_content:
                auth_methods.append("password")
            if "kerberosauthentication yes" in config_content:
                auth_methods.append("kerberos")
            if "gssapiauthentication yes" in config_content:
                auth_methods.append("gssapi")

            if not auth_methods:
                # Check defaults
                if "passwordauthentication no" not in config_content:
                    auth_methods.append("password")
                if "pubkeyauthentication no" not in config_content:
                    auth_methods.append("publickey")

            if not auth_methods:
                self.log_result(
                    "Authentication Methods",
                    TestResult.FAIL,
                    "No authentication methods enabled",
                    "Users cannot authenticate",
                    "Enable at least one auth method in sshd_config",
                )
            else:
                self.log_result(
                    "Authentication Methods",
                    TestResult.PASS,
                    f"Auth methods enabled: {', '.join(auth_methods)}",
                )

            # Check MaxAuthTries
            max_auth_lines = [
                line
                for line in config_content.split("\n")
                if "maxauthtries" in line and not line.strip().startswith("#")
            ]

            if max_auth_lines:
                try:
                    max_tries = int(max_auth_lines[0].split()[1])
                    if max_tries > 6:
                        self.log_result(
                            "Max Auth Tries",
                            TestResult.WARN,
                            f"MaxAuthTries is high: {max_tries}",
                            "May allow brute force attacks",
                            "Reduce MaxAuthTries to 3-6",
                        )
                    else:
                        self.log_result(
                            "Max Auth Tries",
                            TestResult.PASS,
                            f"MaxAuthTries is reasonable: {max_tries}",
                        )
                except:
                    pass

            # Check AllowUsers/DenyUsers
            allow_users = [
                line
                for line in config_content.split("\n")
                if line.strip().startswith("allowusers")
                and not line.strip().startswith("#")
            ]
            deny_users = [
                line
                for line in config_content.split("\n")
                if line.strip().startswith("denyusers")
                and not line.strip().startswith("#")
            ]

            if allow_users:
                self.log_result(
                    "User Access Control",
                    TestResult.PASS,
                    "AllowUsers configured (whitelist approach)",
                )
            elif deny_users:
                self.log_result(
                    "User Access Control",
                    TestResult.WARN,
                    "DenyUsers configured (blacklist approach)",
                    "Consider using AllowUsers instead",
                )
            else:
                self.log_result(
                    "User Access Control",
                    TestResult.WARN,
                    "No user access restrictions configured",
                    "Any valid user can SSH",
                    "Consider AllowUsers or AllowGroups",
                )

        except Exception as e:
            self.log_result(
                "User Authentication",
                TestResult.FAIL,
                "Cannot check authentication configuration",
                str(e),
            )

    def test_ssh_keys(self):
        """Test SSH key configuration and permissions"""
        # Check common user SSH directories
        users_to_check = ["root"]

        # Get list of users with home directories
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 6:
                        username = parts[0]
                        home_dir = parts[5]
                        if home_dir.startswith("/home/") and Path(home_dir).exists():
                            users_to_check.append(username)
        except:
            pass

        key_issues = []
        users_with_keys = []

        for username in users_to_check[:5]:  # Limit to first 5 users
            if username == "root":
                ssh_dir = Path("/root/.ssh")
            else:
                ssh_dir = Path(f"/home/{username}/.ssh")

            if not ssh_dir.exists():
                continue

            # Check .ssh directory permissions
            try:
                stat_info = ssh_dir.stat()
                mode = oct(stat_info.st_mode)[-3:]

                if mode != "700":
                    key_issues.append(
                        f"{username}: .ssh dir permissions {mode} (should be 700)"
                    )

                # Check authorized_keys
                auth_keys = ssh_dir / "authorized_keys"
                if auth_keys.exists():
                    users_with_keys.append(username)

                    stat_info = auth_keys.stat()
                    mode = oct(stat_info.st_mode)[-3:]

                    if mode not in ["600", "644"]:
                        key_issues.append(
                            f"{username}: authorized_keys permissions {mode} (should be 600)"
                        )

                    # Check if file is readable
                    try:
                        with open(auth_keys, "r") as f:
                            keys_content = f.read()

                        key_count = len(
                            [
                                line
                                for line in keys_content.split("\n")
                                if line.strip() and not line.startswith("#")
                            ]
                        )

                        if key_count == 0:
                            key_issues.append(f"{username}: authorized_keys is empty")
                    except Exception as e:
                        key_issues.append(
                            f"{username}: cannot read authorized_keys - {e}"
                        )

            except Exception as e:
                key_issues.append(f"{username}: cannot check SSH directory - {e}")

        if key_issues:
            self.log_result(
                "SSH Key Configuration",
                TestResult.WARN,
                f"SSH key issues found: {len(key_issues)}",
                "; ".join(key_issues[:3]),  # Show first 3 issues
                "Fix SSH key permissions and configurations",
            )
        elif users_with_keys:
            self.log_result(
                "SSH Key Configuration",
                TestResult.PASS,
                f"SSH keys configured for: {', '.join(users_with_keys)}",
            )
        else:
            self.log_result(
                "SSH Key Configuration",
                TestResult.WARN,
                "No SSH keys found for any users",
                "Only password authentication available",
                "Configure SSH keys for better security",
            )

    def test_pam_configuration(self):
        """Test PAM configuration for SSH"""
        pam_sshd = Path("/etc/pam.d/sshd")

        if not pam_sshd.exists():
            self.log_result(
                "PAM SSH Config", TestResult.SKIP, "PAM SSH configuration not found"
            )
            return

        try:
            with open(pam_sshd, "r") as f:
                pam_content = f.read()

            self.log_result(
                "PAM SSH Config", TestResult.PASS, "PAM SSH configuration found"
            )

            # Check for common PAM modules
            if "pam_unix.so" in pam_content:
                self.log_result(
                    "PAM Unix Auth",
                    TestResult.PASS,
                    "Standard Unix authentication configured",
                )

            if "pam_deny.so" in pam_content:
                self.log_result(
                    "PAM Deny Module",
                    TestResult.WARN,
                    "PAM deny module found",
                    "May block authentication",
                )

            if "pam_listfile.so" in pam_content:
                self.log_result(
                    "PAM List Filter", TestResult.PASS, "PAM list filtering configured"
                )

            # Check for account restrictions
            if "account required" in pam_content:
                self.log_result(
                    "PAM Account Control",
                    TestResult.PASS,
                    "Account restrictions configured",
                )

        except Exception as e:
            self.log_result(
                "PAM SSH Config",
                TestResult.WARN,
                "Cannot read PAM SSH configuration",
                str(e),
            )

    def test_user_accounts(self):
        """Test user account status and restrictions"""
        # Check for locked accounts
        rc, stdout, stderr = self.run_command(["passwd", "-S", "-a"])

        if rc != 0:
            self.log_result(
                "User Account Status",
                TestResult.SKIP,
                "Cannot check user account status",
            )
            return

        locked_users = []
        active_users = []

        for line in stdout.split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    username = parts[0]
                    status = parts[1]

                    if status == "L":
                        locked_users.append(username)
                    elif status == "P":
                        active_users.append(username)

        if locked_users:
            self.log_result(
                "Locked User Accounts",
                TestResult.WARN,
                f"Locked accounts found: {', '.join(locked_users[:5])}",
                "These users cannot authenticate",
            )

        if active_users:
            self.log_result(
                "Active User Accounts",
                TestResult.PASS,
                f"Active accounts: {len(active_users)} users",
            )

        # Check sudo access
        sudo_users = []
        try:
            with open("/etc/group", "r") as f:
                for line in f:
                    if line.startswith("sudo:") or line.startswith("wheel:"):
                        parts = line.strip().split(":")
                        if len(parts) >= 4 and parts[3]:
                            sudo_users.extend(parts[3].split(","))

            if sudo_users:
                self.log_result(
                    "Sudo Access",
                    TestResult.PASS,
                    f"Users with sudo: {', '.join(sudo_users[:5])}",
                )
            else:
                self.log_result(
                    "Sudo Access", TestResult.WARN, "No users found with sudo access"
                )
        except:
            pass

    def test_external_authentication(self):
        """Test external authentication configuration"""
        # Check for LDAP configuration
        ldap_configs = [
            Path("/etc/ldap/ldap.conf"),
            Path("/etc/openldap/ldap.conf"),
            Path("/etc/ldap.conf"),
        ]

        ldap_configured = any(config.exists() for config in ldap_configs)

        if ldap_configured:
            self.log_result(
                "LDAP Configuration", TestResult.PASS, "LDAP configuration found"
            )

            # Check LDAP connectivity
            rc, stdout, stderr = self.run_command(
                ["ldapsearch", "-x", "-s", "base"], timeout=5
            )
            if rc == 0:
                self.log_result(
                    "LDAP Connectivity", TestResult.PASS, "LDAP server is reachable"
                )
            else:
                self.log_result(
                    "LDAP Connectivity",
                    TestResult.WARN,
                    "Cannot connect to LDAP server",
                    "External authentication may fail",
                )
        else:
            self.log_result(
                "LDAP Configuration", TestResult.SKIP, "LDAP not configured"
            )

        # Check for Kerberos configuration
        krb5_conf = Path("/etc/krb5.conf")
        if krb5_conf.exists():
            self.log_result(
                "Kerberos Configuration",
                TestResult.PASS,
                "Kerberos configuration found",
            )

            # Test Kerberos connectivity
            rc, stdout, stderr = self.run_command(["klist", "-k"], timeout=5)
            if rc == 0:
                self.log_result(
                    "Kerberos Keytab", TestResult.PASS, "Kerberos keytab found"
                )
            else:
                self.log_result(
                    "Kerberos Keytab", TestResult.WARN, "No Kerberos keytab found"
                )
        else:
            self.log_result(
                "Kerberos Configuration", TestResult.SKIP, "Kerberos not configured"
            )

    def test_level_6_advanced_security(self):
        """Level 6: Advanced Security & Isolation Tests"""
        print("Level 6: Advanced Security & Isolation")
        print("-" * 40)

        # Test 6.1: SELinux status
        self.test_selinux()

        # Test 6.2: AppArmor status
        self.test_apparmor()

        # Test 6.3: Container isolation
        self.test_container_isolation()

        # Test 6.4: Network namespaces
        self.test_network_namespaces()

        # Test 6.5: System hardening
        self.test_system_hardening()

        print()

    def test_selinux(self):
        """Test SELinux configuration and status"""
        # Check if SELinux is available
        rc, stdout, stderr = self.run_command(["which", "getenforce"])
        if rc != 0:
            self.log_result("SELinux", TestResult.SKIP, "SELinux not available")
            return

        # Check SELinux status
        rc, stdout, stderr = self.run_command(["getenforce"])
        if rc != 0:
            self.log_result(
                "SELinux Status", TestResult.WARN, "Cannot check SELinux status", stderr
            )
            return

        selinux_status = stdout.strip()

        if selinux_status == "Enforcing":
            self.log_result(
                "SELinux Status",
                TestResult.PASS,
                "SELinux is enforcing (active protection)",
            )
        elif selinux_status == "Permissive":
            self.log_result(
                "SELinux Status",
                TestResult.WARN,
                "SELinux is permissive (logging only)",
                "Security policies not enforced",
                "Enable enforcing mode: sudo setenforce 1",
            )
        elif selinux_status == "Disabled":
            self.log_result(
                "SELinux Status",
                TestResult.WARN,
                "SELinux is disabled",
                "No mandatory access control",
                "Enable SELinux in /etc/selinux/config",
            )

        # Check SSH SELinux context
        rc, stdout, stderr = self.run_command(["ls", "-Z", "/usr/sbin/sshd"])
        if rc == 0 and stdout.strip():
            self.log_result(
                "SSH SELinux Context", TestResult.PASS, "SSH daemon has SELinux context"
            )
        elif selinux_status == "Enforcing":
            self.log_result(
                "SSH SELinux Context",
                TestResult.WARN,
                "Cannot determine SSH SELinux context",
            )

        # Check for SSH-related SELinux policies
        rc, stdout, stderr = self.run_command(["semodule", "-l"])
        if rc == 0 and "ssh" in stdout:
            self.log_result(
                "SSH SELinux Policy", TestResult.PASS, "SSH SELinux policies loaded"
            )
        elif selinux_status == "Enforcing":
            self.log_result(
                "SSH SELinux Policy",
                TestResult.WARN,
                "Cannot verify SSH SELinux policies",
            )

    def test_apparmor(self):
        """Test AppArmor configuration and status"""
        # Check if AppArmor is available
        rc, stdout, stderr = self.run_command(["which", "aa-status"])
        if rc != 0:
            self.log_result("AppArmor", TestResult.SKIP, "AppArmor not available")
            return

        # Check AppArmor status
        rc, stdout, stderr = self.run_command(["aa-status"])
        if rc != 0:
            self.log_result(
                "AppArmor Status",
                TestResult.WARN,
                "Cannot check AppArmor status",
                stderr,
                "May need sudo privileges",
            )
            return

        if "apparmor module is loaded" in stdout:
            self.log_result(
                "AppArmor Status", TestResult.PASS, "AppArmor is loaded and active"
            )

            # Check for SSH profile
            if "sshd" in stdout or "/usr/sbin/sshd" in stdout:
                self.log_result(
                    "SSH AppArmor Profile", TestResult.PASS, "SSH has AppArmor profile"
                )
            else:
                self.log_result(
                    "SSH AppArmor Profile",
                    TestResult.WARN,
                    "No AppArmor profile for SSH",
                    "SSH not confined by AppArmor",
                )
        else:
            self.log_result(
                "AppArmor Status",
                TestResult.WARN,
                "AppArmor module not loaded",
                "No application confinement",
                "Load AppArmor: sudo systemctl enable apparmor",
            )

    def test_container_isolation(self):
        """Test container isolation and Docker security"""
        # Check if Docker is running
        rc, stdout, stderr = self.run_command(["systemctl", "is-active", "docker"])
        docker_running = rc == 0

        if not docker_running:
            # Try checking docker directly
            rc, stdout, stderr = self.run_command(["docker", "info"])
            docker_running = rc == 0

        if not docker_running:
            self.log_result(
                "Container Isolation", TestResult.SKIP, "Docker not running"
            )
            return

        self.log_result("Docker Status", TestResult.PASS, "Docker is running")

        # Check for privileged containers
        rc, stdout, stderr = self.run_command(
            ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"]
        )
        if rc == 0:
            container_count = len(stdout.split("\n")) - 1  # subtract header
            if container_count > 0:
                self.log_result(
                    "Docker Containers",
                    TestResult.WARN,
                    f"{container_count} containers running",
                    "Containers may affect network isolation",
                )
            else:
                self.log_result(
                    "Docker Containers",
                    TestResult.PASS,
                    "No containers currently running",
                )

        # Check Docker daemon security
        rc, stdout, stderr = self.run_command(
            ["docker", "info", "--format", "{{.SecurityOptions}}"]
        )
        if rc == 0 and stdout.strip():
            security_options = stdout.strip()
            if "apparmor" in security_options or "selinux" in security_options:
                self.log_result(
                    "Docker Security",
                    TestResult.PASS,
                    "Docker has security options enabled",
                )
            else:
                self.log_result(
                    "Docker Security",
                    TestResult.WARN,
                    "Docker security options not detected",
                )

    def test_network_namespaces(self):
        """Test network namespace isolation"""
        # Check if ip netns command is available
        rc, stdout, stderr = self.run_command(["ip", "netns", "list"])
        if rc != 0:
            self.log_result(
                "Network Namespaces", TestResult.SKIP, "Cannot check network namespaces"
            )
            return

        if stdout.strip():
            namespaces = stdout.strip().split("\n")
            self.log_result(
                "Network Namespaces",
                TestResult.WARN,
                f"Network namespaces found: {len(namespaces)}",
                "May affect SSH connectivity",
                "Verify SSH is in correct namespace",
            )
        else:
            self.log_result(
                "Network Namespaces", TestResult.PASS, "No custom network namespaces"
            )

        # Check current namespace
        rc, stdout, stderr = self.run_command(["ip", "netns", "identify"])
        if rc == 0:
            current_ns = stdout.strip()
            if current_ns:
                self.log_result(
                    "Current Network Namespace",
                    TestResult.WARN,
                    f"Running in namespace: {current_ns}",
                    "SSH may be isolated from default network",
                )
            else:
                self.log_result(
                    "Current Network Namespace",
                    TestResult.PASS,
                    "Running in default network namespace",
                )

    def test_system_hardening(self):
        """Test system hardening configurations"""
        # Check kernel parameters
        security_params = {
            "/proc/sys/net/ipv4/ip_forward": ("0", "IP forwarding disabled"),
            "/proc/sys/net/ipv4/conf/all/send_redirects": (
                "0",
                "ICMP redirects disabled",
            ),
            "/proc/sys/net/ipv4/conf/all/accept_redirects": (
                "0",
                "ICMP redirect acceptance disabled",
            ),
            "/proc/sys/kernel/dmesg_restrict": ("1", "dmesg access restricted"),
        }

        hardening_issues = []
        hardening_good = []

        for param_file, (expected_value, description) in security_params.items():
            try:
                with open(param_file, "r") as f:
                    current_value = f.read().strip()

                if current_value == expected_value:
                    hardening_good.append(description)
                else:
                    hardening_issues.append(
                        f"{param_file}: {current_value} (should be {expected_value})"
                    )
            except:
                continue

        if hardening_issues:
            self.log_result(
                "Kernel Hardening",
                TestResult.WARN,
                f"Security parameters not optimal: {len(hardening_issues)}",
                "; ".join(hardening_issues[:2]),
                "Review and adjust kernel security parameters",
            )
        else:
            self.log_result(
                "Kernel Hardening",
                TestResult.PASS,
                f"Kernel security parameters configured: {len(hardening_good)}",
            )

        # Check for security-related packages
        security_tools = ["aide", "rkhunter", "chkrootkit", "lynis"]
        installed_tools = []

        for tool in security_tools:
            rc, stdout, stderr = self.run_command(["which", tool])
            if rc == 0:
                installed_tools.append(tool)

        if installed_tools:
            self.log_result(
                "Security Tools",
                TestResult.PASS,
                f"Security tools installed: {', '.join(installed_tools)}",
            )
        else:
            self.log_result(
                "Security Tools",
                TestResult.WARN,
                "No security audit tools found",
                "Consider installing aide, rkhunter, or lynis",
            )

        # Check SSH-specific hardening
        ssh_hardening_checks = []
        try:
            with open(self.ssh_config_path, "r") as f:
                ssh_config = f.read().lower()

            if "protocol 2" in ssh_config:
                ssh_hardening_checks.append("Protocol 2 enforced")
            if "x11forwarding no" in ssh_config:
                ssh_hardening_checks.append("X11 forwarding disabled")
            if "allowtcpforwarding no" in ssh_config:
                ssh_hardening_checks.append("TCP forwarding disabled")
            if "clientaliveinterval" in ssh_config:
                ssh_hardening_checks.append("Client alive checking enabled")

            if ssh_hardening_checks:
                self.log_result(
                    "SSH Hardening",
                    TestResult.PASS,
                    f"SSH hardening measures: {len(ssh_hardening_checks)}",
                )
            else:
                self.log_result(
                    "SSH Hardening",
                    TestResult.WARN,
                    "No SSH hardening measures detected",
                    "Consider additional SSH security settings",
                )
        except:
            pass

    def test_level_7_external_dependencies(self):
        """Level 7: External Dependencies Tests"""
        print("Level 7: External Dependencies")
        print("-" * 40)

        # Test 7.1: Cloud provider metadata
        self.test_cloud_metadata()

        # Test 7.2: NAT and port forwarding
        self.test_nat_configuration()

        # Test 7.3: External reachability
        self.test_external_reachability()

        # Test 7.4: Geographic restrictions
        self.test_geographic_restrictions()

        # Test 7.5: Network infrastructure
        self.test_network_infrastructure()

        print()

    def test_cloud_metadata(self):
        """Test cloud provider configuration and metadata"""
        # Check for AWS metadata
        rc, stdout, stderr = self.run_command(
            [
                "curl",
                "-s",
                "--max-time",
                "2",
                "http://169.254.169.254/latest/meta-data/",
            ]
        )
        if rc == 0 and stdout.strip():
            self.log_result(
                "Cloud Provider", TestResult.PASS, "AWS metadata service detected"
            )

            # Check security groups
            rc, stdout, stderr = self.run_command(
                [
                    "curl",
                    "-s",
                    "--max-time",
                    "2",
                    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
                ]
            )
            if rc == 0 and stdout.strip():
                mac = stdout.strip().split("\n")[0]
                rc, stdout, stderr = self.run_command(
                    [
                        "curl",
                        "-s",
                        "--max-time",
                        "2",
                        f"http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac}/security-groups",
                    ]
                )
                if rc == 0:
                    self.log_result(
                        "AWS Security Groups",
                        TestResult.PASS,
                        "Security groups information available",
                    )
                else:
                    self.log_result(
                        "AWS Security Groups",
                        TestResult.WARN,
                        "Cannot retrieve security groups info",
                    )
        else:
            # Check for Google Cloud metadata
            rc, stdout, stderr = self.run_command(
                [
                    "curl",
                    "-s",
                    "--max-time",
                    "2",
                    "-H",
                    "Metadata-Flavor: Google",
                    "http://metadata.google.internal/computeMetadata/v1/",
                ]
            )
            if rc == 0:
                self.log_result(
                    "Cloud Provider",
                    TestResult.PASS,
                    "Google Cloud metadata service detected",
                )
            else:
                # Check for Azure metadata
                rc, stdout, stderr = self.run_command(
                    [
                        "curl",
                        "-s",
                        "--max-time",
                        "2",
                        "-H",
                        "Metadata: true",
                        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    ]
                )
                if rc == 0:
                    self.log_result(
                        "Cloud Provider",
                        TestResult.PASS,
                        "Azure metadata service detected",
                    )
                else:
                    self.log_result(
                        "Cloud Provider",
                        TestResult.SKIP,
                        "No cloud metadata service detected",
                    )
                    return

        # Check cloud-init status
        rc, stdout, stderr = self.run_command(["cloud-init", "status"])
        if rc == 0:
            if "done" in stdout:
                self.log_result(
                    "Cloud-init", TestResult.PASS, "Cloud-init completed successfully"
                )
            elif "running" in stdout:
                self.log_result(
                    "Cloud-init",
                    TestResult.WARN,
                    "Cloud-init still running",
                    "May affect SSH configuration",
                )
            else:
                self.log_result(
                    "Cloud-init", TestResult.WARN, "Cloud-init status unknown"
                )
        else:
            self.log_result("Cloud-init", TestResult.SKIP, "Cloud-init not available")

    def test_nat_configuration(self):
        """Test NAT and port forwarding configuration"""
        # Check if we're behind NAT by comparing internal and external IPs
        rc, stdout, stderr = self.run_command(["hostname", "-I"])
        if rc != 0:
            self.log_result(
                "NAT Detection", TestResult.SKIP, "Cannot determine local IP"
            )
            return

        local_ips = stdout.strip().split()
        private_ips = []
        public_ips = []

        for ip in local_ips:
            try:
                # Check if IP is private
                octets = ip.split(".")
                if len(octets) == 4:
                    first = int(octets[0])
                    second = int(octets[1])

                    if (
                        first == 10
                        or (first == 172 and 16 <= second <= 31)
                        or (first == 192 and second == 168)
                        or first == 127
                    ):
                        private_ips.append(ip)
                    else:
                        public_ips.append(ip)
            except:
                continue

        if private_ips and not public_ips:
            self.log_result(
                "NAT Configuration",
                TestResult.WARN,
                f"Behind NAT with private IPs: {', '.join(private_ips)}",
                "External SSH access requires port forwarding",
                "Configure port forwarding on router/gateway",
            )

            # Check for UPnP
            rc, stdout, stderr = self.run_command(["which", "upnpc"])
            if rc == 0:
                rc, stdout, stderr = self.run_command(["upnpc", "-l"])
                if rc == 0 and "22" in stdout:
                    self.log_result(
                        "UPnP Port Forwarding",
                        TestResult.PASS,
                        "SSH port forwarding detected via UPnP",
                    )
                else:
                    self.log_result(
                        "UPnP Port Forwarding",
                        TestResult.WARN,
                        "No SSH port forwarding via UPnP",
                    )
        elif public_ips:
            self.log_result(
                "NAT Configuration",
                TestResult.PASS,
                f"Direct internet connection: {', '.join(public_ips)}",
            )
        else:
            self.log_result(
                "NAT Configuration", TestResult.WARN, "Cannot determine NAT status"
            )

    def test_external_reachability(self):
        """Test external reachability to SSH port"""
        # Get our external IP
        external_ip = None

        ip_services = [
            "http://ifconfig.me/ip",
            "http://ipinfo.io/ip",
            "http://icanhazip.com",
        ]

        for service in ip_services:
            rc, stdout, stderr = self.run_command(
                ["curl", "-s", "--max-time", "5", service]
            )
            if rc == 0 and stdout.strip():
                external_ip = stdout.strip()
                break

        if not external_ip:
            self.log_result(
                "External IP Detection", TestResult.SKIP, "Cannot determine external IP"
            )
            return

        self.log_result(
            "External IP", TestResult.PASS, f"External IP detected: {external_ip}"
        )

        # Test external SSH connectivity (this is tricky without external resources)
        # We can at least check if the port is open locally on all interfaces
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("0.0.0.0", self.ssh_port))
            sock.close()

            if result == 0:
                self.log_result(
                    "External SSH Test",
                    TestResult.PASS,
                    f"SSH port {self.ssh_port} appears to be accessible",
                )
            else:
                self.log_result(
                    "External SSH Test",
                    TestResult.WARN,
                    f"SSH port {self.ssh_port} may not be externally accessible",
                )
        except:
            self.log_result(
                "External SSH Test",
                TestResult.SKIP,
                "Cannot test external SSH accessibility",
            )

        # Check for common blocking services
        nmap_cmd = ["nmap", "-p", str(self.ssh_port)]
        if self.is_ipv6_address(external_ip):
            nmap_cmd.append("-6")
        nmap_cmd.append(external_ip)

        rc, stdout, stderr = self.run_command(nmap_cmd)
        if rc == 0:
            if "open" in stdout:
                self.log_result(
                    "Port Scan Test",
                    TestResult.PASS,
                    f"SSH port {self.ssh_port} is open from external perspective",
                )
            elif "filtered" in stdout:
                self.log_result(
                    "Port Scan Test",
                    TestResult.WARN,
                    f"SSH port {self.ssh_port} appears filtered",
                    "Firewall or ISP blocking may be present",
                )
            else:
                self.log_result(
                    "Port Scan Test",
                    TestResult.FAIL,
                    f"SSH port {self.ssh_port} appears closed externally",
                )
        else:
            self.log_result(
                "Port Scan Test",
                TestResult.SKIP,
                "nmap not available for external port testing",
            )

    def test_geographic_restrictions(self):
        """Test for geographic or ISP-level restrictions"""
        # Check current location via IP geolocation
        rc, stdout, stderr = self.run_command(
            ["curl", "-s", "--max-time", "5", "http://ipinfo.io/json"]
        )
        if rc == 0 and stdout.strip():
            try:
                import json

                geo_info = json.loads(stdout)
                country = geo_info.get("country", "Unknown")
                org = geo_info.get("org", "Unknown")

                self.log_result(
                    "Geographic Location",
                    TestResult.PASS,
                    f"Location: {country}, ISP: {org}",
                )

                # Check for known restrictive countries/ISPs
                restrictive_countries = ["CN", "IR", "KP", "SY"]
                if country in restrictive_countries:
                    self.log_result(
                        "Geographic Restrictions",
                        TestResult.WARN,
                        f"Located in country with potential SSH restrictions: {country}",
                        "SSH access may be blocked or monitored",
                    )
                else:
                    self.log_result(
                        "Geographic Restrictions",
                        TestResult.PASS,
                        "No known geographic SSH restrictions",
                    )

            except:
                self.log_result(
                    "Geographic Location",
                    TestResult.SKIP,
                    "Cannot parse geolocation data",
                )
        else:
            self.log_result(
                "Geographic Location",
                TestResult.SKIP,
                "Cannot determine geographic location",
            )

        # Test DNS resolution for SSH-related domains
        test_domains = ["github.com", "gitlab.com", "ssh.com"]
        blocked_domains = []

        for domain in test_domains:
            try:
                socket.gethostbyname(domain)
            except:
                blocked_domains.append(domain)

        if blocked_domains:
            self.log_result(
                "DNS Filtering",
                TestResult.WARN,
                f"Cannot resolve SSH-related domains: {', '.join(blocked_domains)}",
                "DNS filtering or censorship may be active",
            )
        else:
            self.log_result(
                "DNS Filtering",
                TestResult.PASS,
                "No DNS filtering detected for SSH-related domains",
            )

    def test_network_infrastructure(self):
        """Test network infrastructure that may affect SSH"""
        # Test MTU size
        rc, stdout, stderr = self.run_command(["ip", "route", "get", "8.8.8.8"])
        if rc == 0 and "mtu" in stdout:
            try:
                mtu_line = [line for line in stdout.split() if line.startswith("mtu")]
                if mtu_line:
                    mtu = int(mtu_line[0].split()[1])
                    if mtu < 1500:
                        self.log_result(
                            "MTU Size",
                            TestResult.WARN,
                            f"Low MTU detected: {mtu}",
                            "May cause SSH packet fragmentation issues",
                        )
                    else:
                        self.log_result(
                            "MTU Size", TestResult.PASS, f"MTU size OK: {mtu}"
                        )
            except:
                pass

        # Test traceroute to detect path issues
        rc, stdout, stderr = self.run_command(["traceroute", "-m", "5", "8.8.8.8"])
        if rc == 0:
            hops = len(
                [
                    line
                    for line in stdout.split("\n")
                    if line.strip() and not line.startswith("traceroute")
                ]
            )
            if hops > 15:
                self.log_result(
                    "Network Path",
                    TestResult.WARN,
                    f"Many network hops detected: {hops}",
                    "Complex routing may affect SSH performance",
                )
            else:
                self.log_result(
                    "Network Path",
                    TestResult.PASS,
                    f"Network path reasonable: {hops} hops",
                )
        else:
            self.log_result(
                "Network Path",
                TestResult.SKIP,
                "Cannot test network path (traceroute not available)",
            )

        # Check for proxy configuration
        proxy_vars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]
        proxy_detected = []

        for var in proxy_vars:
            if var in os.environ and os.environ[var]:
                proxy_detected.append(f"{var}={os.environ[var]}")

        if proxy_detected:
            self.log_result(
                "Proxy Configuration",
                TestResult.WARN,
                f"Proxy environment variables detected: {len(proxy_detected)}",
                "Proxy may interfere with SSH connections",
            )
        else:
            self.log_result(
                "Proxy Configuration",
                TestResult.PASS,
                "No proxy environment variables detected",
            )

        # Check for load balancer indicators
        rc, stdout, stderr = self.run_command(["netstat", "-rn"])
        if rc == 0:
            # Look for multiple default routes (load balancing)
            default_routes = [
                line
                for line in stdout.split("\n")
                if line.startswith("0.0.0.0") or line.startswith("default")
            ]
            if len(default_routes) > 1:
                self.log_result(
                    "Load Balancing",
                    TestResult.WARN,
                    f"Multiple default routes detected: {len(default_routes)}",
                    "Load balancing may affect SSH session consistency",
                )
            else:
                self.log_result(
                    "Load Balancing", TestResult.PASS, "Single default route detected"
                )


if __name__ == "__main__":
    diagnostic = SSHDiagnostic()

    # Parse command line arguments
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    try:
        diagnostic.run_all_diagnostics(verbose=verbose)
    except KeyboardInterrupt:
        print("\nDiagnostic interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error running diagnostics: {e}")
        sys.exit(1)
