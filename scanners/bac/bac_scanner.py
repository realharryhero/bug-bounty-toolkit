"""
Broken Access Control (BAC) Scanner - Detects BAC vulnerabilities
"""

import logging
import requests
from typing import List, Dict, Any
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class BrokenAccessControlScanner(BaseScanner):
    """Broken Access Control vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the BAC scanner.

        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('bac')
        self.general_config = config_manager.get('general')

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for BAC vulnerabilities.

        Args:
            target_url: Target URL to scan

        Returns:
            List of Finding objects
        """
        findings = []
        logger.info(f"Starting Broken Access Control scan on {target_url}")
        security_logger.log_scan_start("bac", target_url)

        try:
            # Test for privilege escalation
            findings.extend(self._test_privilege_escalation(target_url))

            # Test for parameter tampering
            findings.extend(self._test_parameter_tampering(target_url))

            # Test for forced browsing
            findings.extend(self._test_forced_browsing(target_url))

        except Exception as e:
            logger.error(f"BAC scan failed: {str(e)}")
            security_logger.log_error("BAC_SCAN_FAILED", str(e), target_url)

        logger.info(f"Broken Access Control scan completed. Found {len(findings)} potential issues.")
        
        verified_findings = self.filter_false_positives(findings, target_url)
        
        for finding in verified_findings:
            self.log_finding_details(finding, "BAC might be false if redirects or caching are involved.")
        
        return verified_findings

    def _test_privilege_escalation(self, target_url: str) -> List[Finding]:
        """Test for privilege escalation by accessing admin-only pages."""
        findings = []
        admin_paths = ['/admin', '/dashboard', '/console', '/admin-panel']

        for path in admin_paths:
            test_url = target_url.rstrip('/') + path
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 10), allow_redirects=False)
                if response.status_code == 200 and "dashboard" in response.text.lower():
                    finding = Finding(
                        title="Privilege Escalation - Admin Panel Access",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description=f"Potential admin panel access at {test_url}",
                        target=test_url,
                        vulnerability_type="Broken Access Control",
                        evidence=f"Accessed {test_url} and received a 200 OK with 'dashboard' in body.",
                        impact="Unauthorized access to administrative functions.",
                        remediation="Ensure that admin pages have strong access controls."
                    )
                    findings.append(finding)
            except requests.RequestException as e:
                logger.debug(f"Error checking {test_url} for privilege escalation: {e}")

        return findings

    def _test_parameter_tampering(self, target_url: str) -> List[Finding]:
        """Test for parameter tampering to gain extra privileges."""
        findings = []
        tamper_params = {'role': 'admin', 'isAdmin': 'true', 'auth': '1'}

        for param, value in tamper_params.items():
            try:
                response = requests.get(target_url, params={param: value}, timeout=self.general_config.get('timeout', 10))
                if response.status_code == 200 and "admin" in response.text.lower():
                    finding = Finding(
                        title="Parameter Tampering - Role Escalation",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        description=f"Potential role escalation by setting `{param}` to `{value}`.",
                        target=target_url,
                        vulnerability_type="Broken Access Control",
                        evidence=f"Parameter `{param}={value}` resulted in a 200 OK with 'admin' in body.",
                        impact="Attackers may be able to grant themselves administrative privileges.",
                        remediation="Do not trust user-controllable parameters for authorization decisions."
                    )
                    findings.append(finding)
            except requests.RequestException as e:
                logger.debug(f"Error checking {target_url} for parameter tampering: {e}")

        return findings

    def _test_forced_browsing(self, target_url: str) -> List[Finding]:
        """Test for forced browsing to access unlinked resources."""
        findings = []
        common_files = ['/config.json', '/.env', '/users.json', '/backup.zip']

        for path in common_files:
            test_url = target_url.rstrip('/') + path
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))
                if response.status_code == 200:
                    finding = Finding(
                        title="Forced Browsing - Sensitive File Exposure",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        description=f"Potential sensitive file exposure at {test_url}",
                        target=test_url,
                        vulnerability_type="Broken Access Control",
                        evidence=f"Accessed {test_url} and received a 200 OK.",
                        impact="Sensitive information may be exposed to unauthorized users.",
                        remediation="Restrict access to sensitive files and directories."
                    )
                    findings.append(finding)
            except requests.RequestException as e:
                logger.debug(f"Error checking {test_url} for forced browsing: {e}")

        return findings
