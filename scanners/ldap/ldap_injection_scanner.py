"""
LDAP Injection Scanner - Detects LDAP injection vulnerabilities
"""

import re
import time
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class LDAPInjectionScanner:
    """LDAP Injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the LDAP injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('ldap')
        self.general_config = config_manager.get('general')

        # Load payloads
        self.payloads = self._load_payloads()

        # Error signatures for LDAP
        self.error_signatures = [
            r"LDAPException",
            r"invalid filter",
            r"No such object",
            r"Protocol error",
            r"Size limit exceeded",
            r"Time limit exceeded",
            r"Auth method not supported",
            r"Invalid credentials",
            r"Operations error"
        ]

    def _load_payloads(self) -> List[str]:
        """Load LDAP injection payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/ldap_payloads.txt')
        payloads = []

        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)

            logger.info(f"Loaded {len(payloads)} LDAP injection payloads")

        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = ["*", ")(uid=*))", "|", "&"]

        return payloads

    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for LDAP injection vulnerabilities by testing each parameter.

        Args:
            target: Target URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting LDAP injection scan on {target}")
        findings = []

        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            logger.info("No query parameters found to test for LDAP injection.")
            return findings

        for param in query_params:
            logger.info(f"Testing parameter '{param}' for LDAP injection.")
            try:
                test_types = self.config.get('test_types', ['error', 'blind'])

                if 'error' in test_types:
                    findings.extend(self._test_error_based(target, param))

                if 'blind' in test_types:
                    findings.extend(self._test_blind_injection(target, param))

            except Exception as e:
                logger.error(f"LDAP injection scan failed for parameter {param}: {str(e)}")
                security_logger.log_error("LDAP_SCAN_ERROR", str(e), target)

        logger.info(f"LDAP injection scan completed - {len(findings)} potential vulnerabilities found")
        return findings

    def _test_error_based(self, target: str, param: str) -> List[Finding]:
        """Test for error-based LDAP injection on a specific parameter."""
        findings = []
        parsed_url = urlparse(target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        for payload in self.payloads:
            original_params = parse_qs(parsed_url.query)
            original_params[param] = [payload]
            test_url = f"{base_url}?{requests.compat.urlencode(original_params, doseq=True)}"

            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))

                for signature in self.error_signatures:
                    if re.search(signature, response.text, re.IGNORECASE):
                        finding = Finding(
                            title=f"LDAP Injection Vulnerability (Error-based) in parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            description=f"Error-based LDAP injection detected in parameter '{param}'. The application returned an LDAP-specific error message.",
                            target=test_url,
                            vulnerability_type="LDAP Injection",
                            payload=payload,
                            evidence=f"LDAP error signature found: {signature}",
                            impact="An attacker could bypass authentication, access sensitive information, or modify LDAP tree data.",
                            remediation="Use parameterized LDAP queries or a safe LDAP API. Sanitize and validate all user-supplied input."
                        )
                        findings.append(finding)
                        security_logger.log_vulnerability_found("LDAP_INJECTION", target, "HIGH", 0.9)
                        logger.warning(f"Potential LDAP injection found in param '{param}': {test_url}")
                        return findings

                time.sleep(self.general_config.get('delay', 1.0))

            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed for payload {payload} in param {param}: {str(e)}")

        return findings

    def _test_blind_injection(self, target: str, param: str) -> List[Finding]:
        """Test for blind LDAP injection using boolean-based techniques on a specific parameter."""
        findings = []
        parsed_url = urlparse(target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        original_params = parse_qs(parsed_url.query)

        true_payload = f"{original_params.get(param, [''])[0]}*)(|(uid=*))"
        false_payload = f"{original_params.get(param, [''])[0]}*)(|(uid=nonexistentuser))"

        try:
            # True case
            true_params = original_params.copy()
            true_params[param] = [true_payload]
            true_url = f"{base_url}?{requests.compat.urlencode(true_params, doseq=True)}"
            true_response = requests.get(true_url, timeout=self.general_config.get('timeout', 10))

            time.sleep(self.general_config.get('delay', 1.0))

            # False case
            false_params = original_params.copy()
            false_params[param] = [false_payload]
            false_url = f"{base_url}?{requests.compat.urlencode(false_params, doseq=True)}"
            false_response = requests.get(false_url, timeout=self.general_config.get('timeout', 10))

            if (true_response.status_code == 200 and false_response.status_code == 200 and
                len(true_response.text) != len(false_response.text)):

                finding = Finding(
                    title=f"Blind LDAP Injection Vulnerability in parameter '{param}'",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description=f"Blind LDAP injection detected in parameter '{param}'. The application responds differently to TRUE and FALSE LDAP conditions.",
                    target=target,
                    vulnerability_type="LDAP Injection",
                    payload=f"True: {true_payload}, False: {false_payload}",
                    evidence=f"Response length difference - True: {len(true_response.text)}, False: {len(false_response.text)}",
                    impact="An attacker could enumerate data from the LDAP directory, bypass authentication, or infer directory schema.",
                    remediation="Use parameterized LDAP queries or a safe LDAP API. Sanitize and validate all user-supplied input."
                )
                findings.append(finding)
                security_logger.log_vulnerability_found("BLIND_LDAP_INJECTION", target, "HIGH", 0.7)

        except requests.exceptions.RequestException as e:
            logger.debug(f"Blind LDAP injection test failed for param {param}: {str(e)}")

        return findings
