"""
XPath Injection Scanner - Detects XPath injection vulnerabilities
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

class XPathInjectionScanner:
    """XPath Injection vulnerability scanner with multiple detection techniques."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the XPath injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('xpath')
        self.general_config = config_manager.get('general')

        # Load payloads
        self.payloads = self._load_payloads()

        # Error signatures for different XML parsers
        self.error_signatures = {
            'generic': [
                r"Invalid XPath expression",
                r"XPath parse error",
                r"xmlXPathEval: evaluation failed",
                r"MS.Internal.Xml.",
                r"System.Xml.XPath",
                r"org.apache.xpath",
            ],
            'libxml': [
                r"libxml2 error",
                r"xmlError",
            ],
            'saxon': [
                r"net.sf.saxon",
                r"SAXON-ERROR",
            ]
        }

    def _load_payloads(self) -> List[str]:
        """Load XPath injection payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/xpath_payloads.txt')
        payloads = []

        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)

            logger.info(f"Loaded {len(payloads)} XPath injection payloads")

        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = [
                "' or '1'='1",
                "') or ('1'='1",
                "' and count(/*)=1 and '1'='1"
            ]

        return payloads

    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for XPath injection vulnerabilities.

        Args:
            target: Target URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting XPath injection scan on {target}")
        findings = []

        try:
            # Test different injection types
            test_types = self.config.get('test_types', ['error', 'blind'])

            if 'error' in test_types:
                findings.extend(self._test_error_based(target))

            if 'blind' in test_types:
                findings.extend(self._test_blind_injection(target))

            logger.info(f"XPath injection scan completed - {len(findings)} potential vulnerabilities found")

        except Exception as e:
            logger.error(f"XPath injection scan failed: {str(e)}")
            security_logger.log_error("XPATH_SCAN_ERROR", str(e), target)

        return findings

    def _test_error_based(self, target: str) -> List[Finding]:
        """Test for error-based XPath injection."""
        findings = []

        # Get baseline response
        try:
            baseline_response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            baseline_content = baseline_response.text
        except Exception as e:
            logger.error(f"Failed to get baseline response: {str(e)}")
            return findings

        # Test error-inducing payloads
        error_payloads = [payload for payload in self.payloads if "'" in payload or '"' in payload]

        for payload in error_payloads[:20]:  # Limit for performance
            test_url = f"{target}?query={payload}"

            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))

                # Check for XML/XPath error signatures
                for parser_type, signatures in self.error_signatures.items():
                    for signature in signatures:
                        if re.search(signature, response.text, re.IGNORECASE):
                            confidence = 0.9  # High confidence for error-based

                            finding = Finding(
                                title=f"XPath Injection Vulnerability ({parser_type.upper()})",
                                severity=Severity.HIGH,
                                confidence=confidence,
                                description=f"Error-based XPath injection detected. The application returned XML/XPath error messages when malicious payloads were injected.",
                                target=test_url,
                                vulnerability_type="XPath Injection",
                                payload=payload,
                                evidence=f"Error signature found: {signature}",
                                impact="An attacker could potentially bypass authentication, extract sensitive information, or manipulate the application's logic.",
                                remediation="Use parameterized XPath queries or pre-compiled expressions. Sanitize user input by escaping special XML/XPath characters."
                            )

                            findings.append(finding)
                            security_logger.log_vulnerability_found("XPATH_INJECTION", target, "HIGH", confidence)
                            logger.warning(f"Potential XPath injection found: {test_url}")
                            break

                    if findings:  # Stop after first finding to avoid duplicates
                        break

                # Rate limiting
                time.sleep(self.general_config.get('delay', 1.0))

            except Exception as e:
                logger.debug(f"Request failed for payload {payload}: {str(e)}")

        return findings

    def _test_blind_injection(self, target: str) -> List[Finding]:
        """Test for blind XPath injection using boolean-based techniques."""
        findings = []

        # Boolean-based payloads
        true_payload = "' or '1'='1"
        false_payload = "' or '1'='2"

        try:
            # Test true condition
            true_url = f"{target}?query={true_payload}"
            true_response = requests.get(true_url, timeout=self.general_config.get('timeout', 30))

            time.sleep(self.general_config.get('delay', 1.0))

            # Test false condition
            false_url = f"{target}?query={false_payload}"
            false_response = requests.get(false_url, timeout=self.general_config.get('timeout', 30))

            # Compare responses
            if (true_response.status_code == 200 and false_response.status_code == 200 and
                len(true_response.text) != len(false_response.text)):

                confidence = 0.7  # Medium confidence for blind injection

                finding = Finding(
                    title="Blind XPath Injection Vulnerability",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    description="Blind XPath injection detected through boolean-based testing. The application responds differently to true and false XPath conditions.",
                    target=target,
                    vulnerability_type="XPath Injection",
                    payload=f"True: {true_payload}, False: {false_payload}",
                    evidence=f"Response length difference - True: {len(true_response.text)}, False: {len(false_response.text)}",
                    impact="An attacker could potentially extract sensitive information from the underlying XML data through blind injection techniques.",
                    remediation="Use parameterized XPath queries or pre-compiled expressions. Sanitize user input by escaping special XML/XPath characters."
                )

                findings.append(finding)
                security_logger.log_vulnerability_found("BLIND_XPATH_INJECTION", target, "HIGH", confidence)

        except Exception as e:
            logger.debug(f"Blind injection test failed: {str(e)}")

        return findings
