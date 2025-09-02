"""
PHP Code Injection Scanner - Detects PHP code injection vulnerabilities
"""

import re
import time
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class PHPCodeInjectionScanner(BaseScanner):
    """PHP code injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the PHP code injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('php_code_injection')
        self.general_config = config_manager.get('general')

        # PHP code injection payloads
        self.payloads = self._load_payloads()

        # Time-based payloads for blind detection
        self.time_payloads = [
            "; sleep(5);",
            "| sleep(5);",
            "&& sleep(5);",
            "`sleep(5)`",
            "$(sleep(5))",
        ]

        # Success indicators for PHP code injection
        self.success_indicators = [
            'phpinfo()',
            'PHP Version',
            'System',
            'Module',
            'Directive',
            'root:x:0:0:',
            'uid=',
            'gid=',
            'groups=',
            'Linux',
            'Unix',
            'GNU',
            'Windows',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for PHP code injection vulnerabilities.

        Args:
            target_url: Target URL to scan

        Returns:
            List of Finding objects
        """
        findings = []

        logger.info(f"Starting PHP code injection scan on {target_url}")
        security_logger.log_scan_start("php_code_injection", target_url)

        try:
            # Find potential injection points
            injection_points = self._find_injection_points(target_url)

            for point in injection_points:
                # Test direct code injection
                findings.extend(self._test_direct_injection(point))

                # Test blind code injection
                findings.extend(self._test_blind_injection(point))

        except Exception as e:
            logger.error(f"PHP code injection scan failed: {str(e)}")
            security_logger.log_error("PHP_CODE_INJECTION_SCAN_FAILED", str(e), target_url)

        logger.info(f"PHP code injection scan completed. Found {len(findings)} potential issues.")
        
        verified_findings = self.filter_false_positives(findings, target_url)
        
        for finding in verified_findings:
            self.log_finding_details(finding, "PHP code injection might be false if execution is disabled or input is validated.")
        
        return verified_findings

    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential PHP code injection points."""
        points = []

        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))

            # Parse URL for existing parameters
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)

            for param_name, param_values in query_params.items():
                points.append({
                    'type': 'url_param',
                    'url': target_url,
                    'parameter': param_name,
                    'method': 'GET'
                })

            # Look for forms that might execute commands
            form_patterns = [
                r'<input[^>]*name=[\'"]([^\'\"]*)[\'"][^>]*>',
                r'<textarea[^>]*name=[\'"]([^\'\"]*)[\'"][^>]*>',
            ]

            for pattern in form_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    param_name = match.group(1)
                    points.append({
                        'type': 'form_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'POST'
                    })

        except Exception as e:
            logger.debug(f"Error finding injection points: {str(e)}")

        return points

    def _test_direct_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test direct PHP code injection."""
        findings = []

        for payload in self.payloads:
            try:
                if injection_point['type'] == 'url_param':
                    # Test URL parameter injection
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)

                    original_value = params.get(injection_point['parameter'], ['test'])[0]
                    params[injection_point['parameter']] = [original_value + payload]

                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))

                elif injection_point['type'] == 'form_param':
                    # Test form parameter injection
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(
                        injection_point['url'],
                        data=data,
                        timeout=self.general_config.get('timeout', 10)
                    )
                else:
                    continue

                # Check for successful code execution
                if self._is_code_injection_successful(response, payload):
                    finding = Finding(
                        vulnerability_id="0x00100c00",
                        cwe_id="CWE-94, CWE-116, CWE-159",
                        title="PHP Code Injection",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description=f"PHP code injection vulnerability detected via parameter '{injection_point['parameter']}'",
                        target=injection_point['url'],
                        vulnerability_type="PHP Code Injection",
                        evidence=f"Payload: {payload}, Parameter: {injection_point['parameter']}",
                        impact="Attacker can execute arbitrary PHP code on the server.",
                        remediation="Use input validation and avoid using user-supplied input in dynamic code execution."
                    )
                    findings.append(finding)
                    return findings  # Stop after first successful injection

            except Exception as e:
                logger.debug(f"Error testing direct injection: {str(e)}")

        return findings

    def _test_blind_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test blind PHP code injection using timing attacks."""
        findings = []

        for payload in self.time_payloads:
            try:
                start_time = time.time()

                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)

                    original_value = params.get(injection_point['parameter'], ['test'])[0]
                    params[injection_point['parameter']] = [original_value + payload]

                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                    response = requests.get(test_url, timeout=15)  # Longer timeout for timing

                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(
                        injection_point['url'],
                        data=data,
                        timeout=15
                    )
                else:
                    continue

                elapsed_time = time.time() - start_time

                # If request took significantly longer (around 5 seconds), likely successful
                if 4 <= elapsed_time <= 8:  # Allow some tolerance
                    finding = Finding(
                        vulnerability_id="0x00100c00",
                        cwe_id="CWE-94, CWE-116, CWE-159",
                        title="Blind PHP Code Injection",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description=f"Timing-based blind PHP code injection detected",
                        target=injection_point['url'],
                        vulnerability_type="PHP Code Injection",
                        evidence=f"Response time: {elapsed_time:.2f}s, Parameter: {injection_point['parameter']}",
                        impact="Application may be vulnerable to blind PHP code injection.",
                        remediation="Implement input validation and avoid dynamic code execution."
                    )
                    findings.append(finding)
                    return findings

            except requests.exceptions.Timeout:
                # Timeout might indicate successful sleep command
                finding = Finding(
                    vulnerability_id="0x00100c00",
                    cwe_id="CWE-94, CWE-116, CWE-159",
                    title="Potential Blind PHP Code Injection (Timeout)",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=f"Request timeout may indicate blind PHP code injection",
                    target=injection_point['url'],
                    vulnerability_type="PHP Code Injection",
                    evidence=f"Request timeout with payload: {payload}",
                    impact="Application may be vulnerable to blind PHP code injection.",
                    remediation="Implement timeout controls and input validation."
                )
                findings.append(finding)
                return findings
            except Exception as e:
                logger.debug(f"Error testing blind injection: {str(e)}")

        return findings

    def _is_code_injection_successful(self, response: requests.Response, payload: str) -> bool:
        """Check if PHP code injection was successful."""
        try:
            response_text = response.text

            for indicator in self.success_indicators:
                if indicator.lower() in response_text.lower():
                    return True

            error_indicators = [
                'parse error',
                'syntax error',
                'unexpected',
                'fatal error',
                'warning',
            ]

            for indicator in error_indicators:
                if indicator in response_text.lower():
                    return True

        except Exception as e:
            logger.debug(f"Error checking code injection success: {str(e)}")

        return False

    def _load_payloads(self) -> List[str]:
        """Load PHP code injection payloads from file."""
        try:
            with open(self.config['payload_file'], 'r') as f:
                return [line.strip() for line in f.readlines()]
        except Exception as e:
            logger.error(f"Failed to load payloads for PHP code injection: {str(e)}")
            return []
