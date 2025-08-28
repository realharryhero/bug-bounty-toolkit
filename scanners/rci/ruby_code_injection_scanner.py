"""
Ruby Code Injection Scanner - Detects Ruby code injection vulnerabilities
"""

import re
import time
import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any

from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()


class RubyCodeInjectionScanner:
    """Ruby code injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the Ruby code injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('rci')
        self.general_config = config_manager.get('general')

        # Payloads for Ruby code injection
        self.direct_payloads = [
            "#{7*7}",  # Simple arithmetic
            "%x(id)",  # OS command execution
            "system('id')",
            "`id`",
            "(1..5).inject(:*)" # Factorial of 5
        ]

        self.time_payloads = [
            "sleep(5)",
        ]

        # Success indicators
        self.success_indicators = [
            '49',  # Result of 7*7
            '120', # Result of (1..5).inject(:*)
            'uid=',  # Output of id command
            'gid=',
            'groups='
        ]

        # Error indicators
        self.error_indicators = [
            'SyntaxError',
            'NameError',
            'NoMethodError',
            'ArgumentError',
            'TypeError',
            'ZeroDivisionError',
            'uninitialized constant'
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for Ruby code injection vulnerabilities.

        Args:
            target_url: Target URL to scan

        Returns:
            List of Finding objects
        """
        findings = []

        logger.info(f"Starting Ruby code injection scan on {target_url}")
        security_logger.log_scan_start("ruby_code_injection", target_url)

        try:
            injection_points = self._find_injection_points(target_url)

            for point in injection_points:
                findings.extend(self._test_direct_injection(point))
                findings.extend(self._test_blind_injection(point))

        except Exception as e:
            logger.error(f"Ruby code injection scan failed: {str(e)}")
            security_logger.log_error("RCI_SCAN_FAILED", str(e), target_url)

        logger.info(f"Ruby code injection scan completed. Found {len(findings)} potential issues.")
        return findings

    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential code injection points."""
        points = []
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))

            # Look for parameters that might be used in eval() or other sinks
            param_keywords = [
                'eval', 'exec', 'code', 'execute', 'run', 'expression',
                'formula', 'calculate', 'render', 'template'
            ]

            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)

            for param_name, param_values in query_params.items():
                if any(keyword in param_name.lower() for keyword in param_keywords):
                    points.append({
                        'type': 'url_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'GET'
                    })

            # Look for forms with fields that might be evaluated
            form_patterns = [
                r'<input[^>]*name=[\'"]([^\'\"]*(?:' + '|'.join(param_keywords) + r')[^\'\"]*)[\'"][^>]*>',
                r'<textarea[^>]*name=[\'"]([^\'\"]*(?:' + '|'.join(param_keywords) + r')[^\'\"]*)[\'"][^>]*>',
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
            logger.debug(f"Error finding injection points for RCI: {str(e)}")

        return points

    def _test_direct_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test for direct Ruby code injection."""
        findings = []

        for payload in self.direct_payloads:
            try:
                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)

                    original_value = params.get(injection_point['parameter'], [''])[0]
                    params[injection_point['parameter']] = [original_value + payload]

                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))

                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(
                        injection_point['url'],
                        data=data,
                        timeout=self.general_config.get('timeout', 10)
                    )
                else:
                    continue

                if self._is_ruby_code_injection_successful(response):
                    finding = Finding(
                        title="Ruby Code Injection",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"Ruby code injection vulnerability detected in parameter '{injection_point['parameter']}'.",
                        target=injection_point['url'],
                        vulnerability_type="Ruby Code Injection",
                        evidence=f"Payload: {payload}, Parameter: {injection_point['parameter']}",
                        impact="Attacker can execute arbitrary Ruby code on the server.",
                        remediation="Avoid using user input in methods that evaluate code, such as 'eval'. Use safe alternatives and sanitize input."
                    )
                    findings.append(finding)
                    return findings # Stop after first success for this point

            except Exception as e:
                logger.debug(f"Error testing direct RCI: {str(e)}")

        return findings

    def _test_blind_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test for blind Ruby code injection using timing attacks."""
        findings = []

        for payload in self.time_payloads:
            try:
                start_time = time.time()

                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)

                    original_value = params.get(injection_point['parameter'], [''])[0]
                    params[injection_point['parameter']] = [original_value + payload]

                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                    response = requests.get(test_url, timeout=15)

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
                if 4 <= elapsed_time <= 8:
                    finding = Finding(
                        title="Blind Ruby Code Injection",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description="Timing-based blind Ruby code injection detected.",
                        target=injection_point['url'],
                        vulnerability_type="Ruby Code Injection",
                        evidence=f"Response time: {elapsed_time:.2f}s, Parameter: {injection_point['parameter']}",
                        impact="Application may be vulnerable to blind code injection.",
                        remediation="Implement input validation and avoid direct code execution."
                    )
                    findings.append(finding)
                    return findings

            except requests.exceptions.Timeout:
                finding = Finding(
                    title="Potential Blind Ruby Code Injection (Timeout)",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Request timeout may indicate blind Ruby code injection.",
                    target=injection_point['url'],
                    vulnerability_type="Ruby Code Injection",
                    evidence=f"Request timeout with payload: {payload}",
                    impact="Application may be vulnerable to blind code injection.",
                    remediation="Implement timeout controls and input validation."
                )
                findings.append(finding)
                return findings
            except Exception as e:
                logger.debug(f"Error testing blind RCI: {str(e)}")

        return findings

    def _is_ruby_code_injection_successful(self, response: requests.Response) -> bool:
        """Check if Ruby code injection was successful."""
        response_text = response.text

        # Check for direct success indicators
        for indicator in self.success_indicators:
            if indicator in response_text:
                return True

        # Check for error messages that indicate code execution
        for error in self.error_indicators:
            if error in response_text:
                return True

        return False
