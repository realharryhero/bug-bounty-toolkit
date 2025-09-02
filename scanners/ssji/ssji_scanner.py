"""
Server-Side JavaScript Injection (SSJI) Scanner
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

class SSJIScanner(BaseScanner):
    """Server-Side JavaScript Injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the SSJI scanner.

        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('ssji')
        self.general_config = config_manager.get('general')

        # SSJI payloads
        self.ssji_payloads = [
            "{{7*7}}",
            "<%= 7*7 %>",
            "${7*7}",
            "#{7*7}",
            "*{7*7}",
            "eval('7*7')",
            "this.constructor.constructor('return process.env')()",
        ]

        # Time-based payloads for blind detection
        self.time_payloads = [
            ";-var d=new Date();while(new Date()-d<5000);",
            "';-var d=new Date();while(new Date()-d<5000);",
            "\";-var d=new Date();while(new Date()-d<5000);",
            "eval('var d=new Date();while(new Date()-d<5000);')",
            "setTimeout(function(){}, 5000)",
        ]

        # Success indicators
        self.success_indicators = [
            '49',
            '{"VUE_DEVTOOLS_UID":', # from process.env
        ]

        self.error_indicators = [
            'SyntaxError',
            'ReferenceError',
            'TypeError',
            'evalmachine',
            'vm.js',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for SSJI vulnerabilities.

        Args:
            target_url: Target URL to scan

        Returns:
            List of Finding objects
        """
        findings = []
        logger.info(f"Starting SSJI scan on {target_url}")
        security_logger.log_scan_start("ssji", target_url)

        try:
            # Find potential injection points
            injection_points = self._find_injection_points(target_url)

            for point in injection_points:
                # Test direct injection
                findings.extend(self._test_direct_injection(point))

                # Test blind injection
                findings.extend(self._test_blind_injection(point))

        except Exception as e:
            logger.error(f"SSJI scan failed: {str(e)}")
            security_logger.log_error("SSJI_SCAN_FAILED", str(e), target_url)

        logger.info(f"SSJI scan completed. Found {len(findings)} potential issues.")
        
        verified_findings = self.filter_false_positives(findings, target_url)
        
        for finding in verified_findings:
            self.log_finding_details(finding, "SSJI might be false if template rendering is secure or input is escaped.")
        
        return verified_findings

    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential SSJI injection points."""
        points = []
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)

            for param_name, param_values in query_params.items():
                if any(keyword in param_name.lower() for keyword in [
                    'data', 'json', 'eval', 'exec', 'template', 'view', 'engine'
                ]):
                    points.append({
                        'type': 'url_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'GET'
                    })
        except Exception as e:
            logger.debug(f"Error finding injection points: {str(e)}")
        return points

    def _test_direct_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test direct SSJI."""
        findings = []
        for payload in self.ssji_payloads:
            try:
                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)
                    original_value = params.get(injection_point['parameter'], ['test'])[0]
                    params[injection_point['parameter']] = [original_value + payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))
                else:
                    continue

                if self._is_ssji_successful(response, payload):
                    finding = Finding(
                        title="Server-Side JavaScript Injection",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description=f"SSJI vulnerability detected in parameter '{injection_point['parameter']}'",
                        target=injection_point['url'],
                        vulnerability_type="SSJI",
                        evidence=f"Payload: {payload}, Parameter: {injection_point['parameter']}",
                        impact="Attacker can execute arbitrary JavaScript on the server.",
                        remediation="Avoid using user input in server-side template rendering or JavaScript execution. Use safe APIs and sandbox execution environments."
                    )
                    findings.append(finding)
                    return findings
            except Exception as e:
                logger.debug(f"Error testing direct SSJI: {str(e)}")
        return findings

    def _test_blind_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test blind SSJI using timing attacks."""
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
                    response = requests.get(test_url, timeout=15)
                else:
                    continue
                elapsed_time = time.time() - start_time
                if 4 <= elapsed_time <= 8:
                    finding = Finding(
                        title="Blind Server-Side JavaScript Injection",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description=f"Timing-based blind SSJI detected in parameter '{injection_point['parameter']}'",
                        target=injection_point['url'],
                        vulnerability_type="SSJI",
                        evidence=f"Response time: {elapsed_time:.2f}s, Parameter: {injection_point['parameter']}",
                        impact="Application may be vulnerable to blind SSJI.",
                        remediation="Avoid using user input in server-side template rendering or JavaScript execution. Use safe APIs and sandbox execution environments."
                    )
                    findings.append(finding)
                    return findings
            except requests.exceptions.Timeout:
                finding = Finding(
                    title="Potential Blind SSJI (Timeout)",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=f"Request timeout may indicate blind SSJI in parameter '{injection_point['parameter']}'",
                    target=injection_point['url'],
                    vulnerability_type="SSJI",
                    evidence=f"Request timeout with payload: {payload}",
                    impact="Application may be vulnerable to blind SSJI.",
                    remediation="Implement timeout controls and input validation."
                )
                findings.append(finding)
                return findings
            except Exception as e:
                logger.debug(f"Error testing blind SSJI: {str(e)}")
        return findings

    def _is_ssji_successful(self, response: requests.Response, payload: str) -> bool:
        """Check if SSJI was successful."""
        response_text = response.text
        for indicator in self.success_indicators:
            if indicator in response_text:
                return True
        for indicator in self.error_indicators:
            if indicator.lower() in response_text.lower():
                return True
        return False
