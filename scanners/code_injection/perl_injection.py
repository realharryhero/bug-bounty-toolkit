"""
Perl Code Injection Scanner - Detects Perl code injection vulnerabilities
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

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class PerlCodeInjectionScanner:
    """Perl code injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the Perl code injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('perl_injection')
        self.general_config = config_manager.get('general')

        # Perl code injection payloads
        self.payloads = self._load_payloads()

        # Time-based payloads for blind detection
        self.time_payloads = [
            "sleep(5);",
            "`sleep 5`",
            "system('sleep 5');",
            "exec('sleep 5');",
            "eval{sleep(5)};",
        ]

        # Success indicators for Perl code injection
        self.success_indicators = [
            'perl',
            'This is perl',
            'version',
            'built for',
            'Copyright',
            'Larry Wall',
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
        Scan for Perl code injection vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting Perl code injection scan on {target_url}")
        findings = []

        try:
            parsed_url = urlparse(target_url)
            
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.warning(f"Invalid URL format: {target_url}")
                return findings

            # Test GET parameters
            if parsed_url.query:
                findings.extend(self._test_get_parameters(target_url))

            # Test POST data if forms are present
            findings.extend(self._test_post_parameters(target_url))

            logger.info(f"Perl injection scan completed. Found {len(findings)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error during Perl injection scan: {str(e)}")
            security_logger.log_error("PERL_INJECTION_SCAN_ERROR", str(e), target_url)

        return findings

    def _load_payloads(self) -> List[str]:
        """Load Perl injection payloads."""
        default_payloads = [
            "'; system('id'); #",
            '"; system("id"); #',
            "'; `id`; #", 
            '"; `id`; #',
            "'; exec('id'); #",
            '"; exec("id"); #',
            "'; print `id`; #",
            '"; print `id`; #',
            "system('id');",
            "`id`",
            "exec('id');",
            "print `id`;",
            "'; system('whoami'); #",
            '"; system("whoami"); #',
            "'; system('pwd'); #",
            '"; system("pwd"); #',
            "'; print $^O; #",  # Print OS name
            '"; print $^O; #',
            "'; print $]; #",   # Print Perl version
            '"; print $]; #',
        ]

        payload_file = self.config.get('payload_file')
        if payload_file:
            try:
                with open(payload_file, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except FileNotFoundError:
                logger.warning(f"Payload file not found: {payload_file}. Using default payloads.")
            except Exception as e:
                logger.error(f"Error loading payload file: {str(e)}")

        return default_payloads

    def _test_get_parameters(self, url: str) -> List[Finding]:
        """Test GET parameters for Perl injection."""
        findings = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return findings

        for param_name in query_params:
            logger.debug(f"Testing GET parameter: {param_name}")
            
            # Test error-based injection
            findings.extend(self._test_error_based_injection(url, param_name, 'GET'))
            
            # Test time-based injection
            findings.extend(self._test_time_based_injection(url, param_name, 'GET'))

        return findings

    def _test_post_parameters(self, url: str) -> List[Finding]:
        """Test POST parameters for Perl injection."""
        findings = []

        try:
            # Get the page to find forms
            response = requests.get(url, timeout=self.general_config.get('timeout', 30))
            
            # Look for forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for form_content in forms:
                # Extract input fields
                inputs = re.findall(r'<input[^>]*name=["\']?([^"\'>\s]+)[^>]*>', form_content, re.IGNORECASE)
                
                for input_name in inputs:
                    logger.debug(f"Testing POST parameter: {input_name}")
                    
                    # Test error-based injection
                    findings.extend(self._test_error_based_injection(url, input_name, 'POST'))
                    
                    # Test time-based injection  
                    findings.extend(self._test_time_based_injection(url, input_name, 'POST'))

        except Exception as e:
            logger.debug(f"Error testing POST parameters: {str(e)}")

        return findings

    def _test_error_based_injection(self, url: str, param_name: str, method: str) -> List[Finding]:
        """Test for error-based Perl injection."""
        findings = []

        for payload in self.payloads:
            try:
                response = self._send_payload(url, param_name, payload, method)
                
                if response and self._analyze_response_for_injection(response.text, payload):
                    confidence = self._calculate_confidence(response.text, payload)
                    
                    if confidence > 0.5:
                        finding = Finding(
                            title="Perl Code Injection",
                            description=f"Potential Perl code injection vulnerability detected in {method} parameter '{param_name}'",
                            severity=Severity.HIGH,
                            confidence=confidence,
                            url=url,
                            method=method,
                            parameter=param_name,
                            payload=payload,
                            evidence=self._extract_evidence(response.text),
                            impact="An attacker could execute arbitrary Perl code on the server, potentially leading to complete system compromise.",
                            remediation="Implement proper input validation and sanitization. Use parameterized queries and avoid direct execution of user input."
                        )
                        findings.append(finding)
                        logger.warning(f"Perl injection vulnerability found: {url} (parameter: {param_name})")
                        break

            except Exception as e:
                logger.debug(f"Error testing payload '{payload}': {str(e)}")

        return findings

    def _test_time_based_injection(self, url: str, param_name: str, method: str) -> List[Finding]:
        """Test for time-based Perl injection."""
        findings = []

        for payload in self.time_payloads:
            try:
                start_time = time.time()
                response = self._send_payload(url, param_name, payload, method)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # If response took significantly longer (> 4 seconds for a 5-second sleep)
                if response_time > 4:
                    finding = Finding(
                        title="Perl Code Injection (Time-based)",
                        description=f"Time-based Perl code injection vulnerability detected in {method} parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        url=url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response time: {response_time:.2f}s (expected delay: 5s)",
                        impact="An attacker could execute arbitrary Perl code on the server, potentially leading to complete system compromise.",
                        remediation="Implement proper input validation and sanitization. Use parameterized queries and avoid direct execution of user input."
                    )
                    findings.append(finding)
                    logger.warning(f"Time-based Perl injection vulnerability found: {url} (parameter: {param_name})")
                    break

            except Exception as e:
                logger.debug(f"Error testing time-based payload '{payload}': {str(e)}")

        return findings

    def _send_payload(self, url: str, param_name: str, payload: str, method: str) -> Optional[requests.Response]:
        """Send payload to target."""
        try:
            if method.upper() == 'GET':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = requests.get(
                    test_url,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    allow_redirects=False
                )
            else:  # POST
                data = {param_name: payload}
                response = requests.post(
                    url,
                    data=data,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    allow_redirects=False
                )
            
            return response

        except requests.RequestException as e:
            logger.debug(f"Request failed for payload '{payload}': {str(e)}")
            return None

    def _analyze_response_for_injection(self, response_text: str, payload: str) -> bool:
        """Analyze response for signs of successful injection."""
        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator.lower() in response_text.lower():
                return True

        # Check for error messages that might indicate injection
        perl_error_patterns = [
            r'syntax error.*near.*line',
            r'can\'t locate.*in @inc',
            r'Global symbol.*requires explicit package',
            r'Bareword.*not allowed',
            r'compilation failed',
            r'perl.*runtime error',
        ]

        for pattern in perl_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _calculate_confidence(self, response_text: str, payload: str) -> float:
        """Calculate confidence level for potential vulnerability."""
        confidence = 0.0
        
        # Check for command execution output
        command_indicators = ['uid=', 'gid=', 'groups=', 'root:x:0:0:']
        for indicator in command_indicators:
            if indicator in response_text:
                confidence += 0.3

        # Check for Perl-specific indicators
        perl_indicators = ['This is perl', 'built for', 'Larry Wall']
        for indicator in perl_indicators:
            if indicator.lower() in response_text.lower():
                confidence += 0.4

        # Check for system information
        system_indicators = ['Linux', 'Unix', 'Windows', 'GNU']
        for indicator in system_indicators:
            if indicator in response_text:
                confidence += 0.1

        return min(confidence, 1.0)

    def _extract_evidence(self, response_text: str) -> str:
        """Extract relevant evidence from response."""
        evidence_lines = []
        
        lines = response_text.split('\n')
        for line in lines[:10]:  # First 10 lines
            line = line.strip()
            if line and any(indicator.lower() in line.lower() for indicator in self.success_indicators):
                evidence_lines.append(line)
        
        return '\n'.join(evidence_lines) or "Response contains indicators of code execution"
