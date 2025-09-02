"""
Command Injection Scanner - Detects OS command injection vulnerabilities
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

class CommandInjectionScanner(BaseScanner):
    """OS Command injection vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the command injection scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('cmdi')
        self.general_config = config_manager.get('general')
        
        # Load payloads
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> List[str]:
        """Load command injection payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/cmdi_payloads.txt')
        payloads = []

        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)

            logger.info(f"Loaded {len(payloads)} command injection payloads")

        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = [
                "; whoami",
                "| whoami",
                "&& id",
                "& dir"
            ]

        return payloads

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for command injection vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        logger.info(f"Starting command injection scan on {target_url}")
        security_logger.log_scan_start("command_injection", target_url)
        
        try:
            test_types = self.config.get('test_types', ['direct', 'blind', 'time'])

            # Find potential injection points
            injection_points = self._find_injection_points(target_url)
            
            for point in injection_points:
                if 'direct' in test_types:
                    findings.extend(self._test_direct_injection(point))
                
                if 'blind' in test_types:
                    findings.extend(self._test_blind_injection(point))
                
                if 'time' in test_types:
                    findings.extend(self._test_time_based_injection(point))

                # Test for encoded payloads separately, as it's a different technique
                findings.extend(self._test_encoded_injection(point))
                
        except Exception as e:
            logger.error(f"Command injection scan failed: {str(e)}")
            security_logger.log_error("CMDI_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"Command injection scan completed. Found {len(findings)} potential issues.")
        
        verified_findings = self.filter_false_positives(findings, target_url)
        
        for finding in verified_findings:
            self.log_finding_details(finding, "Command injection might be false if input sanitization or WAF is present.")
        
        return verified_findings
    
    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential command injection points in URL parameters, forms, and headers."""
        points = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # 1. URL Parameters
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            for param, values in query_params.items():
                points.append({
                    'type': 'url_param',
                    'url': target_url,
                    'parameter': param,
                    'method': 'GET'
                })

            # 2. Forms
            # A more robust regex to find forms and their inputs
            forms = re.finditer(r'<form[^>]*action=[\'"]([^\'"]*)[\'"][^>]*>(.*?)</form>', response.text, re.IGNORECASE | re.DOTALL)
            for form_match in forms:
                action = form_match.group(1)
                form_content = form_match.group(2)
                form_url = urljoin(target_url, action)

                # Find all input and textarea names in the form
                input_names = re.findall(r'<input[^>]*name=[\'"]([^\'"]*)[\'"]', form_content, re.IGNORECASE)
                textarea_names = re.findall(r'<textarea[^>]*name=[\'"]([^\'"]*)[\'"]', form_content, re.IGNORECASE)

                for param_name in set(input_names + textarea_names):
                    points.append({
                        'type': 'form_param',
                        'url': form_url,
                        'parameter': param_name,
                        'method': 'POST' # Assuming POST for simplicity, can be improved
                    })

            # 3. Headers
            # Test common headers that might be processed by the application
            headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Client-IP']
            for header in headers_to_test:
                points.append({
                    'type': 'header',
                    'url': target_url,
                    'parameter': header,
                    'method': 'GET' # Can be tested with POST as well
                })

            # 4. JSON Body (if applicable, requires a POST request)
            # This is more complex as we need to know which endpoints accept JSON.
            # For now, we'll assume that if the word 'api' is in the url, it might accept JSON.
            if 'api' in target_url:
                points.append({
                    'type': 'json_body',
                    'url': target_url,
                    'parameter': 'json_root', # Placeholder for the whole body
                    'method': 'POST'
                })

        except Exception as e:
            logger.debug(f"Error finding injection points: {str(e)}")
        
        # Remove duplicate points
        unique_points = [dict(t) for t in {tuple(d.items()) for d in points}]
        logger.info(f"Found {len(unique_points)} potential injection points.")
        return unique_points
    
    def _test_direct_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test direct command injection."""
        findings = []

        for payload in self.payloads:
            try:
                response = None
                test_url = injection_point['url']
                headers = {'User-Agent': self.general_config.get('user_agent')}

                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(test_url)
                    params = parse_qs(parsed_url.query)
                    original_value = params.get(injection_point['parameter'], [''])[0]
                    params[injection_point['parameter']] = [original_value + payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))
                    
                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(test_url, data=data, headers=headers, timeout=self.general_config.get('timeout', 10))
                    
                elif injection_point['type'] == 'header':
                    headers[injection_point['parameter']] = payload
                    response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))

                elif injection_point['type'] == 'json_body':
                    # Create a simple JSON payload. This can be made more sophisticated.
                    json_payload = {'vulnerable_param': payload}
                    response = requests.post(test_url, json=json_payload, headers=headers, timeout=self.general_config.get('timeout', 10))

                else:
                    continue
                
                # Check for successful command execution
                if self._is_command_injection_successful(response, payload):
                    finding = Finding(
                        title="OS Command Injection",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        description=f"Command injection vulnerability detected via parameter '{injection_point['parameter']}'",
                        target=injection_point['url'],
                        vulnerability_type="Command Injection",
                        evidence=f"Payload: {payload}, Parameter: {injection_point['parameter']}",
                        impact="Attacker can execute arbitrary OS commands on the server.",
                        remediation="Use parameterized commands, input validation, and avoid direct OS command execution."
                    )
                    findings.append(finding)
                    return findings  # Stop after first successful injection
                    
            except Exception as e:
                logger.debug(f"Error testing direct injection: {str(e)}")
        
        return findings
    
    def _test_time_based_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test time-based blind command injection."""
        findings = []
        
        time_payloads = [p for p in self.payloads if 'sleep' in p or 'ping' in p]

        for payload in time_payloads:
            try:
                start_time = time.time()
                response = None
                test_url = injection_point['url']
                headers = {'User-Agent': self.general_config.get('user_agent')}

                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(test_url)
                    params = parse_qs(parsed_url.query)
                    original_value = params.get(injection_point['parameter'], [''])[0]
                    params[injection_point['parameter']] = [original_value + payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    response = requests.get(test_url, headers=headers, timeout=15)
                    
                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(test_url, data=data, headers=headers, timeout=15)

                elif injection_point['type'] == 'header':
                    headers[injection_point['parameter']] = payload
                    response = requests.get(test_url, headers=headers, timeout=15)

                elif injection_point['type'] == 'json_body':
                    json_payload = {'vulnerable_param': payload}
                    response = requests.post(test_url, json=json_payload, headers=headers, timeout=15)

                else:
                    continue
                
                elapsed_time = time.time() - start_time
                
                # If request took significantly longer (around 5 seconds), likely successful
                if 4 <= elapsed_time <= 8:  # Allow some tolerance
                    finding = Finding(
                        title="Blind OS Command Injection",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description=f"Timing-based blind command injection detected",
                        target=injection_point['url'],
                        vulnerability_type="Command Injection",
                        evidence=f"Response time: {elapsed_time:.2f}s, Parameter: {injection_point['parameter']}",
                        impact="Application may be vulnerable to blind command injection.",
                        remediation="Implement input validation and avoid direct OS command execution."
                    )
                    findings.append(finding)
                    return findings
                    
            except requests.exceptions.Timeout:
                # Timeout might indicate successful sleep command
                finding = Finding(
                    title="Potential Blind Command Injection (Timeout)",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=f"Request timeout may indicate blind command injection",
                    target=injection_point['url'],
                    vulnerability_type="Command Injection",
                    evidence=f"Request timeout with payload: {payload}",
                    impact="Application may be vulnerable to blind command injection.",
                    remediation="Implement timeout controls and input validation."
                )
                findings.append(finding)
                return findings
            except Exception as e:
                logger.debug(f"Error testing blind injection: {str(e)}")
        
        return findings
    
    def _test_blind_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test for blind command injection using boolean-based techniques."""
        findings = []

        true_payload = "&& whoami"
        false_payload = "&& non_existent_command_12345"

        try:
            # Test true condition
            true_response = self._send_request_with_payload(injection_point, true_payload)

            # Test false condition
            false_response = self._send_request_with_payload(injection_point, false_payload)

            if true_response and false_response:
                # Compare responses
                if (true_response.status_code == 200 and false_response.status_code == 200 and
                    len(true_response.text) != len(false_response.text)):

                    finding = Finding(
                        title="Blind OS Command Injection",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description="Blind command injection detected through content analysis.",
                        target=injection_point['url'],
                        vulnerability_type="Command Injection",
                        evidence=f"Response length difference - True: {len(true_response.text)}, False: {len(false_response.text)}",
                        impact="Attacker may be able to execute arbitrary commands without direct output.",
                        remediation="Use parameterized commands and validate all user input."
                    )
                    findings.append(finding)

        except Exception as e:
            logger.debug(f"Error testing blind injection: {str(e)}")

        return findings

    def _send_request_with_payload(self, injection_point: Dict[str, Any], payload: str) -> Optional[requests.Response]:
        """Helper function to send a request with a given payload."""
        test_url = injection_point['url']
        headers = {'User-Agent': self.general_config.get('user_agent')}
        response = None

        try:
            if injection_point['type'] == 'url_param':
                parsed_url = urlparse(test_url)
                params = parse_qs(parsed_url.query)
                original_value = params.get(injection_point['parameter'], [''])[0]
                params[injection_point['parameter']] = [original_value + payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))

            elif injection_point['type'] == 'form_param':
                data = {injection_point['parameter']: 'test' + payload}
                response = requests.post(test_url, data=data, headers=headers, timeout=self.general_config.get('timeout', 10))

            elif injection_point['type'] == 'header':
                headers[injection_point['parameter']] = payload
                response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))

            elif injection_point['type'] == 'json_body':
                json_payload = {'vulnerable_param': payload}
                response = requests.post(test_url, json=json_payload, headers=headers, timeout=self.general_config.get('timeout', 10))

        except Exception as e:
            logger.debug(f"Request failed for payload {payload}: {str(e)}")

        return response

    def _test_encoded_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test encoded command injection payloads."""
        findings = []
        
        encoded_payloads = [p for p in self.payloads if '%' in p]

        for payload in encoded_payloads:
            try:
                response = None
                test_url = injection_point['url']
                headers = {'User-Agent': self.general_config.get('user_agent')}

                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(test_url)
                    params = parse_qs(parsed_url.query)
                    original_value = params.get(injection_point['parameter'], [''])[0]
                    # The payload is already encoded, so we append it directly
                    test_url = f"{injection_point['url'].split('?')[0]}?{injection_point['parameter']}={original_value}{payload}"
                    response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))
                    
                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: 'test' + payload}
                    response = requests.post(test_url, data=data, headers=headers, timeout=self.general_config.get('timeout', 10))

                # Encoded payloads in headers or JSON are less common, but we can add them for completeness
                elif injection_point['type'] == 'header':
                    headers[injection_point['parameter']] = payload
                    response = requests.get(test_url, headers=headers, timeout=self.general_config.get('timeout', 10))

                elif injection_point['type'] == 'json_body':
                    json_payload = {'vulnerable_param': payload}
                    response = requests.post(test_url, json=json_payload, headers=headers, timeout=self.general_config.get('timeout', 10))

                else:
                    continue
                
                # Check for successful command execution
                if self._is_command_injection_successful(response, payload):
                    finding = Finding(
                        title="Encoded Command Injection",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"Encoded command injection vulnerability detected",
                        target=injection_point['url'],
                        vulnerability_type="Command Injection",
                        evidence=f"Encoded payload: {payload}, Parameter: {injection_point['parameter']}",
                        impact="Attacker can bypass filtering using encoded payloads.",
                        remediation="Implement proper input validation including decoding checks."
                    )
                    findings.append(finding)
                    return findings
                    
            except Exception as e:
                logger.debug(f"Error testing encoded injection: {str(e)}")
        
        return findings
    
    def _is_command_injection_successful(self, response: requests.Response, payload: str) -> bool:
        """Check if command injection was successful using regex and contextual analysis."""
        if not response:
            return False

        try:
            response_text = response.text.lower()
            
            # Regex patterns for common command outputs
            unix_patterns = {
                'id': r'uid=\d+\(.*\)\s+gid=\d+\(.*\)',
                'whoami': r'\b[a-zA-Z0-9_-]+\b', # Matches a simple username
                'uname': r'linux|darwin|freebsd|unix',
                'passwd': r'root:x:0:0:'
            }
            
            windows_patterns = {
                'whoami': r'[a-z0-9-]+\\[a-z0-9-]+', # domain\user
                'ipconfig': r'ipv4 address.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
                'dir': r'directory of',
                'win.ini': r'for 16-bit app support'
            }

            # Check for payload-specific indicators
            clean_payload = re.sub(r'[^a-zA-Z0-9]', '', payload).lower()
            
            if 'id' in clean_payload:
                if re.search(unix_patterns['id'], response_text): return True
            if 'whoami' in clean_payload:
                if re.search(unix_patterns['whoami'], response_text) or re.search(windows_patterns['whoami'], response_text): return True
            if 'uname' in clean_payload:
                if re.search(unix_patterns['uname'], response_text): return True
            if 'passwd' in clean_payload:
                if re.search(unix_patterns['passwd'], response_text): return True
            if 'ipconfig' in clean_payload:
                if re.search(windows_patterns['ipconfig'], response_text): return True
            if 'dir' in clean_payload:
                if re.search(windows_patterns['dir'], response_text): return True
            if 'win.ini' in clean_payload:
                if re.search(windows_patterns['win.ini'], response_text): return True

            # Generic error-based detection
            error_patterns = [
                r'command not found',
                r'permission denied',
                r'no such file or directory',
                r'syntax error',
                r'unrecognized command',
                r'is not recognized as an internal or external command'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True # Found an error message, which is a strong indicator

        except Exception as e:
            logger.debug(f"Error checking command injection success: {str(e)}")
        
        return False
