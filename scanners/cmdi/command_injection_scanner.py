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

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class CommandInjectionScanner:
    """OS Command injection vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the command injection scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('cmdi')
        self.general_config = config_manager.get('general')
        
        # Command injection payloads for different OS
        self.unix_payloads = [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; id",
            "| id",
            "&& id",
            "; whoami",
            "| whoami",
            "&& whoami",
            "; uname -a",
            "| uname -a",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "`id`",
            "$(id)",
            "`whoami`",
            "$(whoami)",
        ]
        
        self.windows_payloads = [
            "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "| type C:\\windows\\system32\\drivers\\etc\\hosts",
            "&& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "& whoami",
            "| whoami",
            "&& whoami",
            "& dir",
            "| dir",
            "&& dir",
            "& echo %USERNAME%",
            "| echo %USERNAME%",
        ]
        
        # Time-based payloads for blind detection
        self.time_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "& timeout 5",
            "| timeout 5",
            "&& timeout 5",
        ]
        
        # Success indicators for different OS
        self.unix_indicators = [
            'root:x:0:0:',  # /etc/passwd
            'daemon:',
            '/bin/',
            '/usr/',
            '/sbin/',
            'uid=',  # id command output
            'gid=',
            'groups=',
            'Linux',  # uname output
            'Unix',
            'GNU',
        ]
        
        self.windows_indicators = [
            '# Copyright',  # Windows hosts file
            'localhost',
            '127.0.0.1',
            'SYSTEM\\',
            'Program Files',
            'Windows',
            'C:\\',
            'D:\\',
        ]
        
        # Load payloads
        self.payloads = self._load_payloads()
    
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
            # Find potential injection points
            injection_points = self._find_injection_points(target_url)
            
            for point in injection_points:
                # Test direct command injection
                findings.extend(self._test_direct_injection(point))
                
                # Test blind command injection
                findings.extend(self._test_blind_injection(point))
                
                # Test encoded payloads
                findings.extend(self._test_encoded_injection(point))
                
        except Exception as e:
            logger.error(f"Command injection scan failed: {str(e)}")
            security_logger.log_error("CMDI_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"Command injection scan completed. Found {len(findings)} potential issues.")
        return findings
    
    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential command injection points."""
        points = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # Parse URL for existing parameters
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                # Look for parameters that might execute commands
                if any(keyword in param_name.lower() for keyword in [
                    'cmd', 'command', 'exec', 'system', 'shell', 'run',
                    'file', 'filename', 'path', 'script', 'ping', 'host'
                ]):
                    points.append({
                        'type': 'url_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'GET'
                    })
            
            # Look for forms that might execute commands
            form_patterns = [
                r'<input[^>]*name=[\'"]([^\'\"]*(?:cmd|command|exec|system|shell|run|file|filename|path|script|ping|host)[^\'\"]*)[\'"][^>]*>',
                r'<textarea[^>]*name=[\'"]([^\'\"]*(?:cmd|command|exec|system|shell|run|file|filename|path|script|ping|host)[^\'\"]*)[\'"][^>]*>',
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
            
            # Look for file upload or processing endpoints
            upload_indicators = ['upload', 'file', 'import', 'process', 'convert']
            if any(indicator in target_url.lower() for indicator in upload_indicators):
                points.append({
                    'type': 'upload_endpoint',
                    'url': target_url,
                    'parameter': 'filename',
                    'method': 'POST'
                })
            
        except Exception as e:
            logger.debug(f"Error finding injection points: {str(e)}")
        
        return points
    
    def _test_direct_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test direct command injection."""
        findings = []
        
        # Test both Unix and Windows payloads
        all_payloads = self.unix_payloads[:3] + self.windows_payloads[:3]  # First 3 of each
        
        for payload in all_payloads:
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
                    
                elif injection_point['type'] == 'upload_endpoint':
                    # Test filename injection
                    files = {'file': ('test' + payload + '.txt', 'test content')}
                    response = requests.post(
                        injection_point['url'], 
                        files=files, 
                        timeout=self.general_config.get('timeout', 10)
                    )
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
    
    def _test_blind_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test blind command injection using timing attacks."""
        findings = []
        
        for payload in self.time_payloads[:3]:  # Test first 3 time payloads
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
    
    def _test_encoded_injection(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test encoded command injection payloads."""
        findings = []
        
        # URL encoded payloads
        encoded_payloads = [
            "%3B%20cat%20%2Fetc%2Fpasswd",  # ; cat /etc/passwd
            "%7C%20id",  # | id
            "%26%26%20whoami",  # && whoami
        ]
        
        for payload in encoded_payloads:
            try:
                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)
                    
                    original_value = params.get(injection_point['parameter'], ['test'])[0]
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
        """Check if command injection was successful."""
        try:
            response_text = response.text.lower()
            
            # Check for Unix command output
            for indicator in self.unix_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for Windows command output
            for indicator in self.windows_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for command execution errors
            error_indicators = [
                'command not found',
                'permission denied',
                'no such file or directory',
                'syntax error',
                'bad command',
                'invalid command',
                'sh: ',
                'bash: ',
                'cmd.exe',
                'powershell'
            ]
            
            for indicator in error_indicators:
                if indicator in response_text:
                    return True
                    
            # Check if payload is reflected in an error message
            if payload.replace(';', '').replace('|', '').replace('&', '').strip() in response_text:
                # Look for execution context
                execution_contexts = [
                    'execute',
                    'command',
                    'shell',
                    'system',
                    'exec',
                    'process'
                ]
                
                if any(context in response_text for context in execution_contexts):
                    return True
                    
        except Exception as e:
            logger.debug(f"Error checking command injection success: {str(e)}")
        
        return False
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load command injection payloads."""
        return {
            'unix': self.unix_payloads,
            'windows': self.windows_payloads,
            'time_based': self.time_payloads
        }