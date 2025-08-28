"""
Directory Traversal Scanner - Detects path traversal vulnerabilities
"""

import re
import logging
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class DirectoryTraversalScanner:
    """Directory traversal vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the directory traversal scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('traversal')
        self.general_config = config_manager.get('general')
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        # File content signatures to detect successful traversal
        self.file_signatures = {
            '/etc/passwd': [
                r'root:.*:0:0:',
                r'bin:.*:1:1:',
                r'daemon:.*:2:2:',
                r'mail:.*:8:12:',
                r'www-data:.*:33:33:'
            ],
            '/etc/hosts': [
                r'127\.0\.0\.1\s+localhost',
                r'::1\s+localhost'
            ],
            'boot.ini': [
                r'\[boot loader\]',
                r'timeout=',
                r'default='
            ],
            'win.ini': [
                r'\[windows\]',
                r'\[desktop\]'
            ]
        }
    
    def _load_payloads(self) -> List[str]:
        """Load directory traversal payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/traversal_payloads.txt')
        payloads = []
        
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
            
            logger.info(f"Loaded {len(payloads)} directory traversal payloads")
            
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '....//....//etc/passwd'
            ]
        
        return payloads
    
    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for directory traversal vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of findings
        """
        logger.info(f"Starting directory traversal scan on {target}")
        findings = []
        
        try:
            findings.extend(self._test_path_traversal(target))
            findings.extend(self._test_post_path_traversal(target))

            logger.info(f"Directory traversal scan completed - {len(findings)} potential vulnerabilities found")
            
        except Exception as e:
            logger.error(f"Directory traversal scan failed: {str(e)}")
            security_logger.log_error("TRAVERSAL_SCAN_ERROR", str(e), target)
        
        return findings
    
    def _test_path_traversal(self, target: str) -> List[Finding]:
        """Test for path traversal vulnerabilities."""
        findings = []
        
        for payload in self.payloads:
            # Test different parameter positions
            test_urls = [
                f"{target}?file={payload}",
                f"{target}?path={payload}",
                f"{target}?page={payload}",
                f"{target}?include={payload}",
                f"{target}?doc={payload}"
            ]
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                    
                    if response.status_code == 200:
                        # Check for successful traversal indicators
                        confidence = self._detect_traversal_success(response.text, payload)
                        
                        if confidence >= 0.6:
                            finding = Finding(
                                title="Directory Traversal Vulnerability",
                                severity=Severity.HIGH,
                                confidence=confidence,
                                description="Directory traversal vulnerability detected. The application allows access to files outside the intended directory through path manipulation.",
                                target=test_url,
                                vulnerability_type="Directory Traversal",
                                payload=payload,
                                evidence=self._get_traversal_evidence(response.text, payload),
                                impact="An attacker could potentially access sensitive files on the server, including configuration files, source code, or system files.",
                                remediation="Implement proper input validation, use whitelisting for allowed files, and avoid direct file path concatenation with user input."
                            )
                            
                            findings.append(finding)
                            security_logger.log_vulnerability_found("DIRECTORY_TRAVERSAL", test_url, "HIGH", confidence)
                            logger.warning(f"Directory traversal vulnerability found: {test_url}")
                    
                except Exception as e:
                    logger.debug(f"Request failed for traversal payload {payload}: {str(e)}")
        
        return findings
    
    def _detect_traversal_success(self, response_text: str, payload: str) -> float:
        """
        Detect if directory traversal was successful.
        
        Args:
            response_text: HTTP response content
            payload: Traversal payload used
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.0
        
        # Check for specific file content signatures
        for file_path, signatures in self.file_signatures.items():
            if file_path in payload.lower():
                for signature in signatures:
                    if re.search(signature, response_text, re.IGNORECASE | re.MULTILINE):
                        confidence += 0.8
                        return min(1.0, confidence)
        
        # Check for generic Unix/Linux file indicators
        unix_indicators = [
            r'root:x:0:0:',
            r'/bin/bash',
            r'/sbin/nologin',
            r'# This file',
            r'127\.0\.0\.1.*localhost'
        ]
        
        unix_matches = sum(1 for indicator in unix_indicators 
                          if re.search(indicator, response_text, re.IGNORECASE))
        if unix_matches >= 2:
            confidence += 0.7
        
        # Check for Windows file indicators
        windows_indicators = [
            r'\[boot loader\]',
            r'\[operating systems\]',
            r'\[windows\]',
            r'C:\\',
            r'Program Files'
        ]
        
        windows_matches = sum(1 for indicator in windows_indicators 
                             if re.search(indicator, response_text, re.IGNORECASE))
        if windows_matches >= 2:
            confidence += 0.7
        
        # Check for error messages that might indicate file access
        error_indicators = [
            r'Permission denied',
            r'No such file or directory',
            r'Access is denied',
            r'File not found',
            r'Invalid path'
        ]
        
        for indicator in error_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                confidence += 0.3
                break
        
        return min(1.0, confidence)
    
    def _get_traversal_evidence(self, response_text: str, payload: str) -> str:
        """Get evidence of successful directory traversal."""
        # Return first few lines of response that might contain file content
        lines = response_text.split('\n')[:5]
        evidence_lines = []
        
        for line in lines:
            line = line.strip()
            if line and len(line) > 10:  # Skip very short lines
                # Truncate long lines
                if len(line) > 100:
                    line = line[:100] + "..."
                evidence_lines.append(line)
        
        return "Response content: " + " | ".join(evidence_lines) if evidence_lines else "File content detected in response"

    def _test_post_path_traversal(self, target: str) -> List[Finding]:
        """Test for path traversal vulnerabilities in POST requests."""
        findings = []
        try:
            response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                return findings

            logger.info(f"Found {len(forms)} forms on {target} to test for POST-based traversal.")

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()

                if method != 'post':
                    continue

                form_url = urljoin(target, action)
                inputs = form.find_all(['input', 'textarea', 'select'])

                for payload in self.payloads:
                    for input_tag in inputs:
                        param_name = input_tag.get('name')
                        if not param_name:
                            continue

                        # Create data payload for POST request
                        data = {}
                        for i in inputs:
                            name = i.get('name')
                            if name:
                                value = i.get('value', 'test')
                                data[name] = value

                        data[param_name] = payload

                        try:
                            post_response = requests.post(form_url, data=data, timeout=self.general_config.get('timeout', 30))

                            if post_response.status_code == 200:
                                confidence = self._detect_traversal_success(post_response.text, payload)

                                if confidence >= 0.6:
                                    finding = Finding(
                                        title="Directory Traversal Vulnerability (POST-based)",
                                        severity=Severity.HIGH,
                                        confidence=confidence,
                                        description="Directory traversal vulnerability detected in a POST request. The application allows access to files outside the intended directory through path manipulation in a POST parameter.",
                                        target=form_url,
                                        vulnerability_type="Directory Traversal",
                                        payload=payload,
                                        evidence=self._get_traversal_evidence(post_response.text, payload),
                                        impact="An attacker could potentially access sensitive files on the server, including configuration files, source code, or system files.",
                                        remediation="Implement proper input validation for all POST parameters, use whitelisting for allowed files, and avoid direct file path concatenation with user input."
                                    )

                                    findings.append(finding)
                                    security_logger.log_vulnerability_found("DIRECTORY_TRAVERSAL_POST", form_url, "HIGH", confidence)
                                    logger.warning(f"POST-based directory traversal vulnerability found: {form_url} with param '{param_name}'")
                        except Exception as e:
                            logger.debug(f"POST request failed for traversal payload {payload}: {str(e)}")

        except requests.RequestException as e:
            logger.warning(f"Could not fetch target {target} to check for forms: {e}")

        return findings