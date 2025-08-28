"""
HTTP Header Injection Scanner - Detects CRLF injection and response splitting vulnerabilities
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner, register_scanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()


@register_scanner('header_injection')
class HeaderInjectionScanner(BaseScanner):
    """HTTP Header Injection vulnerability scanner."""
    
    def __init__(self, config_manager):
        """Initialize the header injection scanner."""
        super().__init__(config_manager)
        
        # Load payloads from config
        self.payloads = self._load_payloads()
        self.test_headers = self.config.get('test_headers', [])
        
        # Detection patterns
        self.injection_patterns = [
            r'Set-Cookie:\s*injected=true',
            r'<script>alert\(',
            r'Content-Type:\s*text/html',
        ]
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load header injection payloads from configuration."""
        return self.config.get('payload_patterns', {
            'crlf': ["\r\nSet-Cookie: injected=true"],
            'response_splitting': ["\r\n\r\n<script>alert('xss')</script>"]
        })
    
    def scan(self, target: str) -> List[Finding]:
        """
        Scan for HTTP header injection vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of Finding objects representing discovered vulnerabilities
        """
        if not self.is_enabled():
            logger.debug("Header injection scanner is disabled")
            return []
        
        logger.info(f"Starting header injection scan on {target}")
        findings = []
        
        try:
            # Test header injections
            findings.extend(self._test_header_injection(target))
            
        except Exception as e:
            logger.error(f"Error during header injection scan: {str(e)}")
        
        logger.info(f"Header injection scan completed. Found {len(findings)} potential vulnerabilities")
        return findings
    
    def _test_header_injection(self, target: str) -> List[Finding]:
        """Test for header injection vulnerabilities."""
        findings = []
        
        for header_name in self.test_headers:
            for payload_type, payloads in self.payloads.items():
                for payload in payloads[:self.config.get('max_payloads_per_param', 5)]:
                    finding = self._test_payload_in_header(target, header_name, payload, payload_type)
                    if finding:
                        findings.append(finding)
        
        return findings
    
    def _test_payload_in_header(self, target: str, header_name: str, payload: str, payload_type: str) -> Optional[Finding]:
        """Test a specific payload in a header."""
        try:
            headers = {header_name: payload}
            
            response = requests.get(
                target,
                headers=headers,
                timeout=self.config.get('timeout', 30),
                allow_redirects=False,
                verify=False
            )
            
            # Check if payload was reflected in response headers
            response_headers = response.headers
            for header_key, header_value in response_headers.items():
                if self._is_injection_detected(header_value, payload):
                    logger.warning(f"Potential header injection in {header_name}: {payload[:50]}...")
                    
                    return Finding(
                        vulnerability_type="HEADER_INJECTION",
                        severity=Severity.MEDIUM,
                        confidence=self.config.get('confidence_threshold', 0.8),
                        target=target,
                        description=f"Potential HTTP header injection vulnerability detected in {header_name} header",
                        evidence=f"Payload: {payload}\nReflected in: {header_key}: {header_value[:100]}...",
                        remediation="Validate and sanitize all user input before including in HTTP headers. "
                                  "Use proper encoding and escaping techniques."
                    )
            
            # Check if payload was reflected in response body
            if self._is_injection_detected(response.text, payload):
                logger.warning(f"Potential response splitting in {header_name}: {payload[:50]}...")
                
                return Finding(
                    vulnerability_type="RESPONSE_SPLITTING",
                    severity=Severity.HIGH,
                    confidence=self.config.get('confidence_threshold', 0.8),
                    target=target,
                    description=f"Potential HTTP response splitting vulnerability detected via {header_name} header",
                    evidence=f"Payload: {payload}\nResponse contains injected content",
                    remediation="Validate and sanitize all user input. Never include unvalidated user input "
                              "in HTTP response headers or status lines."
                )
        
        except requests.RequestException as e:
            logger.debug(f"Request failed for header injection test: {str(e)}")
        except Exception as e:
            logger.error(f"Error testing header injection payload: {str(e)}")
        
        return None
    
    def _is_injection_detected(self, response_content: str, payload: str) -> bool:
        """Check if the injection was successful."""
        # Look for injection patterns in the response
        for pattern in self.injection_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True
        
        # Check for direct payload reflection
        if "injected=true" in response_content or "alert(" in response_content:
            return True
        
        return False