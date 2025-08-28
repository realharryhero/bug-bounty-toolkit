"""
XSS Scanner - Detects Cross-Site Scripting vulnerabilities
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
from scanners.base_scanner import BaseScanner, register_scanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

@register_scanner('xss')
class XSSScanner(BaseScanner):
    """Cross-Site Scripting vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the XSS scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        # XSS detection patterns
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*src\s*=',
            r'<img[^>]*onerror\s*=',
            r'<svg[^>]*onload\s*=',
            r'alert\s*\(',
            r'confirm\s*\(',
            r'prompt\s*\(',
        ]
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/xss_payloads.txt')
        payloads = []
        
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
            
            logger.info(f"Loaded {len(payloads)} XSS payloads")
            
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "';alert('XSS');//"
            ]
        
        return payloads
    
    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for XSS vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of findings
        """
        logger.info(f"Starting XSS scan on {target}")
        findings = []
        
        try:
            # Test different XSS types
            test_types = self.config.get('test_types', ['reflected', 'stored', 'dom'])
            
            if 'reflected' in test_types:
                findings.extend(self._test_reflected_xss(target))
            
            if 'stored' in test_types:
                findings.extend(self._test_stored_xss(target))
            
            if 'dom' in test_types:
                findings.extend(self._test_dom_xss(target))
            
            logger.info(f"XSS scan completed - {len(findings)} potential vulnerabilities found")
            
        except Exception as e:
            logger.error(f"XSS scan failed: {str(e)}")
            security_logger.log_error("XSS_SCAN_ERROR", str(e), target)
        
        return findings
    
    def _test_reflected_xss(self, target: str) -> List[Finding]:
        """Test for reflected XSS vulnerabilities."""
        findings = []
        
        for payload in self.payloads[:15]:  # Limit payloads for performance
            # Create unique marker for this payload
            marker = f"XSS_TEST_{hash(payload) % 10000}"
            test_payload = payload.replace("XSS", marker)
            
            test_url = f"{target}?q={test_payload}"
            
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                
                if response.status_code == 200:
                    # Check if payload is reflected in response
                    if marker in response.text:
                        # Check if payload is executed (not just reflected)
                        confidence = self._calculate_xss_confidence(response.text, test_payload)
                        
                        if confidence >= self.config.get('confidence_threshold', 0.5):
                            finding = Finding(
                                title="Reflected XSS Vulnerability",
                                severity=Severity.MEDIUM,
                                confidence=confidence,
                                description="Reflected Cross-Site Scripting vulnerability detected. User input is reflected in the response without proper encoding or filtering.",
                                target=test_url,
                                vulnerability_type="Cross-Site Scripting",
                                payload=test_payload,
                                evidence=f"Payload reflected in response with marker: {marker}",
                                impact="An attacker could execute malicious scripts in the context of the victim's browser, potentially stealing cookies, session tokens, or performing actions on behalf of the user.",
                                remediation="Encode all user input before displaying it in HTML context. Use Content Security Policy (CSP) headers to prevent script execution."
                            )
                            
                            findings.append(finding)
                            security_logger.log_vulnerability_found("REFLECTED_XSS", target, "MEDIUM", confidence)
                            logger.warning(f"Potential reflected XSS found: {test_url}")
                
                time.sleep(self.general_config.get('delay', 1.0))
                
            except Exception as e:
                logger.debug(f"Request failed for XSS payload {test_payload}: {str(e)}")
        
        return findings
    
    def _test_stored_xss(self, target: str) -> List[Finding]:
        """Test for stored XSS vulnerabilities."""
        findings = []
        
        # This is a simplified implementation - would need form detection in production
        logger.info("Stored XSS testing requires form submission capabilities")
        logger.info("This is a placeholder implementation")
        
        return findings
    
    def _test_dom_xss(self, target: str) -> List[Finding]:
        """Test for DOM-based XSS vulnerabilities."""
        findings = []
        
        # DOM XSS payloads that work in URL fragments
        dom_payloads = [
            "#<script>alert('DOM_XSS')</script>",
            "#javascript:alert('DOM_XSS')",
            "#<img src=x onerror=alert('DOM_XSS')>",
        ]
        
        for payload in dom_payloads:
            test_url = f"{target}{payload}"
            
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                
                if response.status_code == 200:
                    # Look for JavaScript patterns that might process the fragment
                    js_patterns = [
                        r'location\.hash',
                        r'window\.location\.hash',
                        r'document\.location\.hash',
                        r'location\.href',
                        r'document\.URL',
                        r'document\.referrer'
                    ]
                    
                    js_usage_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                       for pattern in js_patterns)
                    
                    if js_usage_found:
                        confidence = 0.4  # Lower confidence for DOM XSS detection
                        
                        finding = Finding(
                            title="Potential DOM-based XSS Vulnerability",
                            severity=Severity.MEDIUM,
                            confidence=confidence,
                            description="Potential DOM-based XSS detected. The page uses JavaScript to process URL parameters which may lead to XSS if not properly handled.",
                            target=test_url,
                            vulnerability_type="Cross-Site Scripting",
                            payload=payload,
                            evidence="JavaScript code found that processes URL/location properties",
                            impact="An attacker could potentially execute malicious scripts through DOM manipulation.",
                            remediation="Properly validate and encode data before using it in DOM operations. Avoid using dangerous JavaScript functions with user-controlled data."
                        )
                        
                        findings.append(finding)
                        security_logger.log_vulnerability_found("DOM_XSS", target, "MEDIUM", confidence)
                        break  # Stop after first potential DOM XSS
                
                time.sleep(self.general_config.get('delay', 1.0))
                
            except Exception as e:
                logger.debug(f"Request failed for DOM XSS payload {payload}: {str(e)}")
        
        return findings
    
    def _calculate_xss_confidence(self, response_text: str, payload: str) -> float:
        """
        Calculate confidence score for XSS detection.
        
        Args:
            response_text: HTTP response content
            payload: XSS payload used
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.0
        
        # Base confidence for payload reflection
        if payload in response_text:
            confidence += 0.3
        
        # Check if payload appears in potentially executable context
        dangerous_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'javascript:.*' + re.escape(payload),
            r'on\w+\s*=\s*["\'].*' + re.escape(payload),
            r'<iframe[^>]*src\s*=\s*["\'].*' + re.escape(payload),
        ]
        
        for context in dangerous_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                confidence += 0.4
                break
        
        # Check for XSS pattern matches
        pattern_matches = sum(1 for pattern in self.xss_patterns 
                            if re.search(pattern, response_text, re.IGNORECASE))
        
        if pattern_matches > 0:
            confidence += min(0.3, pattern_matches * 0.1)
        
        return min(1.0, confidence)