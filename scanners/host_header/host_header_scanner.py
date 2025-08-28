"""
Host Header Injection Scanner - Detects host header injection vulnerabilities
"""

import logging
import requests
import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class HostHeaderScanner:
    """Host header injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the Host Header scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('host_header')
        self.general_config = config_manager.get('general')

        # Malicious host headers to test
        self.malicious_hosts = [
            'evil.com',
            'attacker.com',
            'localhost',
            '127.0.0.1',
            'example.com',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for host header injection vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting host header injection scan on {target_url}")
        findings = []

        try:
            # Test host header reflection
            findings.extend(self._test_host_reflection(target_url))
            
            # Test password reset poisoning
            findings.extend(self._test_password_reset_poisoning(target_url))
            
            # Test cache poisoning
            findings.extend(self._test_cache_poisoning(target_url))
            
            # Test routing-based SSRF
            findings.extend(self._test_routing_ssrf(target_url))

        except Exception as e:
            logger.error(f"Error during host header scan: {str(e)}")
            security_logger.log_error("HOST_HEADER_SCAN_ERROR", str(e), target_url)

        logger.info(f"Host header injection scan completed - {len(findings)} findings")
        return findings

    def _test_host_reflection(self, target_url: str) -> List[Finding]:
        """Test for host header reflection in response."""
        findings = []
        
        parsed_url = urlparse(target_url)
        original_host = parsed_url.netloc
        
        for malicious_host in self.malicious_hosts:
            try:
                response = requests.get(
                    target_url,
                    headers={
                        'Host': malicious_host,
                        'User-Agent': self.general_config.get('user_agent')
                    },
                    timeout=self.general_config.get('timeout', 30),
                    allow_redirects=False
                )
                
                if self._is_host_reflected(response, malicious_host):
                    finding = Finding(
                        title="Host Header Reflection",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        description=f"Host header is reflected in response content with malicious host '{malicious_host}'",
                        url=target_url,
                        method="GET",
                        evidence=self._extract_reflection_evidence(response, malicious_host),
                        impact="Host header reflection can lead to password reset poisoning, cache poisoning, or phishing attacks.",
                        remediation="Validate the Host header against a whitelist of allowed hosts. Use absolute URLs instead of relative ones."
                    )
                    findings.append(finding)
                    logger.warning(f"Host header reflection found with host: {malicious_host}")
                    break  # Found one, no need to test more
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing host header reflection with {malicious_host}: {str(e)}")

        return findings

    def _test_password_reset_poisoning(self, target_url: str) -> List[Finding]:
        """Test for password reset poisoning via host header."""
        findings = []
        
        # Common password reset endpoints
        reset_endpoints = [
            '/forgot-password',
            '/password-reset', 
            '/reset-password',
            '/forgot',
            '/password/reset',
            '/account/forgot-password',
            '/user/forgot-password',
            '/auth/forgot-password',
        ]
        
        parsed_url = urlparse(target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for endpoint in reset_endpoints:
            test_url = base_url + endpoint
            
            for malicious_host in self.malicious_hosts[:2]:  # Test fewer for reset endpoints
                try:
                    # Try GET first to see if endpoint exists
                    response = requests.get(
                        test_url,
                        headers={
                            'Host': malicious_host,
                            'User-Agent': self.general_config.get('user_agent')
                        },
                        timeout=self.general_config.get('timeout', 30),
                        allow_redirects=False
                    )
                    
                    if response.status_code == 200 and self._looks_like_reset_page(response):
                        if self._is_host_reflected(response, malicious_host):
                            finding = Finding(
                                title="Password Reset Poisoning",
                                severity=Severity.HIGH,
                                confidence=0.8,
                                description=f"Password reset page reflects malicious host header '{malicious_host}', enabling password reset poisoning",
                                url=test_url,
                                method="GET",
                                evidence=f"Reset page found at {endpoint}, reflects host: {malicious_host}",
                                impact="Attackers can poison password reset emails to redirect users to malicious sites and steal credentials.",
                                remediation="Use absolute URLs in password reset emails and validate the Host header against trusted domains."
                            )
                            findings.append(finding)
                            logger.warning(f"Password reset poisoning found at {test_url}")
                            break
                            
                except requests.RequestException as e:
                    logger.debug(f"Error testing password reset poisoning at {test_url}: {str(e)}")

        return findings

    def _test_cache_poisoning(self, target_url: str) -> List[Finding]:
        """Test for cache poisoning via host header."""
        findings = []
        
        parsed_url = urlparse(target_url)
        
        for malicious_host in self.malicious_hosts[:3]:  # Test a few hosts
            try:
                # Send request with malicious host
                response1 = requests.get(
                    target_url,
                    headers={
                        'Host': malicious_host,
                        'User-Agent': self.general_config.get('user_agent'),
                        'Cache-Control': 'no-cache'  # Try to bypass cache first time
                    },
                    timeout=self.general_config.get('timeout', 30)
                )
                
                # Send normal request to see if cache was poisoned
                response2 = requests.get(
                    target_url,
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    timeout=self.general_config.get('timeout', 30)
                )
                
                if self._is_cache_poisoned(response2, malicious_host):
                    finding = Finding(
                        title="Cache Poisoning via Host Header",
                        severity=Severity.HIGH,
                        confidence=0.6,
                        description=f"Cache poisoning detected using malicious host '{malicious_host}'",
                        url=target_url,
                        method="GET",
                        evidence=f"Subsequent request without malicious host still reflects: {malicious_host}",
                        impact="Cache poisoning can serve malicious content to all users, leading to widespread compromise.",
                        remediation="Exclude the Host header from cache keys or validate it strictly before caching responses."
                    )
                    findings.append(finding)
                    logger.warning(f"Cache poisoning detected with host: {malicious_host}")
                    break
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing cache poisoning with {malicious_host}: {str(e)}")

        return findings

    def _test_routing_ssrf(self, target_url: str) -> List[Finding]:
        """Test for routing-based SSRF via host header."""
        findings = []
        
        # Internal/localhost targets for SSRF testing
        internal_hosts = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '192.168.1.1',
            '10.0.0.1',
            'metadata.google.internal',  # GCP metadata
            '169.254.169.254',  # AWS metadata
        ]
        
        for internal_host in internal_hosts:
            try:
                response = requests.get(
                    target_url,
                    headers={
                        'Host': internal_host,
                        'User-Agent': self.general_config.get('user_agent')
                    },
                    timeout=self.general_config.get('timeout', 30)
                )
                
                if self._detects_internal_access(response, internal_host):
                    finding = Finding(
                        title="Routing-based SSRF via Host Header",
                        severity=Severity.HIGH,
                        confidence=0.5,
                        description=f"Potential routing-based SSRF detected using host '{internal_host}'",
                        url=target_url,
                        method="GET",
                        evidence=self._extract_ssrf_evidence(response, internal_host),
                        impact="Routing-based SSRF can allow access to internal services and metadata endpoints.",
                        remediation="Validate and sanitize the Host header. Implement proper routing controls."
                    )
                    findings.append(finding)
                    logger.warning(f"Routing-based SSRF detected with host: {internal_host}")
                    break
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing routing SSRF with {internal_host}: {str(e)}")

        return findings

    def _is_host_reflected(self, response: requests.Response, malicious_host: str) -> bool:
        """Check if malicious host is reflected in response."""
        content = response.text
        
        # Check in response body
        if malicious_host in content:
            return True
            
        # Check in headers
        for header_value in response.headers.values():
            if malicious_host in header_value:
                return True
                
        return False

    def _looks_like_reset_page(self, response: requests.Response) -> bool:
        """Check if response looks like a password reset page."""
        content = response.text.lower()
        
        reset_indicators = [
            'password reset', 'forgot password', 'reset your password',
            'enter your email', 'reset link', 'forgot your password',
            'password recovery', 'account recovery'
        ]
        
        return any(indicator in content for indicator in reset_indicators)

    def _is_cache_poisoned(self, response: requests.Response, malicious_host: str) -> bool:
        """Check if cache was poisoned with malicious host."""
        # Check if malicious host appears in normal request
        return self._is_host_reflected(response, malicious_host)

    def _detects_internal_access(self, response: requests.Response, internal_host: str) -> bool:
        """Detect if internal access was gained via host header."""
        content = response.text.lower()
        
        # Look for metadata service responses
        if internal_host == '169.254.169.254' or 'metadata.google' in internal_host:
            metadata_indicators = [
                'computeMetadata', 'meta-data', 'instance-id',
                'ami-id', 'security-groups', 'iam/security-credentials',
                'service-accounts', 'access_token'
            ]
            
            for indicator in metadata_indicators:
                if indicator.lower() in content:
                    return True
        
        # Look for localhost/internal service indicators
        if internal_host in ['localhost', '127.0.0.1', '0.0.0.0']:
            internal_indicators = [
                'apache', 'nginx', 'server status', 'phpinfo',
                'directory listing', 'index of', 'default page',
                'localhost', 'internal server', 'development'
            ]
            
            for indicator in internal_indicators:
                if indicator in content:
                    return True
        
        return False

    def _extract_reflection_evidence(self, response: requests.Response, malicious_host: str) -> str:
        """Extract evidence of host header reflection."""
        evidence = [f"Malicious host: {malicious_host}"]
        
        # Check where it's reflected
        if malicious_host in response.text:
            evidence.append("Reflected in response body")
            
        for header_name, header_value in response.headers.items():
            if malicious_host in header_value:
                evidence.append(f"Reflected in {header_name} header")
                break
                
        evidence.append(f"Status Code: {response.status_code}")
        
        return "; ".join(evidence)

    def _extract_ssrf_evidence(self, response: requests.Response, internal_host: str) -> str:
        """Extract evidence of SSRF via host header."""
        evidence = [f"Internal host: {internal_host}"]
        evidence.append(f"Status Code: {response.status_code}")
        
        content = response.text.lower()
        
        if 'metadata' in internal_host and any(word in content for word in ['computeMetadata', 'meta-data', 'instance-id']):
            evidence.append("Metadata service response detected")
        elif internal_host in ['localhost', '127.0.0.1'] and any(word in content for word in ['apache', 'nginx', 'phpinfo']):
            evidence.append("Internal service response detected")
            
        return "; ".join(evidence)