"""
CORS Misconfiguration Scanner - Detects Cross-Origin Resource Sharing vulnerabilities
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

class CORSScanner:
    """CORS misconfiguration vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the CORS scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('cors')
        self.general_config = config_manager.get('general')

        # Test origins for CORS misconfiguration
        self.test_origins = [
            'null',
            'https://evil.com',
            'http://evil.com', 
            'https://attacker.com',
            'http://attacker.com',
            'https://example.com',
            'http://example.com',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for CORS misconfigurations.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting CORS misconfiguration scan on {target_url}")
        findings = []

        try:
            # Test wildcard CORS
            findings.extend(self._test_wildcard_cors(target_url))
            
            # Test origin reflection
            findings.extend(self._test_origin_reflection(target_url))
            
            # Test null origin bypass
            findings.extend(self._test_null_origin(target_url))
            
            # Test subdomain wildcard bypass
            findings.extend(self._test_subdomain_bypass(target_url))
            
            # Test insecure protocols
            findings.extend(self._test_protocol_bypass(target_url))

        except Exception as e:
            logger.error(f"Error during CORS scan: {str(e)}")
            security_logger.log_error("CORS_SCAN_ERROR", str(e), target_url)

        logger.info(f"CORS scan completed - {len(findings)} findings")
        return findings

    def _test_wildcard_cors(self, target_url: str) -> List[Finding]:
        """Test for wildcard CORS with credentials."""
        findings = []
        
        try:
            response = requests.get(
                target_url,
                headers={'Origin': 'https://evil.com'},
                timeout=self.general_config.get('timeout', 30)
            )
            
            cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
            cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if cors_origin == '*' and cors_credentials == 'true':
                finding = Finding(
                    title="CORS Wildcard with Credentials",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    description="CORS is configured to allow all origins (*) with credentials enabled",
                    url=target_url,
                    method="GET",
                    evidence=f"Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: {cors_credentials}",
                    impact="Attackers can make authenticated cross-origin requests from any domain, potentially accessing sensitive data.",
                    remediation="Never use wildcard (*) in Access-Control-Allow-Origin when Access-Control-Allow-Credentials is true. Specify exact trusted origins."
                )
                findings.append(finding)
                logger.warning(f"Critical CORS misconfiguration found: wildcard with credentials at {target_url}")

        except requests.RequestException as e:
            logger.debug(f"Error testing wildcard CORS: {str(e)}")

        return findings

    def _test_origin_reflection(self, target_url: str) -> List[Finding]:
        """Test for origin reflection vulnerability."""
        findings = []
        
        for origin in self.test_origins:
            try:
                response = requests.get(
                    target_url,
                    headers={'Origin': origin},
                    timeout=self.general_config.get('timeout', 30)
                )
                
                cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
                cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if cors_origin == origin and cors_credentials == 'true':
                    finding = Finding(
                        title="CORS Origin Reflection with Credentials",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"CORS reflects arbitrary origin '{origin}' with credentials enabled",
                        url=target_url,
                        method="GET",
                        evidence=f"Origin: {origin} → Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: {cors_credentials}",
                        impact="Attackers can make authenticated cross-origin requests from malicious domains, accessing sensitive user data.",
                        remediation="Validate origins against a whitelist of trusted domains instead of reflecting arbitrary origins."
                    )
                    findings.append(finding)
                    logger.warning(f"CORS origin reflection vulnerability found with origin: {origin}")
                    break  # Found one, no need to test more origins

            except requests.RequestException as e:
                logger.debug(f"Error testing origin reflection with {origin}: {str(e)}")

        return findings

    def _test_null_origin(self, target_url: str) -> List[Finding]:
        """Test for null origin bypass."""
        findings = []
        
        try:
            response = requests.get(
                target_url,
                headers={'Origin': 'null'},
                timeout=self.general_config.get('timeout', 30)
            )
            
            cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
            cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if cors_origin == 'null' and cors_credentials == 'true':
                finding = Finding(
                    title="CORS Null Origin Bypass",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    description="CORS allows null origin with credentials enabled",
                    url=target_url,
                    method="GET",
                    evidence=f"Origin: null → Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: {cors_credentials}",
                    impact="Attackers can bypass CORS restrictions using null origin from sandboxed contexts or data URLs.",
                    remediation="Do not allow null origin in CORS configuration. Validate against specific trusted origins."
                )
                findings.append(finding)
                logger.warning(f"CORS null origin bypass found at {target_url}")

        except requests.RequestException as e:
            logger.debug(f"Error testing null origin: {str(e)}")

        return findings

    def _test_subdomain_bypass(self, target_url: str) -> List[Finding]:
        """Test for subdomain wildcard bypass."""
        findings = []
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Create subdomain bypass attempts
        bypass_origins = [
            f"https://evil.{domain}",
            f"http://evil.{domain}",
            f"https://attacker{domain}",
            f"http://attacker{domain}",
        ]
        
        for origin in bypass_origins:
            try:
                response = requests.get(
                    target_url,
                    headers={'Origin': origin},
                    timeout=self.general_config.get('timeout', 30)
                )
                
                cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
                cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if cors_origin == origin and cors_credentials == 'true':
                    finding = Finding(
                        title="CORS Subdomain Bypass",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        description=f"CORS allows potentially malicious subdomain origin '{origin}'",
                        url=target_url,
                        method="GET",
                        evidence=f"Origin: {origin} → Access-Control-Allow-Origin: {cors_origin}, Access-Control-Allow-Credentials: {cors_credentials}",
                        impact="Attackers controlling subdomains or similar domains can make authenticated requests.",
                        remediation="Use exact domain matching instead of wildcard patterns for subdomains."
                    )
                    findings.append(finding)
                    logger.warning(f"CORS subdomain bypass found with origin: {origin}")
                    break

            except requests.RequestException as e:
                logger.debug(f"Error testing subdomain bypass with {origin}: {str(e)}")

        return findings

    def _test_protocol_bypass(self, target_url: str) -> List[Finding]:
        """Test for insecure protocol bypass."""
        findings = []
        
        parsed_url = urlparse(target_url)
        if parsed_url.scheme == 'https':
            # Test if HTTP origin is allowed on HTTPS endpoint
            http_origin = f"http://{parsed_url.netloc}"
            
            try:
                response = requests.get(
                    target_url,
                    headers={'Origin': http_origin},
                    timeout=self.general_config.get('timeout', 30)
                )
                
                cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
                cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if cors_origin == http_origin and cors_credentials == 'true':
                    finding = Finding(
                        title="CORS Insecure Protocol Bypass",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        description="CORS allows HTTP origin on HTTPS endpoint with credentials",
                        url=target_url,
                        method="GET",
                        evidence=f"HTTPS endpoint accepts HTTP origin: {http_origin}",
                        impact="Attackers can downgrade security by making requests from HTTP to HTTPS endpoints.",
                        remediation="Only allow HTTPS origins for HTTPS endpoints to prevent protocol downgrade attacks."
                    )
                    findings.append(finding)
                    logger.warning(f"CORS protocol downgrade vulnerability found at {target_url}")

            except requests.RequestException as e:
                logger.debug(f"Error testing protocol bypass: {str(e)}")

        return findings