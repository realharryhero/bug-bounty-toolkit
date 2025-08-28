"""
Clickjacking Scanner - Detects clickjacking vulnerabilities via X-Frame-Options analysis
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

class ClickjackingScanner:
    """Clickjacking vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the Clickjacking scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('clickjacking')
        self.general_config = config_manager.get('general')

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for clickjacking vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting clickjacking scan on {target_url}")
        findings = []

        try:
            # Test X-Frame-Options header
            findings.extend(self._test_x_frame_options(target_url))
            
            # Test Content Security Policy frame-ancestors
            findings.extend(self._test_csp_frame_ancestors(target_url))
            
            # Test for frame-busting bypass
            findings.extend(self._test_frame_busting_bypass(target_url))

        except Exception as e:
            logger.error(f"Error during clickjacking scan: {str(e)}")
            security_logger.log_error("CLICKJACKING_SCAN_ERROR", str(e), target_url)

        logger.info(f"Clickjacking scan completed - {len(findings)} findings")
        return findings

    def _test_x_frame_options(self, target_url: str) -> List[Finding]:
        """Test X-Frame-Options header for clickjacking protection."""
        findings = []
        
        try:
            response = requests.get(
                target_url,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')}
            )
            
            x_frame_options = response.headers.get('X-Frame-Options', '').upper()
            
            if not x_frame_options:
                # No X-Frame-Options header present
                finding = Finding(
                    title="Missing X-Frame-Options Header",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    description="The X-Frame-Options header is not present, allowing the page to be embedded in frames",
                    url=target_url,
                    method="GET",
                    evidence="No X-Frame-Options header found in response",
                    impact="The page can be embedded in frames, potentially enabling clickjacking attacks where users are tricked into clicking hidden elements.",
                    remediation="Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header to prevent framing by unauthorized domains."
                )
                findings.append(finding)
                logger.warning(f"Missing X-Frame-Options header at {target_url}")
                
            elif x_frame_options == 'ALLOWALL':
                # Explicitly allows all framing (deprecated and dangerous)
                finding = Finding(
                    title="Permissive X-Frame-Options Header",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    description="X-Frame-Options is set to ALLOWALL, explicitly allowing framing from any domain",
                    url=target_url,
                    method="GET",
                    evidence=f"X-Frame-Options: {x_frame_options}",
                    impact="The page can be embedded by any domain, creating significant clickjacking risk.",
                    remediation="Change X-Frame-Options to DENY or SAMEORIGIN to restrict framing appropriately."
                )
                findings.append(finding)
                logger.warning(f"Dangerous X-Frame-Options ALLOWALL at {target_url}")
                
            elif 'ALLOW-FROM' in x_frame_options:
                # Check for ALLOW-FROM directive (deprecated)
                finding = Finding(
                    title="Deprecated X-Frame-Options ALLOW-FROM",
                    severity=Severity.LOW,
                    confidence=0.6,
                    description="X-Frame-Options uses deprecated ALLOW-FROM directive",
                    url=target_url,
                    method="GET",
                    evidence=f"X-Frame-Options: {x_frame_options}",
                    impact="ALLOW-FROM is not supported by all browsers and may not provide consistent protection.",
                    remediation="Use Content-Security-Policy frame-ancestors directive instead of X-Frame-Options ALLOW-FROM."
                )
                findings.append(finding)
                logger.info(f"Deprecated ALLOW-FROM directive found at {target_url}")

        except requests.RequestException as e:
            logger.debug(f"Error testing X-Frame-Options: {str(e)}")

        return findings

    def _test_csp_frame_ancestors(self, target_url: str) -> List[Finding]:
        """Test Content-Security-Policy frame-ancestors directive."""
        findings = []
        
        try:
            response = requests.get(
                target_url,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')}
            )
            
            csp_header = response.headers.get('Content-Security-Policy', '')
            x_frame_options = response.headers.get('X-Frame-Options', '')
            
            if csp_header:
                frame_ancestors = self._extract_frame_ancestors(csp_header)
                
                if frame_ancestors is None:
                    # CSP exists but no frame-ancestors directive
                    if not x_frame_options:
                        finding = Finding(
                            title="Missing frame-ancestors in CSP",
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            description="Content-Security-Policy exists but lacks frame-ancestors directive",
                            url=target_url,
                            method="GET",
                            evidence=f"CSP present but no frame-ancestors directive. CSP: {csp_header[:100]}...",
                            impact="Without frame-ancestors directive, the page may still be vulnerable to clickjacking.",
                            remediation="Add 'frame-ancestors 'self'' or 'frame-ancestors 'none'' to your Content-Security-Policy."
                        )
                        findings.append(finding)
                        logger.info(f"Missing frame-ancestors in CSP at {target_url}")
                        
                elif '*' in frame_ancestors:
                    # Wildcard allows all domains
                    finding = Finding(
                        title="Permissive frame-ancestors in CSP",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description="Content-Security-Policy frame-ancestors allows all domains with wildcard",
                        url=target_url,
                        method="GET",
                        evidence=f"frame-ancestors directive: {frame_ancestors}",
                        impact="Wildcard in frame-ancestors allows any domain to embed the page, enabling clickjacking attacks.",
                        remediation="Replace wildcard with specific trusted domains or use 'none' or 'self' as appropriate."
                    )
                    findings.append(finding)
                    logger.warning(f"Permissive frame-ancestors wildcard at {target_url}")

        except requests.RequestException as e:
            logger.debug(f"Error testing CSP frame-ancestors: {str(e)}")

        return findings

    def _test_frame_busting_bypass(self, target_url: str) -> List[Finding]:
        """Test for frame-busting code and potential bypasses."""
        findings = []
        
        try:
            response = requests.get(
                target_url,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')}
            )
            
            # Check if there's any frame-busting JavaScript
            frame_busting_patterns = [
                r'if\s*\(\s*top\s*!=\s*self\s*\)',
                r'if\s*\(\s*self\s*!=\s*top\s*\)',
                r'if\s*\(\s*parent\s*!=\s*self\s*\)',
                r'if\s*\(\s*parent\.frames\.length\s*>\s*0\s*\)',
                r'top\.location\s*=\s*self\.location',
                r'top\.location\.href\s*=\s*self\.location\.href',
                r'window\.top\.location\s*=\s*window\.location',
            ]
            
            frame_busting_found = False
            for pattern in frame_busting_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    frame_busting_found = True
                    break
            
            x_frame_options = response.headers.get('X-Frame-Options', '')
            csp_header = response.headers.get('Content-Security-Policy', '')
            has_frame_ancestors = 'frame-ancestors' in csp_header.lower()
            
            # If frame-busting code is present but no modern protections
            if frame_busting_found and not x_frame_options and not has_frame_ancestors:
                finding = Finding(
                    title="Reliance on JavaScript Frame-Busting",
                    severity=Severity.LOW,
                    confidence=0.5,
                    description="Page relies on JavaScript frame-busting code without modern header-based protection",
                    url=target_url,
                    method="GET",
                    evidence="JavaScript frame-busting code detected without X-Frame-Options or CSP frame-ancestors",
                    impact="JavaScript frame-busting can be bypassed using various techniques, providing insufficient protection against clickjacking.",
                    remediation="Implement X-Frame-Options or CSP frame-ancestors headers as primary protection, with JavaScript as defense-in-depth."
                )
                findings.append(finding)
                logger.info(f"JavaScript-only frame protection at {target_url}")

        except requests.RequestException as e:
            logger.debug(f"Error testing frame-busting bypass: {str(e)}")

        return findings

    def _extract_frame_ancestors(self, csp_header: str) -> Optional[str]:
        """Extract frame-ancestors directive from CSP header."""
        # Look for frame-ancestors directive
        match = re.search(r'frame-ancestors\s+([^;]+)', csp_header, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None