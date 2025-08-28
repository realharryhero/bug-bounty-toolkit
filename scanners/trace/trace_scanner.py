"""
ASP.NET Trace Scanner - Detects if ASP.NET tracing is enabled and other ASP.NET debug features
"""

import logging
import requests
import re
from urllib.parse import urljoin, urlparse
from typing import List
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class TraceScanner:
    """ASP.NET Tracing and debug feature vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the ASP.NET Trace scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('trace')
        self.general_config = config_manager.get('general')

        # Common ASP.NET debug and trace endpoints
        self.trace_endpoints = [
            "trace.axd",
            "Trace.axd", 
            "TRACE.AXD",
            "elmah.axd",
            "Elmah.axd",
            "ELMAH.AXD",
            "glimpse.axd",
            "Glimpse.axd",
            "GLIMPSE.AXD",
        ]

        # Debug/development pages to check
        self.debug_endpoints = [
            "Web.config",
            "web.config", 
            "WEB.CONFIG",
            "Global.asax",
            "global.asax",
            "GLOBAL.ASAX",
            "App_Data/",
            "app_data/",
            "APP_DATA/",
            "Bin/",
            "bin/",
            "BIN/",
        ]

        # ASP.NET error patterns that might leak information
        self.error_patterns = [
            r'Server Error in \'.*?\' Application',
            r'Runtime Error',
            r'Parser Error',
            r'Configuration Error', 
            r'Compilation Error',
            r'Line \d+',
            r'Source File:',
            r'Stack Trace:',
            r'Version Information:',
            r'Microsoft .NET Framework',
            r'System\.Web\.',
            r'at System\.',
        ]

    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for ASP.NET tracing and debug features.

        Args:
            target: Target URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting ASP.NET Trace and Debug scan on {target}")
        findings = []

        try:
            # Test for ASP.NET trace endpoints
            findings.extend(self._test_trace_endpoints(target))
            
            # Test for debug/development endpoints
            findings.extend(self._test_debug_endpoints(target))
            
            # Test for information disclosure in error pages
            findings.extend(self._test_error_disclosure(target))
            
            # Test for debug compilation
            findings.extend(self._test_debug_compilation(target))

        except Exception as e:
            logger.error(f"Error during ASP.NET trace scan: {str(e)}")
            security_logger.log_error("ASPNET_TRACE_SCAN_ERROR", str(e), target)

        logger.info(f"ASP.NET Trace scan completed - {len(findings)} findings")
        return findings

    def _test_trace_endpoints(self, target: str) -> List[Finding]:
        """Test for accessible trace endpoints."""
        findings = []
        
        for endpoint in self.trace_endpoints:
            try:
                trace_url = urljoin(target, endpoint)
                response = requests.get(
                    trace_url, 
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    verify=False, 
                    allow_redirects=False
                )

                if self._analyze_trace_response(response, endpoint):
                    severity = Severity.HIGH if "trace.axd" in endpoint.lower() else Severity.MEDIUM
                    confidence = 0.9
                    
                    finding = Finding(
                        title=f"ASP.NET {endpoint} Enabled",
                        severity=severity,
                        confidence=confidence,
                        description=f"ASP.NET {endpoint} is accessible and may expose sensitive debugging information.",
                        url=trace_url,
                        method="GET",
                        evidence=self._extract_trace_evidence(response),
                        impact=f"The {endpoint} endpoint can expose sensitive application information including session IDs, request details, physical paths, and stack traces.",
                        remediation=f"Disable {endpoint} in production by setting appropriate configuration in Web.config.",
                    )
                    findings.append(finding)
                    security_logger.log_vulnerability_found("ASPNET_TRACE_ENABLED", trace_url, severity.value, confidence)
                    logger.warning(f"ASP.NET {endpoint} is accessible at {trace_url}")

            except requests.exceptions.RequestException as e:
                logger.debug(f"Failed to test {endpoint}: {str(e)}")

        return findings

    def _test_debug_endpoints(self, target: str) -> List[Finding]:
        """Test for accessible debug/development endpoints."""
        findings = []
        
        for endpoint in self.debug_endpoints:
            try:
                debug_url = urljoin(target, endpoint)
                response = requests.get(
                    debug_url,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    verify=False,
                    allow_redirects=False
                )

                if self._analyze_debug_response(response, endpoint):
                    finding = Finding(
                        title=f"ASP.NET Debug Endpoint Accessible",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        description=f"ASP.NET debug endpoint '{endpoint}' is accessible and may expose sensitive information.",
                        url=debug_url,
                        method="GET",
                        evidence=f"Status: {response.status_code}, Content-Length: {len(response.content)}",
                        impact="Debug endpoints can expose configuration details, source code paths, and other sensitive information.",
                        remediation="Remove or restrict access to debug endpoints in production environments.",
                    )
                    findings.append(finding)
                    logger.warning(f"Debug endpoint accessible: {debug_url}")

            except requests.exceptions.RequestException as e:
                logger.debug(f"Failed to test debug endpoint {endpoint}: {str(e)}")

        return findings

    def _test_error_disclosure(self, target: str) -> List[Finding]:
        """Test for information disclosure in error pages."""
        findings = []
        
        # Generate errors by requesting non-existent pages with different extensions
        error_tests = [
            "nonexistent.aspx",
            "invalid.asmx",
            "missing.ashx",
            "error.svc",
            "test.aspx?param=",
            "test.aspx?id=abc",
        ]
        
        for test_path in error_tests:
            try:
                error_url = urljoin(target, test_path)
                response = requests.get(
                    error_url,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    verify=False,
                    allow_redirects=False
                )

                if self._analyze_error_response(response):
                    finding = Finding(
                        title="ASP.NET Error Information Disclosure",
                        severity=Severity.LOW,
                        confidence=0.7,
                        description="ASP.NET error pages are disclosing sensitive information about the application structure and framework.",
                        url=error_url,
                        method="GET",
                        evidence=self._extract_error_evidence(response),
                        impact="Information disclosed in error pages can assist attackers in understanding the application structure and finding additional attack vectors.",
                        remediation="Configure custom error pages and disable detailed error messages in production by setting customErrors mode='On' in Web.config.",
                    )
                    findings.append(finding)
                    logger.info(f"Information disclosure found in error page: {error_url}")
                    break  # Only report one error disclosure finding

            except requests.exceptions.RequestException as e:
                logger.debug(f"Failed to test error page {test_path}: {str(e)}")

        return findings

    def _test_debug_compilation(self, target: str) -> List[Finding]:
        """Test if debug compilation is enabled."""
        findings = []
        
        try:
            # Try to access a page that might trigger compilation errors
            response = requests.get(
                target,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')},
                verify=False
            )

            # Check for debug compilation indicators in response headers
            debug_headers = ['X-AspNet-Version', 'X-Powered-By']
            debug_indicators = []
            
            for header in debug_headers:
                if header in response.headers:
                    debug_indicators.append(f"{header}: {response.headers[header]}")

            # Check for debug compilation in response content
            debug_content_patterns = [
                r'debug="true"',
                r'compilation debug="true"',
                r'<compilation[^>]*debug="true"',
            ]
            
            for pattern in debug_content_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    debug_indicators.append("Debug compilation detected in response")

            if debug_indicators:
                finding = Finding(
                    title="ASP.NET Debug Compilation Enabled",
                    severity=Severity.LOW,
                    confidence=0.6,
                    description="ASP.NET application appears to have debug compilation enabled.",
                    url=target,
                    method="GET",
                    evidence='; '.join(debug_indicators),
                    impact="Debug compilation can lead to performance issues and potential information disclosure through detailed error messages.",
                    remediation="Set debug='false' in the <compilation> element of Web.config for production environments.",
                )
                findings.append(finding)

        except requests.exceptions.RequestException as e:
            logger.debug(f"Failed to test debug compilation: {str(e)}")

        return findings

    def _analyze_trace_response(self, response: requests.Response, endpoint: str) -> bool:
        """Analyze response to determine if trace endpoint is accessible."""
        if response.status_code != 200:
            return False

        content = response.text.lower()
        
        # Check for trace.axd specific indicators
        if "trace.axd" in endpoint.lower():
            trace_indicators = [
                "application trace",
                "request details",
                "trace information",
                "requests to this application",
                "remaining"
            ]
        # Check for ELMAH indicators
        elif "elmah" in endpoint.lower():
            trace_indicators = [
                "error log",
                "elmah",
                "error details",
                "exception",
                "stack trace"
            ]
        # Check for Glimpse indicators  
        elif "glimpse" in endpoint.lower():
            trace_indicators = [
                "glimpse",
                "diagnostics",
                "profiling",
                "debugging"
            ]
        else:
            trace_indicators = ["debug", "trace", "diagnostic"]

        return any(indicator in content for indicator in trace_indicators)

    def _analyze_debug_response(self, response: requests.Response, endpoint: str) -> bool:
        """Analyze response to determine if debug endpoint is accessible."""
        if response.status_code in [200, 301, 302]:
            # Check if we got actual content (not just a redirect)
            if endpoint.endswith('.config') and response.status_code == 200:
                return len(response.content) > 100  # Config files should have content
            elif endpoint.endswith('/') and response.status_code == 200:
                return 'directory' in response.text.lower() or len(response.content) > 500
            elif response.status_code == 200:
                return len(response.content) > 0

        return False

    def _analyze_error_response(self, response: requests.Response) -> bool:
        """Analyze response for error information disclosure."""
        content = response.text
        
        # Check for ASP.NET error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
                
        return False

    def _extract_trace_evidence(self, response: requests.Response) -> str:
        """Extract evidence from trace response."""
        content = response.text
        evidence_parts = []
        
        # Extract key indicators
        if "Application Trace" in content:
            evidence_parts.append("Contains 'Application Trace' text")
        if "Request Details" in content:
            evidence_parts.append("Shows request details")
        if "trace information" in content.lower():
            evidence_parts.append("Contains trace information")
            
        evidence_parts.append(f"Status Code: {response.status_code}")
        evidence_parts.append(f"Content-Length: {len(response.content)}")
        
        return "; ".join(evidence_parts)

    def _extract_error_evidence(self, response: requests.Response) -> str:
        """Extract evidence from error response."""
        content = response.text
        evidence_parts = []
        
        # Extract specific error information
        for pattern in self.error_patterns[:5]:  # First 5 patterns
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                evidence_parts.extend(matches[:2])  # Max 2 matches per pattern
                
        if not evidence_parts:
            evidence_parts.append("Contains ASP.NET error information")
            
        return "; ".join(evidence_parts[:3])  # Max 3 pieces of evidence
