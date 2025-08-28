"""
ASP.NET Trace Scanner - Detects if ASP.NET tracing is enabled
"""

import logging
import requests
from urllib.parse import urljoin
from typing import List
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class TraceScanner:
    """ASP.NET Tracing vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the ASP.NET Trace scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('trace')
        self.general_config = config_manager.get('general')

    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for ASP.NET tracing.

        Args:
            target: Target URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting ASP.NET Trace scan on {target}")
        findings = []

        trace_url = urljoin(target, "trace.axd")

        try:
            response = requests.get(trace_url, timeout=self.general_config.get('timeout', 10), verify=False, allow_redirects=False)

            if response.status_code == 200 and "Application Trace" in response.text:
                finding = Finding(
                    title="ASP.NET Tracing Enabled",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    description="ASP.NET tracing is enabled and accessible. This can expose sensitive information about the application, such as session IDs, physical paths, and other debugging details.",
                    target=trace_url,
                    vulnerability_type="Configuration",
                    evidence=f"The trace.axd page is accessible and returned a 200 OK status code. The response contains the text 'Application Trace'.",
                    impact="An attacker can use the information exposed by trace.axd to gain a deeper understanding of the application, which can aid in further attacks. The exposed information can include sensitive data.",
                    remediation="Disable ASP.NET tracing in the Web.config file by setting <trace enabled=\"false\" /> within the <system.web> section.",
                    references=["https://portswigger.net/kb/issues/00100280_asp-net-tracing-enabled"]
                )
                findings.append(finding)
                security_logger.log_vulnerability_found("ASPNET_TRACE_ENABLED", trace_url, "MEDIUM", 0.9)
                logger.warning(f"ASP.NET Tracing is enabled at {trace_url}")

        except requests.exceptions.RequestException as e:
            logger.debug(f"ASP.NET Trace scan failed for {trace_url}: {str(e)}")

        logger.info(f"ASP.NET Trace scan completed - {len(findings)} findings")
        return findings
