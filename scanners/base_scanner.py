"""
Base Scanner Class - Shared functionality for all vulnerability scanners.
"""
import requests
import logging
from urllib.parse import urljoin
from typing import List, Dict, Any
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class BaseScanner:
    """Base class for vulnerability scanners with common verification and testing methods."""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.general_config = config_manager.get('general')
    
    def verify_finding(self, finding: Finding, target_url: str) -> bool:
        """Verify a finding by attempting to access a protected page."""
        try:
            protected_url = urljoin(target_url, '/admin')  # Customize to a known protected endpoint
            response = requests.get(protected_url, cookies=getattr(finding, 'cookies', None), timeout=10)
            if response.status_code == 200 and 'login' not in response.text.lower():
                logger.info(f"Finding verified: Access to {protected_url} succeeded.")
                return True
            else:
                logger.info(f"Finding likely false positive: Could not access {protected_url}.")
                return False
        except Exception as e:
            logger.debug(f"Verification failed: {str(e)}")
            return False
    
    def manual_test_finding(self, finding: Finding, target_url: str):
        """Provide step-by-step manual testing for beginners."""
        print("=== Manual Vulnerability Test ===")
        print(f"Testing: {finding.title}")
        print(f"Description: {finding.description}")
        print("Steps:")
        print("1. Open your browser and navigate to the target URL.")
        print("2. Apply the payload or exploit from the finding.")
        print("3. Check if the vulnerability allows unauthorized access.")
        print("4. Visit a protected page (e.g., /admin) to confirm.")
        print("Note: False positives can occur due to redirects, caching, or rate limits. Check server logs.")
        verified = self.verify_finding(finding, target_url)
        print(f"Automated verification result: {'Likely Real' if verified else 'Likely False Positive'}")
    
    def filter_false_positives(self, findings: List[Finding], target_url: str) -> List[Finding]:
        """Filter out likely false positives by verifying each finding."""
        verified = []
        for finding in findings:
            if self.verify_finding(finding, target_url):
                verified.append(finding)
        return verified
    
    def log_finding_details(self, finding: Finding, reason: str):
        """Log detailed info about a finding for beginners."""
        logger.warning(f"Finding: {finding.title}. Reason for potential false positive: {reason}")
