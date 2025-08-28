"""
CSRF Scanner - Detects Cross-Site Request Forgery vulnerabilities
"""

import re
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner, register_scanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

@register_scanner('csrf')
class CSRFScanner(BaseScanner):
    """Cross-Site Request Forgery vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the CSRF scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        
        # CSRF token patterns to look for
        self.token_patterns = [
            r'csrf[_-]?token',
            r'authenticity[_-]?token',
            r'_token',
            r'csrfmiddlewaretoken',
            r'__RequestVerificationToken',
        ]
    
    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for CSRF vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of findings
        """
        logger.info(f"Starting CSRF scan on {target}")
        findings = []
        
        try:
            # Get the target page
            response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all forms
                forms = soup.find_all('form')
                
                for form in forms:
                    form_findings = self._analyze_form(form, target)
                    findings.extend(form_findings)
            
            logger.info(f"CSRF scan completed - {len(findings)} potential vulnerabilities found")
            
        except Exception as e:
            logger.error(f"CSRF scan failed: {str(e)}")
            security_logger.log_error("CSRF_SCAN_ERROR", str(e), target)
        
        return findings
    
    def _analyze_form(self, form, base_url: str) -> List[Finding]:
        """
        Analyze a form for CSRF vulnerabilities.
        
        Args:
            form: BeautifulSoup form element
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of findings
        """
        findings = []
        
        # Get form attributes
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # Only analyze POST forms (CSRF is mainly a concern for state-changing operations)
        if method != 'post':
            return findings
        
        # Resolve form action URL
        if action:
            form_url = urljoin(base_url, action)
        else:
            form_url = base_url
        
        # Check for CSRF protection mechanisms
        csrf_issues = []
        
        # 1. Check for CSRF tokens
        if self.config.get('check_tokens', True):
            has_csrf_token = self._has_csrf_token(form)
            if not has_csrf_token:
                csrf_issues.append("No CSRF token found")
        
        # 2. Check for SameSite cookie attributes (would need session analysis)
        # This is simplified - would need actual cookie inspection
        
        # 3. Check for Referer header validation (hard to test without interaction)
        
        # If issues found, create finding
        if csrf_issues:
            confidence = self._calculate_csrf_confidence(csrf_issues, form)
            
            if confidence >= 0.5:  # Only report medium+ confidence findings
                # Get form fields for evidence
                inputs = form.find_all(['input', 'textarea', 'select'])
                field_info = []
                
                for input_elem in inputs:
                    field_type = input_elem.get('type', 'text')
                    field_name = input_elem.get('name', 'unnamed')
                    field_info.append(f"{field_name} ({field_type})")
                
                finding = Finding(
                    title="Potential CSRF Vulnerability",
                    severity=self._get_csrf_severity(csrf_issues),
                    confidence=confidence,
                    description=f"Form submission may be vulnerable to Cross-Site Request Forgery attacks. Issues found: {', '.join(csrf_issues)}",
                    target=form_url,
                    vulnerability_type="Cross-Site Request Forgery",
                    evidence=f"Form method: {method.upper()}, Fields: {', '.join(field_info)}",
                    impact="An attacker could potentially trick users into performing unintended actions on the application.",
                    remediation="Implement CSRF tokens, validate Referer headers, use SameSite cookie attributes, and consider double-submit cookies."
                )
                
                findings.append(finding)
                security_logger.log_vulnerability_found("CSRF", form_url, finding.severity.value, confidence)
        
        return findings
    
    def _has_csrf_token(self, form) -> bool:
        """Check if form has CSRF token protection."""
        inputs = form.find_all('input')
        
        for input_elem in inputs:
            input_name = input_elem.get('name', '').lower()
            input_id = input_elem.get('id', '').lower()
            
            # Check if input name/id matches CSRF token patterns
            for pattern in self.token_patterns:
                if re.search(pattern, input_name, re.IGNORECASE) or re.search(pattern, input_id, re.IGNORECASE):
                    return True
        
        return False
    
    def _calculate_csrf_confidence(self, issues: List[str], form) -> float:
        """Calculate confidence score for CSRF vulnerability."""
        confidence = 0.0
        
        # Base confidence for missing CSRF token
        if "No CSRF token found" in issues:
            confidence += 0.6
        
        # Check if form has sensitive fields
        sensitive_field_patterns = [
            r'password',
            r'email',
            r'amount',
            r'transfer',
            r'delete',
            r'update',
            r'admin',
        ]
        
        inputs = form.find_all(['input', 'textarea'])
        has_sensitive_fields = False
        
        for input_elem in inputs:
            field_name = input_elem.get('name', '').lower()
            field_id = input_elem.get('id', '').lower()
            
            for pattern in sensitive_field_patterns:
                if re.search(pattern, field_name) or re.search(pattern, field_id):
                    has_sensitive_fields = True
                    break
            
            if has_sensitive_fields:
                break
        
        if has_sensitive_fields:
            confidence += 0.3
        
        return min(1.0, confidence)
    
    def _get_csrf_severity(self, issues: List[str]) -> Severity:
        """Determine CSRF vulnerability severity based on issues."""
        if "No CSRF token found" in issues:
            return Severity.MEDIUM
        else:
            return Severity.LOW