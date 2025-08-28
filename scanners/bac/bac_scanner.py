"""
Broken Access Control (BAC) Scanner - Detects comprehensive BAC vulnerabilities
"""

import logging
import requests
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional, Tuple
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class BrokenAccessControlScanner:
    """Comprehensive Broken Access Control vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the BAC scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('bac')
        self.general_config = config_manager.get('general')
        
        # Admin/privileged paths to test
        self.admin_paths = [
            '/admin', '/admin/', '/administrator', '/administrator/',
            '/dashboard', '/dashboard/', '/control', '/control/',
            '/console', '/console/', '/manager', '/manager/',
            '/admin-panel', '/admin-panel/', '/admin_panel', '/admin_panel/',
            '/cpanel', '/cpanel/', '/wp-admin', '/wp-admin/',
            '/phpmyadmin', '/phpmyadmin/', '/adminer', '/adminer/',
            '/grafana', '/grafana/', '/kibana', '/kibana/',
            '/admin/login', '/admin/dashboard', '/admin/users',
            '/admin/config', '/admin/settings', '/admin/panel',
            '/management', '/management/', '/supervisor', '/supervisor/',
        ]
        
        # Sensitive files and directories
        self.sensitive_paths = [
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/config.json', '/config.yml', '/config.yaml', '/settings.json',
            '/users.json', '/users.xml', '/users.csv', '/accounts.json',
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/database.sql',
            '/web.config', '/Web.config', '/.htaccess', '/.htpasswd',
            '/robots.txt', '/sitemap.xml', '/.git/', '/.svn/',
            '/composer.json', '/package.json', '/yarn.lock', '/Gemfile',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/readme.txt', '/README.md', '/CHANGELOG.md', '/LICENSE',
            '/logs/', '/log/', '/tmp/', '/temp/', '/cache/',
            '/uploads/', '/files/', '/documents/', '/download/',
        ]
        
        # Parameter tampering tests
        self.privilege_params = {
            'role': ['admin', 'administrator', 'root', 'superuser', '1', 'true'],
            'isAdmin': ['true', '1', 'yes', 'admin'],
            'admin': ['true', '1', 'yes', 'admin'],
            'auth': ['1', 'true', 'admin', 'authenticated'],
            'user_level': ['1', '9', '99', 'admin', 'root'],
            'access_level': ['1', '9', '99', 'admin', 'full'],
            'privileges': ['admin', 'full', 'all', '1', '999'],
            'permission': ['admin', 'write', 'full', 'all', '1'],
            'group': ['admin', 'administrators', 'root', 'wheel'],
            'type': ['admin', 'administrator', 'root', 'superuser'],
        }
        
        # HTTP methods to test for method-based access control bypass
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for BAC vulnerabilities.

        Args:
            target_url: Target URL to scan

        Returns:
            List of Finding objects
        """
        findings = []
        logger.info(f"Starting Broken Access Control scan on {target_url}")
        security_logger.log_scan_start("bac", target_url)

        try:
            # Test for privilege escalation through direct access
            findings.extend(self._test_privilege_escalation(target_url))

            # Test for parameter tampering
            findings.extend(self._test_parameter_tampering(target_url))

            # Test for forced browsing
            findings.extend(self._test_forced_browsing(target_url))
            
            # Test for HTTP method bypasses
            findings.extend(self._test_http_method_bypass(target_url))
            
            # Test for path traversal access control bypass
            findings.extend(self._test_path_traversal_bypass(target_url))
            
            # Test for referrer-based access control bypass
            findings.extend(self._test_referrer_bypass(target_url))
            
            # Test for user ID enumeration and horizontal privilege escalation
            findings.extend(self._test_user_enumeration(target_url))

        except Exception as e:
            logger.error(f"BAC scan failed: {str(e)}")
            security_logger.log_error("BAC_SCAN_FAILED", str(e), target_url)

        logger.info(f"Broken Access Control scan completed. Found {len(findings)} potential issues.")
        return findings

    def _test_privilege_escalation(self, target_url: str) -> List[Finding]:
        """Test for privilege escalation by accessing admin-only pages."""
        findings = []
        
        base_url = self._get_base_url(target_url)
        
        for path in self.admin_paths:
            test_url = base_url + path.lstrip('/')
            try:
                response = requests.get(
                    test_url, 
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    allow_redirects=False
                )
                
                if self._is_admin_page_accessible(response, test_url):
                    confidence = self._calculate_admin_confidence(response)
                    
                    if confidence > (self.config.get('confidence_threshold', 0.6)):
                        finding = Finding(
                            title="Privilege Escalation - Admin Panel Access",
                            severity=Severity.HIGH,
                            confidence=confidence,
                            description=f"Administrative interface appears to be accessible without authentication at {test_url}",
                            url=test_url,
                            method="GET",
                            evidence=self._extract_admin_evidence(response),
                            impact="Unauthorized access to administrative functions could allow complete system compromise.",
                            remediation="Implement proper authentication and authorization controls for administrative interfaces."
                        )
                        findings.append(finding)
                        logger.warning(f"Potential admin panel access found: {test_url}")
                        
            except requests.RequestException as e:
                logger.debug(f"Error checking {test_url} for privilege escalation: {e}")

        return findings

    def _test_parameter_tampering(self, target_url: str) -> List[Finding]:
        """Test for parameter tampering to gain extra privileges."""
        findings = []
        
        parsed_url = urlparse(target_url)
        base_params = parse_qs(parsed_url.query)
        
        for param_name, param_values in self.privilege_params.items():
            for param_value in param_values:
                try:
                    # Test GET parameter tampering
                    test_params = base_params.copy()
                    test_params[param_name] = [param_value]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    response = requests.get(
                        test_url,
                        params=test_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                    
                    if self._detect_privilege_escalation(response, param_name, param_value):
                        finding = Finding(
                            title="Parameter Tampering - Role Escalation",
                            severity=Severity.HIGH,
                            confidence=0.7,
                            description=f"Potential privilege escalation detected by setting parameter '{param_name}' to '{param_value}'",
                            url=test_url,
                            method="GET",
                            parameter=param_name,
                            payload=param_value,
                            evidence=self._extract_privilege_evidence(response, param_name, param_value),
                            impact="Attackers may be able to escalate their privileges by manipulating parameters.",
                            remediation="Implement server-side authorization checks that don't rely on user-controllable parameters."
                        )
                        findings.append(finding)
                        logger.warning(f"Parameter tampering vulnerability found: {param_name}={param_value}")
                        break  # Found one for this parameter, move to next
                        
                except requests.RequestException as e:
                    logger.debug(f"Error testing parameter tampering {param_name}={param_value}: {e}")

        return findings

    def _test_forced_browsing(self, target_url: str) -> List[Finding]:
        """Test for forced browsing to access unlinked resources."""
        findings = []
        base_url = self._get_base_url(target_url)

        for path in self.sensitive_paths:
            test_url = base_url + path.lstrip('/')
            try:
                response = requests.get(
                    test_url, 
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    allow_redirects=False
                )
                
                if self._is_sensitive_file_exposed(response, path):
                    severity = self._determine_file_severity(path)
                    confidence = self._calculate_exposure_confidence(response, path)
                    
                    if confidence > 0.5:
                        finding = Finding(
                            title="Forced Browsing - Sensitive Resource Exposure",
                            severity=severity,
                            confidence=confidence,
                            description=f"Sensitive resource exposed through direct access: {test_url}",
                            url=test_url,
                            method="GET",
                            evidence=self._extract_exposure_evidence(response, path),
                            impact=self._get_file_impact(path),
                            remediation="Restrict access to sensitive files and directories. Implement proper access controls."
                        )
                        findings.append(finding)
                        logger.warning(f"Sensitive file exposure found: {test_url}")
                        
            except requests.RequestException as e:
                logger.debug(f"Error checking {test_url} for forced browsing: {e}")

        return findings

    def _test_http_method_bypass(self, target_url: str) -> List[Finding]:
        """Test for HTTP method-based access control bypass."""
        findings = []
        
        # First, test the original URL with GET to establish baseline
        try:
            baseline_response = requests.get(
                target_url,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')},
                allow_redirects=False
            )
            
            baseline_code = baseline_response.status_code
            
            # If GET is forbidden/unauthorized, test other methods
            if baseline_code in [401, 403, 405]:
                for method in self.methods[1:]:  # Skip GET as it's already tested
                    try:
                        response = requests.request(
                            method,
                            target_url,
                            timeout=self.general_config.get('timeout', 30),
                            headers={'User-Agent': self.general_config.get('user_agent')},
                            allow_redirects=False
                        )
                        
                        if response.status_code == 200 and response.status_code != baseline_code:
                            finding = Finding(
                                title="HTTP Method Bypass - Access Control",
                                severity=Severity.MEDIUM,
                                confidence=0.8,
                                description=f"Access control bypass detected using {method} method when GET returned {baseline_code}",
                                url=target_url,
                                method=method,
                                evidence=f"GET: {baseline_code}, {method}: {response.status_code}",
                                impact=f"Attackers can bypass access controls by using the {method} HTTP method.",
                                remediation="Implement consistent access controls across all HTTP methods."
                            )
                            findings.append(finding)
                            logger.warning(f"HTTP method bypass found: {method} on {target_url}")
                            
                    except requests.RequestException as e:
                        logger.debug(f"Error testing {method} method: {e}")
                        
        except requests.RequestException as e:
            logger.debug(f"Error establishing baseline for method bypass test: {e}")

        return findings

    def _test_path_traversal_bypass(self, target_url: str) -> List[Finding]:
        """Test for path traversal-based access control bypass."""
        findings = []
        
        parsed_url = urlparse(target_url)
        path_variations = [
            parsed_url.path + '../admin/',
            parsed_url.path + '../../admin/',
            parsed_url.path + '../../../admin/',
            parsed_url.path + '..%2fadmin%2f',
            parsed_url.path + '..%5cadmin%5c',
            parsed_url.path.replace('/', '//') + '../admin/',
        ]
        
        for variation in path_variations:
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{variation}"
            try:
                response = requests.get(
                    test_url,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')},
                    allow_redirects=False
                )
                
                if self._is_admin_page_accessible(response, test_url):
                    finding = Finding(
                        title="Path Traversal Access Control Bypass",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description="Access control bypass detected using path traversal techniques",
                        url=test_url,
                        method="GET",
                        evidence=f"Path traversal '{variation}' resulted in access to administrative interface",
                        impact="Attackers can bypass access controls using path manipulation techniques.",
                        remediation="Implement proper path normalization and access control validation."
                    )
                    findings.append(finding)
                    logger.warning(f"Path traversal bypass found: {test_url}")
                    break  # Found one, no need to test more variations
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing path traversal bypass {test_url}: {e}")

        return findings

    def _test_referrer_bypass(self, target_url: str) -> List[Finding]:
        """Test for referrer-based access control bypass."""
        findings = []
        
        # Common referrer values that might bypass access controls
        referrer_values = [
            'http://localhost/',
            'http://127.0.0.1/',
            'http://admin.localhost/',
            f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}/admin/",
            f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}/",
            'https://www.google.com/',
        ]
        
        # First establish baseline
        try:
            baseline_response = requests.get(
                target_url,
                timeout=self.general_config.get('timeout', 30),
                headers={'User-Agent': self.general_config.get('user_agent')},
                allow_redirects=False
            )
            baseline_code = baseline_response.status_code
            
            if baseline_code in [401, 403]:  # Only test if initially blocked
                for referrer in referrer_values:
                    try:
                        response = requests.get(
                            target_url,
                            timeout=self.general_config.get('timeout', 30),
                            headers={
                                'User-Agent': self.general_config.get('user_agent'),
                                'Referer': referrer
                            },
                            allow_redirects=False
                        )
                        
                        if response.status_code == 200 and response.status_code != baseline_code:
                            finding = Finding(
                                title="Referrer-based Access Control Bypass",
                                severity=Severity.MEDIUM,
                                confidence=0.6,
                                description=f"Access control bypass detected using referrer '{referrer}'",
                                url=target_url,
                                method="GET",
                                evidence=f"No Referer: {baseline_code}, With Referer '{referrer}': {response.status_code}",
                                impact="Attackers can bypass access controls by manipulating the HTTP Referer header.",
                                remediation="Do not rely on the HTTP Referer header for access control decisions."
                            )
                            findings.append(finding)
                            logger.warning(f"Referrer bypass found with: {referrer}")
                            break
                            
                    except requests.RequestException as e:
                        logger.debug(f"Error testing referrer bypass with {referrer}: {e}")
                        
        except requests.RequestException as e:
            logger.debug(f"Error establishing baseline for referrer bypass test: {e}")

        return findings

    def _test_user_enumeration(self, target_url: str) -> List[Finding]:
        """Test for user ID enumeration and horizontal privilege escalation."""
        findings = []
        
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        # Look for user ID-like parameters
        user_params = ['id', 'user_id', 'userId', 'uid', 'user', 'account_id', 'accountId']
        
        for param in user_params:
            if param in query_params:
                original_value = query_params[param][0]
                test_values = [
                    '1', '2', '3', '10', '100', '999',  # Numeric IDs
                    'admin', 'administrator', 'root', 'test',  # Common usernames
                    f"{original_value}1", f"{int(original_value) + 1 if original_value.isdigit() else '1'}"  # Adjacent values
                ]
                
                for test_value in test_values:
                    try:
                        test_params = query_params.copy()
                        test_params[param] = [test_value]
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        response = requests.get(
                            test_url,
                            params=test_params,
                            timeout=self.general_config.get('timeout', 30),
                            headers={'User-Agent': self.general_config.get('user_agent')}
                        )
                        
                        if response.status_code == 200 and self._detect_user_data_exposure(response, test_value):
                            finding = Finding(
                                title="Horizontal Privilege Escalation - User Data Exposure",
                                severity=Severity.MEDIUM,
                                confidence=0.6,
                                description=f"Potential access to other user's data by manipulating '{param}' parameter",
                                url=test_url,
                                method="GET",
                                parameter=param,
                                payload=test_value,
                                evidence=f"Parameter '{param}' set to '{test_value}' returned user data",
                                impact="Attackers may access other users' private information.",
                                remediation="Implement proper authorization checks to ensure users can only access their own data."
                            )
                            findings.append(finding)
                            logger.warning(f"User enumeration vulnerability found: {param}={test_value}")
                            break  # Found one for this parameter
                            
                    except requests.RequestException as e:
                        logger.debug(f"Error testing user enumeration {param}={test_value}: {e}")

        return findings

    # Helper methods
    def _get_base_url(self, url: str) -> str:
        """Extract base URL for path testing."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def _is_admin_page_accessible(self, response: requests.Response, url: str) -> bool:
        """Check if response indicates an accessible admin page."""
        if response.status_code != 200:
            return False
            
        content = response.text.lower()
        admin_indicators = [
            'dashboard', 'admin panel', 'administration', 'control panel',
            'admin login', 'administrator', 'management', 'console',
            'users', 'settings', 'configuration', 'admin menu',
            'logout', 'welcome admin', 'admin area'
        ]
        
        return any(indicator in content for indicator in admin_indicators)

    def _calculate_admin_confidence(self, response: requests.Response) -> float:
        """Calculate confidence for admin page detection."""
        content = response.text.lower()
        score = 0.0
        
        # Strong indicators
        strong_indicators = ['admin panel', 'administration', 'admin dashboard', 'control panel']
        for indicator in strong_indicators:
            if indicator in content:
                score += 0.3
                
        # Medium indicators  
        medium_indicators = ['dashboard', 'admin', 'management', 'settings']
        for indicator in medium_indicators:
            if indicator in content:
                score += 0.2
                
        return min(score, 1.0)

    def _extract_admin_evidence(self, response: requests.Response) -> str:
        """Extract evidence of admin page access."""
        content = response.text
        evidence = []
        
        # Look for specific admin-related text
        admin_patterns = [
            r'admin\s*panel',
            r'dashboard',
            r'administration',
            r'control\s*panel',
            r'management\s*console'
        ]
        
        for pattern in admin_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                evidence.extend(matches[:2])  # Limit to 2 matches per pattern
                
        if not evidence:
            evidence.append("Page contains administrative interface indicators")
            
        return "; ".join(evidence[:3])  # Limit total evidence

    def _detect_privilege_escalation(self, response: requests.Response, param: str, value: str) -> bool:
        """Detect if parameter tampering resulted in privilege escalation."""
        content = response.text.lower()
        
        escalation_indicators = [
            'admin', 'administrator', 'root', 'superuser',
            'welcome admin', 'admin panel', 'dashboard',
            'elevated privileges', 'administrative access'
        ]
        
        return any(indicator in content for indicator in escalation_indicators)

    def _extract_privilege_evidence(self, response: requests.Response, param: str, value: str) -> str:
        """Extract evidence of privilege escalation."""
        content = response.text
        evidence = [f"Parameter {param}={value} in request"]
        
        # Look for privilege-related content
        if 'admin' in content.lower():
            evidence.append("Response contains 'admin' text")
        if 'dashboard' in content.lower():
            evidence.append("Response contains dashboard elements")
            
        return "; ".join(evidence)

    def _is_sensitive_file_exposed(self, response: requests.Response, path: str) -> bool:
        """Check if sensitive file is exposed."""
        if response.status_code not in [200, 301, 302]:
            return False
            
        # File should have actual content
        if len(response.content) < 10:
            return False
            
        # Check for file-specific indicators
        content = response.text.lower()
        
        if path.endswith('.env'):
            return 'database_url' in content or 'api_key' in content or '=' in content
        elif path.endswith('.json'):
            try:
                json.loads(response.text)
                return True
            except:
                return False
        elif path.endswith('.sql'):
            return 'create table' in content or 'insert into' in content
        elif path.endswith('.config'):
            return 'configuration' in content or '<configuration>' in content
            
        return True

    def _determine_file_severity(self, path: str) -> Severity:
        """Determine severity based on file type."""
        high_risk_files = ['.env', 'config.json', 'users.json', '.htpasswd', 'database.sql']
        medium_risk_files = ['.htaccess', 'robots.txt', 'composer.json', 'package.json']
        
        for high_file in high_risk_files:
            if high_file in path:
                return Severity.HIGH
                
        for medium_file in medium_risk_files:
            if medium_file in path:
                return Severity.MEDIUM
                
        return Severity.LOW

    def _calculate_exposure_confidence(self, response: requests.Response, path: str) -> float:
        """Calculate confidence for file exposure."""
        base_confidence = 0.7 if response.status_code == 200 else 0.3
        
        # Bonus for actual content
        if len(response.content) > 100:
            base_confidence += 0.2
            
        return min(base_confidence, 1.0)

    def _extract_exposure_evidence(self, response: requests.Response, path: str) -> str:
        """Extract evidence of file exposure."""
        evidence = [f"Status: {response.status_code}"]
        evidence.append(f"Content-Length: {len(response.content)}")
        
        if len(response.content) > 0:
            preview = response.text[:100].replace('\n', ' ').strip()
            evidence.append(f"Content preview: {preview}...")
            
        return "; ".join(evidence)

    def _get_file_impact(self, path: str) -> str:
        """Get impact description for specific file types."""
        if '.env' in path:
            return "Environment files can contain database credentials, API keys, and other sensitive configuration data."
        elif 'config' in path:
            return "Configuration files may expose system details, database connections, and security settings."
        elif 'users' in path or 'accounts' in path:
            return "User data files can expose usernames, passwords, email addresses, and personal information."
        elif 'backup' in path or '.sql' in path:
            return "Backup files may contain complete database dumps with sensitive user and system data."
        else:
            return "Exposed files may contain sensitive information that could assist in further attacks."

    def _detect_user_data_exposure(self, response: requests.Response, user_id: str) -> bool:
        """Detect if response contains user data."""
        content = response.text.lower()
        
        user_data_indicators = [
            'email', 'username', 'profile', 'account', 'user',
            'phone', 'address', 'personal', 'private'
        ]
        
        return any(indicator in content for indicator in user_data_indicators)
