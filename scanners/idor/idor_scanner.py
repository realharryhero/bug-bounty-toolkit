"""
Insecure Direct Object References (IDOR) Scanner - Detects IDOR vulnerabilities
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional, Set
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner, register_scanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

@register_scanner('idor')
class IDORScanner(BaseScanner):
    """Insecure Direct Object References vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the IDOR scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        # Common parameter names that might contain object references
        self.id_parameters = [
            'id', 'user_id', 'userid', 'user', 'uid',
            'account_id', 'accountid', 'account',
            'profile_id', 'profileid', 'profile',
            'document_id', 'documentid', 'doc_id', 'docid',
            'file_id', 'fileid', 'file',
            'order_id', 'orderid', 'order',
            'invoice_id', 'invoiceid', 'invoice',
            'ticket_id', 'ticketid', 'ticket',
            'message_id', 'messageid', 'message', 'msg_id',
            'post_id', 'postid', 'post',
            'comment_id', 'commentid', 'comment',
            'page_id', 'pageid', 'page',
            'item_id', 'itemid', 'item',
            'product_id', 'productid', 'product',
            'customer_id', 'customerid', 'customer',
            'transaction_id', 'transactionid', 'transaction',
        ]
        
        # Endpoints that commonly have IDOR vulnerabilities
        self.sensitive_endpoints = [
            '/profile', '/user', '/account', '/admin',
            '/document', '/file', '/download', '/view',
            '/edit', '/delete', '/update', '/modify',
            '/order', '/invoice', '/payment', '/billing',
            '/message', '/chat', '/mail', '/email',
            '/api/user', '/api/profile', '/api/account',
            '/api/document', '/api/file', '/api/order',
        ]
        
        # Sensitive data patterns that indicate successful IDOR
        self.sensitive_patterns = [
            r'email["\s]*[:=]["\s]*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            r'phone["\s]*[:=]["\s]*[\d\-\+\(\)\s]+',
            r'ssn["\s]*[:=]["\s]*\d{3}-?\d{2}-?\d{4}',
            r'credit[_\s]*card["\s]*[:=]["\s]*\d{4}[*\-\s]*\d{4}[*\-\s]*\d{4}[*\-\s]*\d{4}',
            r'password["\s]*[:=]["\s]*[^"\s,}]+',
            r'address["\s]*[:=]["\s]*[^"\n,}]+',
            r'birth[_\s]*date["\s]*[:=]["\s]*\d{4}[-/]\d{2}[-/]\d{2}',
            r'salary["\s]*[:=]["\s]*[\d,]+',
            r'balance["\s]*[:=]["\s]*[\d,\.]+',
            r'token["\s]*[:=]["\s]*[a-zA-Z0-9_\-]+',
            r'api[_\s]*key["\s]*[:=]["\s]*[a-zA-Z0-9_\-]+',
        ]
    
    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for IDOR vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        logger.info(f"Starting IDOR scan on {target_url}")
        security_logger.log_scan_start("idor", target_url)
        
        try:
            # Find potential IDOR endpoints
            idor_endpoints = self._find_idor_endpoints(target_url)
            
            for endpoint in idor_endpoints:
                # Test sequential ID manipulation
                findings.extend(self._test_sequential_ids(endpoint))
                
                # Test common ID values
                findings.extend(self._test_common_ids(endpoint))
                
                # Test negative and zero values
                findings.extend(self._test_boundary_ids(endpoint))
                
                # Test UUID/GUID manipulation
                findings.extend(self._test_uuid_manipulation(endpoint))
                
        except Exception as e:
            logger.error(f"IDOR scan failed: {str(e)}")
            security_logger.log_error("IDOR_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"IDOR scan completed. Found {len(findings)} potential issues.")
        return findings
    
    def _find_idor_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Find endpoints that might have IDOR vulnerabilities."""
        endpoints = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # Parse URL for existing ID parameters
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                if any(id_param in param_name.lower() for id_param in self.id_parameters):
                    if param_values and param_values[0].isdigit():
                        endpoints.append({
                            'type': 'url_param',
                            'url': target_url,
                            'parameter': param_name,
                            'original_value': param_values[0],
                            'method': 'GET'
                        })
            
            # Look for links with ID parameters
            link_patterns = [
                r'<a[^>]*href=[\'"]([^\'\"]*(?:' + '|'.join(self.id_parameters) + r')=\d+[^\'\"]*)[\'"][^>]*>',
                r'<form[^>]*action=[\'"]([^\'\"]*)[\'"][^>]*>',
            ]
            
            for pattern in link_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    link_url = match.group(1)
                    if link_url.startswith('/'):
                        full_url = urljoin(target_url, link_url)
                    elif link_url.startswith('http'):
                        full_url = link_url
                    else:
                        full_url = urljoin(target_url, link_url)
                    
                    # Parse the link for ID parameters
                    link_parsed = urlparse(full_url)
                    link_params = parse_qs(link_parsed.query)
                    
                    for param_name, param_values in link_params.items():
                        if any(id_param in param_name.lower() for id_param in self.id_parameters):
                            if param_values and param_values[0].isdigit():
                                endpoints.append({
                                    'type': 'url_param',
                                    'url': full_url,
                                    'parameter': param_name,
                                    'original_value': param_values[0],
                                    'method': 'GET'
                                })
            
            # Look for API endpoints
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for sensitive_path in self.sensitive_endpoints[:5]:  # Test first 5 paths
                api_url = urljoin(base_url, sensitive_path)
                endpoints.append({
                    'type': 'api_endpoint',
                    'url': api_url,
                    'parameter': 'id',
                    'original_value': '1',
                    'method': 'GET'
                })
            
        except Exception as e:
            logger.debug(f"Error finding IDOR endpoints: {str(e)}")
        
        return endpoints
    
    def _test_sequential_ids(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test sequential ID manipulation."""
        findings = []
        
        try:
            original_value = int(endpoint['original_value'])
        except (ValueError, KeyError):
            return findings
        
        # Test values around the original ID
        test_values = [
            original_value - 1,
            original_value + 1,
            original_value - 2,
            original_value + 2,
            1,  # First record
            2,  # Second record
        ]
        
        # Get baseline response first
        try:
            baseline_response = self._make_request(endpoint, str(original_value))
            if baseline_response.status_code != 200:
                return findings  # Skip if original doesn't work
                
        except Exception as e:
            logger.debug(f"Error getting baseline response: {str(e)}")
            return findings
        
        for test_id in test_values:
            if test_id == original_value or test_id <= 0:
                continue
                
            try:
                response = self._make_request(endpoint, str(test_id))
                
                if self._is_idor_successful(baseline_response, response, str(test_id)):
                    finding = Finding(
                        title="Insecure Direct Object References (IDOR)",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"IDOR vulnerability allows access to other users' data",
                        target=endpoint['url'],
                        vulnerability_type="Insecure Direct Object References",
                        evidence=f"Accessed ID {test_id} via parameter '{endpoint['parameter']}'",
                        impact="Attacker can access unauthorized data by manipulating object references.",
                        remediation="Implement proper authorization checks and use indirect object references."
                    )
                    findings.append(finding)
                    return findings  # Stop after first successful IDOR
                    
            except Exception as e:
                logger.debug(f"Error testing sequential ID {test_id}: {str(e)}")
        
        return findings
    
    def _test_common_ids(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test common ID values that might exist."""
        findings = []
        
        # Common IDs that often exist in systems
        common_ids = ['1', '2', '3', '10', '100', '1000', '999', '1001']
        
        # Get baseline response
        try:
            baseline_response = self._make_request(endpoint, endpoint['original_value'])
            if baseline_response.status_code != 200:
                return findings
        except Exception:
            return findings
        
        for test_id in common_ids:
            if test_id == endpoint['original_value']:
                continue
                
            try:
                response = self._make_request(endpoint, test_id)
                
                if self._is_idor_successful(baseline_response, response, test_id):
                    finding = Finding(
                        title="IDOR - Common ID Access",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        description=f"IDOR vulnerability allows access to common ID values",
                        target=endpoint['url'],
                        vulnerability_type="Insecure Direct Object References",
                        evidence=f"Accessed common ID {test_id} via parameter '{endpoint['parameter']}'",
                        impact="Attacker can access data using predictable ID values.",
                        remediation="Implement authorization checks and consider using UUIDs instead of sequential IDs."
                    )
                    findings.append(finding)
                    return findings
                    
            except Exception as e:
                logger.debug(f"Error testing common ID {test_id}: {str(e)}")
        
        return findings
    
    def _test_boundary_ids(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test boundary values like 0, negative numbers."""
        findings = []
        
        boundary_values = ['0', '-1', '-2', '999999', '9999999']
        
        # Get baseline response
        try:
            baseline_response = self._make_request(endpoint, endpoint['original_value'])
            if baseline_response.status_code != 200:
                return findings
        except Exception:
            return findings
        
        for test_id in boundary_values:
            try:
                response = self._make_request(endpoint, test_id)
                
                # Check for different types of issues
                if response.status_code == 200:
                    if self._contains_sensitive_data(response):
                        finding = Finding(
                            title="IDOR - Boundary Value Access",
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            description=f"Boundary value {test_id} returns sensitive data",
                            target=endpoint['url'],
                            vulnerability_type="Insecure Direct Object References",
                            evidence=f"Boundary value {test_id} accessible via parameter '{endpoint['parameter']}'",
                            impact="Attacker may access unexpected data using boundary values.",
                            remediation="Implement proper input validation and authorization checks."
                        )
                        findings.append(finding)
                        return findings
                elif response.status_code == 500 and test_id in ['-1', '-2']:
                    # Negative IDs causing errors might indicate vulnerability
                    finding = Finding(
                        title="Potential IDOR - Error on Negative ID",
                        severity=Severity.LOW,
                        confidence=0.4,
                        description=f"Negative ID values cause server errors",
                        target=endpoint['url'],
                        vulnerability_type="Insecure Direct Object References",
                        evidence=f"Negative ID {test_id} causes HTTP 500 error",
                        impact="Application may not properly validate ID parameters.",
                        remediation="Implement proper input validation for ID parameters."
                    )
                    findings.append(finding)
                    
            except Exception as e:
                logger.debug(f"Error testing boundary ID {test_id}: {str(e)}")
        
        return findings
    
    def _test_uuid_manipulation(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test UUID/GUID manipulation if original value looks like UUID."""
        findings = []
        
        original_value = endpoint['original_value']
        
        # Check if original value looks like a UUID
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, original_value, re.IGNORECASE):
            return findings
        
        # Try common UUID patterns
        test_uuids = [
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000002',
            '11111111-1111-1111-1111-111111111111',
            '12345678-1234-1234-1234-123456789012',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        ]
        
        # Get baseline response
        try:
            baseline_response = self._make_request(endpoint, original_value)
            if baseline_response.status_code != 200:
                return findings
        except Exception:
            return findings
        
        for test_uuid in test_uuids:
            try:
                response = self._make_request(endpoint, test_uuid)
                
                if self._is_idor_successful(baseline_response, response, test_uuid):
                    finding = Finding(
                        title="IDOR - UUID Manipulation",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        description=f"IDOR vulnerability with UUID manipulation",
                        target=endpoint['url'],
                        vulnerability_type="Insecure Direct Object References",
                        evidence=f"Accessed UUID {test_uuid} via parameter '{endpoint['parameter']}'",
                        impact="Even with UUIDs, authorization checks may be missing.",
                        remediation="Implement proper authorization checks for all object references."
                    )
                    findings.append(finding)
                    return findings
                    
            except Exception as e:
                logger.debug(f"Error testing UUID {test_uuid}: {str(e)}")
        
        return findings
    
    def _make_request(self, endpoint: Dict[str, Any], test_value: str) -> requests.Response:
        """Make a request with the test value."""
        if endpoint['type'] == 'url_param':
            # Replace parameter value in URL
            parsed_url = urlparse(endpoint['url'])
            params = parse_qs(parsed_url.query)
            params[endpoint['parameter']] = [test_value]
            
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            return requests.get(test_url, timeout=self.general_config.get('timeout', 10))
            
        elif endpoint['type'] == 'api_endpoint':
            # Test API endpoint with ID in path
            test_url = f"{endpoint['url']}/{test_value}"
            return requests.get(test_url, timeout=self.general_config.get('timeout', 10))
        
        else:
            raise ValueError(f"Unknown endpoint type: {endpoint['type']}")
    
    def _is_idor_successful(self, baseline_response: requests.Response, test_response: requests.Response, test_id: str) -> bool:
        """Check if IDOR attack was successful."""
        try:
            # Response must be successful
            if test_response.status_code != 200:
                return False
            
            # Response should be different from baseline (different user data)
            if test_response.text == baseline_response.text:
                return False
            
            # Check for sensitive data in response
            if self._contains_sensitive_data(test_response):
                return True
            
            # Check if response contains the test ID (indicating it found that record)
            if test_id in test_response.text and test_id not in baseline_response.text:
                # Make sure it's not just reflecting the ID in an error message
                if not self._is_error_response(test_response):
                    return True
            
            # Check response length - significant difference might indicate different data
            baseline_length = len(baseline_response.text)
            test_length = len(test_response.text)
            
            if baseline_length > 100 and test_length > 100:
                length_diff_ratio = abs(baseline_length - test_length) / max(baseline_length, test_length)
                if 0.1 < length_diff_ratio < 0.9:  # Significant but not complete difference
                    return True
                    
        except Exception as e:
            logger.debug(f"Error checking IDOR success: {str(e)}")
        
        return False
    
    def _contains_sensitive_data(self, response: requests.Response) -> bool:
        """Check if response contains sensitive data patterns."""
        try:
            response_text = response.text
            
            for pattern in self.sensitive_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            
            # Check for common sensitive field names
            sensitive_fields = [
                'email', 'phone', 'address', 'ssn', 'credit_card',
                'password', 'token', 'api_key', 'balance', 'salary'
            ]
            
            response_lower = response_text.lower()
            for field in sensitive_fields:
                if field in response_lower:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _is_error_response(self, response: requests.Response) -> bool:
        """Check if response is an error message."""
        response_text = response.text.lower()
        
        error_indicators = [
            'error', 'exception', 'not found', 'invalid',
            'unauthorized', 'forbidden', 'access denied',
            'bad request', 'internal server error'
        ]
        
        return any(indicator in response_text for indicator in error_indicators)
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load IDOR payloads."""
        return {
            'sequential': ['1', '2', '3', '10', '100'],
            'boundary': ['0', '-1', '999999'],
            'common': ['admin', 'test', 'guest', '1000']
        }