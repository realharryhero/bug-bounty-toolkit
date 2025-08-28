"""
NoSQL Injection Scanner - Detects NoSQL injection vulnerabilities
"""

import logging
import requests
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class NoSQLScanner:
    """NoSQL injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the NoSQL scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('nosql')
        self.general_config = config_manager.get('general')

        # MongoDB injection payloads
        self.mongodb_payloads = [
            "true, true",
            "1, 1", 
            "', '",
            '1; return true',
            "'; return true; var a='",
            "1'; return true; var a='1",
            '\' || \'1\'==\'1',
            "' || '1'=='1",
            "1' || '1'=='1' || '1'=='1",
            '$gt',
            '{"$gt":""}',
            '{"$ne":""}',
            '{"$exists":"true"}',
            '{"$regex":".*"}',
            '[$ne]',
            '{"$where":"return true"}',
            '{"$where":"1==1"}',
        ]

        # Time-based payloads for blind NoSQL injection
        self.time_payloads = [
            '{"$where":"sleep(5000)"}',
            '{"$where":"sleep(5000)||true"}',
            '; sleep(5000)',
            '\'; sleep(5000); var a=\'',
            '1\'; sleep(5000); var a=\'1',
        ]

        # Error-based payloads
        self.error_payloads = [
            '{"$where":"this.a.b"}',
            '{"$where":"return this.a.b.c.d"}',
            '{"$where":"function(){return this.a.b.c.d}()"}',
            "'; throw new Error('nosql'); var a='",
            '1\'; throw new Error(\'nosql\'); var a=\'1',
        ]

        # NoSQL error patterns
        self.error_patterns = [
            'MongoError',
            'MongoDB', 
            'CastError',
            'ValidationError',
            r'TypeError.*ObjectId',
            r'SyntaxError.*JSON',
            'nosql',
            'ReferenceError',
            r'this\.a\.b is undefined',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for NoSQL injection vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting NoSQL injection scan on {target_url}")
        findings = []

        try:
            # Test GET parameters
            findings.extend(self._test_get_parameters(target_url))
            
            # Test POST data
            findings.extend(self._test_post_data(target_url))
            
            # Test JSON payloads
            findings.extend(self._test_json_payloads(target_url))

        except Exception as e:
            logger.error(f"Error during NoSQL scan: {str(e)}")
            security_logger.log_error("NOSQL_SCAN_ERROR", str(e), target_url)

        logger.info(f"NoSQL injection scan completed - {len(findings)} findings")
        return findings

    def _test_get_parameters(self, target_url: str) -> List[Finding]:
        """Test GET parameters for NoSQL injection."""
        findings = []
        
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return findings
        
        for param_name in query_params:
            original_value = query_params[param_name][0]
            
            # Test MongoDB payloads
            findings.extend(self._test_parameter_payloads(
                target_url, param_name, self.mongodb_payloads, 'GET', 'MongoDB'
            ))
            
            # Test time-based payloads
            findings.extend(self._test_time_based_parameter(
                target_url, param_name, 'GET'
            ))
            
            # Test error-based payloads
            findings.extend(self._test_error_based_parameter(
                target_url, param_name, 'GET'
            ))
            
            if findings:  # If we found vulnerabilities, no need to test more parameters
                break

        return findings

    def _test_post_data(self, target_url: str) -> List[Finding]:
        """Test POST data for NoSQL injection."""
        findings = []
        
        # Common form parameter names to test
        test_params = ['username', 'password', 'email', 'user', 'login', 'id']
        
        for param_name in test_params:
            # Test MongoDB payloads
            findings.extend(self._test_parameter_payloads(
                target_url, param_name, self.mongodb_payloads, 'POST', 'MongoDB'
            ))
            
            # Test time-based payloads
            findings.extend(self._test_time_based_parameter(
                target_url, param_name, 'POST'
            ))
            
            if findings:  # If we found vulnerabilities, no need to test more
                break

        return findings

    def _test_json_payloads(self, target_url: str) -> List[Finding]:
        """Test JSON payloads for NoSQL injection."""
        findings = []
        
        json_payloads = [
            {"$ne": ""},
            {"$gt": ""},
            {"$exists": True},
            {"$regex": ".*"},
            {"$where": "return true"},
            {"$where": "1==1"},
            {"$where": "this.a.b.c.d"},  # Error-based
        ]
        
        for payload in json_payloads:
            try:
                # Test with common parameter names
                test_data = {"username": payload, "password": payload}
                
                response = requests.post(
                    target_url,
                    json=test_data,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')}
                )
                
                if self._analyze_nosql_response(response, json.dumps(payload)):
                    finding = Finding(
                        title="NoSQL Injection via JSON",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description="NoSQL injection vulnerability detected in JSON parameters",
                        url=target_url,
                        method="POST",
                        payload=json.dumps(test_data),
                        evidence=self._extract_nosql_evidence(response, json.dumps(payload)),
                        impact="Attackers can manipulate NoSQL queries, potentially bypassing authentication or accessing unauthorized data.",
                        remediation="Validate and sanitize all input parameters. Use parameterized queries and proper input validation for NoSQL databases."
                    )
                    findings.append(finding)
                    logger.warning(f"NoSQL injection found via JSON payload: {payload}")
                    break  # Found one, no need to test more

            except requests.RequestException as e:
                logger.debug(f"Error testing JSON payload {payload}: {str(e)}")

        return findings

    def _test_parameter_payloads(self, target_url: str, param_name: str, payloads: List[str], method: str, injection_type: str) -> List[Finding]:
        """Test specific parameter with payloads."""
        findings = []
        
        parsed_url = urlparse(target_url)
        
        for payload in payloads:
            try:
                if method == 'GET':
                    query_params = parse_qs(parsed_url.query)
                    query_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    response = requests.get(
                        test_url,
                        params=query_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                else:  # POST
                    data = {param_name: payload}
                    response = requests.post(
                        target_url,
                        data=data,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                
                if self._analyze_nosql_response(response, payload):
                    severity = Severity.HIGH if 'true' in payload or '$ne' in payload else Severity.MEDIUM
                    
                    finding = Finding(
                        title=f"{injection_type} NoSQL Injection",
                        severity=severity,
                        confidence=0.7,
                        description=f"NoSQL injection vulnerability detected in {method} parameter '{param_name}'",
                        url=target_url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_nosql_evidence(response, payload),
                        impact="Attackers can manipulate NoSQL queries to bypass authentication, access unauthorized data, or perform unauthorized operations.",
                        remediation="Implement proper input validation and sanitization. Use parameterized queries and avoid direct insertion of user input into NoSQL queries."
                    )
                    findings.append(finding)
                    logger.warning(f"NoSQL injection found in {param_name} with payload: {payload}")
                    break  # Found one for this parameter
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing {method} parameter {param_name} with payload {payload}: {str(e)}")

        return findings

    def _test_time_based_parameter(self, target_url: str, param_name: str, method: str) -> List[Finding]:
        """Test parameter for time-based NoSQL injection."""
        findings = []
        
        for payload in self.time_payloads:
            try:
                start_time = time.time()
                
                if method == 'GET':
                    parsed_url = urlparse(target_url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    response = requests.get(
                        test_url,
                        params=query_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                else:  # POST
                    data = {param_name: payload}
                    response = requests.post(
                        target_url,
                        data=data,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                # If response took significantly longer (> 4 seconds for a 5-second sleep)
                if response_time > 4:
                    finding = Finding(
                        title="Time-based NoSQL Injection",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description=f"Time-based NoSQL injection vulnerability detected in {method} parameter '{param_name}'",
                        url=target_url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response time: {response_time:.2f}s (expected delay: 5s)",
                        impact="Attackers can perform blind NoSQL injection attacks to extract sensitive information through timing analysis.",
                        remediation="Implement proper input validation to prevent NoSQL injection. Avoid direct insertion of user input into NoSQL queries."
                    )
                    findings.append(finding)
                    logger.warning(f"Time-based NoSQL injection found in {param_name}")
                    break
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing time-based NoSQL in {param_name}: {str(e)}")

        return findings

    def _test_error_based_parameter(self, target_url: str, param_name: str, method: str) -> List[Finding]:
        """Test parameter for error-based NoSQL injection."""
        findings = []
        
        for payload in self.error_payloads:
            try:
                if method == 'GET':
                    parsed_url = urlparse(target_url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param_name] = [payload]
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    response = requests.get(
                        test_url,
                        params=query_params,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                else:  # POST
                    data = {param_name: payload}
                    response = requests.post(
                        target_url,
                        data=data,
                        timeout=self.general_config.get('timeout', 30),
                        headers={'User-Agent': self.general_config.get('user_agent')}
                    )
                
                if self._detect_nosql_errors(response):
                    finding = Finding(
                        title="Error-based NoSQL Injection",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        description=f"Error-based NoSQL injection vulnerability detected in {method} parameter '{param_name}'",
                        url=target_url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_error_evidence(response),
                        impact="Attackers can extract information about the database structure and potentially sensitive data through error messages.",
                        remediation="Implement proper error handling to avoid exposing database errors. Validate input to prevent NoSQL injection."
                    )
                    findings.append(finding)
                    logger.warning(f"Error-based NoSQL injection found in {param_name}")
                    break
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing error-based NoSQL in {param_name}: {str(e)}")

        return findings

    def _analyze_nosql_response(self, response: requests.Response, payload: str) -> bool:
        """Analyze response for NoSQL injection indicators."""
        # Check for different response (potential bypass)
        if response.status_code == 200:
            content = response.text.lower()
            
            # Look for successful authentication/bypass indicators
            success_indicators = [
                'welcome', 'dashboard', 'profile', 'success',
                'logged in', 'authentication successful',
                'admin', 'user panel', 'member area'
            ]
            
            for indicator in success_indicators:
                if indicator in content:
                    return True
        
        # Check for NoSQL-specific errors
        return self._detect_nosql_errors(response)

    def _detect_nosql_errors(self, response: requests.Response) -> bool:
        """Detect NoSQL-specific error messages."""
        content = response.text
        
        import re
        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def _extract_nosql_evidence(self, response: requests.Response, payload: str) -> str:
        """Extract evidence of NoSQL injection."""
        evidence = [f"Payload: {payload}"]
        evidence.append(f"Status Code: {response.status_code}")
        
        if self._detect_nosql_errors(response):
            evidence.append("NoSQL error detected in response")
        
        # Look for authentication bypass indicators
        content = response.text.lower()
        if any(word in content for word in ['welcome', 'dashboard', 'success', 'logged in']):
            evidence.append("Potential authentication bypass detected")
        
        return "; ".join(evidence)

    def _extract_error_evidence(self, response: requests.Response) -> str:
        """Extract evidence from error-based injection."""
        evidence = [f"Status Code: {response.status_code}"]
        
        content = response.text
        
        import re
        for pattern in self.error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                evidence.append(f"NoSQL error: {matches[0]}")
                break
        
        return "; ".join(evidence)