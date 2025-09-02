"""
Client-side JSON Injection Scanner - Detects DOM-based JSON injection vulnerabilities
Covers CWE-79, CWE-116, CWE-159 for reflected, stored, and DOM-based scenarios
"""

import re
import time
import json
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs, quote
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class ClientSideJSONInjectionScanner(BaseScanner):
    """Client-side JSON injection vulnerability scanner for DOM-based attacks."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the client-side JSON injection scanner.

        Args:
            config_manager: Configuration manager instance
        """
        super().__init__(config_manager)
        self.config = config_manager.get_scanner_config('client_json')
        self.general_config = config_manager.get('general', {})

        # Client-side JSON injection payloads
        self.json_payloads = [
            # Basic JSON injection - breaking out of string context
            '","test":"injected',
            '\\"test\\":\\"injected\\',
            '"},"injected":"value',
            
            # JSON injection with XSS
            '","xss":"<script>alert(1)</script>',
            '\\"xss\\":\\"<img src=x onerror=alert(1)>\\',
            '"},"xss":"<svg onload=alert(1)>',
            
            # JSON injection with function calls
            '","eval":"alert(1)',
            '\\"exec\\":\\"console.log(document.cookie)\\',
            '"},"callback":"malicious_function',
            
            # Boolean manipulation
            '","admin":true,"test":"',
            '\\"isAdmin\\":true,\\"test\\":\\"',
            '"},"authorized":true,"dummy":"',
            
            # Array injection
            '"],["injected","value',
            '\\"],[\\"injected\\",\\"value\\',
            
            # Object injection
            '"}},{"injected":"value',
            '\\"}},{\\"injected\\":\\"value\\',
            
            # Prototype pollution attempts
            '","__proto__":{"isAdmin":true},"test":"',
            '\\"constructor\\":{\\"prototype\\":{\\"isAdmin\\":true}},\\"test\\":\\"',
            
            # JSONP callback manipulation
            'callback=malicious_function',
            'jsonp=alert(1)',
            'cb=eval(atob("YWxlcnQoMSk="))',  # Base64 encoded alert(1)
        ]

        # JavaScript patterns that indicate JSON usage
        self.json_js_patterns = [
            r'JSON\.parse\s*\(',
            r'JSON\.stringify\s*\(',
            r'eval\s*\(',
            r'Function\s*\(',
            r'$.parseJSON',
            r'jQuery\.parseJSON',
            r'angular\.fromJson',
            r'JSON\s*\.',
            r'\.parseJSON\s*\(',
            r'JSON\[',
            r'response\.json\s*\(',
            r'fetch\s*\([^)]*\)\.then\s*\([^)]*\)\.json\s*\(',
        ]

        # JSONP patterns
        self.jsonp_patterns = [
            r'callback\s*=',
            r'jsonp\s*=',
            r'cb\s*=',
            r'\w+\s*\(\s*\{',  # Function call with object parameter
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

        # Error signatures for client-side JSON errors
        self.client_error_signatures = [
            r"SyntaxError.*JSON",
            r"JSON\.parse.*error",
            r"Unexpected token.*JSON",
            r"JSON parsing error",
            r"Invalid JSON",
            r"JSON syntax error",
            r"SyntaxError.*Unexpected token",
            r"TypeError.*JSON",
        ]

    def scan(self, target: str, **kwargs) -> List[Finding]:
        """
        Scan for client-side JSON injection vulnerabilities.

        Args:
            target: Target URL to scan
            **kwargs: Additional parameters

        Returns:
            List of findings
        """
        findings = []
        
        try:
            logger.info(f"Starting client-side JSON injection scan on {target}")
            
            # Test for DOM-based JSON injection
            findings.extend(self._test_dom_json_injection(target))
            
            # Test for reflected DOM-based JSON injection
            findings.extend(self._test_reflected_dom_json_injection(target))
            
            # Test for stored DOM-based JSON injection
            findings.extend(self._test_stored_dom_json_injection(target))
            
            # Test for JSONP injection
            findings.extend(self._test_jsonp_injection(target))
            
            logger.info(f"Client-side JSON injection scan completed. Found {len(findings)} potential vulnerabilities.")
            
        except Exception as e:
            logger.error(f"Error during client-side JSON injection scan: {str(e)}")
            
        return findings

    def _test_dom_json_injection(self, target: str) -> List[Finding]:
        """Test for DOM-based JSON injection vulnerabilities."""
        findings = []
        
        try:
            # First, check if the page uses JSON in JavaScript
            response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code != 200:
                return findings
                
            page_content = response.text
            
            # Check for JSON usage in JavaScript
            json_usage_found = any(re.search(pattern, page_content, re.IGNORECASE) 
                                 for pattern in self.json_js_patterns)
            
            if not json_usage_found:
                logger.debug(f"No JSON usage detected in JavaScript for {target}")
                return findings
                
            # Test JSON injection in URL fragments and parameters
            for payload in self.json_payloads:
                # Test in URL fragment (hash)
                test_url = f"{target}#{quote(payload)}"
                finding = self._test_json_payload(test_url, payload, "DOM-based")
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
                        
                        finding = self._test_json_payload(test_url, payload, "DOM-based")
                        if finding:
                            findings.append(finding)
                            
        except Exception as e:
            logger.error(f"Error testing DOM-based JSON injection: {str(e)}")
            
        return findings

    def _test_reflected_dom_json_injection(self, target: str) -> List[Finding]:
        """Test for reflected DOM-based JSON injection vulnerabilities."""
        findings = []
        
        try:
            # Test JSON injection in URL parameters that get reflected in JavaScript
            parsed_url = urlparse(target)
            
            # Add test parameters if none exist
            test_params = ['data', 'json', 'config', 'params', 'query', 'search']
            
            for param in test_params:
                for payload in self.json_payloads:
                    test_url = f"{target}{'&' if parsed_url.query else '?'}{param}={quote(payload)}"
                    
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                    
                    if response.status_code == 200:
                        # Check if payload is reflected in JavaScript context
                        if self._is_payload_in_js_context(response.text, payload):
                            # Check for JSON usage
                            json_usage_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                                 for pattern in self.json_js_patterns)
                            
                            # Check for JSON errors
                            error_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                            for pattern in self.client_error_signatures)
                            
                            if json_usage_found or error_found:
                                confidence = 0.8 if error_found else 0.6
                                
                                finding = Finding(
                                    title="Client-side JSON Injection (Reflected DOM-based)",
                                    severity=Severity.MEDIUM,
                                    confidence=confidence,
                                    description=f"Reflected DOM-based JSON injection detected. Parameter '{param}' is reflected in JavaScript context where JSON operations are performed.",
                                    target=test_url,
                                    vulnerability_type="Client-side JSON Injection",
                                    payload=payload,
                                    evidence=f"Payload reflected in JavaScript context with JSON usage",
                                    impact="An attacker could potentially manipulate JSON data on the client-side to inject malicious content, bypass authentication, or execute arbitrary JavaScript code.",
                                    remediation="Properly validate and encode all user input before using in JSON operations. Use safe JSON parsing methods and avoid eval() with user-controlled data.",
                                    cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                                )
                                
                                findings.append(finding)
                                security_logger.log_vulnerability_found("CLIENT_JSON_REFLECTED", target, "MEDIUM", confidence)
                                break
                                
        except Exception as e:
            logger.error(f"Error testing reflected DOM-based JSON injection: {str(e)}")
            
        return findings

    def _test_stored_dom_json_injection(self, target: str) -> List[Finding]:
        """Test for stored DOM-based JSON injection vulnerabilities."""
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
                    for payload in self.json_payloads:
                        # Submit payload to form
                        form_data = {input_name: payload}
                        
                        try:
                            post_response = requests.post(target, data=form_data, 
                                                        timeout=self.general_config.get('timeout', 30))
                            
                            if post_response.status_code == 200:
                                # Check if stored data is used in JSON operations
                                json_usage_found = any(re.search(pattern, post_response.text, re.IGNORECASE) 
                                                     for pattern in self.json_js_patterns)
                                
                                # Check for JSON error patterns
                                error_found = any(re.search(pattern, post_response.text, re.IGNORECASE) 
                                                for pattern in self.client_error_signatures)
                                
                                if json_usage_found or error_found:
                                    confidence = 0.7 if error_found else 0.5
                                    
                                    finding = Finding(
                                        title="Client-side JSON Injection (Stored DOM-based)",
                                        severity=Severity.MEDIUM,
                                        confidence=confidence,
                                        description=f"Stored DOM-based JSON injection detected in field '{input_name}'. Stored data is used in client-side JSON operations.",
                                        target=target,
                                        vulnerability_type="Client-side JSON Injection",
                                        payload=payload,
                                        evidence=f"JSON usage detected with stored input in field '{input_name}'",
                                        impact="An attacker could store malicious JSON that gets executed when other users visit the page, potentially leading to XSS, data manipulation, or authentication bypass.",
                                        remediation="Validate and encode all stored data before using in JSON operations. Use safe JSON parsing methods and implement proper input sanitization.",
                                        cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                                    )
                                    
                                    findings.append(finding)
                                    security_logger.log_vulnerability_found("CLIENT_JSON_STORED", target, "MEDIUM", confidence)
                                    break
                                    
                        except Exception as e:
                            logger.debug(f"Error submitting form data: {str(e)}")
                            
        except Exception as e:
            logger.error(f"Error testing stored DOM-based JSON injection: {str(e)}")
            
        return findings

    def _test_jsonp_injection(self, target: str) -> List[Finding]:
        """Test for JSONP injection vulnerabilities."""
        findings = []
        
        try:
            # Test JSONP callback parameters
            jsonp_params = ['callback', 'jsonp', 'cb', 'call']
            
            for param in jsonp_params:
                for payload in ['alert(1)', 'malicious_function', '<script>alert(1)</script>']:
                    test_url = f"{target}{'&' if '?' in target else '?'}{param}={payload}"
                    
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                    
                    if response.status_code == 200:
                        # Check if it's a JSONP response
                        if self._is_jsonp_response(response.text, payload):
                            confidence = 0.9
                            
                            finding = Finding(
                                title="Client-side JSON Injection (JSONP)",
                                severity=Severity.HIGH,
                                confidence=confidence,
                                description=f"JSONP injection detected. Callback parameter '{param}' allows injection of arbitrary JavaScript code.",
                                target=test_url,
                                vulnerability_type="Client-side JSON Injection",
                                payload=payload,
                                evidence=f"JSONP callback parameter '{param}' accepts arbitrary input",
                                impact="An attacker could execute arbitrary JavaScript code in the context of the application, leading to XSS, data theft, or session hijacking.",
                                remediation="Validate JSONP callback parameters against a whitelist of allowed function names. Consider using CORS instead of JSONP.",
                                cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                            )
                            
                            findings.append(finding)
                            security_logger.log_vulnerability_found("CLIENT_JSON_JSONP", target, "HIGH", confidence)
                            break
                            
        except Exception as e:
            logger.error(f"Error testing JSONP injection: {str(e)}")
            
        return findings

    def _test_json_payload(self, test_url: str, payload: str, injection_type: str) -> Optional[Finding]:
        """Test a specific JSON payload and return finding if vulnerability detected."""
        try:
            response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
            
            if response.status_code == 200:
                # Check for JSON error patterns in response
                error_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                for pattern in self.client_error_signatures)
                
                # Check for JSON usage patterns
                json_usage_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                     for pattern in self.json_js_patterns)
                
                # Check for DOM sinks that could be exploited
                dom_sink_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                   for pattern in self.dom_sink_patterns)
                
                # Check if payload breaks JSON structure
                json_break_found = self._check_json_structure_break(response.text, payload)
                
                if error_found or json_break_found or (json_usage_found and dom_sink_found):
                    confidence = 0.8 if error_found else 0.6 if json_break_found else 0.4
                    
                    return Finding(
                        title=f"Client-side JSON Injection ({injection_type})",
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        description=f"{injection_type} JSON injection vulnerability detected. The application uses client-side JSON operations that may be exploitable.",
                        target=test_url,
                        vulnerability_type="Client-side JSON Injection",
                        payload=payload,
                        evidence="JSON error patterns or vulnerable usage detected in client-side code",
                        impact="An attacker could potentially manipulate JSON data to inject malicious content, bypass authentication, or execute arbitrary JavaScript code.",
                        remediation="Implement proper input validation and encoding. Use safe JSON parsing methods and avoid dynamic JSON construction with user input.",
                        cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                    )
                    
        except Exception as e:
            logger.debug(f"Error testing JSON payload {payload}: {str(e)}")
            
        return None

    def _is_payload_in_js_context(self, content: str, payload: str) -> bool:
        """Check if payload appears in JavaScript context."""
        # Look for payload within <script> tags or JavaScript event handlers
        js_contexts = [
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']',
            r'var\s+\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']',
        ]
        
        return any(re.search(pattern, content, re.DOTALL | re.IGNORECASE) 
                  for pattern in js_contexts)

    def _is_jsonp_response(self, content: str, callback: str) -> bool:
        """Check if response is JSONP with the injected callback."""
        # Look for the callback function being called
        jsonp_pattern = f"{re.escape(callback)}\\s*\\("
        return bool(re.search(jsonp_pattern, content, re.IGNORECASE))

    def _check_json_structure_break(self, content: str, payload: str) -> bool:
        """Check if payload breaks JSON structure in the response."""
        try:
            # Look for JSON-like structures in the response that contain the payload
            json_pattern = r'\{[^{}]*' + re.escape(payload) + r'[^{}]*\}?'
            json_matches = re.findall(json_pattern, content, re.DOTALL)
            
            for match in json_matches:
                try:
                    # Try to parse as JSON - if it fails, structure is broken
                    json.loads(match)
                except json.JSONDecodeError:
                    return True
                    
        except Exception as e:
            logger.debug(f"Error checking JSON structure: {str(e)}")
            
        return False

    def _extract_json_from_response(self, content: str) -> List[str]:
        """Extract potential JSON objects from response content."""
        json_objects = []
        
        # Look for JSON objects in script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for script in scripts:
            # Look for JSON-like structures
            json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
            potential_json = re.findall(json_pattern, script)
            json_objects.extend(potential_json)
            
        return json_objects

    def _test_prototype_pollution(self, target: str) -> List[Finding]:
        """Test for prototype pollution through JSON injection."""
        findings = []
        
        pollution_payloads = [
            '{"__proto__":{"isAdmin":true}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '{"__proto__":{"toString":"alert"}}',
        ]
        
        try:
            for payload in pollution_payloads:
                test_url = f"{target}{'&' if '?' in target else '?'}data={quote(payload)}"
                
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                
                if response.status_code == 200:
                    # Look for signs of prototype pollution
                    pollution_indicators = [
                        r'isAdmin.*true',
                        r'prototype.*pollution',
                        r'__proto__',
                        r'constructor.*prototype',
                    ]
                    
                    pollution_found = any(re.search(pattern, response.text, re.IGNORECASE) 
                                        for pattern in pollution_indicators)
                    
                    if pollution_found:
                        confidence = 0.7
                        
                        finding = Finding(
                            title="Client-side JSON Injection (Prototype Pollution)",
                            severity=Severity.HIGH,
                            confidence=confidence,
                            description="Prototype pollution vulnerability detected through JSON injection. Attacker can modify object prototypes.",
                            target=test_url,
                            vulnerability_type="Client-side JSON Injection",
                            payload=payload,
                            evidence="Prototype pollution indicators detected in response",
                            impact="An attacker could modify JavaScript object prototypes, potentially leading to privilege escalation, XSS, or application logic bypass.",
                            remediation="Use Object.create(null) for objects, validate JSON structure, and implement proper input sanitization. Consider using Map instead of objects for user data.",
                            cwe_ids=["CWE-79", "CWE-116", "CWE-159"]
                        )
                        
                        findings.append(finding)
                        security_logger.log_vulnerability_found("CLIENT_JSON_PROTOTYPE", target, "HIGH", confidence)
                        break
                        
        except Exception as e:
            logger.error(f"Error testing prototype pollution: {str(e)}")
            
        return findings
