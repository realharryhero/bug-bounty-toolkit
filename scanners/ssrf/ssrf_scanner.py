"""
Server-Side Request Forgery (SSRF) Scanner - Detects SSRF vulnerabilities
"""

import re
import logging
import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class SSRFScanner:
    """Server-Side Request Forgery vulnerability scanner."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the SSRF scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('ssrf')
        self.general_config = config_manager.get('general')
        
        # Common SSRF target URLs
        self.ssrf_targets = [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://169.254.169.254",  # AWS metadata service
            "http://metadata.google.internal",  # GCP metadata service
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/version",
            "gopher://127.0.0.1:22",
            "dict://127.0.0.1:11211",
            "ftp://127.0.0.1",
        ]
        
        # URL encoding variations
        self.encoding_variations = [
            lambda x: x,  # No encoding
            lambda x: x.replace("127.0.0.1", "0x7f000001"),  # Hex encoding
            lambda x: x.replace("127.0.0.1", "2130706433"),  # Decimal encoding
            lambda x: x.replace("localhost", "127.0.0.1"),  # localhost to IP
            lambda x: x.replace("http://", "http:\\/\\/"),  # Escape slashes
        ]
        
        # Response indicators for successful SSRF
        self.success_indicators = [
            "root:x:0:0:",  # /etc/passwd
            "amazon-web-services",  # AWS metadata
            "computeMetadata",  # GCP metadata
            "instance-identity",
            "security-credentials",
            "user-data",
            "SSH-",  # SSH banner
            "Microsoft Windows",
        ]
        
        # Load payloads
        self.payloads = self._load_payloads()
        
    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan target for SSRF vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        logger.info(f"Starting SSRF scan on {target_url}")
        security_logger.log_scan_start("ssrf", target_url)
        
        try:
            # Find potential SSRF injection points
            injection_points = self._find_injection_points(target_url)
            
            for point in injection_points:
                # Test basic SSRF payloads
                findings.extend(self._test_basic_ssrf(point))
                
                # Test cloud metadata endpoints
                findings.extend(self._test_cloud_metadata(point))
                
                # Test protocol smuggling
                findings.extend(self._test_protocol_smuggling(point))
                
                # Test blind SSRF
                findings.extend(self._test_blind_ssrf(point))
                
        except Exception as e:
            logger.error(f"SSRF scan failed: {str(e)}")
            security_logger.log_error("SSRF_SCAN_FAILED", str(e), target_url)
        
        logger.info(f"SSRF scan completed. Found {len(findings)} potential issues.")
        return findings
    
    def _find_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """Find potential SSRF injection points."""
        points = []
        
        try:
            response = requests.get(target_url, timeout=self.general_config.get('timeout', 10))
            
            # Parse URL for existing parameters
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                # Look for URL-like parameters
                if any(keyword in param_name.lower() for keyword in ['url', 'link', 'src', 'href', 'redirect', 'uri', 'path', 'file', 'callback']):
                    points.append({
                        'type': 'url_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'GET'
                    })
            
            # Look for forms that might accept URLs
            form_patterns = [
                r'<input[^>]*name=[\'"]([^\'\"]*(?:url|link|src|href|redirect|uri|path|file|callback)[^\'\"]*)[\'"][^>]*>',
                r'<textarea[^>]*name=[\'"]([^\'\"]*(?:url|link|src|href|redirect|uri|path|file|callback)[^\'\"]*)[\'"][^>]*>',
            ]
            
            for pattern in form_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    param_name = match.group(1)
                    points.append({
                        'type': 'form_param',
                        'url': target_url,
                        'parameter': param_name,
                        'method': 'POST'
                    })
            
            # Look for API endpoints that might accept URLs in JSON
            if 'api' in target_url.lower() or 'json' in response.headers.get('content-type', '').lower():
                points.append({
                    'type': 'json_param',
                    'url': target_url,
                    'parameter': 'url',
                    'method': 'POST'
                })
            
        except Exception as e:
            logger.debug(f"Error finding injection points: {str(e)}")
        
        return points
    
    def _test_basic_ssrf(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test basic SSRF payloads."""
        findings = []
        
        for target in self.ssrf_targets[:5]:  # Test first 5 targets
            for encoding_func in self.encoding_variations[:3]:  # Test first 3 encodings
                try:
                    encoded_target = encoding_func(target)
                    
                    if injection_point['type'] == 'url_param':
                        # Test URL parameter injection
                        parsed_url = urlparse(injection_point['url'])
                        params = parse_qs(parsed_url.query)
                        params[injection_point['parameter']] = [encoded_target]
                        
                        new_query = urlencode(params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        
                        response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))
                        
                    elif injection_point['type'] == 'form_param':
                        # Test form parameter injection
                        data = {injection_point['parameter']: encoded_target}
                        response = requests.post(
                            injection_point['url'], 
                            data=data, 
                            timeout=self.general_config.get('timeout', 10)
                        )
                        
                    elif injection_point['type'] == 'json_param':
                        # Test JSON parameter injection
                        json_data = {injection_point['parameter']: encoded_target}
                        response = requests.post(
                            injection_point['url'], 
                            json=json_data,
                            headers={'Content-Type': 'application/json'},
                            timeout=self.general_config.get('timeout', 10)
                        )
                    else:
                        continue
                    
                    # Check for successful SSRF
                    if self._is_ssrf_successful(response, target):
                        finding = Finding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            description=f"SSRF vulnerability detected via parameter '{injection_point['parameter']}'",
                            target=injection_point['url'],
                            vulnerability_type="Server-Side Request Forgery",
                            evidence=f"Payload: {encoded_target}, Parameter: {injection_point['parameter']}",
                            impact="Attacker may access internal resources, cloud metadata, or perform port scanning.",
                            remediation="Implement URL validation, whitelist allowed hosts, and use network segmentation."
                        )
                        findings.append(finding)
                        return findings  # Stop after first successful finding
                        
                except Exception as e:
                    logger.debug(f"Error testing basic SSRF: {str(e)}")
        
        return findings
    
    def _test_cloud_metadata(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test cloud metadata service access."""
        findings = []
        
        cloud_endpoints = [
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/instance/name",
        ]
        
        for endpoint in cloud_endpoints:
            try:
                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)
                    params[injection_point['parameter']] = [endpoint]
                    
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))
                    
                elif injection_point['type'] == 'form_param':
                    data = {injection_point['parameter']: endpoint}
                    response = requests.post(
                        injection_point['url'], 
                        data=data, 
                        timeout=self.general_config.get('timeout', 10)
                    )
                else:
                    continue
                
                # Check for cloud metadata in response
                if self._contains_cloud_metadata(response):
                    finding = Finding(
                        title="Cloud Metadata SSRF",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        description=f"SSRF allows access to cloud metadata services",
                        target=injection_point['url'],
                        vulnerability_type="Server-Side Request Forgery",
                        evidence=f"Accessed: {endpoint}, Parameter: {injection_point['parameter']}",
                        impact="Attacker may access sensitive cloud metadata including credentials and configuration.",
                        remediation="Block access to metadata services and implement strict URL validation."
                    )
                    findings.append(finding)
                    return findings  # Critical finding, stop here
                    
            except Exception as e:
                logger.debug(f"Error testing cloud metadata: {str(e)}")
        
        return findings
    
    def _test_protocol_smuggling(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test protocol smuggling attacks."""
        findings = []
        
        protocol_payloads = [
            "file:///etc/passwd",
            "ftp://127.0.0.1:21",
            "dict://127.0.0.1:11211/stat",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        
        for payload in protocol_payloads[:2]:  # Test first 2 protocols
            try:
                if injection_point['type'] == 'url_param':
                    parsed_url = urlparse(injection_point['url'])
                    params = parse_qs(parsed_url.query)
                    params[injection_point['parameter']] = [payload]
                    
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    response = requests.get(test_url, timeout=self.general_config.get('timeout', 10))
                    
                    if self._is_protocol_smuggling_successful(response, payload):
                        finding = Finding(
                            title="Protocol Smuggling SSRF",
                            severity=Severity.HIGH,
                            confidence=0.7,
                            description=f"SSRF allows protocol smuggling attacks",
                            target=injection_point['url'],
                            vulnerability_type="Server-Side Request Forgery",
                            evidence=f"Protocol payload: {payload}, Parameter: {injection_point['parameter']}",
                            impact="Attacker may access local files or interact with internal services.",
                            remediation="Restrict allowed protocols and implement proper URL validation."
                        )
                        findings.append(finding)
                        return findings
                        
            except Exception as e:
                logger.debug(f"Error testing protocol smuggling: {str(e)}")
        
        return findings
    
    def _test_blind_ssrf(self, injection_point: Dict[str, Any]) -> List[Finding]:
        """Test blind SSRF using timing attacks."""
        findings = []
        
        # Test with a delay payload
        delay_payload = "http://127.0.0.1:22"  # SSH port should cause delay
        
        try:
            start_time = time.time()
            
            if injection_point['type'] == 'url_param':
                parsed_url = urlparse(injection_point['url'])
                params = parse_qs(parsed_url.query)
                params[injection_point['parameter']] = [delay_payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = requests.get(test_url, timeout=15)  # Longer timeout for timing
                
            elif injection_point['type'] == 'form_param':
                data = {injection_point['parameter']: delay_payload}
                response = requests.post(
                    injection_point['url'], 
                    data=data, 
                    timeout=15
                )
            else:
                return findings
            
            elapsed_time = time.time() - start_time
            
            # If request took significantly longer, might indicate SSRF
            if elapsed_time > 5:  # 5+ seconds indicates potential SSRF
                finding = Finding(
                    title="Potential Blind SSRF",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    description=f"Timing-based blind SSRF detected",
                    target=injection_point['url'],
                    vulnerability_type="Server-Side Request Forgery",
                    evidence=f"Response time: {elapsed_time:.2f}s, Parameter: {injection_point['parameter']}",
                    impact="Application may be vulnerable to blind SSRF attacks.",
                    remediation="Implement timeout controls and URL validation."
                )
                findings.append(finding)
                
        except requests.exceptions.Timeout:
            # Timeout might indicate successful SSRF to internal service
            finding = Finding(
                title="Potential Blind SSRF (Timeout)",
                severity=Severity.MEDIUM,
                confidence=0.6,
                description=f"Request timeout may indicate blind SSRF",
                target=injection_point['url'],
                vulnerability_type="Server-Side Request Forgery",
                evidence=f"Request timeout with payload: {delay_payload}",
                impact="Application may be vulnerable to blind SSRF attacks.",
                remediation="Implement timeout controls and URL validation."
            )
            findings.append(finding)
        except Exception as e:
            logger.debug(f"Error testing blind SSRF: {str(e)}")
        
        return findings
    
    def _is_ssrf_successful(self, response: requests.Response, target: str) -> bool:
        """Check if SSRF was successful."""
        try:
            response_text = response.text.lower()
            
            # Check for success indicators
            for indicator in self.success_indicators:
                if indicator.lower() in response_text:
                    return True
            
            # Check for specific target indicators
            if 'localhost' in target or '127.0.0.1' in target:
                localhost_indicators = [
                    'connection refused',
                    'connection timeout',
                    'unable to connect',
                    'network unreachable'
                ]
                
                # Sometimes even error messages indicate successful SSRF
                if any(indicator in response_text for indicator in localhost_indicators):
                    return True
            
            # Check response status
            if response.status_code == 200 and len(response.text) > 100:
                return True
                
        except Exception as e:
            logger.debug(f"Error checking SSRF success: {str(e)}")
        
        return False
    
    def _contains_cloud_metadata(self, response: requests.Response) -> bool:
        """Check if response contains cloud metadata."""
        try:
            response_text = response.text.lower()
            
            cloud_indicators = [
                'ami-',  # AWS AMI ID
                'i-',    # AWS instance ID
                'vpc-',  # AWS VPC ID
                'sg-',   # AWS security group
                'arn:aws:',
                'amazon-web-services',
                'computemetadata',
                'metadata-flavor: google',
                'instance-identity',
                'security-credentials'
            ]
            
            return any(indicator in response_text for indicator in cloud_indicators)
            
        except Exception:
            return False
    
    def _is_protocol_smuggling_successful(self, response: requests.Response, payload: str) -> bool:
        """Check if protocol smuggling was successful."""
        try:
            response_text = response.text.lower()
            
            if payload.startswith('file://'):
                # Look for file system indicators
                file_indicators = ['root:x:', 'daemon:', '/bin/', '/usr/', '/etc/']
                return any(indicator in response_text for indicator in file_indicators)
                
            elif payload.startswith('ftp://'):
                # Look for FTP indicators
                ftp_indicators = ['220 ', 'ftp server', 'welcome', '230 ']
                return any(indicator in response_text for indicator in ftp_indicators)
                
            elif payload.startswith('dict://'):
                # Look for dict protocol indicators
                dict_indicators = ['stat', 'version', 'uptime']
                return any(indicator in response_text for indicator in dict_indicators)
                
            elif payload.startswith('gopher://'):
                # Look for gopher/redis indicators
                gopher_indicators = ['redis_version', 'info', 'server']
                return any(indicator in response_text for indicator in gopher_indicators)
                
        except Exception:
            pass
        
        return False
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load SSRF payloads."""
        return {
            'internal_hosts': self.ssrf_targets,
            'protocols': ['file://', 'ftp://', 'dict://', 'gopher://'],
            'cloud_metadata': [
                'http://169.254.169.254',
                'http://metadata.google.internal'
            ]
        }