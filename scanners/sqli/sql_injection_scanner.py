"""
SQL Injection Scanner - Detects SQL injection vulnerabilities
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

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class SQLInjectionScanner:
    """SQL Injection vulnerability scanner with multiple detection techniques."""
    
    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the SQL injection scanner.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('sqli')
        self.general_config = config_manager.get('general')
        
        # Load payloads
        self.payloads = self._load_payloads()
        
        # Error signatures for different databases
        self.error_signatures = {
            'mysql': [
                r"You have an error in your SQL syntax",
                r"mysql_fetch_array\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_num_rows\(\)",
                r"Duplicate entry '.*' for key",
            ],
            'postgresql': [
                r"PostgreSQL query failed",
                r"pg_query\(\)",
                r"pg_exec\(\)",
                r"ERROR: syntax error at or near",
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle JDBC",
                r"oracle.jdbc",
            ],
            'mssql': [
                r"Microsoft OLE DB Provider",
                r"Microsoft JET Database Engine",
                r"ODBC SQL Server Driver",
                r"Unclosed quotation mark",
            ],
            'sqlite': [
                r"SQLite error",
                r"sqlite3.OperationalError",
                r"near \".*\": syntax error",
            ]
        }
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads from file."""
        payload_file = self.config.get('payload_file', 'payloads/sqli_payloads.txt')
        payloads = []
        
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
            
            logger.info(f"Loaded {len(payloads)} SQL injection payloads")
            
        except FileNotFoundError:
            logger.warning(f"Payload file not found: {payload_file}")
            # Use built-in payloads as fallback
            payloads = [
                "' OR 1=1--",
                "\" OR 1=1--",
                "' UNION SELECT NULL--",
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--"
            ]
        
        return payloads
    
    def scan(self, target: str) -> List[Finding]:
        """
        Scan target for SQL injection vulnerabilities.
        
        Args:
            target: Target URL to scan
            
        Returns:
            List of findings
        """
        logger.info(f"Starting SQL injection scan on {target}")
        findings = []
        
        try:
            # Test different injection types
            test_types = self.config.get('test_types', ['error', 'blind', 'time', 'union'])
            
            if 'error' in test_types:
                findings.extend(self._test_error_based(target))
            
            if 'blind' in test_types:
                findings.extend(self._test_blind_injection(target))
            
            if 'time' in test_types:
                findings.extend(self._test_time_based(target))
            
            if 'union' in test_types:
                findings.extend(self._test_union_based(target))
            
            logger.info(f"SQL injection scan completed - {len(findings)} potential vulnerabilities found")
            
        except Exception as e:
            logger.error(f"SQL injection scan failed: {str(e)}")
            security_logger.log_error("SQLI_SCAN_ERROR", str(e), target)
        
        return findings
    
    def _test_error_based(self, target: str) -> List[Finding]:
        """Test for error-based SQL injection."""
        findings = []
        
        # Get baseline response
        try:
            baseline_response = requests.get(target, timeout=self.general_config.get('timeout', 30))
            baseline_content = baseline_response.text
        except Exception as e:
            logger.error(f"Failed to get baseline response: {str(e)}")
            return findings
        
        # Test error-inducing payloads
        error_payloads = [payload for payload in self.payloads if "'" in payload or '"' in payload]
        
        for payload in error_payloads[:10]:  # Limit to first 10 for performance
            test_url = f"{target}?id={payload}"
            
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                
                # Check for database error signatures
                for db_type, signatures in self.error_signatures.items():
                    for signature in signatures:
                        if re.search(signature, response.text, re.IGNORECASE):
                            confidence = 0.9  # High confidence for error-based
                            
                            finding = Finding(
                                title=f"SQL Injection Vulnerability ({db_type.upper()})",
                                severity=Severity.HIGH,
                                confidence=confidence,
                                description=f"Error-based SQL injection detected. The application returned database error messages when malicious SQL payloads were injected.",
                                target=test_url,
                                vulnerability_type="SQL Injection",
                                payload=payload,
                                evidence=f"Database error signature found: {signature}",
                                impact="An attacker could potentially extract sensitive data from the database, modify data, or gain unauthorized access.",
                                remediation="Use parameterized queries/prepared statements to prevent SQL injection. Validate and sanitize all user input."
                            )
                            
                            findings.append(finding)
                            security_logger.log_vulnerability_found("SQL_INJECTION", target, "HIGH", confidence)
                            logger.warning(f"Potential SQL injection found: {test_url}")
                            break
                    
                    if findings:  # Stop after first finding to avoid duplicates
                        break
                
                # Rate limiting
                time.sleep(self.general_config.get('delay', 1.0))
                
            except Exception as e:
                logger.debug(f"Request failed for payload {payload}: {str(e)}")
        
        return findings
    
    def _test_blind_injection(self, target: str) -> List[Finding]:
        """Test for blind SQL injection using boolean-based techniques."""
        findings = []
        
        # Boolean-based payloads
        true_payload = "1' OR '1'='1"
        false_payload = "1' OR '1'='2"
        
        try:
            # Test true condition
            true_url = f"{target}?id={true_payload}"
            true_response = requests.get(true_url, timeout=self.general_config.get('timeout', 30))
            
            time.sleep(self.general_config.get('delay', 1.0))
            
            # Test false condition
            false_url = f"{target}?id={false_payload}"
            false_response = requests.get(false_url, timeout=self.general_config.get('timeout', 30))
            
            # Compare responses
            if (true_response.status_code == 200 and false_response.status_code == 200 and
                len(true_response.text) != len(false_response.text)):
                
                confidence = 0.7  # Medium confidence for blind injection
                
                finding = Finding(
                    title="Blind SQL Injection Vulnerability",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    description="Blind SQL injection detected through boolean-based testing. The application responds differently to true and false SQL conditions.",
                    target=target,
                    vulnerability_type="SQL Injection",
                    payload=f"True: {true_payload}, False: {false_payload}",
                    evidence=f"Response length difference - True: {len(true_response.text)}, False: {len(false_response.text)}",
                    impact="An attacker could potentially extract sensitive data from the database through blind injection techniques.",
                    remediation="Use parameterized queries/prepared statements to prevent SQL injection. Validate and sanitize all user input."
                )
                
                findings.append(finding)
                security_logger.log_vulnerability_found("BLIND_SQL_INJECTION", target, "HIGH", confidence)
        
        except Exception as e:
            logger.debug(f"Blind injection test failed: {str(e)}")
        
        return findings
    
    def _test_time_based(self, target: str) -> List[Finding]:
        """Test for time-based blind SQL injection."""
        findings = []
        time_delay = self.config.get('time_delay', 5)
        
        # Time-based payloads
        time_payloads = [
            f"1' OR SLEEP({time_delay})--",
            f"1' OR pg_sleep({time_delay})--",
            f"1'; WAITFOR DELAY '0:0:{time_delay}'--"
        ]
        
        for payload in time_payloads:
            test_url = f"{target}?id={payload}"
            
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Check if response took significantly longer
                if response_time >= time_delay:
                    confidence = 0.8  # High confidence for time-based
                    
                    finding = Finding(
                        title="Time-based SQL Injection Vulnerability",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        description=f"Time-based SQL injection detected. The application delayed response by {response_time:.2f} seconds when a time-based payload was injected.",
                        target=test_url,
                        vulnerability_type="SQL Injection",
                        payload=payload,
                        evidence=f"Response delay: {response_time:.2f} seconds (expected: {time_delay}s)",
                        impact="An attacker could potentially extract sensitive data from the database through time-based blind injection techniques.",
                        remediation="Use parameterized queries/prepared statements to prevent SQL injection. Validate and sanitize all user input."
                    )
                    
                    findings.append(finding)
                    security_logger.log_vulnerability_found("TIME_BASED_SQL_INJECTION", target, "HIGH", confidence)
                    break  # Stop after first successful time-based detection
                
                time.sleep(self.general_config.get('delay', 1.0))
                
            except Exception as e:
                logger.debug(f"Time-based test failed for payload {payload}: {str(e)}")
        
        return findings
    
    def _test_union_based(self, target: str) -> List[Finding]:
        """Test for UNION-based SQL injection."""
        findings = []
        
        # UNION payloads with different column counts
        union_payloads = [
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--", 
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--"
        ]
        
        for payload in union_payloads:
            test_url = f"{target}?id={payload}"
            
            try:
                response = requests.get(test_url, timeout=self.general_config.get('timeout', 30))
                
                # Look for UNION success indicators
                if response.status_code == 200 and ('NULL' in response.text or 
                                                   any(str(i) in response.text for i in range(1, 10))):
                    
                    confidence = 0.6  # Medium confidence for UNION-based
                    
                    finding = Finding(
                        title="UNION-based SQL Injection Vulnerability",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        description="UNION-based SQL injection detected. The application appears to execute injected UNION queries.",
                        target=test_url,
                        vulnerability_type="SQL Injection",
                        payload=payload,
                        evidence="UNION query appears to be executed successfully",
                        impact="An attacker could potentially extract sensitive data from the database using UNION-based techniques.",
                        remediation="Use parameterized queries/prepared statements to prevent SQL injection. Validate and sanitize all user input."
                    )
                    
                    findings.append(finding)
                    security_logger.log_vulnerability_found("UNION_SQL_INJECTION", target, "HIGH", confidence)
                    break  # Stop after first successful UNION detection
                
                time.sleep(self.general_config.get('delay', 1.0))
                
            except Exception as e:
                logger.debug(f"UNION test failed for payload {payload}: {str(e)}")
        
        return findings