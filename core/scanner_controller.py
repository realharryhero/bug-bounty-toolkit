"""
Scanner Controller - Manages and coordinates vulnerability scanners
"""

import logging
import asyncio
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import ScanResults, Finding, Severity, ReportGenerator
from core.utils.logger import get_security_logger

# Import scanner modules
from scanners.sqli.sql_injection_scanner import SQLInjectionScanner
from scanners.xss.xss_scanner import XSSScanner
from scanners.csrf.csrf_scanner import CSRFScanner
from scanners.traversal.directory_traversal_scanner import DirectoryTraversalScanner
from scanners.auth.auth_bypass_scanner import AuthBypassScanner
from scanners.ssrf.ssrf_scanner import SSRFScanner
from scanners.xxe.xxe_scanner import XXEScanner
from scanners.cmdi.command_injection_scanner import CommandInjectionScanner
from scanners.idor.idor_scanner import IDORScanner
from scanners.rci.ruby_code_injection_scanner import RubyCodeInjectionScanner
from scanners.php_code_injection.php_code_injection_scanner import PHPCodeInjectionScanner
from scanners.bac.bac_scanner import BrokenAccessControlScanner
from scanners.ldap.ldap_injection_scanner import LDAPInjectionScanner
from scanners.xpath.xpath_injection_scanner import XPathInjectionScanner
from scanners.trace.trace_scanner import TraceScanner
from scanners.ssji.ssji_scanner import SSJIScanner

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class ScannerController:
    """Controls and coordinates vulnerability scanning operations."""
    
    def __init__(self, config_manager: ConfigManager, args):
        """
        Initialize the scanner controller.
        
        Args:
            config_manager: Configuration manager instance
            args: Command line arguments
        """
        self.config = config_manager
        self.args = args
        self.report_generator = ReportGenerator()
        
        # Initialize scanners
        self.scanners = {
            'sqli': SQLInjectionScanner(config_manager),
            'xss': XSSScanner(config_manager),
            'csrf': CSRFScanner(config_manager),
            'traversal': DirectoryTraversalScanner(config_manager),
            'auth': AuthBypassScanner(config_manager),
            'ssrf': SSRFScanner(config_manager),
            'xxe': XXEScanner(config_manager),
            'cmdi': CommandInjectionScanner(config_manager),
            'idor': IDORScanner(config_manager),
            'rci': RubyCodeInjectionScanner(config_manager),
            'php_code_injection': PHPCodeInjectionScanner(config_manager),
            'bac': BrokenAccessControlScanner(config_manager),
            'ldap': LDAPInjectionScanner(config_manager),
            'ssji': SSJIScanner(config_manager),
            'xpath': XPathInjectionScanner(config_manager),
            'trace': TraceScanner(config_manager),
        }
    
    def run_scan(self, scan_type: str) -> ScanResults:
        """
        Run the specified vulnerability scan.
        
        Args:
            scan_type: Type of scan to run ('sqli', 'xss', 'all', etc.)
            
        Returns:
            ScanResults containing findings and metadata
        """
        start_time = datetime.now()
        target = self.args.target
        
        logger.info(f"Starting {scan_type} scan on {target}")
        security_logger.log_scan_start(scan_type, target)
        
        try:
            if scan_type == "all":
                findings = self._run_all_scanners()
            elif scan_type in self.scanners:
                if self.config.is_scanner_enabled(scan_type):
                    scanner = self.scanners[scan_type]
                    findings = scanner.scan(target)
                else:
                    logger.warning(f"Scanner {scan_type} is disabled in configuration")
                    findings = []
            else:
                logger.error(f"Unknown scan type: {scan_type}")
                findings = []
            
            end_time = datetime.now()
            
            # Log scan completion
            security_logger.log_scan_complete(scan_type, target, len(findings))
            
            # Create scan results
            results = self.report_generator.create_scan_results(
                scan_type=scan_type,
                target=target,
                start_time=start_time,
                end_time=end_time,
                findings=findings,
                scanner_config=self.config.get('scanners'),
                command_line_args=vars(self.args)
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            security_logger.log_error("SCAN_FAILED", str(e), target)
            raise
    
    def _run_all_scanners(self) -> List[Finding]:
        """Run all enabled scanners."""
        all_findings = []
        
        # Run enabled scanners
        enabled_scanners = [name for name in self.scanners.keys() 
                          if self.config.is_scanner_enabled(name)]
        
        if self.args.threads > 1:
            # Run scanners in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                future_to_scanner = {}
                
                for scanner_name in enabled_scanners:
                    scanner = self.scanners[scanner_name]
                    future = executor.submit(scanner.scan, self.args.target)
                    future_to_scanner[future] = scanner_name
                
                for future in concurrent.futures.as_completed(future_to_scanner):
                    scanner_name = future_to_scanner[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        logger.info(f"Completed {scanner_name} scan - {len(findings)} findings")
                    except Exception as e:
                        logger.error(f"Scanner {scanner_name} failed: {str(e)}")
        else:
            # Run scanners sequentially
            for scanner_name in enabled_scanners:
                try:
                    scanner = self.scanners[scanner_name]
                    findings = scanner.scan(self.args.target)
                    all_findings.extend(findings)
                    logger.info(f"Completed {scanner_name} scan - {len(findings)} findings")
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {str(e)}")
        
        return all_findings