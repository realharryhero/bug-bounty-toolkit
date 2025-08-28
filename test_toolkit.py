#!/usr/bin/env python3
"""
Simple test script to verify the bug bounty toolkit functionality
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.authorization.auth_manager import AuthorizationManager
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import ReportGenerator, Finding, Severity
from core.utils.logger import setup_logging
from scanners.sqli.sql_injection_scanner import SQLInjectionScanner
from scanners.xss.xss_scanner import XSSScanner
from scanners.csrf.csrf_scanner import CSRFScanner
from scanners.traversal.directory_traversal_scanner import DirectoryTraversalScanner
from scanners.xpath.xpath_injection_scanner import XPathInjectionScanner
from scanners.cmdi.command_injection_scanner import CommandInjectionScanner
from scanners.put.put_scanner import PutScanner

def test_imports():
    """Test that all core modules can be imported."""
    print("Testing imports...")
    
    try:
        from core.authorization.auth_manager import AuthorizationManager
        from core.config.config_manager import ConfigManager
        from core.reporting.report_generator import ReportGenerator, Finding, Severity
        from core.utils.logger import setup_logging
        from scanners.sqli.sql_injection_scanner import SQLInjectionScanner
        from scanners.xss.xss_scanner import XSSScanner
        from scanners.csrf.csrf_scanner import CSRFScanner
        from scanners.traversal.directory_traversal_scanner import DirectoryTraversalScanner
        from scanners.ssji.ssji_scanner import SSJIScanner
        from scanners.put.put_scanner import PutScanner
        assert 'AuthorizationManager' in globals()
        assert 'ConfigManager' in globals()
        assert 'ReportGenerator' in globals()
        assert 'SQLInjectionScanner' in globals()
        assert 'XSSScanner' in globals()
        assert 'CSRFScanner' in globals()
        assert 'DirectoryTraversalScanner' in globals()
        assert 'XPathInjectionScanner' in globals()
        assert 'CommandInjectionScanner' in globals()
        assert 'PutScanner' in globals()
        assert 'SSJIScanner' in globals()
        print("✅ All imports successful")
        return True
    except (ImportError, AssertionError) as e:
        print(f"❌ Import error: {e}")
        return False

def test_configuration():
    """Test configuration loading."""
    print("Testing configuration...")
    
    try:
        config_manager = ConfigManager("config/default.yml")
        
        # Test basic config access
        threads = config_manager.get('general.threads')
        timeout = config_manager.get('general.timeout')
        
        if threads and timeout:
            print(f"✅ Configuration loaded - Threads: {threads}, Timeout: {timeout}")
            return True
        else:
            print("❌ Configuration values not found")
            return False
            
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def test_authorization():
    """Test authorization framework."""
    print("Testing authorization...")
    
    try:
        auth_manager = AuthorizationManager()
        
        # Test blacklist functionality
        if auth_manager._is_blacklisted("localhost"):
            print("✅ Authorization blacklist working")
            return True
        else:
            print("❌ Authorization blacklist not working")
            return False
            
    except Exception as e:
        print(f"❌ Authorization error: {e}")
        return False

def test_reporting():
    """Test report generation."""
    print("Testing reporting...")
    
    try:
        from datetime import datetime
        
        # Create temporary directory for test
        with tempfile.TemporaryDirectory() as temp_dir:
            report_gen = ReportGenerator(temp_dir)
            
            # Create a test finding
            finding = report_gen.create_finding(
                title="Test Finding",
                severity=Severity.MEDIUM,
                confidence=0.8,
                description="This is a test finding",
                target="https://example.com",
                vulnerability_type="Test"
            )
            
            # Create scan results
            start_time = datetime.now()
            end_time = datetime.now()
            
            scan_results = report_gen.create_scan_results(
                scan_type="test",
                target="https://example.com",
                start_time=start_time,
                end_time=end_time,
                findings=[finding]
            )
            
            # Generate report
            report_path = report_gen.generate_report(scan_results, "json")
            
            if os.path.exists(report_path):
                print("✅ Report generation working")
                return True
            else:
                print("❌ Report not generated")
                return False
                
    except Exception as e:
        print(f"❌ Reporting error: {e}")
        return False

def test_scanners():
    """Test scanner initialization."""
    print("Testing scanners...")
    
    try:
        from core.config.config_manager import ConfigManager
        from scanners.sqli.sql_injection_scanner import SQLInjectionScanner
        from scanners.xss.xss_scanner import XSSScanner
        from scanners.csrf.csrf_scanner import CSRFScanner
        from scanners.traversal.directory_traversal_scanner import DirectoryTraversalScanner
        from scanners.ssji.ssji_scanner import SSJIScanner    
        from scanners.put.put_scanner import PutScanner
        config_manager = ConfigManager("config/default.yml")
        
        # Initialize scanners
        sqli_scanner = SQLInjectionScanner(config_manager)
        xss_scanner = XSSScanner(config_manager)
        csrf_scanner = CSRFScanner(config_manager)
        traversal_scanner = DirectoryTraversalScanner(config_manager)
        ssji_scanner = SSJIScanner(config_manager)
        put_scanner = PutScanner(config_manager)
        cmdi_scanner = CommandInjectionScanner(config_manager)
        
        # Check if payloads are loaded
        if (hasattr(sqli_scanner, 'payloads') and len(sqli_scanner.payloads) > 0 and
            hasattr(xss_scanner, 'payloads') and len(xss_scanner.payloads) > 0 and
            hasattr(ssji_scanner, 'ssji_payloads') and len(ssji_scanner.ssji_payloads) > 0) and
            hasattr(cmdi_scanner, 'payloads') and len(cmdi_scanner.payloads) > 0):
            print("✅ Scanners initialized with payloads")
            return True
        else:
            print("❌ Scanners not properly initialized")
            return False
            
    except Exception as e:
        print(f"❌ Scanner error: {e}")
        return False

def test_ldap_scanner():
    """Test the LDAP injection scanner."""
    print("Testing LDAP Injection Scanner...")
    try:
        from core.config.config_manager import ConfigManager
        from scanners.ldap.ldap_injection_scanner import LDAPInjectionScanner

        config_manager = ConfigManager("config/default.yml")
        ldap_scanner = LDAPInjectionScanner(config_manager)

        test_url = "http://test.com/login?id=123&user=test"

        with patch('requests.get') as mock_get:
            # --- Test Error-Based LDAPi ---
            mock_response_error = Mock()
            mock_response_error.status_code = 200
            mock_response_error.text = "An LDAPException occurred"

            mock_response_normal = Mock()
            mock_response_normal.status_code = 200
            mock_response_normal.text = "Normal response"

            num_payloads = len(ldap_scanner.payloads)
            side_effects = [mock_response_normal] * num_payloads + [mock_response_error]
            mock_get.side_effect = side_effects

            # Temporarily disable blind scan to isolate error-based test
            ldap_scanner.config['test_types'] = ['error']
            findings = ldap_scanner.scan(test_url)

            assert len(findings) == 1
            assert "in parameter 'user'" in findings[0].title
            print("✅ LDAP error-based scan successful")

            # --- Test Blind LDAPi ---
            mock_get.reset_mock()

            mock_response_true = Mock()
            mock_response_true.status_code = 200
            mock_response_true.text = "Welcome admin"

            mock_response_false = Mock()
            mock_response_false.status_code = 200
            mock_response_false.text = "Invalid credentials"

            # For the 'id' param, both true and false payloads should result in the same "normal" response
            # For the 'user' param, true payload gets "Welcome", false gets "Invalid"
            side_effects = [mock_response_normal, mock_response_normal] + [mock_response_true, mock_response_false]
            mock_get.side_effect = side_effects

            # Temporarily disable error-based scan to isolate blind test
            ldap_scanner.config['test_types'] = ['blind']
            findings = ldap_scanner.scan(test_url)

            assert len(findings) == 1
            assert "in parameter 'user'" in findings[0].title
            print("✅ LDAP blind injection scan successful")

        return True
    except Exception as e:
        print(f"❌ LDAP Scanner test error: {e}")
        import traceback
        traceback.print_exc()

def test_xpath_scanner():
    """Test the XPath injection scanner."""
    print("Testing XPath Injection Scanner...")

    config_manager = ConfigManager("config/default.yml")
    scanner = XPathInjectionScanner(config_manager)

    # Mock responses
    def mock_requests_get(url, timeout):
        response = Mock()
        response.status_code = 200
        if "query=' or '1'='1" in url:
            response.text = "<html><body>Found</body></html>"
        elif "query=' or '1'='2" in url:
            response.text = "<html><body></body></html>"
        elif "query='" in url:
            response.text = "Invalid XPath expression"
        else:
            response.text = "<html><body>Hello</body></html>"
        return response

    with patch('requests.get', side_effect=mock_requests_get):
        findings = scanner.scan("http://test.com/search")

    error_based_found = any("Error-based XPath injection detected" in f.description for f in findings)
    blind_based_found = any("Blind XPath injection detected" in f.description for f in findings)

    if error_based_found and blind_based_found:
        print("✅ XPath Injection Scanner working")
        return True
    else:
        print("❌ XPath Injection Scanner not working")

def test_cmdi_scanner():
    """Test CMDi scanner initialization."""
    print("Testing CMDi Scanner...")

    try:
        from core.config.config_manager import ConfigManager
        from scanners.cmdi.command_injection_scanner import CommandInjectionScanner

        config_manager = ConfigManager("config/default.yml")
        cmdi_scanner = CommandInjectionScanner(config_manager)

        if hasattr(cmdi_scanner, 'payloads') and len(cmdi_scanner.payloads) > 0:
            print("✅ CMDi scanner initialized with payloads")
            return True
        else:
            print("❌ CMDi scanner not properly initialized")
            return False

    except Exception as e:
        print(f"❌ CMDi scanner error: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 50)
    print("Bug Bounty Toolkit - Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_configuration,
        test_authorization,
        test_reporting,
        test_scanners,
        test_ldap_scanner
        test_xpath_scanner
        test_cmdi_scanner
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 50)
    
    if failed == 0:
        print("🎉 All tests passed! Toolkit is ready to use.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())