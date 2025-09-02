#!/usr/bin/env python3
"""
Test cases for Client-side XPath Injection Scanner
"""

import sys
import re
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config.config_manager import ConfigManager
from scanners.client_xpath.client_xpath_injection_scanner import ClientSideXPathInjectionScanner
from core.reporting.report_generator import Finding, Severity

class TestClientSideXPathInjectionScanner(unittest.TestCase):
    """Test cases for ClientSideXPathInjectionScanner"""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.get_scanner_config.return_value = {}
        self.mock_config.get.return_value = {'timeout': 30}
        
        self.scanner = ClientSideXPathInjectionScanner(self.mock_config)

    def test_scanner_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertIsInstance(self.scanner, ClientSideXPathInjectionScanner)
        self.assertIsNotNone(self.scanner.dom_payloads)
        self.assertIsNotNone(self.scanner.xpath_js_patterns)

    @patch('requests.get')
    def test_dom_xpath_injection_detection(self, mock_get):
        """Test DOM-based XPath injection detection."""
        # Mock response with XPath usage
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <script>
            var query = document.location.hash.substring(1);
            var result = document.evaluate(query, document, null, XPathResult.ANY_TYPE, null);
            document.getElementById('result').innerHTML = result.stringValue;
        </script>
        """
        mock_get.return_value = mock_response

        findings = self.scanner._test_dom_xpath_injection("https://example.com")
        
        # Should detect XPath usage in JavaScript
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].vulnerability_type, "Client-side XPath Injection")

    @patch('requests.get')
    def test_reflected_dom_xpath_injection(self, mock_get):
        """Test reflected DOM-based XPath injection detection."""
        # Mock response with reflected payload and XPath usage
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <script>
            var userInput = "' or '1'='1";
            var xpath = "/users[name='" + userInput + "']";
            var result = document.evaluate(xpath, xmlDoc, null, XPathResult.ANY_TYPE, null);
        </script>
        """
        mock_get.return_value = mock_response

        findings = self.scanner._test_reflected_dom_xpath_injection("https://example.com")
        
        # Should detect reflected XPath injection
        self.assertGreater(len(findings), 0)

    @patch('requests.post')
    @patch('requests.get')
    def test_stored_dom_xpath_injection(self, mock_get, mock_post):
        """Test stored DOM-based XPath injection detection."""
        # Mock GET response with form
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.text = """
        <form method="post">
            <input name="search" type="text">
            <input type="submit">
        </form>
        """
        mock_get.return_value = mock_get_response

        # Mock POST response with XPath usage
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.text = """
        <script>
            var storedQuery = "' or '1'='1";
            var result = document.evaluate(storedQuery, document, null, XPathResult.ANY_TYPE, null);
        </script>
        """
        mock_post.return_value = mock_post_response

        findings = self.scanner._test_stored_dom_xpath_injection("https://example.com")
        
        # Should detect stored XPath injection
        self.assertGreater(len(findings), 0)

    def test_payload_in_js_context_detection(self):
        """Test detection of payload in JavaScript context."""
        content_with_payload = """
        <script>
            var data = "' or '1'='1";
            processXPath(data);
        </script>
        """
        
        payload = "' or '1'='1"
        result = self.scanner._is_payload_in_js_context(content_with_payload, payload)
        self.assertTrue(result)

    def test_xpath_patterns_detection(self):
        """Test XPath pattern detection in JavaScript."""
        content_with_xpath = """
        <script>
            var result = document.evaluate("/users/user[@id='1']", document, null, XPathResult.ANY_TYPE, null);
            var nodes = xmlDoc.selectNodes("//user");
        </script>
        """
        
        xpath_found = any(re.search(pattern, content_with_xpath, re.IGNORECASE) 
                         for pattern in self.scanner.xpath_js_patterns)
        self.assertTrue(xpath_found)

if __name__ == '__main__':
    unittest.main()
