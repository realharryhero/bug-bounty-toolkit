#!/usr/bin/env python3
"""
Test cases for Client-side JSON Injection Scanner
"""

import sys
import re
import json
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config.config_manager import ConfigManager
from scanners.client_json.client_json_injection_scanner import ClientSideJSONInjectionScanner
from core.reporting.report_generator import Finding, Severity

class TestClientSideJSONInjectionScanner(unittest.TestCase):
    """Test cases for ClientSideJSONInjectionScanner"""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.get_scanner_config.return_value = {}
        self.mock_config.get.return_value = {'timeout': 30}
        
        self.scanner = ClientSideJSONInjectionScanner(self.mock_config)

    def test_scanner_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertIsInstance(self.scanner, ClientSideJSONInjectionScanner)
        self.assertIsNotNone(self.scanner.json_payloads)
        self.assertIsNotNone(self.scanner.json_js_patterns)

    @patch('requests.get')
    def test_dom_json_injection_detection(self, mock_get):
        """Test DOM-based JSON injection detection."""
        # Mock response with JSON usage
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <script>
            var data = location.hash.substring(1);
            var jsonData = JSON.parse(data);
            document.getElementById('result').innerHTML = jsonData.message;
        </script>
        """
        mock_get.return_value = mock_response

        findings = self.scanner._test_dom_json_injection("https://example.com")
        
        # Should detect JSON usage in JavaScript
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].vulnerability_type, "Client-side JSON Injection")

    @patch('requests.get')
    def test_reflected_dom_json_injection(self, mock_get):
        """Test reflected DOM-based JSON injection detection."""
        # Mock response with reflected payload and JSON usage
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <script>
            var userInput = "','test':'injected";
            var jsonStr = '{"data":"' + userInput + '"}';
            var parsed = JSON.parse(jsonStr);
        </script>
        """
        mock_get.return_value = mock_response

        findings = self.scanner._test_reflected_dom_json_injection("https://example.com")
        
        # Should detect reflected JSON injection
        self.assertGreater(len(findings), 0)

    @patch('requests.post')
    @patch('requests.get')
    def test_stored_dom_json_injection(self, mock_get, mock_post):
        """Test stored DOM-based JSON injection detection."""
        # Mock GET response with form
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.text = """
        <form method="post">
            <input name="data" type="text">
            <input type="submit">
        </form>
        """
        mock_get.return_value = mock_get_response

        # Mock POST response with JSON usage
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.text = """
        <script>
            var storedData = "','test':'injected";
            var config = JSON.parse('{"setting":"' + storedData + '"}');
        </script>
        """
        mock_post.return_value = mock_post_response

        findings = self.scanner._test_stored_dom_json_injection("https://example.com")
        
        # Should detect stored JSON injection
        self.assertGreater(len(findings), 0)

    @patch('requests.get')
    def test_jsonp_injection_detection(self, mock_get):
        """Test JSONP injection detection."""
        # Mock JSONP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'malicious_function({"data": "value"});'
        mock_get.return_value = mock_response

        findings = self.scanner._test_jsonp_injection("https://example.com")
        
        # Should detect JSONP injection
        self.assertGreater(len(findings), 0)

    def test_payload_in_js_context_detection(self):
        """Test detection of payload in JavaScript context."""
        content_with_payload = """
        <script>
            var data = "','test':'injected";
            var json = '{"data":"' + data + '"}';
        </script>
        """
        
        payload = "','test':'injected"
        result = self.scanner._is_payload_in_js_context(content_with_payload, payload)
        self.assertTrue(result)

    def test_json_structure_break_detection(self):
        """Test detection of JSON structure breaking."""
        content = '{"data":"value","test":"injected"}'
        payload = '","test":"injected'
        
        result = self.scanner._check_json_structure_break(content, payload)
        # This should return False since the JSON is still valid
        self.assertFalse(result)
        
        # Test with broken JSON
        broken_content = '{"data":"value","test":"injected"'
        result = self.scanner._check_json_structure_break(broken_content, payload)
        self.assertTrue(result)

    def test_jsonp_response_detection(self):
        """Test JSONP response detection."""
        jsonp_content = 'myCallback({"data": "value"});'
        callback = 'myCallback'
        
        result = self.scanner._is_jsonp_response(jsonp_content, callback)
        self.assertTrue(result)

    def test_json_patterns_detection(self):
        """Test JSON pattern detection in JavaScript."""
        content_with_json = """
        <script>
            var data = JSON.parse(userInput);
            var result = JSON.stringify(data);
            $.parseJSON(response);
        </script>
        """
        
        json_found = any(re.search(pattern, content_with_json, re.IGNORECASE) 
                        for pattern in self.scanner.json_js_patterns)
        self.assertTrue(json_found)

if __name__ == '__main__':
    unittest.main()
