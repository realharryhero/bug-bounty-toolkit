import unittest
import subprocess
import time
import os
import sys
from unittest.mock import Mock, patch
import urllib.request

# Add the root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanners.code_injection.perl_injection import PerlInjectionScanner

class TestPerlInjectionScanner(unittest.TestCase):

    def setUp(self):
        self.mock_config = Mock()
        self.mock_config.get.return_value = {'timeout': 30}

    @patch('urllib.request.urlopen')
    @patch.object(PerlInjectionScanner, 'filter_false_positives')
    def test_scan_vulnerable_url(self, mock_filter, mock_urlopen):
        """Tests the scanner against a vulnerable URL."""
        # Mock the urlopen to raise timeout after delay
        import urllib.error
        def side_effect(*args, **kwargs):
            time.sleep(11)  # Sleep longer than the 10 second threshold
            raise urllib.error.URLError("Timeout")
        mock_urlopen.side_effect = side_effect
        
        # Mock filter_false_positives to return the findings as is
        mock_filter.side_effect = lambda findings, target: findings
        
        scanner = PerlInjectionScanner(self.mock_config)
        target_url = "http://localhost:8000/?cmd=print('hello')"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 1, "Should find one vulnerability")
        self.assertEqual(vulnerabilities[0].payload, 'sleep(10)')

    def test_scan_non_vulnerable_url(self):
        """Tests the scanner against a non-vulnerable URL."""
        scanner = PerlInjectionScanner(self.mock_config)
        # A URL with a different parameter that is not used by the server
        target_url = "http://localhost:8000/?p=1"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 0, "Should not find any vulnerabilities")

    def test_scan_url_without_params(self):
        """Tests the scanner against a URL with no parameters."""
        scanner = PerlInjectionScanner(self.mock_config)
        target_url = "http://localhost:8000/"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 0, "Should not find any vulnerabilities")

if __name__ == '__main__':
    unittest.main()
