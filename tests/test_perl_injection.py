import unittest
import subprocess
import time
import os
import sys

# Add the root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanners.code_injection.perl_injection import PerlCodeInjectionScanner

class TestPerlCodeInjectionScanner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the vulnerable server in a separate process
        cls.server_process = subprocess.Popen(
            [sys.executable, 'tests/vulnerable_server.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give the server a moment to start up
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        # Terminate the server process
        cls.server_process.terminate()
        cls.server_process.wait()

    def test_scan_vulnerable_url(self):
        """Tests the scanner against a vulnerable URL."""
        scanner = PerlCodeInjectionScanner()
        target_url = "http://localhost:8000/?cmd=print('hello')"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 1, "Should find one vulnerability")
        self.assertEqual(vulnerabilities[0]['param'], 'cmd')
        self.assertEqual(vulnerabilities[0]['payload'], 'sleep(10)')

    def test_scan_non_vulnerable_url(self):
        """Tests the scanner against a non-vulnerable URL."""
        scanner = PerlCodeInjectionScanner()
        # A URL with a different parameter that is not used by the server
        target_url = "http://localhost:8000/?p=1"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 0, "Should not find any vulnerabilities")

    def test_scan_url_without_params(self):
        """Tests the scanner against a URL with no parameters."""
        scanner = PerlCodeInjectionScanner()
        target_url = "http://localhost:8000/"
        vulnerabilities = scanner.scan(target_url)
        self.assertEqual(len(vulnerabilities), 0, "Should not find any vulnerabilities")

if __name__ == '__main__':
    unittest.main()
