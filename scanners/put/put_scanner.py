import logging
import requests
import random
import string
from urllib.parse import urlparse, urljoin
from typing import List

from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class PutScanner:
    """
    Scanner to detect if HTTP PUT method is enabled on the web server.
    This corresponds to CWE-650.
    """

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the PutScanner.

        Args:
            config_manager: The configuration manager instance.
        """
        self.config = config_manager.get_scanner_config('put')
        self.general_config = config_manager.get('general')
        self.timeout = self.general_config.get('timeout', 30)

    def scan(self, target: str) -> List[Finding]:
        """
        Scans the given target to check if HTTP PUT is enabled.

        Args:
            target: The target URL to scan.

        Returns:
            A list of findings. An empty list if no vulnerability is found.
        """
        logger.info(f"Starting PUT scan on {target}")
        findings = []

        # Generate a random filename and content
        random_filename = f"test_put_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}.txt"
        test_content = f"This is a test file for PUT vulnerability detection. Random ID: {''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}"

        # We should try to put the file in the root directory of the web server, and the current path
        parsed_target = urlparse(target)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}/"

        test_urls = [urljoin(base_url, random_filename)]
        if parsed_target.path and parsed_target.path != '/':
            test_urls.append(urljoin(target, random_filename))

        for test_url in set(test_urls):
            try:
                finding = self._test_put_at_url(test_url, test_content)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Error while scanning {test_url} for PUT vulnerability: {e}")

        logger.info(f"PUT scan completed for {target}. Found {len(findings)} vulnerabilities.")
        return findings

    def _test_put_at_url(self, test_url: str, test_content: str) -> Finding | None:
        """
        Tests for PUT vulnerability at a specific URL.

        Args:
            test_url: The URL to test.
            test_content: The content to upload.

        Returns:
            A Finding object if vulnerable, otherwise None.
        """
        try:
            # 1. Send the PUT request to upload the file
            logger.info(f"Attempting to PUT a file to {test_url}")
            put_response = requests.put(test_url, data=test_content, timeout=self.timeout, verify=False)

            # 2. Check if the PUT request was successful
            if put_response.status_code in [200, 201, 204]:
                logger.warning(f"PUT request to {test_url} returned status {put_response.status_code}. This is a strong indicator.")

                # 3. Verify by sending a GET request to retrieve the file
                logger.info(f"Verifying upload by sending GET to {test_url}")
                get_response = requests.get(test_url, timeout=self.timeout, verify=False)

                if get_response.status_code == 200 and get_response.text == test_content:
                    logger.error(f"VULNERABILITY CONFIRMED: File successfully uploaded and retrieved from {test_url}")

                    # 4. Try to clean up by deleting the file
                    self._cleanup_file(test_url)

                    # Create a finding
                    finding = Finding(
                        title="HTTP PUT Method Enabled",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        description=(
                            "The HTTP PUT method is enabled on the web server. This allows an attacker to upload arbitrary files "
                            "to the server, potentially leading to remote code execution or website defacement."
                        ),
                        target=test_url,
                        vulnerability_type="CWE-650: Trusting HTTP Permission Methods on the Server Side",
                        payload=test_content,
                        evidence=f"A file was successfully uploaded to {test_url} via PUT (status: {put_response.status_code}) and retrieved via GET.",
                        remediation=(
                            "Disable the HTTP PUT method on the web server unless it is explicitly required. If required, ensure "
                            "proper authentication and authorization controls are in place."
                        )
                    )
                    security_logger.log_vulnerability_found("HTTP_PUT_ENABLED", test_url, "HIGH", 1.0)
                    return finding
                else:
                    logger.info(f"Verification failed for {test_url}. GET status: {get_response.status_code}, content match: {get_response.text == test_content}")

            else:
                logger.info(f"PUT request to {test_url} returned status {put_response.status_code}. Likely not vulnerable here.")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Request to {test_url} failed: {e}")

        return None

    def _cleanup_file(self, url: str):
        """
        Tries to delete the uploaded file using the DELETE method.
        """
        try:
            logger.info(f"Attempting to clean up by sending DELETE to {url}")
            delete_response = requests.delete(url, timeout=self.timeout, verify=False)
            if delete_response.status_code in [200, 202, 204]:
                logger.info(f"Successfully cleaned up file at {url}")
            else:
                logger.warning(f"Failed to clean up file at {url}. Status code: {delete_response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Cleanup request for {url} failed: {e}")
