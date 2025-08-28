import urllib.request
import time
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

class PerlCodeInjectionScanner:
    """
    Scans for Perl code injection vulnerabilities.
    """

    def __init__(self):
        self.name = "Perl code injection"
        self.severity = "High"
        self.id = 0x00100e00
        self.cwe = ["CWE-94", "CWE-95", "CWE-116"]

    def scan(self, target_url):
        """
        Scans the given target URL for Perl code injection vulnerabilities
        by injecting time-based payloads.

        Args:
            target_url (str): The target URL to scan, including query parameters.

        Returns:
            list: A list of vulnerabilities found.
        """
        vulnerabilities = []
        # Using a 10-second sleep payload
        payload = "sleep(10)"
        sleep_duration = 10

        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            return []

        for param in query_params:
            original_value = query_params[param][0]

            # Create a copy of the params to modify
            modified_params = query_params.copy()
            modified_params[param] = [payload]

            new_query_string = urlencode(modified_params, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=new_query_string))

            start_time = time.time()
            try:
                # Set a timeout greater than the sleep duration
                urllib.request.urlopen(new_url, timeout=sleep_duration + 5)
            except Exception:
                # Catch exceptions like timeouts, which are expected if the vulnerability exists
                pass
            end_time = time.time()

            # If the request took longer than our sleep duration, we found a vulnerability
            if (end_time - start_time) >= sleep_duration:
                vulnerabilities.append({
                    "url": new_url,
                    "param": param,
                    "payload": payload
                })

        return vulnerabilities
