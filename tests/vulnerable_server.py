import http.server
import socketserver
import os
from urllib.parse import urlparse, parse_qs

PORT = 8000

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        if 'cmd' in query_params:
            cmd = query_params['cmd'][0]
            # This is the vulnerable part!
            os.system(f"perl -e \"{cmd}\"")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Command executed.")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Hello, world!")

if __name__ == "__main__":
    # Ensure the server runs in the tests directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()
