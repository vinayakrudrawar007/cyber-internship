
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as up

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = up.urlparse(self.path).query
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(b"<html><body>Path: " + self.path.encode() + b"<br/>Form page</body></html>")

HTTPServer(('localhost',5000),H).serve_forever()
