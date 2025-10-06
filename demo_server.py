from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import os

TEMPLATE = open("demo_vuln_template.html","r",encoding="utf-8").read()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]
        content = TEMPLATE.replace("{q}", q)
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))
    def do_POST(self):
        length = int(self.headers.get("Content-Length",0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        name = params.get("name",[""])[0]
        s = TEMPLATE.replace("{q}", name)
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(s.encode("utf-8"))

if __name__ == "__main__":
    port = 8000
    print("Starting demo server on http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1",port), Handler).serve_forever()
