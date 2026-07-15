"""
Minimal local HTTP server that logs every POST body it receives, used to
manually verify Splunk/Elastic adapter wiring against a real HTTP request
(not just mocked requests.post) without depending on a real Splunk/Elastic
instance. Prints one line per received request so a driving script can
grep the process output.
"""
import http.server
import json
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        print(f"RECEIVED PATH={self.path} AUTH={self.headers.get('Authorization')} BODY={body}",
             flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"errors": False, "text": "Success"}).encode())

    def log_message(self, format, *args):
        pass  # silence default request logging; we print our own line above


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    print(f"MOCK SINK LISTENING on {port}", flush=True)
    server.serve_forever()
