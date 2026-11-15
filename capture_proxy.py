from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json

OLLAMA = "http://localhost:11434"

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))

        print("\n========== EXACT REQUEST TO OLLAMA ==========")
        try:
            print(json.dumps(json.loads(body), indent=2))
        except Exception:
            print(body.decode(errors="replace"))
        print("=============================================\n")

        req = Request(
            OLLAMA + self.path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urlopen(req, timeout=120) as response:
                result = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.end_headers()
                self.wfile.write(result)
        except HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_error(502, str(e))

    def log_message(self, *args):
        pass

HTTPServer(("localhost", 11435), Handler).serve_forever()
