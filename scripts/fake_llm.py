"""Fake LLM for testing the network sensor: an HTTPS server that answers every
POST by streaming small SSE "tokens" every 40 ms, the way chat UIs do.

  python3 scripts/fake_llm.py            # listens on port 8443
  # send a "prompt" through the Lantern proxy, the way an employee's browser would:
  curl -sk -x http://localhost:3128 https://host.docker.internal:8443 -d "$(printf 'prompt %.0s' {1..40})"
"""
import os, ssl, subprocess, tempfile, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        for i in range(80):                       # 80 tokens x 40 ms = 3.2 s reply
            self.wfile.write(f'data: {{"token": "word{i} "}}\n\n'.encode())
            self.wfile.flush()
            time.sleep(0.04)

d = tempfile.mkdtemp()
cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fake-llm",
                "-keyout", key, "-out", cert], check=True, capture_output=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv = ThreadingHTTPServer(("0.0.0.0", 8443), H)     # all interfaces, so the proxy container can reach it
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("fake LLM on port 8443")
srv.serve_forever()
