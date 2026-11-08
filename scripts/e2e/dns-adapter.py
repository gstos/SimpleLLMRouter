#!/usr/bin/env python3
"""Test-only adapter: lego's httpreq DNS provider -> pebble-challtestsrv.

lego POSTs {"fqdn", "value"} to /present and /cleanup (with basic auth);
challtestsrv expects {"host", "value"} on /set-txt and /clear-txt.
Usage: dns-adapter.py <listen-port> <challtestsrv-management-url> <user> <password>
"""
import base64, json, sys, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

port, mgmt, user, password = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != expected:
            self.send_response(401); self.end_headers(); return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        path = {"/present": "/set-txt", "/cleanup": "/clear-txt"}.get(self.path)
        if not path:
            self.send_response(404); self.end_headers(); return
        payload = {"host": body["fqdn"]}
        if path == "/set-txt":
            payload["value"] = body["value"]
        req = urllib.request.Request(mgmt + path, data=json.dumps(payload).encode(), method="POST")
        urllib.request.urlopen(req).read()
        self.send_response(200); self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
