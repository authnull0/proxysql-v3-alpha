# Stub of authn-service's do-authenticationV4: holds stall_slow for HOLD seconds (a push nobody has
# answered yet), approves everyone else at once.
import json, os, sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
HOLD = float(os.environ.get("HOLD", "20"))
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        user = body.get("dbUser", "")
        sys.stderr.write("stub: login %s proxySessionId=%s\n" % (user, body.get("proxySessionId")))
        if user.startswith("stall_slow"):
            time.sleep(HOLD)
        if user.startswith("stall_deny"):
            time.sleep(1)
            out = json.dumps({"isValid": False, "message": "denied by the stub"}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
            return
        out = json.dumps({"isValid": True, "requestId": "stub-" + user, "credentialSubject": {
            "databaseName": body.get("databaseName", "postgres"),
            "privilege": [p.strip() for p in os.environ.get("PRIVS", "READ").split(",")], "tables": ["t"], "fieldMasking": {"t": []}, **({"session": {**({"endsAt": int(time.time()) + int(os.environ["ENDS_IN"])} if os.environ.get("ENDS_IN") else {}), **({"record": True} if os.environ.get("RECORD") else {})}} if (os.environ.get("ENDS_IN") or os.environ.get("RECORD")) else {})}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", 18099), H).serve_forever()
