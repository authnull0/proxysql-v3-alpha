# A MySQL login as the console's connection string makes it: "-u<user>,<token> -p<token>" -- the
# token, not the account's password. The stub approves stall_fast and refuses stall_deny; a user
# ProxySQL has no account for is refused before any MFA call.
import os, subprocess
def login(user, password):
    r = subprocess.run(["mysql", "-h127.0.0.1", "-P16033", "-u" + user, "-Dstalldb", "-N", "-B", "-e", "select x from t limit 1"],
        capture_output=True, text=True, env=dict(os.environ, MYSQL_PWD=password))
    return r.returncode, (r.stdout.strip() or r.stderr.strip())[:150]
tok = "0d1e2f3a-4b5c-6d7e-8f90-a1b2c3d4e5f6"
print("token login, approved:      rc=%d %s" % login("stall_fast," + tok, tok))
print("token login, refused:       rc=%d %s" % login("stall_deny," + tok, tok))
print("unknown user with token:    rc=%d %s" % login("nobody," + tok, tok))
print("no token, wrong password:   rc=%d %s" % login("stall_fast", "wrong"))
