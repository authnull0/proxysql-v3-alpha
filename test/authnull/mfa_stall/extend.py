# An extended grant (authnull_session_ends.h): the stub says the grant ends ENDS_IN (15) s after login.
# At 5 s the admin moves this session's end to 35 s after login, as the database agent does when the
# grant is extended. The session must go on past 15 s and end at about 35 s.
import os, subprocess, sys, time
env = dict(os.environ, PGPASSWORD=os.environ["STALL_PW"], PGSSLMODE="disable")
admin = dict(os.environ, PGPASSWORD=os.environ["ADMIN_PW"], PGSSLMODE="disable")
def adm(q):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", "16132", "-U", "admin,agent", "-d", "admin", "-Atc", q],
        capture_output=True, text=True, env=admin)
p = subprocess.Popen(["psql", "-h", "127.0.0.1", "-p", "16133", "-U", "stall_fast,tok", "-d", "stalldb", "-Atq"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
t0 = time.time()
p.stdin.write("select x from t;\n"); p.stdin.flush(); print("login:", p.stdout.readline().strip())
sid = adm("SELECT SessionID FROM stats_pgsql_processlist").stdout.strip().split("\n")[0]
print("bad command:", adm("PGSQL SET SESSION ENDS x 1").stdout.strip())
print("unknown session:", adm("PGSQL SET SESSION ENDS 99999 %d" % int(t0 + 35)).stdout.strip())
extended = False
last_ok = 0.0
while time.time() - t0 < 50:
    if not extended and time.time() - t0 >= 5:
        print("extend", sid, "->", adm("PGSQL SET SESSION ENDS %s %d" % (sid, int(t0 + 35))).stdout.strip(), flush=True)
        extended = True
    try:
        p.stdin.write("select x from t;\n"); p.stdin.flush()
        line = p.stdout.readline().strip()
    except BrokenPipeError:
        line = "(connection gone)"
    el = time.time() - t0
    print(f"{el:5.1f}s {line[:90]}", flush=True)
    if line == "1":
        last_ok = el
    else:
        break
    time.sleep(3)
ended = time.time() - t0
ok = last_ok > 20 and 30 <= ended <= 42
print(("PASS" if ok else "FAIL") + f" session answered until {last_ok:.1f}s and ended at {ended:.1f}s (grant end moved from 15 s to 35 s)")
sys.exit(0 if ok else 1)
