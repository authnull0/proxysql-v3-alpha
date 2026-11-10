# One session; find it in the process list; kill it through the admin interface; its next query fails.
import os, subprocess, time
env = dict(os.environ, PGPASSWORD=os.environ["STALL_PW"], PGSSLMODE="disable")
admin = dict(os.environ, PGPASSWORD=os.environ["ADMIN_PW"], PGSSLMODE="disable")
def adm(q):
    return subprocess.run(["psql", "-h", "127.0.0.1", "-p", "16132", "-U", "admin,agent", "-d", "admin", "-Atc", q],
        capture_output=True, text=True, env=admin)
p = subprocess.Popen(["psql", "-h", "127.0.0.1", "-p", "16133", "-U", "stall_fast,tok", "-d", "stalldb", "-Atq"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
p.stdin.write("select x from t;\n"); p.stdin.flush(); print("before:", p.stdout.readline().strip())
rows = adm("SELECT SessionID, user, database, cli_host, command, time_ms FROM stats_pgsql_processlist").stdout.strip()
print("processlist:", rows)
sid = rows.split("|")[0]
print("bad id:", adm("PGSQL KILL CONNECTION 0").stdout.strip())
print("unknown id:", adm("PGSQL KILL CONNECTION 99999").stdout.strip())
r = adm("PGSQL KILL CONNECTION " + sid)
print("kill", sid, "->", r.stdout.strip(), (r.stderr or "").strip()[:80])
time.sleep(2)
try:
    p.stdin.write("select x from t;\n"); p.stdin.flush(); after = p.stdout.readline().strip()
except BrokenPipeError:
    after = "(connection gone)"
print("after:", after or "(connection closed)")
print("processlist after:", adm("SELECT count(*) FROM stats_pgsql_processlist").stdout.strip())
