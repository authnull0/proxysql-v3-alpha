# One session as stall_fast, querying every 3 s for 45 s: with the stub saying the grant ends 20 s
# after login, ProxySQL must end the session about then.
import os, subprocess, time
env = dict(os.environ, PGPASSWORD=os.environ["STALL_PW"], PGSSLMODE="disable")
p = subprocess.Popen(["psql", "-h", "127.0.0.1", "-p", "16133", "-U", "stall_fast,tok", "-d", "stalldb", "-Atq"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
t0 = time.time()
while time.time() - t0 < 45:
    try:
        p.stdin.write("select x from t;\n"); p.stdin.flush()
        line = p.stdout.readline().strip()
    except BrokenPipeError:
        line = "(connection gone)"
    print(f"{time.time()-t0:5.1f}s {line[:90]}", flush=True)
    if not line or "terminat" in line.lower() or "ended" in line.lower() or "gone" in line or "closed" in line.lower():
        break
    time.sleep(3)
