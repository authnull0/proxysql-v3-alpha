# MySQL session limits: the stub says the access grant ends ENDS_IN s after login; querying every
# 3 s, the session must be ended about then.
import os, subprocess, time
env = dict(os.environ, MYSQL_PWD=os.environ["STALL_PW"])
p = subprocess.Popen(["mysql", "-h127.0.0.1", "-P16033", "-ustall_fast,tok", "-Dstalldb", "-N", "-B", "-n"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
t0 = time.time()
while time.time() - t0 < 40:
    try:
        p.stdin.write("select x from t limit 1;\n"); p.stdin.flush(); line = p.stdout.readline().strip()
    except BrokenPipeError:
        line = "(connection gone)"
    print(f"{time.time()-t0:5.1f}s {line[:110]}", flush=True)
    if not line or "ended" in line.lower() or "gone" in line or "lost" in line.lower(): break
    time.sleep(3)
