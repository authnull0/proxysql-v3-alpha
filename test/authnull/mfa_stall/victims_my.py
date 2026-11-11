# MySQL version of victims.py: N sessions logged in as stall_fast run SELECT every 100 ms; at T_SLOW
# a stall_slow login starts (its push held by the stub), then a fresh stall_fast login is timed.
import os, subprocess, sys, threading, time
N, RUN, T_SLOW = int(sys.argv[1]), float(sys.argv[2]), 3.0
env = dict(os.environ, MYSQL_PWD=os.environ["STALL_PW"])
def mysql(user, *extra):
    return ["mysql", "-h127.0.0.1", "-P16033", "-u" + user + ",tok", "-Dstalldb", "-N", "-B", "-n", "--connect-timeout=120", *extra]
worst = [0.0] * N; done = [0] * N; ready = [False] * N
def victim(i):
    p = subprocess.Popen(mysql("stall_fast"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
    p.stdin.write("select x from t;\n"); p.stdin.flush(); p.stdout.readline()
    ready[i] = True
    end = time.time() + RUN
    while time.time() < end:
        t = time.time(); p.stdin.write("select x from t;\n"); p.stdin.flush(); p.stdout.readline()
        worst[i] = max(worst[i], time.time() - t); done[i] += 1; time.sleep(0.1)
    p.stdin.close(); p.wait()
ts = [threading.Thread(target=victim, args=(i,)) for i in range(N)]
[t.start() for t in ts]
while not all(ready): time.sleep(0.05)
time.sleep(T_SLOW)
t0 = time.time()
slows = [subprocess.Popen(mysql("stall_slow", "-e", "select x from t"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
         for _ in range(int(os.environ.get("SLOWS", "1")))]
slow = slows[0]
time.sleep(2)
t = time.time(); r = subprocess.run(mysql("stall_fast", "-e", "select x from t"), capture_output=True, env=env)
fresh = time.time() - t
deny = subprocess.run(mysql("stall_deny", "-e", "select x from t"), capture_output=True, text=True, env=env)
gone = subprocess.Popen(mysql("stall_slow", "-e", "select x from t"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
time.sleep(1); gone.kill()
[t.join() for t in ts]
[s.wait() for s in slows]
print(f"held logins: {len(slows)}, all succeeded: {all(s.returncode == 0 for s in slows)}")
print(f"denied login rc={deny.returncode} (want non-zero): {deny.stderr.strip()[:160]}")
print(f"victims={N} worst latency per session (s): " + " ".join(f"{w:.2f}" for w in worst))
print(f"stalled (>1s): {sum(w > 1 for w in worst)}/{N}   queries per session: {done}")
print(f"fresh stall_fast login during the hold: {fresh:.2f}s rc={r.returncode}   slow login took {time.time()-t0:.1f}s rc={slow.returncode}")
