# N sessions already logged in as stall_fast, each running SELECT every 100 ms; at T_SLOW a
# stall_slow login starts (its push held by the stub), at T_SLOW+2 a fresh stall_fast login is
# timed. Prints each victim's worst query latency during the run.
import os, subprocess, sys, threading, time
N, RUN, T_SLOW = int(sys.argv[1]), float(sys.argv[2]), 3.0
env = dict(os.environ, PGPASSWORD=os.environ["STALL_PW"], PGCONNECT_TIMEOUT="120", PGSSLMODE="disable")
def psql(user, *extra):
    return ["psql", "-h", "127.0.0.1", "-p", "16133", "-U", user + ",tok", "-d", "stalldb", "-Atq", *extra]
worst = [0.0] * N; done = [0] * N
def victim(i):
    p = subprocess.Popen(psql("stall_fast"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
    p.stdin.write("select x from t;\n"); p.stdin.flush(); p.stdout.readline()  # logged in
    ready[i] = True
    end = time.time() + RUN
    while time.time() < end:
        t = time.time(); p.stdin.write("select x from t;\n"); p.stdin.flush(); p.stdout.readline()
        worst[i] = max(worst[i], time.time() - t); done[i] += 1; time.sleep(0.1)
    p.stdin.close(); p.wait()
ready = [False] * N
ts = [threading.Thread(target=victim, args=(i,)) for i in range(N)]
[t.start() for t in ts]
while not all(ready): time.sleep(0.05)
time.sleep(T_SLOW)
t0 = time.time()
slows = [subprocess.Popen(psql("stall_slow", "-c", "select x from t"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
         for _ in range(int(os.environ.get("SLOWS", "1")))]
slow = slows[0]
time.sleep(2)
t = time.time(); r = subprocess.run(psql("stall_fast", "-c", "select x from t"), capture_output=True, env=env)
fresh = time.time() - t
# A refusal still refuses; a client that hangs up mid-push does no harm.
deny = subprocess.run(psql("stall_deny", "-c", "select x from t"), capture_output=True, env=env)
gone = subprocess.Popen(psql("stall_slow", "-c", "select x from t"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
time.sleep(1); gone.kill()
[t.join() for t in ts]
[s.wait() for s in slows]
print(f"held logins: {len(slows)}, all succeeded: {all(s.returncode == 0 for s in slows)}")
print(f"denied login rc={deny.returncode} (want non-zero)")
print(f"victims={N} worst latency per session (s): " + " ".join(f"{w:.2f}" for w in worst))
print(f"stalled (>1s): {sum(w > 1 for w in worst)}/{N}   queries per session: {done}")
print(f"fresh stall_fast login during the hold: {fresh:.2f}s rc={r.returncode}   slow login took {time.time()-t0:.1f}s rc={slow.returncode}")
