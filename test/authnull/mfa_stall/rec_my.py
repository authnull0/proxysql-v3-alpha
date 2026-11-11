# MySQL recording check: as stall_fast (the stub grants PRIVS, here READ,INSERT) run a select, an
# insert, a duplicate insert (an error that quotes the value), a refused ALTER USER with a password,
# and a select of a literal; then show the spool and count syslog lines holding any of the values.
import os, subprocess, sys, time
env = dict(os.environ, MYSQL_PWD=os.environ["STALL_PW"])
sql = ("select x from t;\ninsert into t values (2, 'bob@acme.example');\ninsert into t values (3, 'jane@acme.example');\n"
       "ALTER USER 'stall_fast'@'%' IDENTIFIED BY 'TopSecret1';\nselect 'Leaky' as v;\n")
r = subprocess.run(["mysql", "-h127.0.0.1", "-P16033", "-ustall_fast,tok", "-Dstalldb", "-N", "-B", "-n", "--force"],
    input=sql, capture_output=True, text=True, env=env)
print(r.stdout.strip()); print(r.stderr.strip())
time.sleep(6)
print("-- spool:")
print(subprocess.run("sudo sh -c 'ls -l /tmp/stalltest/spool; cat /tmp/stalltest/spool/*.jsonl'", shell=True, capture_output=True, text=True).stdout)
pid = os.environ.get("PX", "")
n = subprocess.run(f"sudo grep -a 'AuthSQL' /var/log/syslog | grep -a '\\[{pid}\\]' | grep -acE 'TopSecret1|Leaky|jane@acme|bob@acme'", shell=True, capture_output=True, text=True).stdout.strip()
print("-- syslog lines with a value:", n)
