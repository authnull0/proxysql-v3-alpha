# One session as stall_fast (READ only): a select, a refused insert, a refused password change,
# an error. With RECORD set the stub asks for recording; each statement must land in the spool.
import os, subprocess, time
env = dict(os.environ, PGPASSWORD=os.environ["STALL_PW"], PGSSLMODE="disable")
sql = "select x from t;\ninsert into t values (2);\nALTER ROLE stall_fast PASSWORD 'TopSecret1';\nselect * from nosuch;\nselect 'Leaky' as v;\n"
r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", "16133", "-U", "stall_fast,tok", "-d", "stalldb", "-Atq"],
    input=sql, capture_output=True, text=True, env=env)
print(r.stdout.strip()); print(r.stderr.strip())
