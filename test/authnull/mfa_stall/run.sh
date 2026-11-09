#!/bin/bash
# MFA stall test: see README.md. Usage: run.sh <pgsql threads> <victims> [proxysql binary]
# Everything lives in /tmp/stalltest and is torn down on exit.
set -u; THREADS=$1; N=$2; BIN=${3:-$HOME/nolog-build/src/proxysql}; cd /tmp/stalltest
export STALL_PW=$(openssl rand -hex 12); ADMIN_PW=$(openssl rand -hex 12)
cleanup() { kill $PX $STUB 2>/dev/null; sleep 1; kill -9 $PX 2>/dev/null; sudo docker rm -f stalltest-pg >/dev/null 2>&1; rm -rf /tmp/stalltest/data; }
trap cleanup EXIT
sudo docker rm -f stalltest-pg >/dev/null 2>&1
sudo docker run -d --rm --name stalltest-pg -p 127.0.0.1:15499:5432 -e POSTGRES_PASSWORD=$STALL_PW -e POSTGRES_DB=stalldb postgres:16-alpine >/dev/null
for i in $(seq 30); do sudo docker exec stalltest-pg pg_isready -U postgres -q && break; sleep 1; done; sleep 2
sudo docker exec -i stalltest-pg psql -q -U postgres -d stalldb -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE ROLE stall_fast LOGIN PASSWORD '$STALL_PW'; CREATE ROLE stall_slow LOGIN PASSWORD '$STALL_PW'; CREATE ROLE stall_deny LOGIN PASSWORD '$STALL_PW';
CREATE TABLE t (x int); INSERT INTO t VALUES (1); GRANT SELECT ON t TO stall_fast, stall_slow, stall_deny;
SQL
python3 stub.py & STUB=$!
mkdir -p data
cat > proxysql.cnf <<CNF
datadir="/tmp/stalltest/data"
errorlog="/tmp/stalltest/data/proxysql.log"
admin_variables= { admin_credentials="admin:$ADMIN_PW" mysql_ifaces="127.0.0.1:16032" pgsql_ifaces="127.0.0.1:16132" }
mysql_variables= { threads=1 interfaces="127.0.0.1:16033" }
pgsql_variables= { threads=$THREADS interfaces="127.0.0.1:16133" authentication_method=1 }
authnull = { org_id = 2 tenant_id = 1 api_url = "http://127.0.0.1:18099/auth" allow_insecure_http = "true" backend_roles = "off" }
CNF
$BIN -f --initial -c /tmp/stalltest/proxysql.cnf -D /tmp/stalltest/data >/tmp/stalltest/px.out 2>&1 & PX=$!
for i in $(seq 30); do PGPASSWORD=$ADMIN_PW psql -h 127.0.0.1 -p 16132 -U 'admin,agent' -d admin -Atqc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
PGPASSWORD=$ADMIN_PW psql -h 127.0.0.1 -p 16132 -U 'admin,agent' -d admin -q -v ON_ERROR_STOP=1 <<SQL
INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (0, '127.0.0.1', 15499);
INSERT INTO pgsql_users (username, password, default_hostgroup) VALUES ('stall_fast', '$STALL_PW', 0), ('stall_slow', '$STALL_PW', 0), ('stall_deny', '$STALL_PW', 0);
LOAD PGSQL SERVERS TO RUNTIME; LOAD PGSQL USERS TO RUNTIME;
SQL
PGPASSWORD=$ADMIN_PW psql -h 127.0.0.1 -p 16132 -U 'admin,agent' -d admin -Atc "select variable_name, variable_value from global_variables where variable_name='pgsql-threads'"
echo "== $BIN pgsql threads=$THREADS, hold 20s"
python3 victims.py $N 14 2>&1
sleep 1; kill -0 $PX 2>/dev/null && echo "proxysql still running" || echo "PROXYSQL DIED"
echo "-- AuthSQL log:"; sudo grep -a "AuthSQL\[$PX\]" /var/log/syslog | grep -aE "approved|refus|ERROR" | tail -6 | cut -c1-200
