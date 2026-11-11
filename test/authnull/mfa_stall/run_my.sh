#!/bin/bash
# MySQL version of run.sh. Usage: run_my.sh <mysql threads> <victims> [proxysql binary] [script]
# Everything lives in /tmp/stalltest and is torn down. The stub (stub.py) answers for authn-service.
set -u; THREADS=$1; N=$2; BIN=${3:-$HOME/asyncmfa-build/src/proxysql}; SCRIPT=${4:-victims_my.py}; cd /tmp/stalltest
export STALL_PW=$(openssl rand -hex 12); export ADMIN_PW=$(openssl rand -hex 12)
cleanup() { kill $PX $STUB 2>/dev/null; sleep 1; kill -9 $PX 2>/dev/null; sudo docker rm -f stalltest-my >/dev/null 2>&1; rm -rf /tmp/stalltest/data; sudo rm -rf /tmp/stalltest/spool; }
trap cleanup EXIT
sudo docker rm -f stalltest-my >/dev/null 2>&1
sudo docker run -d --rm --name stalltest-my -p 127.0.0.1:15498:3306 -e MYSQL_ROOT_PASSWORD=$STALL_PW -e MYSQL_DATABASE=stalldb mysql:8.0 >/dev/null
for i in $(seq 90); do sudo docker exec stalltest-my mysql -uroot -p$STALL_PW -e 'select 1' stalldb >/dev/null 2>&1 && break; sleep 2; done
sudo docker exec -i stalltest-my mysql -uroot -p$STALL_PW stalldb 2>/dev/null <<SQL
CREATE USER 'stall_fast'@'%' IDENTIFIED WITH mysql_native_password BY '$STALL_PW';
CREATE USER 'stall_slow'@'%' IDENTIFIED WITH mysql_native_password BY '$STALL_PW';
CREATE USER 'stall_deny'@'%' IDENTIFIED WITH mysql_native_password BY '$STALL_PW';
CREATE TABLE t (x int, email varchar(64) unique); INSERT INTO t VALUES (1, 'jane@acme.example');
GRANT SELECT, INSERT ON stalldb.* TO 'stall_fast'@'%', 'stall_slow'@'%', 'stall_deny'@'%';
SQL
python3 stub.py & STUB=$!
mkdir -p data
cat > proxysql.cnf <<CNF
datadir="/tmp/stalltest/data"
errorlog="/tmp/stalltest/data/proxysql.log"
admin_variables= { admin_credentials="admin:$ADMIN_PW" mysql_ifaces="127.0.0.1:16032" pgsql_ifaces="127.0.0.1:16132" }
mysql_variables= { threads=$THREADS interfaces="127.0.0.1:16033" }
pgsql_variables= { threads=1 interfaces="127.0.0.1:16133" }
authnull = { org_id = 2 tenant_id = 1 api_url = "http://127.0.0.1:18099/auth" allow_insecure_http = "true" backend_roles = "off" }
CNF
AUTHNULL_RECORDING_DIR=/tmp/stalltest/spool $BIN -f --initial -c /tmp/stalltest/proxysql.cnf -D /tmp/stalltest/data >/tmp/stalltest/px.out 2>&1 & PX=$!
for i in $(seq 30); do MYSQL_PWD=$ADMIN_PW mysql -h127.0.0.1 -P16032 -u'admin,agent' -e 'select 1' >/dev/null 2>&1 && break; sleep 1; done
MYSQL_PWD=$ADMIN_PW mysql -h127.0.0.1 -P16032 -u'admin,agent' <<SQL
INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '127.0.0.1', 15498);
INSERT INTO mysql_users (username, password, default_hostgroup) VALUES ('stall_fast', '$STALL_PW', 0), ('stall_slow', '$STALL_PW', 0), ('stall_deny', '$STALL_PW', 0);
LOAD MYSQL SERVERS TO RUNTIME; LOAD MYSQL USERS TO RUNTIME;
SQL
echo "== $BIN mysql threads=$THREADS, $SCRIPT"
PX=$PX python3 $SCRIPT $N 25 2>&1
sleep 1; kill -0 $PX 2>/dev/null && echo "proxysql still running" || echo "PROXYSQL DIED"
echo "-- AuthSQL log:"; sudo grep -a "AuthSQL\[$PX\]" /var/log/syslog | grep -aE "approved|refus|not approved|ERROR|ending|closing" | tail -8 | cut -c1-220
