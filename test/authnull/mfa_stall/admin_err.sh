#!/bin/bash
# Admin errors on the PgSQL admin port must not take ProxySQL down. Usage: admin_err.sh [proxysql binary]
# Starts a throwaway ProxySQL (admin 127.0.0.1:16132, data in /tmp/stalltest/data), sends statements that
# answer with an error, and after each checks that ProxySQL is still running and that a good query works.
# Needs psql and python3 (stub.py stands in for authn-service). Everything is torn down on exit.
set -u; BIN=${1:-$HOME/asyncmfa-build/src/proxysql}; cd /tmp/stalltest
ADMIN_PW=$(openssl rand -hex 12)
cleanup() { kill $PX $STUB 2>/dev/null; sleep 1; kill -9 $PX 2>/dev/null; rm -rf /tmp/stalltest/data; }
trap cleanup EXIT
python3 stub.py & STUB=$!
mkdir -p data
cat > proxysql.cnf <<CNF
datadir="/tmp/stalltest/data"
errorlog="/tmp/stalltest/data/proxysql.log"
admin_variables= { admin_credentials="admin:$ADMIN_PW" mysql_ifaces="127.0.0.1:16032" pgsql_ifaces="127.0.0.1:16132" }
mysql_variables= { threads=1 interfaces="127.0.0.1:16033" }
pgsql_variables= { threads=1 interfaces="127.0.0.1:16133" authentication_method=1 }
authnull = { org_id = 2 tenant_id = 1 api_url = "http://127.0.0.1:18099/auth" allow_insecure_http = "true" backend_roles = "off" }
CNF
$BIN -f --initial -c /tmp/stalltest/proxysql.cnf -D /tmp/stalltest/data >/tmp/stalltest/px.out 2>&1 & PX=$!
adm() { PGPASSWORD=$ADMIN_PW psql -h 127.0.0.1 -p 16132 -U 'admin,agent' -d admin -v VERBOSITY=verbose -Atc "$1" 2>&1; }
for i in $(seq 30); do adm 'select 1' >/dev/null && break; sleep 1; done
echo "== $BIN"
FAIL=0
while IFS= read -r q; do
	out=$(adm "$q" | head -1 | cut -c1-120)
	sleep 0.5
	if kill -0 $PX 2>/dev/null && [ "$(adm 'select 1')" = 1 ]; then st=up; else st=DIED; FAIL=1; fi
	printf '%-45s -> %-6s %s\n' "$q" "$st" "$out"
	[ $st = DIED ] && break
done <<'Q'
select * from nosuch_table;
nonsense;
SET pgsql-nosuch_variable = 1;
LOAD PGSQL QUERY RULES FROM NOSUCH;
SAVE PGSQL VARIABLES TO NOSUCH;
PROXYSQL NOSUCH;
PROXYSQL START;
KILL CONNECTION 99999;
PROXYSQL RESUME;
select 1;
Q
# the same connection must go on answering after an error
if [ $FAIL = 0 ]; then
	same=$(printf 'PROXYSQL START;\nnonsense;\nselect 42;\n' | PGPASSWORD=$ADMIN_PW psql -h 127.0.0.1 -p 16132 -U 'admin,agent' -d admin -At 2>/dev/null)
	echo "same connection, after two errors: select 42 -> ${same:-nothing}"; [ "$same" = 42 ] || FAIL=1
fi
[ $FAIL = 0 ] && echo "PASS: proxysql still running" || { echo "FAIL: PROXYSQL DIED"; tail -5 /tmp/stalltest/px.out | cut -c1-200; }
