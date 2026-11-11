# MFA stall test (integration)

Does a login waiting on its MFA push hold up anyone else? It runs a throwaway ProxySQL
(127.0.0.1:16132/16133, data in /tmp/stalltest/data) in front of a throwaway Postgres container
(postgres:16-alpine on 127.0.0.1:15499), with `stub.py` standing in for authn-service:

- `stall_fast` is approved at once,
- `stall_slow` is held for 20 s (a push nobody has answered yet),
- `stall_deny` is refused.

`victims.py` logs in N `stall_fast` sessions that query every 100 ms. It then starts `SLOWS` held
logins, times a fresh login, checks that a refusal still refuses, and hangs up one held login.
Everything is torn down on exit.

The test needs a built ProxySQL, docker (via sudo), psql and python3. Copy this directory to
`/tmp/stalltest` and run:

    ./run.sh <pgsql threads> <victims> [proxysql binary]
    SLOWS=6 ./run.sh 4 8 ./src/proxysql

Lab, 9 Nov 2026. With the push call made on the worker thread (before authnull_async_call.h):

    threads=1, 4 victims:          4/4 stalled 19.95 s, fresh login 18.1 s
    threads=4, 8 victims, 6 held:  3/8 stalled ~40 s, fresh login 38.1 s, one held login failed

With the call made off the thread:

    threads=1, 4 victims:          0/4 stalled (worst 0.00 s), fresh login 0.13 s
    threads=4, 8 victims, 6 held:  0/8 stalled (worst 0.01 s), fresh login 0.11 s, all 6 held logins succeeded

## Access grant end

`grantend.py` runs one `stall_fast` session that queries every 3 seconds. With `ENDS_IN=20`, the
stub's approval carries `session.endsAt` 20 seconds out, as authn-service sends it for a login let
through on an access grant. ProxySQL must end the session then. To run it, swap `victims.py` for
`grantend.py` in `run.sh`. Result on the lab, 10 Nov 2026: queries answered until 17.1 s, and at
20.1 s `ERROR: Session ended: the access grant it was approved on has ended`.

## Killing a session

`killtest.py` opens one session, finds it in `stats_pgsql_processlist`, and sends `PGSQL KILL
CONNECTION` with a bad id, an unknown id and then its own id. To run it, swap `victims.py` for
`killtest.py` in `run.sh`, and export `ADMIN_PW` there. Result on the lab, 10 Nov 2026:
- the bad id and the unknown id were answered as rows (`0|usage: …`, `0|no PgSQL session 99999`)
  and ProxySQL stayed up;
- the kill answered `1|session 4 killed`, and the session's next query got "server closed the
  connection".

## Session recording (`rectest.sh`)

`RECORD=1 ./rectest.sh 2 0 [proxysql binary]` makes the stub ask for recording
(`credentialSubject.session.record`). `rec.py` runs, as `stall_fast` (READ only), a select, a refused
insert, a refused `ALTER ROLE ... PASSWORD`, a statement that errors, and a select of a literal. The
script prints the spool (`AUTHNULL_RECORDING_DIR=/tmp/stalltest/spool`) and counts the syslog lines
holding the password, the literal or the table name, which must be 0.

Lab, 10 Nov 2026: five lines in one 0600 bucket file, in a 0700 directory. The refused statements have
`allowed: false` and the refusal. The password reads `'***'`. The error is `[42P01] relation "nosuch" does not exist`.
There were 0 syslog lines. Without `RECORD` there is no spool at all.

## MySQL (`run_my.sh`)

`./run_my.sh <mysql threads> <victims> [proxysql binary] [script]` does the same with a `mysql:8.0`
container (127.0.0.1:15498) behind ProxySQL's MySQL port (16033), using the `mysql` client.
- `victims_my.py` (the default) is the stall test.
- `rec_my.py` (with `PRIVS=READ,INSERT RECORD=1`) is the recording check.
- `limits_my.py` (with `ENDS_IN=12`) is the access-grant end.

Lab, 11 Nov 2026, 1 MySQL thread, 4 victims:

    blocking call (on-prem before this change): 4/4 stalled 19.94 s, fresh login 18.05 s
    off the thread:                              0/4 stalled (worst 0.00 s), fresh login 0.07 s

- **Refusal:** the refused login reads "Access denied: multi-factor authentication was not
  approved: denied by the stub", so the client now sees authn-service's reason.
- **Recording:** six lines. The password reads `'***'` and the duplicate-key error reads
  `Duplicate entry '***' for key '***'`. 0 syslog lines held a value.
- **Session limits:** the session was ended about 12 s after login.
