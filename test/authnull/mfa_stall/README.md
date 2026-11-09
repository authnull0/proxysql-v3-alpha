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
