// Standalone test for include/authnull_query.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_query_test.cpp -o /tmp/authnull_query_test && /tmp/authnull_query_test
//
// Exits non-zero on any failure.
#include "authnull_query.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

using P = std::vector<std::string>;
static const P READ_ONLY = {"READ"};
static const P READ_WRITE = {"READ", "WRITE"};
static const P ALL = {"READ", "WRITE", "EXECUTE"};

static void permits(AuthnullDialect d, const P& granted, const std::string& sql, bool want, const char* why) {
	bool got = authnullQueryPermitted(granted, sql, d);
	if (got != want) {
		std::fprintf(stderr, "FAIL [%s] %s\n  sql: %s\n  got %s, want %s\n",
			d == AuthnullDialect::Postgres ? "pg" : "mysql", why, sql.c_str(),
			got ? "permitted" : "refused", want ? "permitted" : "refused");
		failures++;
	}
}

int main() {
	const auto PG = AuthnullDialect::Postgres;
	const auto MY = AuthnullDialect::MySQL;

	// --- what a READ-only session may do ---
	permits(PG, READ_ONLY, "select count(*) from priv_scratch", true, "plain select");
	permits(PG, READ_ONLY, "  SELECT * FROM customers WHERE id = 1;", true, "select with trailing semicolon");
	permits(PG, READ_ONLY, "/* tool header */ select 1", true, "leading block comment");
	permits(PG, READ_ONLY, "-- note\nselect 1", true, "leading line comment");
	permits(PG, READ_ONLY, "with t as (select 1 as x) select x from t", true, "read-only CTE");
	permits(PG, READ_ONLY, "explain select * from customers", true, "explain without analyze");
	permits(PG, READ_ONLY, "show search_path", true, "show");
	permits(PG, READ_ONLY, "select 'a; delete from customers' as s", true, "semicolon inside a string");
	permits(PG, READ_ONLY, "select $$; delete from customers$$", true, "semicolon inside a dollar quote");
	permits(PG, READ_ONLY, "select \"delete\" from t", true, "keyword as a quoted identifier");
	permits(PG, READ_ONLY, "values (1),(2)", true, "values");
	permits(PG, READ_ONLY, "", true, "empty query");

	// --- live bypasses found on 2 Nov (both wrote rows as a READ-only user) ---
	permits(PG, READ_ONLY, "with d as (insert into priv_scratch values (101,'cte') returning id) select id from d",
		false, "data-modifying CTE");
	permits(PG, READ_ONLY, "select 1; insert into priv_scratch values (102,'multi')", false, "multi-statement");

	// --- other ways a READ-only session could write ---
	permits(PG, READ_ONLY, "insert into t values (1)", false, "insert");
	permits(PG, READ_ONLY, "/* hi */ insert into t values (1)", false, "insert behind a comment");
	permits(PG, READ_ONLY, "select 1 -- x\n; delete from t", false, "statement after a line comment");
	permits(PG, READ_ONLY, "select 1 /* ; */ ; delete from t", false, "statement after a block comment");
	permits(PG, READ_ONLY, "select 'a\\'; delete from t; --'", false,
		"backslash does not escape in a standard Postgres string");
	permits(PG, READ_ONLY, "select /* /* nested */ */ 1; delete from t", false, "nested Postgres comment");
	permits(PG, READ_ONLY, "explain analyze delete from t", false, "explain analyze runs the statement");
	permits(PG, READ_ONLY, "select * into new_t from customers", false, "select into creates a table");
	permits(PG, READ_ONLY, "select * from t for update", false, "select for update takes write locks");
	permits(PG, READ_ONLY, "select set_config('default_transaction_read_only','off',false)", false, "set_config");
	permits(PG, READ_ONLY, "select pg_terminate_backend(123)", false, "pg_terminate_backend");
	permits(PG, READ_ONLY, "select setval('s', 1)", false, "setval");
	permits(PG, READ_ONLY, "select dblink_exec('dbname=x', 'delete from t')", false, "dblink_exec");
	permits(PG, READ_ONLY, "select lo_import('/etc/passwd')", false, "lo_import");
	permits(PG, READ_ONLY, "copy t from stdin", false, "copy from");
	permits(PG, READ_ONLY, "set role postgres", false, "set");
	permits(PG, READ_ONLY, "do $$ begin delete from t; end $$", false, "anonymous code block");
	permits(PG, READ_ONLY, "select 'unterminated", false, "unterminated string is refused, not guessed");
	permits(PG, READ_ONLY, "select 1 /* unterminated", false, "unterminated comment is refused");

	// --- WRITE sessions ---
	permits(PG, READ_WRITE, "insert into t values (1)", true, "write session inserts");
	permits(PG, READ_WRITE, "update t set x = 1 where id = 2", true, "write session updates");
	permits(PG, READ_WRITE, "select 1; insert into t values (1)", true, "multi-statement within granted privileges");
	permits(PG, READ_WRITE, "drop table t", false, "write session cannot drop");
	permits(PG, READ_WRITE, "select 1; drop table t", false, "multi-statement needing more than granted");
	permits(PG, ALL, "drop table t", true, "full session drops");

	// --- MySQL rules differ in quoting and comments ---
	permits(MY, READ_ONLY, "select 'a\\'; delete from t; --'", true, "backslash escapes in a MySQL string");
	permits(MY, READ_ONLY, "select 1 # note ; delete from t", true, "MySQL hash comment runs to end of line");
	permits(MY, READ_ONLY, "select 1 # note\n; delete from t", false, "statement after a MySQL hash comment");
	permits(MY, READ_ONLY, "select `delete` from t", true, "backtick identifier");
	permits(MY, READ_ONLY, "/*!50000 delete from t */", false, "MySQL executable comment is code");
	permits(MY, READ_ONLY, "select * from t into outfile '/tmp/x'", false, "select into outfile");
	permits(MY, READ_ONLY, "select load_file('/etc/passwd')", false, "load_file");
	permits(MY, READ_ONLY, "replace into t values (1)", false, "replace");
	permits(MY, READ_ONLY, "select 1; delete from t", false, "multi-statement");
	permits(MY, READ_ONLY, "select * from customers", true, "plain select");

	// --- custom privileges: a policy may name SQL verbs instead of READ/WRITE/EXECUTE ---
	// SELECT and INSERT mean exactly that: no UPDATE or DELETE riding along with "WRITE".
	const P SEL_INS = {"SELECT", "INSERT"};
	permits(PG, SEL_INS, "select * from t", true, "verbs: select");
	permits(PG, SEL_INS, "insert into t values (1)", true, "verbs: insert");
	permits(PG, SEL_INS, "update t set a = 1", false, "verbs: update not granted");
	permits(PG, SEL_INS, "delete from t", false, "verbs: delete not granted");
	permits(PG, SEL_INS, "truncate t", false, "verbs: truncate not granted");
	permits(PG, SEL_INS, "copy t from stdin", true, "verbs: copy from is an insert");
	permits(PG, SEL_INS, "insert into t values (1) on conflict (id) do update set a = 2", false, "verbs: upsert also updates");
	permits(PG, SEL_INS, "merge into t using s on t.id = s.id when matched then update set a = 1", false, "verbs: merge");
	permits(PG, SEL_INS, "select * from t for update", false, "verbs: row lock needs update");
	permits(PG, SEL_INS, "with d as (delete from t returning id) select id from d", false, "verbs: delete inside a CTE");
	permits(PG, SEL_INS, "create table x (id int)", false, "verbs: DDL");
	permits(PG, SEL_INS, "select nextval('s')", false, "verbs: nextval changes a sequence");
	permits(MY, SEL_INS, "insert into t values (1) on duplicate key update a = 2", false, "verbs: mysql upsert also updates");
	permits(MY, SEL_INS, "replace into t values (1)", false, "verbs: mysql replace deletes");

	const P SEL_UPD = {"SELECT", "UPDATE"};
	permits(PG, SEL_UPD, "update t set a = 1 where id = 2", true, "verbs: update");
	permits(PG, SEL_UPD, "select * from t for update", true, "verbs: row lock with update");
	permits(PG, SEL_UPD, "select setval('s', 5)", true, "verbs: setval with update");
	permits(PG, SEL_UPD, "insert into t values (1)", false, "verbs: insert not granted");
	permits(PG, {"SELECT", "INSERT", "UPDATE"}, "insert into t values (1) on conflict (id) do update set a = 2", true, "verbs: upsert with both");
	permits(MY, {"SELECT", "INSERT", "DELETE"}, "replace into t values (1)", true, "verbs: replace with both");

	permits(PG, {"SELECT", "DELETE"}, "delete from t where id = 1", true, "verbs: delete");
	permits(PG, {"SELECT", "TRUNCATE"}, "truncate table t", true, "verbs: truncate");
	permits(PG, {"SELECT", "TRUNCATE"}, "delete from t", false, "verbs: truncate is not delete");
	permits(PG, {"SELECT"}, "select 1", true, "verbs: SELECT is READ");
	permits(PG, {"select", " insert "}, "insert into t values (1)", true, "verbs: case and spaces");
	permits(PG, {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"merge into t using s on t.id = s.id when matched then update set a = 1 when not matched then insert values (1)",
		true, "verbs: merge with all three");

	// --- the groups are unchanged ---
	permits(PG, READ_WRITE, "truncate t", false, "groups: WRITE still cannot truncate");
	permits(PG, ALL, "truncate t", true, "groups: EXECUTE still can");
	permits(PG, READ_WRITE, "insert into t values (1) on conflict (id) do update set a = 2", true, "groups: upsert");
	permits(PG, READ_WRITE, "select * from t for update", true, "groups: row lock");
	permits(PG, READ_WRITE, "select nextval('s')", true, "groups: nextval");
	permits(MY, READ_WRITE, "replace into t values (1)", true, "groups: replace");
	permits(PG, {"READ", "INSERT"}, "insert into t values (1)", true, "groups and verbs mixed");
	permits(PG, {"READ", "INSERT"}, "update t set a = 1", false, "groups and verbs mixed: no update");
	permits(PG, {"WRITE"}, "select 1", false, "groups: WRITE does not read");
	permits(PG, {"BOGUS"}, "select 1", false, "an unknown privilege grants nothing");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::puts("ok");
	return 0;
}
