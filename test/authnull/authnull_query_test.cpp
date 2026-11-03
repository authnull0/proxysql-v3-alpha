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

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::puts("ok");
	return 0;
}
