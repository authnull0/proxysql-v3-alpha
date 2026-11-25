// Standalone test for include/authnull_blocklist.h: a policy's blocked commands and patterns, and
// the row cap's CommandComplete tag; reading them from a login answer (authnull_login_answer.h); a
// capped statement's recording (authnull_recording.h).
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_blocklist_test.cpp -o /tmp/authnull_blocklist_test && /tmp/authnull_blocklist_test
//
// Exits non-zero on any failure.
#include "authnull_login_answer.h"
#include "authnull_recording.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

static AuthnullStatementPolicy policy(std::vector<std::string> commands, std::vector<std::string> patterns) {
	AuthnullStatementPolicy p;
	for (const auto& c : commands) p.blocked_commands.push_back(authnullPolicyCommand(c));
	for (const auto& s : patterns) p.blocked_patterns.push_back(authnullPolicyPattern(s));
	return p;
}

static const AuthnullStatementPolicy P = policy({"DROP", "DELETE", "alter "}, {"*from   CUSTOMERS*", "truncate *"});

static void rule(const AuthnullStatementPolicy& p, const std::string& sql, const std::string& want, const char* why,
		AuthnullDialect d = AuthnullDialect::Postgres) {
	const std::string got = authnullBlockedRule(p, sql, d);
	if (got != want) {
		std::fprintf(stderr, "FAIL %s\n  sql: %s\n  got [%s], want [%s]\n", why, sql.c_str(), got.c_str(), want.c_str());
		failures++;
	}
}
static void both(const std::string& sql, const std::string& want, const char* why) {
	rule(P, sql, want, why, AuthnullDialect::Postgres);
	rule(P, sql, want, why, AuthnullDialect::MySQL);
}

static void match(const std::string& pat, const std::string& text, bool want) {
	if (authnullWildcardMatch(pat, text) != want) {
		std::fprintf(stderr, "FAIL wildcard [%s] vs [%s]: want %s\n", pat.c_str(), text.c_str(), want ? "match" : "no match");
		failures++;
	}
}

static void expect(bool ok, const std::string& what) {
	if (!ok) {
		std::fprintf(stderr, "FAIL %s\n", what.c_str());
		failures++;
	}
}

int main() {
	// --- keywords ---
	both("DROP TABLE t", "DROP", "plain DROP");
	both("drop table t", "DROP", "lower case");
	both("/* x */ DrOp table t", "DROP", "a comment before, mixed case");
	both("DELETE FROM t WHERE id = 1", "DELETE", "DELETE");
	both("ALTER TABLE t ADD c int", "ALTER", "a listed keyword written with a space");
	both("SELECT 1", "", "SELECT is not listed");
	both("select 'drop table t'", "", "a keyword in a string");
	both("select 1 -- ; drop table t\n", "", "a keyword in a line comment");
	both("select /* ; drop table t */ 1", "", "a keyword in a block comment");
	both("select deleted_at from t", "", "a column named like a keyword");
	both("update t set c = 'DELETE'", "", "UPDATE is not listed");
	both("(DELETE FROM t)", "DELETE", "opening parentheses");
	rule(P, "SELECT `drop` FROM t", "", "MySQL quoted name", AuthnullDialect::MySQL);
	rule(P, "SELECT \"drop\" FROM t", "", "Postgres quoted name");
	rule(P, "/*!50000 DROP */ TABLE t", "DROP", "MySQL executable comment is code", AuthnullDialect::MySQL);
	rule(P, "select 1 # ; drop table t", "", "MySQL '#' comment", AuthnullDialect::MySQL);
	rule(P, "select $$; drop table t$$", "", "Postgres dollar quote");
	rule(P, "select /* /* nested */ ; drop table t */ 1", "", "Postgres nested comment");
	rule(P, "DR/**/OP TABLE t", "", "MySQL reads DR/**/OP as two words", AuthnullDialect::MySQL);

	// --- several statements ---
	both("select 1; drop table t", "DROP", "the second statement");
	both("select 1;delete from t;", "DELETE", "no spaces, trailing semicolon");
	both("select 1; select 2", "", "two harmless statements");

	// --- WITH ---
	both("WITH x AS (select 1) DELETE FROM t", "DELETE", "WITH ... DELETE");
	both("with recursive x(n) as (select 1 union all select n+1 from x where n < 3) delete from t", "DELETE", "WITH RECURSIVE and a column list");
	both("WITH a AS (select 1), b AS (select 2) DELETE FROM t", "DELETE", "two CTEs");
	rule(P, "WITH d AS (DELETE FROM t RETURNING id) SELECT id FROM d", "DELETE", "a writing CTE");
	rule(P, "WITH a AS MATERIALIZED (select 1) select * from a", "", "MATERIALIZED, nothing blocked");
	rule(P, "WITH a AS NOT MATERIALIZED (select 1) delete from t", "DELETE", "NOT MATERIALIZED");
	rule(P, "WITH RECURSIVE x(n) AS (select 1) CYCLE n SET c USING p DELETE FROM t", "DELETE", "CYCLE clause");
	both("WITH x AS (select 1) SELECT * FROM x", "", "WITH ... SELECT");

	// --- EXPLAIN / PREPARE ---
	rule(P, "EXPLAIN ANALYZE DELETE FROM t", "DELETE", "EXPLAIN ANALYZE runs it");
	rule(P, "EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t", "DELETE", "EXPLAIN (ANALYZE ...)");
	rule(P, "EXPLAIN DELETE FROM t", "", "plain EXPLAIN runs nothing");
	rule(policy({"EXPLAIN"}, {}), "EXPLAIN SELECT 1", "EXPLAIN", "EXPLAIN itself listed");
	rule(P, "EXPLAIN ANALYZE FORMAT=TREE SELECT 1", "", "MySQL EXPLAIN ANALYZE FORMAT=", AuthnullDialect::MySQL);
	rule(P, "PREPARE p AS DELETE FROM t", "DELETE", "Postgres PREPARE ... AS");
	rule(P, "PREPARE p FROM 'DROP TABLE t'", "DROP", "MySQL PREPARE ... FROM '...'", AuthnullDialect::MySQL);
	rule(P, "PREPARE p AS SELECT 1", "", "Postgres PREPARE of a SELECT");

	// --- patterns ---
	both("select * from customers", "pattern *from customers*", "pattern");
	both("SELECT *\n  FROM    Customers WHERE 1=1", "pattern *from customers*", "case and whitespace");
	both("select * /* hi */ from/**/customers", "pattern *from customers*", "comments become a space");
	both("select * from orders", "", "other table");
	both("select 1; select * from customers", "pattern *from customers*", "second statement");
	both("truncate t", "pattern truncate *", "anchored pattern");
	both("select 1; truncate t", "pattern truncate *", "anchored pattern, second statement");
	both("select 'truncate t'", "", "anchored pattern does not match inside");
	rule(policy({}, {"*'a  b'*"}), "select 'a   b'", "pattern *'a b'*", "whitespace collapsed in patterns and strings alike");
	rule(policy({}, {"select 1"}), "  select   1  ", "pattern select 1", "no star: the whole statement, trimmed");
	rule(policy({}, {"select 1"}), "select 12", "", "no star: exact");

	// --- empty lists ---
	rule(AuthnullStatementPolicy{}, "DROP TABLE t; select * from customers", "", "empty policy");
	rule(policy({""}, {""}), "DROP TABLE t", "", "empty entries");
	rule(P, "select 'unterminated", "", "unreadable: left to the privilege check");

	// --- wildcard ---
	match("*", "", true);
	match("*", "anything", true);
	match("", "", true);
	match("", "x", false);
	match("a*", "abc", true);
	match("*c", "abc", true);
	match("a*c", "ac", true);
	match("a*c", "abcbc", true);
	match("a*b*c", "abc", true);
	match("a*b*c", "acb", false);
	match("ab*ba", "aba", false);
	match("*aa*aa*", "aaa", false);
	match("*aa*aa*", "aaaa", true);
	match("**x**", "yxy", true);
	{
		std::string big(200000, 'a');
		match("*a*a*a*a*a*a*a*a*b", big, false); // no backtracking blow-up
	}

	// --- the CommandComplete tag of a capped result ---
	expect(authnullCappedTag("SELECT 10", 3) == "SELECT 3", "SELECT tag");
	expect(authnullCappedTag("FETCH 10", 3) == "FETCH 3", "FETCH tag");
	expect(authnullCappedTag("UPDATE 10", 3) == "UPDATE 10", "UPDATE tag kept");
	expect(authnullCappedTag("SELECTED", 3) == "SELECTED", "not a SELECT tag");
	expect(authnullBlockedMessage("DROP") == "Access denied: blocked by policy (DROP)", "message");
	expect(authnullCappedNotice(3) == "result capped at 3 rows by policy", "notice");

	// --- the login answer ---
	const std::string base = R"({"isValid":true,"credentialSubject":{"databaseName":"shop","privilege":["READ"],"tables":["t"],"fieldMasking":{})";
	AuthnullLoginAnswer a = authnullJudgeLoginAnswer(0, 200, base + R"(,"blockedCommands":["drop","DELETE",7,""],"blockedPatterns":["*FROM  customers*"],"maxRows":3}})");
	expect(a.approved, "approved: " + a.why);
	expect(a.policy.blocked_commands == std::vector<std::string>{"DROP", "DELETE"}, "blockedCommands");
	expect(a.policy.blocked_patterns == std::vector<std::string>{"*from customers*"}, "blockedPatterns");
	expect(a.policy.max_rows == 3, "maxRows");
	a = authnullJudgeLoginAnswer(0, 200, base + "}}");
	expect(a.approved && a.policy.blocked_commands.empty() && a.policy.blocked_patterns.empty() && a.policy.max_rows == 0, "fields missing: none");
	a = authnullJudgeLoginAnswer(0, 200, base + R"(,"blockedCommands":"DROP","blockedPatterns":null,"maxRows":0}})");
	expect(a.approved && a.policy.blocked_commands.empty() && a.policy.blocked_patterns.empty() && a.policy.max_rows == 0, "wrong types, zero: none");
	a = authnullJudgeLoginAnswer(0, 200, base + R"(,"maxRows":-5}})");
	expect(a.policy.max_rows == 0, "negative maxRows: no cap");
	a = authnullJudgeLoginAnswer(0, 200, base + R"(,"maxRows":"3"}})");
	expect(a.policy.max_rows == 0, "maxRows as a string: no cap");

	// --- the recording marks a capped statement ---
	AuthnullRecordedStatement st;
	st.statement = "select * from t";
	expect(authnullRecordLine(st).find("capped") == std::string::npos, "not capped: no key");
	st.capped = true;
	expect(authnullRecordLine(st).find("\"capped\":true") != std::string::npos, "capped: " + authnullRecordLine(st));

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("authnull_blocklist_test: all passed\n");
	return 0;
}
