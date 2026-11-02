// Standalone test for include/authnull_auth.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_auth_test.cpp -o /tmp/authnull_auth_test && /tmp/authnull_auth_test
//
// Exits non-zero on the first failure.
#include "authnull_auth.h"

#include <cstdio>

// The session types as proxysql_structs.h orders them. The header takes the type as a template
// parameter, so this test does not need ProxySQL's headers.
enum session_type { MYSQL, ADMIN, STATS, SQLITE, CLICKHOUSE, PGSQL };

static int failures = 0;

static void expect(bool got, bool want, const char* what) {
	if (got != want) {
		std::fprintf(stderr, "FAIL %s: got %d, want %d\n", what, got, want);
		failures++;
	}
}

int main() {
	// The bypass this replaces: on the Postgres client port, a database role named "admin" kept the
	// password the client sent and never called AuthNull.
	expect(authnullRequiresMFA(PGSQL, PGSQL, "admin"), true, "client port, role named admin");
	expect(authnullRequiresMFA(PGSQL, PGSQL, "ADMIN"), true, "client port, role named ADMIN");
	expect(authnullRequiresMFA(PGSQL, PGSQL, "dbmfa_reader"), true, "client port, ordinary role");
	expect(authnullRequiresMFA(PGSQL, PGSQL, ""), true, "client port, empty name");

	// ProxySQL's own interfaces (6132 admin, stats) authenticate against ProxySQL's credentials and
	// have no AuthNull token: they keep the normal password check, whatever the username.
	expect(authnullRequiresMFA(ADMIN, PGSQL, "admin"), false, "admin interface, admin");
	expect(authnullRequiresMFA(ADMIN, PGSQL, "radmin"), false, "admin interface, radmin");
	expect(authnullRequiresMFA(STATS, PGSQL, "stats"), false, "stats interface");
	expect(authnullRequiresMFA(SQLITE, PGSQL, "admin"), false, "sqlite interface");

	// The MySQL client port gates the same way (MySQL_Session.cpp: session_type == MYSQL).
	expect(authnullRequiresMFA(MYSQL, MYSQL, "admin"), true, "mysql client port, admin");
	expect(authnullRequiresMFA(ADMIN, MYSQL, "admin"), false, "mysql admin interface");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::puts("ok");
	return 0;
}
