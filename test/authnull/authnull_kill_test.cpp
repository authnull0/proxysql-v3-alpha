// Standalone test for include/authnull_kill.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_kill_test.cpp -o /tmp/authnull_kill_test && /tmp/authnull_kill_test
//
// PGSQL KILL CONNECTION <id> (the admin interface) ends a Postgres client session; the database
// agent sends it for a kill from the AuthNull console (authnull-service docs/DB-LIVE-SESSIONS.md).
// The id is read strictly: what the admin KILL CONNECTION's atoi() would take as 0, or as a prefix,
// is refused.
#include "authnull_kill.h"

#include <cstdio>
#include <initializer_list>

static int failures = 0;
static void expect(bool ok, const char* what) {
	if (!ok) { std::fprintf(stderr, "FAIL %s\n", what); failures++; }
}

int main() {
	uint32_t id = 0;
	expect(authnullParseKillID("PGSQL KILL CONNECTION 42", id) && id == 42, "an id");
	expect(authnullParseKillID("pgsql kill connection 7", id) && id == 7, "any case");
	expect(authnullParseKillID("PGSQL KILL CONNECTION 4294967295", id) && id == 4294967295u, "the largest");
	for (const char* bad : {"PGSQL KILL CONNECTION ", "PGSQL KILL CONNECTION 0", "PGSQL KILL CONNECTION -3",
	                        "PGSQL KILL CONNECTION 12abc", "PGSQL KILL CONNECTION 4294967296", "PGSQL KILL CONNECTION 1 2",
	                        "KILL CONNECTION 5", "PGSQL KILL CONNECTION 99999999999999999999"}) {
		expect(!authnullParseKillID(bad, id), bad);
	}
	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
