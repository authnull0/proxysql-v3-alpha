// Standalone test for include/authnull_session_ends.h: the admin command that moves an open
// session's access-grant end (an extended grant, authnull-service docs/DB-ACCESS-REQUESTS.md).
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude -Ideps/json test/authnull/authnull_session_ends_test.cpp -o /tmp/authnull_session_ends_test && /tmp/authnull_session_ends_test
//
// Exits non-zero on any failure.
#include "authnull_session_ends.h"

#include <cstdio>
#include <string>

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) {
		std::fprintf(stderr, "FAIL %s\n", what.c_str());
		failures++;
	}
}

int main() {
	AuthnullSessionEnds e;
	expect(authnullParseSetSessionEnds("PGSQL SET SESSION ENDS 42 1794303775", e), "pgsql parses");
	expect(e.pgsql && e.id == 42 && e.ends_s == 1794303775LL, "pgsql fields");
	expect(authnullParseSetSessionEnds("mysql set session ends 7 1794303775", e), "mysql, any case");
	expect(!e.pgsql && e.id == 7 && e.ends_s == 1794303775LL, "mysql fields");
	for (const char* bad : {
		"PGSQL SET SESSION ENDS", "PGSQL SET SESSION ENDS 42", "PGSQL SET SESSION ENDS 42 ", "PGSQL SET SESSION ENDS x 1",
		"PGSQL SET SESSION ENDS 0 1794303775", "PGSQL SET SESSION ENDS 42 0", "PGSQL SET SESSION ENDS 42 17943x",
		"PGSQL SET SESSION ENDS 42 1794303775 9", "PGSQL SET SESSION ENDS 4294967296 1794303775",
		"PGSQL SET SESSION ENDS -1 1794303775", "SQLITE SET SESSION ENDS 1 2", "PGSQL KILL CONNECTION 4", "",
	}) {
		expect(!authnullParseSetSessionEnds(bad, e), std::string("refused: ") + bad);
	}
	expect(!authnullParseSetSessionEnds(nullptr, e), "null");

	// Only a session that came in on a grant (it has limits) gets a new end; the others say why not.
	AuthnullSessionLimits limits;
	AuthnullSessionLimit l;
	l.started_s = 1000;
	l.max_minutes = 0;
	l.ends_s = 2000;
	limits.set(5, l);
	expect(limits.set_ends(5, 4000), "a session with a grant end moves");
	AuthnullSessionLimit got;
	expect(limits.get(5, got) && got.ends_s == 4000 && got.started_s == 1000, "only its end changed");
	expect(authnullSessionLimitReason(got, 3000, 0).empty(), "it goes on past the old end");
	expect(!authnullSessionLimitReason(got, 4000, 0).empty(), "and ends at the new one");
	expect(!limits.set_ends(6, 4000), "a session without limits does not get one");
	expect(!limits.get(6, got), "and nothing was added for it");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::puts("ok");
	return 0;
}
