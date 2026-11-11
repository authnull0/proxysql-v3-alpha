// Standalone test for include/authnull_session_limits.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_session_limits_test.cpp -o /tmp/authnull_session_limits_test && /tmp/authnull_session_limits_test
#include "authnull_session_limits.h"

#include <cstdio>
#include <string>

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}

int main() {
	using nlohmann::json;
	int max = -1, idle = -1;

	// What authn-service sends (credentialSubject.session).
	expect(authnullSessionLimitFromJSON(json::parse(R"({"databaseName":"d","session":{"maxDurationMinutes":30,"idleTimeoutMinutes":5}})"), max, idle)
		&& max == 30 && idle == 5, "both limits");
	expect(authnullSessionLimitFromJSON(json::parse(R"({"session":{"idleTimeoutMinutes":10}})"), max, idle) && max == 0 && idle == 10, "idle only");
	expect(!authnullSessionLimitFromJSON(json::parse(R"({"databaseName":"d"})"), max, idle) && max == 0 && idle == 0, "no session block: no limits");
	expect(!authnullSessionLimitFromJSON(json::parse(R"({"session":{}})"), max, idle), "empty session block");
	expect(!authnullSessionLimitFromJSON(json::parse(R"({"session":{"maxDurationMinutes":-5,"idleTimeoutMinutes":"7"}})"), max, idle),
		"negative and non-integer values are no limit");
	expect(authnullSessionLimitFromJSON(json::parse(R"({"session":{"maxDurationMinutes":99999999}})"), max, idle) && max == 525600,
		"capped at a year");

	// The rules.
	AuthnullSessionLimit l;
	l.started_s = 1000;
	l.max_minutes = 30;
	l.idle_minutes = 5;
	expect(authnullSessionLimitReason(l, 1000 + 29 * 60, 0).empty(), "29 min in, busy");
	expect(authnullSessionLimitReason(l, 1000 + 30 * 60, 0).find("maximum session length") != std::string::npos, "30 min in: ended");
	expect(authnullSessionLimitReason(l, 1000 + 60, 4 * 60 * 1000ULL + 59999).empty(), "idle 4:59");
	expect(authnullSessionLimitReason(l, 1000 + 60, 5 * 60 * 1000ULL).find("idle") != std::string::npos, "idle 5:00: ended");
	AuthnullSessionLimit none;
	expect(authnullSessionLimitReason(none, 1LL << 40, ~0ULL).empty(), "no limits never ends a session");

	// The registry.
	AuthnullSessionLimits& r = authnullSessionLimits();
	AuthnullSessionLimit got;
	r.set(42, l);
	expect(r.get(42, got) && got.max_minutes == 30, "stored");
	expect(!r.get(43, got), "another session has none");
	r.erase(42);
	expect(!r.get(42, got) && r.size() == 0, "erased with the session");

	// An access grant's end (credentialSubject.session.endsAt, Unix seconds): the session ends then,
	// whatever the policy's own limits say (authnull-service docs/DB-ACCESS-REQUESTS.md).
	{
		int mx = 0, idle = 0;
		long long ends = 0;
		auto cs = json::parse(R"({"session":{"endsAt":1794312000}})");
		expect(authnullSessionLimitFromJSON(cs, mx, idle, ends), "endsAt alone is a limit");
		expect(ends == 1794312000 && mx == 0 && idle == 0, "endsAt read");
		cs = json::parse(R"({"session":{"endsAt":1794312000,"maxDurationMinutes":30}})");
		authnullSessionLimitFromJSON(cs, mx, idle, ends);
		expect(ends == 1794312000 && mx == 30, "endsAt beside the policy's limits");
		for (const char* bad : {R"({"session":{"endsAt":"soon"}})", R"({"session":{"endsAt":-5}})", R"({"session":{}})"}) {
			auto b = json::parse(bad);
			bool any = authnullSessionLimitFromJSON(b, mx, idle, ends);
			expect(!any && ends == 0, "an endsAt that does not read is no limit");
		}
		AuthnullSessionLimit l;
		l.started_s = 1794310000;
		l.ends_s = 1794312000;
		expect(authnullSessionLimitReason(l, 1794311999, 0).empty(), "before the grant's end");
		expect(authnullSessionLimitReason(l, 1794312000, 0).find("access grant") != std::string::npos, "at the grant's end");
		l.max_minutes = 10; // the policy's limit comes first
		expect(authnullSessionLimitReason(l, 1794310600, 0).find("maximum session") != std::string::npos, "the earlier limit");
	}

	// MySQL and PostgreSQL number their sessions separately: one id is two sessions, so each engine
	// keeps its own registry.
	{
		AuthnullSessionLimit pg, my, got;
		pg.max_minutes = 1;
		my.max_minutes = 2;
		authnullSessionLimits().set(777001, pg);
		authnullMySQLSessionLimits().set(777001, my);
		expect(authnullSessionLimits().get(777001, got) && got.max_minutes == 1, "the PostgreSQL entry");
		expect(authnullMySQLSessionLimits().get(777001, got) && got.max_minutes == 2, "the MySQL entry");
		authnullMySQLSessionLimits().erase(777001);
		expect(authnullSessionLimits().get(777001, got), "erasing MySQL's leaves PostgreSQL's");
		authnullSessionLimits().erase(777001);
	}

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
