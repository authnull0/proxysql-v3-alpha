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

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
