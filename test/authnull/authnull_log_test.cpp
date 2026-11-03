// Standalone test for include/authnull_log.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_log_test.cpp -o /tmp/authnull_log_test && /tmp/authnull_log_test
#include "authnull_log.h"

#include <cstdio>
#include <string>

static int failures = 0;

static void expect(bool cond, const char* what) {
	if (!cond) { std::fprintf(stderr, "FAIL %s\n", what); failures++; }
}

int main() {
	// The connection token is a bearer credential: it was logged in full at INFO on every login.
	const std::string token = "51e294dc-2c0d-40ae-87ce-18e1f5dba5de";
	std::string h = authnullTokenHint(token);
	expect(h.find("18e1f5dba5de") == std::string::npos, "hint must not carry the token");
	expect(h.rfind("51e294dc", 0) == 0, "hint starts with the first 8 characters");
	expect(h.size() <= 12, "hint is short");
	expect(authnullTokenHint("") == "(none)", "empty token");
	expect(authnullTokenHint("abc").find("abc") == std::string::npos, "a short token is not shown whole");

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
