// Standalone test for include/authnull_refusal.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_refusal_test.cpp -o /tmp/authnull_refusal_test && /tmp/authnull_refusal_test
//
// A database login authn-service refuses used to reach the client as the bare "Access denied for
// user ..." -- the reason ("request access in the AuthNull console", "blocked by policy") was only
// in ProxySQL's log. The person now reads it.
#include "authnull_refusal.h"

#include <cstdio>
#include <string>

static int failures = 0;
static void expect(bool ok, const char* what) {
	if (!ok) {
		std::fprintf(stderr, "FAIL %s\n", what);
		failures++;
	}
}

int main() {
	const std::string base = "ProxySQL Error: Access denied for user 'dbmfa_writer'@'172.18.0.11' (using password: YES)";
	expect(authnullDeniedMessage(base, "") == base, "no reason: as before");
	expect(authnullDeniedMessage(base, "   ") == base, "a blank reason: as before");
	expect(authnullDeniedMessage(base, "this database needs an approved access request: request access in the AuthNull console") ==
		base + ": this database needs an approved access request: request access in the AuthNull console", "the reason follows");
	// What reaches a client's terminal is text: no control characters, and bounded.
	std::string ctl = authnullDeniedMessage(base, "line one\nline two\r\x1b[31mred\x07");
	expect(ctl.find('\n') == std::string::npos && ctl.find('\r') == std::string::npos && ctl.find('\x1b') == std::string::npos &&
		ctl.find('\x07') == std::string::npos, "control characters removed");
	expect(ctl.find("line one line two") != std::string::npos, "newlines become spaces");
	std::string longer = authnullDeniedMessage(base, std::string(1000, 'x'));
	expect(longer.size() <= base.size() + 2 + kAuthnullRefusalMax + 3, "bounded");
	expect(longer.substr(longer.size() - 3) == "...", "marked as cut");

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
