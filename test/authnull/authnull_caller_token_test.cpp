// Standalone test for include/authnull_caller_token.h. No ProxySQL build needed:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_caller_token_test.cpp -o /tmp/authnull_caller_token_test && /tmp/authnull_caller_token_test
#include "authnull_caller_token.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}

int main() {
	// The token endpoint's answer (authnull-service proxyauth.TokenHandler).
	{
		std::string t;
		long e = 0;
		expect(authnullParseTokenResponse(R"({"accessToken":"dpt.2.abc","tokenType":"Bearer","expiresIn":900,"expiresAt":"x"})", t, e)
			&& t == "dpt.2.abc" && e == 900, "a token response");
		expect(!authnullParseTokenResponse(R"({"error":"invalid client credentials"})", t, e), "an error response");
		expect(!authnullParseTokenResponse(R"({"accessToken":"gwt.2.abc","expiresIn":900})", t, e), "another component's token");
		expect(!authnullParseTokenResponse(R"({"accessToken":"dpt.2.abc","expiresIn":0})", t, e), "no lifetime");
		expect(!authnullParseTokenResponse(R"({"accessToken":"dpt.2.abc"})", t, e), "lifetime missing");
		expect(!authnullParseTokenResponse("<html>", t, e) && !authnullParseTokenResponse("", t, e), "not JSON");
	}

	long now = 1000;
	int fetches = 0;
	bool ok = true;
	std::vector<std::string> issued = {"dpt.2.a", "dpt.2.b", "dpt.2.c", "dpt.2.d"};
	AuthnullCallerToken cache(
		[&](std::string& t, long& in, std::string& err) {
			if (!ok) { err = "token endpoint answered 503"; fetches++; return false; }
			t = issued[fetches++ % issued.size()];
			in = 900;
			return true;
		},
		[&] { return now; });
	std::string err;

	// First login fetches; later ones reuse the token until a minute before it expires.
	expect(cache.get(err) == "dpt.2.a" && fetches == 1 && err.empty(), "first login fetches");
	now += 500;
	expect(cache.get(err) == "dpt.2.a" && fetches == 1, "reused while fresh");
	now += 341; // 1841: 59s left
	expect(cache.get(err) == "dpt.2.b" && fetches == 2, "refreshed a minute before expiry");

	// The endpoint goes down: the still-valid token keeps being sent, and the endpoint is asked
	// at most every 10 seconds.
	ok = false;
	now += 841; // 2682: 59s left of b's 2741
	expect(cache.get(err) == "dpt.2.b" && fetches == 3 && !err.empty(), "failed refresh keeps the valid token");
	now += 5;
	expect(cache.get(err) == "dpt.2.b" && fetches == 3, "no retry within 10 seconds");
	now += 60; // 2747: b has expired
	expect(cache.get(err).empty() && fetches == 4 && err.find("503") != std::string::npos, "expired and the endpoint down: no token, and why");
	now += 3;
	expect(cache.get(err).empty() && fetches == 4, "still backing off");

	// The endpoint is back.
	ok = true;
	now += 10;
	std::string c = cache.get(err);
	expect(!c.empty() && fetches == 5 && err.empty(), "recovers after the backoff");

	// authn-service refused the token (revoked): drop it, fetch a new one on the next login.
	cache.invalidate("dpt.2.other");
	expect(cache.get(err) == c && fetches == 5, "invalidating some other token changes nothing");
	cache.invalidate(c);
	std::string d = cache.get(err);
	expect(!d.empty() && d != c && fetches == 6, "invalidated token is replaced at once");

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
