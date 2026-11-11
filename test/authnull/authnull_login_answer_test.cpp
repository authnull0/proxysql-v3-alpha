// Standalone test for include/authnull_login_answer.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_login_answer_test.cpp -o /tmp/authnull_login_answer_test && /tmp/authnull_login_answer_test
//
// The MySQL login asks authn-service the same question as the PostgreSQL one and must judge the
// answer the same way: anything but an explicit, complete approval denies; a refusal's message is
// kept for the client; the policy's session controls and recording flag come with an approval.
#include "authnull_login_answer.h"

#include <cstdio>
#include <string>

static int failures = 0;
static void expect(bool ok, const std::string& what) {
	if (!ok) { std::fprintf(stderr, "FAIL %s\n", what.c_str()); failures++; }
}

static AuthnullLoginAnswer judge(int curl, long http, const std::string& body) {
	return authnullJudgeLoginAnswer(curl, http, body);
}

int main() {
	using nlohmann::json;

	// The request: what both engines send, with this session's id and the engine named.
	json req = json::parse(authnullLoginRequest("mysql", 2, 1, "app_rw", "10.0.0.5", "10.0.0.1", "shop", "tok-1", 4242, 1794300000));
	expect(req["databaseType"] == "mysql" && req["dbUser"] == "app_rw" && req["username"] == "app_rw" && req["userIp"] == "10.0.0.5" &&
		req["database_host"] == "10.0.0.1" && req["databaseName"] == "shop" && req["hostname"] == "shop" && req["token"] == "tok-1" &&
		req["proxySessionId"] == 4242 && req["orgId"] == 2 && req["tenantId"] == 1 && req["credentialType"] == "DATABASE" &&
		req["timestamp"] == 1794300000, "request: " + req.dump());

	// An approval with everything a session needs.
	std::string ok = R"({"isValid":true,"credentialSubject":{"databaseName":"shop","privilege":["SELECT","INSERT"],"tables":["orders"],
		"fieldMasking":{"orders":["card"]},"session":{"maxDurationMinutes":30,"idleTimeoutMinutes":5,"endsAt":1794312000,"record":true}}})";
	AuthnullLoginAnswer a = judge(0, 200, ok);
	expect(a.approved && a.database == "shop" && a.privileges.size() == 2 && a.tables.size() == 1 &&
		a.masking["orders"].size() == 1 && a.masking["orders"][0] == "card", "approval: " + a.why);
	expect(a.has_limits && a.max_minutes == 30 && a.idle_minutes == 5 && a.ends_s == 1794312000 && a.record, "session controls");
	// The legacy shape: under credential.credentialSubject.
	a = judge(0, 200, R"({"isValid":true,"credential":{"credentialSubject":{"databaseName":"shop","privilege":["READ"],"fieldMasking":{}}}})");
	expect(a.approved && !a.has_limits && !a.record, "legacy shape: " + a.why);

	// A refusal keeps authn-service's message for the client.
	a = judge(0, 200, R"({"isValid":false,"message":"this database needs an approved access request: request access in the AuthNull console"})");
	expect(!a.approved && a.refusal.find("approved access request") != std::string::npos, "refusal message: " + a.refusal);

	// Everything else denies, with no message for the client.
	for (const auto& c : {
		std::make_tuple(28, 0L, std::string("")),                                                   // timeout
		std::make_tuple(0, 500L, std::string(R"({"isValid":true})")),                               // HTTP error
		std::make_tuple(0, 200L, std::string("not json")),
		std::make_tuple(0, 200L, std::string(R"({"isValid":"true"})")),
		std::make_tuple(0, 200L, std::string(R"({"isValid":true})")),                               // no credentialSubject
		std::make_tuple(0, 200L, std::string(R"({"isValid":true,"credentialSubject":{"privilege":["READ"],"fieldMasking":{}}})")),
		std::make_tuple(0, 200L, std::string(R"({"isValid":true,"credentialSubject":{"databaseName":"shop","privilege":[],"fieldMasking":{}}})")),
		std::make_tuple(0, 200L, std::string(R"({"isValid":true,"credentialSubject":{"databaseName":"shop","privilege":["READ"]}})")),
		std::make_tuple(-1, 0L, std::string("")),                                                   // never ran
	}) {
		a = judge(std::get<0>(c), std::get<1>(c), std::get<2>(c));
		expect(!a.approved && a.refusal.empty() && !a.why.empty(), "deny: " + std::get<2>(c) + " -> " + a.why);
	}

	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
