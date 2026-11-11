#ifndef AUTHNULL_LOGIN_ANSWER_H
#define AUTHNULL_LOGIN_ANSWER_H

// A database login's question to authn-service (do-authenticationV4), and how its answer is judged.
//
// The MySQL login (MySQL_Session) builds its request and judges the answer here; the call itself
// runs off the worker thread (authnull_mfa_call.h). The rules are the PostgreSQL path's
// (PgSQL_Protocol.cpp): anything but an explicit, complete approval denies -- a timeout, an HTTP
// error, an unreadable body, isValid that is not boolean true, or an approval missing the database,
// the privileges or the field-masking map. A refusal's message is kept for the client
// (authnull_refusal.h). An approval brings the policy's session controls (authnull_session_limits.h)
// and whether to record the session (authnull_recording.h).
// test/authnull/authnull_login_answer_test.cpp.

#include <map>
#include <string>
#include <vector>

#include "../deps/json/json.hpp"

// authnullLoginRequest is the request body. token is the connection token the client sent
// ("user,token"); it is a bearer credential and is never logged.
inline std::string authnullLoginRequest(const std::string& engine, int org_id, int tenant_id, const std::string& user,
		const std::string& client_ip, const std::string& proxy_ip, const std::string& database, const std::string& token,
		unsigned long long proxy_session_id, long long now_s) {
	nlohmann::json req = {
		{"username", user},
		{"credentialType", "DATABASE"},
		{"orgId", org_id},
		{"tenantId", tenant_id},
		{"requestId", ""},
		{"dbUser", user},
		{"userIp", client_ip},
		{"database_host", proxy_ip},
		{"hostname", database},
		{"databaseType", engine},
		{"databaseName", database},
		{"token", token},
		// The access log keeps it, so the session ProxySQL's process list shows can be named
		// (authnull-service docs/DB-LIVE-SESSIONS.md).
		{"proxySessionId", proxy_session_id},
		{"timestamp", now_s},
	};
	return req.dump();
}

struct AuthnullLoginAnswer {
	bool approved = false;
	std::string why;     // for the log, when not approved
	std::string refusal; // authn-service's message for the client, when it refused
	std::string database;
	std::vector<std::string> privileges;
	std::vector<std::string> tables;
	std::map<std::string, std::vector<std::string>> masking; // table -> masked columns
	bool has_limits = false;
	int max_minutes = 0, idle_minutes = 0;
	long long ends_s = 0;
	bool record = false;
};

// authnullJudgeLoginAnswer reads the call's outcome: curl_code (CURLcode; -1 when it never ran),
// the HTTP status and the body.
inline AuthnullLoginAnswer authnullJudgeLoginAnswer(int curl_code, long http_code, const std::string& body) {
	AuthnullLoginAnswer a;
	if (curl_code != 0) {
		a.why = curl_code < 0 ? "the MFA call could not be made" : "the MFA call failed (curl " + std::to_string(curl_code) + ")";
		return a;
	}
	if (http_code < 200 || http_code >= 300) {
		a.why = "authn-service answered HTTP " + std::to_string(http_code);
		return a;
	}
	nlohmann::json r;
	try {
		r = nlohmann::json::parse(body);
	} catch (const nlohmann::json::exception&) {
		a.why = "authn-service's answer is not JSON";
		return a;
	}
	if (!r.is_object() || !r.contains("isValid") || !r["isValid"].is_boolean() || !r["isValid"].get<bool>()) {
		a.why = "refused by authn-service";
		if (r.is_object() && r.contains("message") && r["message"].is_string()) {
			a.refusal = r["message"].get<std::string>();
		}
		return a;
	}
	const nlohmann::json* cs = nullptr;
	if (r.contains("credential") && r["credential"].is_object() && r["credential"].contains("credentialSubject") &&
		r["credential"]["credentialSubject"].is_object()) {
		cs = &r["credential"]["credentialSubject"];
	} else if (r.contains("credentialSubject") && r["credentialSubject"].is_object()) {
		cs = &r["credentialSubject"];
	}
	// An approval alone opens nothing: without the privileges and the masking map the session would
	// run unrestricted and unmasked.
	if (cs == nullptr) {
		a.why = "approved, but the answer carries no credentialSubject";
		return a;
	}
	const nlohmann::json& c = *cs;
	if (!c.contains("databaseName") || !c["databaseName"].is_string()) {
		a.why = "approved, but credentialSubject has no databaseName";
		return a;
	}
	try {
		if (c.contains("privilege") && c["privilege"].is_array()) {
			a.privileges = c["privilege"].get<std::vector<std::string>>();
		}
		if (c.contains("tables") && c["tables"].is_array()) {
			a.tables = c["tables"].get<std::vector<std::string>>();
		}
	} catch (const nlohmann::json::exception&) {
		a.privileges.clear();
	}
	if (a.privileges.empty()) {
		a.why = "approved, but no privileges were returned";
		return a;
	}
	if (!c.contains("fieldMasking") || !c["fieldMasking"].is_object()) {
		a.why = "approved, but credentialSubject has no fieldMasking object";
		return a;
	}
	const nlohmann::json& fm = c["fieldMasking"];
	for (const auto& t : a.tables) {
		if (fm.contains(t) && fm[t].is_array()) {
			try {
				a.masking[t] = fm[t].get<std::vector<std::string>>();
			} catch (const nlohmann::json::exception&) {
				a.masking[t] = {};
			}
		} else {
			a.masking[t] = {};
		}
	}
	a.database = c["databaseName"].get<std::string>();
	if (c.contains("session") && c["session"].is_object()) {
		const nlohmann::json& s = c["session"];
		auto minutes = [&s](const char* k) -> int {
			if (!s.contains(k) || !s[k].is_number_integer()) return 0;
			long long v = s[k].get<long long>();
			if (v <= 0) return 0;
			return v > 525600 ? 525600 : static_cast<int>(v);
		};
		a.max_minutes = minutes("maxDurationMinutes");
		a.idle_minutes = minutes("idleTimeoutMinutes");
		if (s.contains("endsAt") && s["endsAt"].is_number_integer() && s["endsAt"].get<long long>() > 0) {
			a.ends_s = s["endsAt"].get<long long>();
		}
		a.has_limits = a.max_minutes > 0 || a.idle_minutes > 0 || a.ends_s > 0;
		a.record = s.contains("record") && s["record"].is_boolean() && s["record"].get<bool>();
	}
	a.approved = true;
	return a;
}

#endif // AUTHNULL_LOGIN_ANSWER_H
