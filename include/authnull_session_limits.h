#ifndef AUTHNULL_SESSION_LIMITS_H
#define AUTHNULL_SESSION_LIMITS_H

// Session controls for database logins (conditional access: session controls).
//
// A policy can limit the sessions it lets in: actions.session.maxDurationMinutes and
// idleTimeoutMinutes, which the SSH proxy already enforces. authn-service now sends them to
// ProxySQL with the authorization payload, as credentialSubject.session, and ProxySQL closes a
// session that reaches either:
//
//   - the thread's maintenance pass (PgSQL_Thread::ProcessAllSessions_MaintenanceLoop) checks
//     every session regularly, so an idle or over-long session is closed even if the client never
//     sends another query;
//   - the query path checks the maximum length again before each query, so an expired session
//     cannot run one more statement between two passes.
//
// Idle time is ProxySQL's own measure (PgSQL_Session::IdleTime: time since the client last sent or
// received anything, zero while a query runs), so a long-running query is not "idle".
//
// The rules and the JSON reading are pure functions; the registry is a mutex-guarded map keyed by
// the session's thread_session_id (unique for the process). test/authnull/authnull_session_limits_test.cpp.

#include <mutex>
#include <string>
#include <unordered_map>

#include "../deps/json/json.hpp"

struct AuthnullSessionLimit {
	long long started_s = 0; // when the session was let in (Unix seconds)
	int max_minutes = 0;     // 0: no limit
	int idle_minutes = 0;    // 0: no limit
	long long ends_s = 0;    // an access grant's end, Unix seconds; 0: none
};

// authnullSessionLimitFromJSON reads credentialSubject.session: the policy's limits, and endsAt --
// the end of the access grant the login was let through on (authnull-service
// docs/DB-ACCESS-REQUESTS.md). False when it carries no limit.
inline bool authnullSessionLimitFromJSON(const nlohmann::json& cs, int& max_minutes, int& idle_minutes, long long& ends_s) {
	max_minutes = idle_minutes = 0;
	ends_s = 0;
	if (!cs.is_object() || !cs.contains("session") || !cs["session"].is_object()) return false;
	const nlohmann::json& s = cs["session"];
	auto read = [&s](const char* k) -> int {
		if (!s.contains(k) || !s[k].is_number_integer()) return 0;
		long long v = s[k].get<long long>();
		if (v <= 0) return 0;
		return v > 525600 ? 525600 : static_cast<int>(v); // at most a year
	};
	max_minutes = read("maxDurationMinutes");
	idle_minutes = read("idleTimeoutMinutes");
	if (s.contains("endsAt") && s["endsAt"].is_number_integer() && s["endsAt"].get<long long>() > 0) {
		ends_s = s["endsAt"].get<long long>();
	}
	return max_minutes > 0 || idle_minutes > 0 || ends_s > 0;
}

inline bool authnullSessionLimitFromJSON(const nlohmann::json& cs, int& max_minutes, int& idle_minutes) {
	long long ends_s = 0;
	bool any = authnullSessionLimitFromJSON(cs, max_minutes, idle_minutes, ends_s);
	return any && (max_minutes > 0 || idle_minutes > 0);
}

// authnullSessionLimitReason says why the session must end now, or "" when it may go on.
// idle_ms is how long the client has been idle (0 while a query runs, or when not measured).
inline std::string authnullSessionLimitReason(const AuthnullSessionLimit& l, long long now_s, unsigned long long idle_ms) {
	if (l.max_minutes > 0 && now_s - l.started_s >= static_cast<long long>(l.max_minutes) * 60) {
		return "the policy's maximum session length (" + std::to_string(l.max_minutes) + " min) was reached";
	}
	if (l.idle_minutes > 0 && idle_ms / 1000 >= static_cast<unsigned long long>(l.idle_minutes) * 60) {
		return "idle for longer than the policy's idle timeout (" + std::to_string(l.idle_minutes) + " min)";
	}
	if (l.ends_s > 0 && now_s >= l.ends_s) {
		return "the access grant it was approved on has ended";
	}
	return "";
}

// AuthnullSessionLimits holds the limits of the sessions that have any.
class AuthnullSessionLimits {
public:
	void set(unsigned long long id, const AuthnullSessionLimit& l) {
		std::lock_guard<std::mutex> lock(mu_);
		m_[id] = l;
	}
	bool get(unsigned long long id, AuthnullSessionLimit& out) {
		std::lock_guard<std::mutex> lock(mu_);
		auto it = m_.find(id);
		if (it == m_.end()) return false;
		out = it->second;
		return true;
	}
	// set_ends moves the access-grant end of a session that has limits (authnull_session_ends.h);
	// false, and nothing added, for one that has none.
	bool set_ends(unsigned long long id, long long ends_s) {
		std::lock_guard<std::mutex> lock(mu_);
		auto it = m_.find(id);
		if (it == m_.end()) return false;
		it->second.ends_s = ends_s;
		return true;
	}
	void erase(unsigned long long id) {
		std::lock_guard<std::mutex> lock(mu_);
		m_.erase(id);
	}
	size_t size() {
		std::lock_guard<std::mutex> lock(mu_);
		return m_.size();
	}

private:
	std::mutex mu_;
	std::unordered_map<unsigned long long, AuthnullSessionLimit> m_;
};

inline AuthnullSessionLimits& authnullSessionLimits() {
	static AuthnullSessionLimits l;
	return l;
}

// The MySQL sessions' limits: ProxySQL numbers its MySQL and PostgreSQL sessions separately, so the
// same id names two sessions and each engine keeps its own registry.
inline AuthnullSessionLimits& authnullMySQLSessionLimits() {
	static AuthnullSessionLimits l;
	return l;
}

#endif // AUTHNULL_SESSION_LIMITS_H
