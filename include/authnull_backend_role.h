// The restricted backend role for an approved database session.
//
// A policy's privileges were enforced only by ProxySQL reading the SQL text (authnull_query.h),
// which cannot see what a function does inside. For a policy whose privileges are READ and/or
// WRITE, database-agent creates a login role holding exactly those privileges on exactly the
// policy's tables and registers it in pgsql_users. After MFA approves a session, ProxySQL connects
// to Postgres as that role instead of the policy's own, so the database refuses what the policy
// did not grant (PgSQL_Protocol.cpp).
//
// Both sides derive the role's name from the policy's shape, independently:
//
//	"an_" + first 16 hex of SHA-256("v1|<db, lower>|<role>|<privileges, upper, sorted>|<tables, sorted>")
//
// where a table is lower case, its bare name in schema public and schema.table otherwise.
//
// Privileges may also be SQL verbs (custom privileges, AUTH-227): SELECT, INSERT, UPDATE, DELETE,
// TRUNCATE, with READ = SELECT and WRITE = INSERT, UPDATE, DELETE. A verb set that is exactly whole
// groups is named as those groups ("v1", above), so SELECT alone is READ's role; any other set is
//
//	"an_" + first 16 hex of SHA-256("v2|<db, lower>|<role>|<verbs, upper, sorted>|<tables, sorted>")
// database-agent's BackendRoleName (src/pkg/backendrole.go) computes the same; both test files
// assert the same vectors. EXECUTE in the privileges means no restricted role: DDL needs what the
// policy's own role holds.
//
// backend_roles in [authnull] (or AUTHNULL_BACKEND_ROLES) says what happens when the role is not
// in pgsql_users yet -- an agent not upgraded, a grant that failed:
//	prefer   (default) the policy's own role, with a warning
//	enforce  refuse the session
//	off      never switch
#ifndef AUTHNULL_BACKEND_ROLE_H
#define AUTHNULL_BACKEND_ROLE_H

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <vector>

#include <openssl/evp.h>

enum class AuthnullBackendRoleMode { Off, Prefer, Enforce };

inline AuthnullBackendRoleMode authnullParseBackendRoleMode(std::string v) {
	std::string s;
	for (char c : v) {
		if (!std::isspace(static_cast<unsigned char>(c))) s += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	if (s == "off") return AuthnullBackendRoleMode::Off;
	if (s == "enforce") return AuthnullBackendRoleMode::Enforce;
	return AuthnullBackendRoleMode::Prefer;
}

namespace authnull_backend_role_detail {

inline std::string trim(const std::string& s) {
	size_t a = 0, b = s.size();
	while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
	while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
	return s.substr(a, b - a);
}

inline std::string lower(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return s;
}

inline std::string upper(std::string s) {
	for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	return s;
}

inline std::string canonicalTable(const std::string& t) {
	std::string s = trim(t);
	size_t dot = s.find('.');
	std::string schema = "public", name = s;
	if (dot != std::string::npos) {
		schema = lower(trim(s.substr(0, dot)));
		name = trim(s.substr(dot + 1));
	}
	name = lower(name);
	return schema == "public" ? name : schema + "." + name;
}

inline bool sha256Hex(const std::string& in, std::string& out) {
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int len = 0;
	if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1) return false;
	static const char* hex = "0123456789abcdef";
	out.clear();
	for (unsigned int i = 0; i < len; i++) {
		out += hex[md[i] >> 4];
		out += hex[md[i] & 0xf];
	}
	return true;
}

} // namespace authnull_backend_role_detail

// authnullBackendRoleName sets out to the restricted role's name and returns true, or returns false
// when the session keeps the policy's own role (EXECUTE granted, an unknown privilege, none at all)
// -- or logs in as a just-in-time account (jit_..., authnull-service docs/DB-JIT-ACCOUNTS.md), which
// the backend created with exactly the policy's privileges and is its own restricted role.
inline bool authnullBackendRoleName(const std::string& database, const std::string& role,
	const std::vector<std::string>& privileges, const std::vector<std::string>& tables, std::string& out) {
	// Qualified, not a using-directive: ProxySQL has a global d::trim() that would make calls ambiguous.
	namespace d = authnull_backend_role_detail;
	if (d::lower(d::trim(role)).rfind("jit_", 0) == 0) return false;
	std::set<std::string> verbs;
	for (const auto& p : privileges) {
		std::string u = d::upper(d::trim(p));
		if (u == "READ") verbs.insert("SELECT");
		else if (u == "WRITE") { verbs.insert("INSERT"); verbs.insert("UPDATE"); verbs.insert("DELETE"); }
		else if (u == "SELECT" || u == "INSERT" || u == "UPDATE" || u == "DELETE" || u == "TRUNCATE") verbs.insert(u);
		else return false; // EXECUTE, or a privilege nobody knows
	}
	if (verbs.empty()) return false;
	// Whole groups keep the v1 name.
	bool read = verbs.count("SELECT") > 0;
	bool write = verbs.count("INSERT") && verbs.count("UPDATE") && verbs.count("DELETE");
	size_t grouped = (read ? 1 : 0) + (write ? 3 : 0);
	std::string version = "v2";
	std::set<std::string> privs = verbs;
	if (grouped == verbs.size()) {
		version = "v1";
		privs.clear();
		if (read) privs.insert("READ");
		if (write) privs.insert("WRITE");
	}

	std::set<std::string> ts;
	for (const auto& t : tables) {
		if (!d::trim(t).empty()) ts.insert(d::canonicalTable(t));
	}

	std::string canonical = version + "|" + d::lower(d::trim(database)) + "|" + d::trim(role) + "|";
	bool first = true;
	for (const auto& p : privs) { canonical += (first ? "" : ",") + p; first = false; }
	canonical += "|";
	first = true;
	for (const auto& t : ts) { canonical += (first ? "" : ",") + t; first = false; }

	std::string digest;
	if (!d::sha256Hex(canonical, digest)) return false;
	out = "an_" + digest.substr(0, 16);
	return true;
}

#endif // AUTHNULL_BACKEND_ROLE_H
