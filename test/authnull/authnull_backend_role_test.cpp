// Standalone test for include/authnull_backend_role.h. Needs OpenSSL's libcrypto, nothing of ProxySQL:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_backend_role_test.cpp -lcrypto -o /tmp/authnull_backend_role_test && /tmp/authnull_backend_role_test
//
// Exits non-zero on any failure.
#include "authnull_backend_role.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

static void expect(bool cond, const std::string& what) {
	if (!cond) {
		std::fprintf(stderr, "FAIL %s\n", what.c_str());
		failures++;
	}
}

static std::string name(const std::string& db, const std::string& role,
	const std::vector<std::string>& privs, const std::vector<std::string>& tables, bool* okOut = nullptr) {
	std::string out;
	bool ok = authnullBackendRoleName(db, role, privs, tables, out);
	if (okOut) *okOut = ok;
	return ok ? out : "";
}

int main() {
	// The vectors database-agent asserts (src/pkg/backendrole_test.go), computed independently in
	// Python before either implementation. The agent creates the role under this name and ProxySQL
	// looks it up under this name: they must agree exactly.
	const std::vector<std::string> four = {"customers", "employees", "orders", "priv_scratch"};
	expect(name("dbmfa_test", "dbmfa_writer", {"READ"}, four) == "an_8f3a1492e83ffc13", "vector READ");
	expect(name("dbmfa_test", "dbmfa_writer", {"READ", "WRITE"}, four) == "an_7722746c2680046f", "vector READ,WRITE");
	expect(name("salesdb", "readonly_app", {"READ"}, {}) == "an_2f3f12694f5ff113", "vector no tables");

	// Canonical: case, order, duplicates and surrounding space do not change the name.
	expect(name("DBMFA_TEST ", "dbmfa_writer", {"write", "READ", "READ"}, {"Orders", "customers", " employees", "priv_scratch"})
		== "an_7722746c2680046f", "canonical form");
	expect(name("d", "r", {"READ"}, {"Sales . Orders"}) == name("d", "r", {"READ"}, {"sales.orders"}), "schema-qualified table");
	expect(name("d", "r", {"READ"}, {"public.t"}) == name("d", "r", {"READ"}, {"t"}), "public schema is the bare name");

	// Custom privileges (AUTH-227): verbs. A verb set that is exactly whole groups keeps its v1 name
	// (SELECT is READ; SELECT, INSERT, UPDATE, DELETE is READ, WRITE), so roles made before verbs
	// reached ProxySQL stay valid; any other set is v2, over the sorted verbs. Vectors computed in
	// Python; database-agent asserts the same.
	expect(name("dbmfa_test", "dbmfa_writer", {"SELECT"}, four) == "an_8f3a1492e83ffc13", "SELECT is READ's role");
	expect(name("dbmfa_test", "dbmfa_writer", {"SELECT", "INSERT", "UPDATE", "DELETE"}, four) == "an_7722746c2680046f",
		"all four verbs are READ,WRITE's role");
	expect(name("dbmfa_test", "dbmfa_writer", {"READ", "INSERT", "UPDATE", "DELETE"}, four) == "an_7722746c2680046f", "mixed, whole groups");
	expect(name("dbmfa_test", "dbmfa_writer", {"SELECT", "INSERT"}, four) == "an_f0e09c5084ba5b55", "vector v2 SELECT,INSERT");
	expect(name("dbmfa_test", "dbmfa_writer", {"read", " insert"}, four) == "an_f0e09c5084ba5b55", "READ,INSERT is SELECT,INSERT");
	expect(name("salesdb", "readonly_app", {"UPDATE", "TRUNCATE", "SELECT"}, {}) == "an_937b3d2d6c1ba244", "vector v2 with TRUNCATE");

	// No restricted role when EXECUTE is granted, a privilege is unknown, or none is given.
	bool ok = true;
	name("d", "r", {"READ", "EXECUTE"}, {"t"}, &ok); expect(!ok, "EXECUTE keeps the policy's role");
	name("d", "r", {"EXECUTE"}, {"t"}, &ok); expect(!ok, "EXECUTE only");
	name("d", "r", {}, {"t"}, &ok); expect(!ok, "no privileges");
	name("d", "r", {"READ", "ADMIN"}, {"t"}, &ok); expect(!ok, "unknown privilege");

	// A just-in-time account (authnull-service docs/DB-JIT-ACCOUNTS.md) already holds exactly the
	// policy's privileges: it gets no restricted role, so the session runs as the account itself --
	// whatever backend_roles says (enforce would otherwise refuse every such login).
	ok = true;
	name("dbmfa_test", "jit_sathyam_e2e0a11c", {"READ"}, four, &ok);
	expect(!ok, "a jit_ account gets no restricted role");
	name("dbmfa_test", "JIT_Dev_3f9a2c1e", {"SELECT", "INSERT"}, {}, &ok);
	expect(!ok, "jit_ in any case gets no restricted role");
	name("dbmfa_test", " jit_dev_3f9a2c1e", {"READ"}, {}, &ok);
	expect(!ok, "a jit_ account with surrounding space gets no restricted role");
	// Only the prefix: other names are unchanged.
	name("dbmfa_test", "jitter", {"READ"}, {}, &ok);
	expect(ok, "jitter is not a jit_ account");
	name("dbmfa_test", "app_jit_rw", {"READ"}, {}, &ok);
	expect(ok, "a role with jit_ inside is not a jit_ account");

	// Mode setting: prefer unless it says otherwise.
	expect(authnullParseBackendRoleMode("") == AuthnullBackendRoleMode::Prefer, "empty is prefer");
	expect(authnullParseBackendRoleMode("prefer") == AuthnullBackendRoleMode::Prefer, "prefer");
	expect(authnullParseBackendRoleMode(" ENFORCE ") == AuthnullBackendRoleMode::Enforce, "enforce");
	expect(authnullParseBackendRoleMode("off") == AuthnullBackendRoleMode::Off, "off");
	expect(authnullParseBackendRoleMode("bogus") == AuthnullBackendRoleMode::Prefer, "unknown is prefer");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::puts("ok");
	return 0;
}
