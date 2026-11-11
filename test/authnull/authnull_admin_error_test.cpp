// Standalone test for include/authnull_admin_error.h. Run from the repository root:
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_admin_error_test.cpp -o /tmp/authnull_admin_error_test && /tmp/authnull_admin_error_test
//
// An error on the PostgreSQL admin interface is answered with an ErrorResponse whose SQLSTATE says
// what went wrong: a syntax error, an unknown table or column, or (anything else) an internal error.
// It used to be 28000 (invalid authorization) for every SQLite error.
#include "authnull_admin_error.h"

#include <cstdio>
#include <cstring>

static int failures = 0;
static void expect_state(const char* msg, const char* want) {
	const char* got = authnullAdminSqlState(msg);
	if (!got || std::strcmp(got, want) != 0) {
		std::fprintf(stderr, "FAIL \"%s\": want %s, got %s\n", msg ? msg : "(null)", want, got ? got : "(null)");
		failures++;
	}
}

// Stands in for PGSQL_ERROR_CODES (PgSQL_Error_Helper.h), which needs the rest of ProxySQL.
enum class FakeCodes { ERRCODE_SYNTAX_ERROR, ERRCODE_UNDEFINED_TABLE, ERRCODE_UNDEFINED_COLUMN, ERRCODE_INTERNAL_ERROR };

int main() {
	expect_state("ProxySQL Admin Error: near \"nonsense\": syntax error", "42601");
	expect_state("near \"LOAD\": syntax error", "42601");
	expect_state("incomplete input", "42601");
	expect_state("ProxySQL Admin Error: no such table: nosuch_table", "42P01");
	expect_state("no such column: nosuch", "42703");
	expect_state("ProxySQL already started", "XX000");
	expect_state("Unknown thread id: 99999", "XX000");
	expect_state("ProxySQL Admin Error: Cannot extract configuration", "XX000");
	expect_state("", "XX000");
	expect_state(nullptr, "XX000");
	if (authnullAdminErrorCode<FakeCodes>("near \"x\": syntax error") != FakeCodes::ERRCODE_SYNTAX_ERROR) { std::fputs("FAIL code syntax\n", stderr); failures++; }
	if (authnullAdminErrorCode<FakeCodes>("no such table: t") != FakeCodes::ERRCODE_UNDEFINED_TABLE) { std::fputs("FAIL code table\n", stderr); failures++; }
	if (authnullAdminErrorCode<FakeCodes>("no such column: c") != FakeCodes::ERRCODE_UNDEFINED_COLUMN) { std::fputs("FAIL code column\n", stderr); failures++; }
	if (authnullAdminErrorCode<FakeCodes>("ProxySQL already started") != FakeCodes::ERRCODE_INTERNAL_ERROR) { std::fputs("FAIL code other\n", stderr); failures++; }
	if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
	std::puts("ok");
	return 0;
}
