#ifndef AUTHNULL_ADMIN_ERROR_H
#define AUTHNULL_ADMIN_ERROR_H

// The SQLSTATE of an error answered on the PostgreSQL admin interface.
//
// Admin errors are SQLite errors ("near \"x\": syntax error", "no such table: t") or ProxySQL's own
// ("ProxySQL already started"). Postgres clients and drivers read the SQLSTATE, so a syntax error is
// 42601, an unknown table 42P01, an unknown column 42703, and anything else XX000 (internal error).
// Every SQLite error used to read 28000 (invalid authorization). Used by SQLite3_to_Postgres and
// ProxySQL_Admin::send_error_msg_to_client. test/authnull/authnull_admin_error_test.cpp.

#include <cstring>

inline const char* authnullAdminSqlState(const char* msg) {
	if (!msg) return "XX000";
	if (strstr(msg, "syntax error") || strstr(msg, "incomplete input")) return "42601";
	if (strstr(msg, "no such table")) return "42P01";
	if (strstr(msg, "no such column")) return "42703";
	return "XX000";
}

// authnullAdminErrorCode is the same answer as a PGSQL_ERROR_CODES value, for generate_error_packet()
// (a template so the test needs no PgSQL_Error_Helper.h).
template <typename Codes>
inline Codes authnullAdminErrorCode(const char* msg) {
	const char* st = authnullAdminSqlState(msg);
	if (strcmp(st, "42601") == 0) return Codes::ERRCODE_SYNTAX_ERROR;
	if (strcmp(st, "42P01") == 0) return Codes::ERRCODE_UNDEFINED_TABLE;
	if (strcmp(st, "42703") == 0) return Codes::ERRCODE_UNDEFINED_COLUMN;
	return Codes::ERRCODE_INTERNAL_ERROR;
}

#endif
