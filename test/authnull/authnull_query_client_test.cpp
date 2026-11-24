// Standalone test for include/authnull_query.h: what desktop clients send on their own.
//
//   g++ -std=c++17 -Wall -Wextra -Iinclude test/authnull/authnull_query_client_test.cpp -o /tmp/authnull_query_client_test && /tmp/authnull_query_client_test
//
// pgAdmin, DBeaver and the JDBC / libpq drivers set up every connection with statements nobody
// typed: SET DateStyle, set_config('bytea_output', ...), SET NAMES, BEGIN / COMMIT, USE. These used
// to need EXECUTE (anything not a read or a write did), so a session granted SELECT could not open
// in pgAdmin at all, and the console hid pgAdmin unless a policy granted READ, WRITE and EXECUTE.
// Session housekeeping needs no privilege now -- except what changes who the session is (SET ROLE,
// SESSION AUTHORIZATION, set_config('role', ...)) or reaches past it (SET GLOBAL, SET PASSWORD),
// and whatever a SET reads or calls still counts.
//
// Exits non-zero on any failure.
#include "authnull_query.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

using P = std::vector<std::string>;
static const P SELECT_ONLY = {"SELECT"};
static const P INSERT_ONLY = {"INSERT"};

static void permits(AuthnullDialect d, const P& granted, const std::string& sql, bool want, const char* why) {
	bool got = authnullQueryPermitted(granted, sql, d);
	if (got != want) {
		std::fprintf(stderr, "FAIL [%s] %s\n  sql: %s\n  got %s, want %s\n",
			d == AuthnullDialect::Postgres ? "pg" : "mysql", why, sql.c_str(),
			got ? "permitted" : "refused", want ? "permitted" : "refused");
		failures++;
	}
}

int main() {
	const auto PG = AuthnullDialect::Postgres;
	const auto MY = AuthnullDialect::MySQL;

	// --- pgAdmin 4 and libpq / JDBC on connect (PostgreSQL), as a SELECT-only session ---
	permits(PG, SELECT_ONLY, "SET DateStyle=ISO; SET client_min_messages=notice; SET client_encoding='utf-8';",
		true, "pgAdmin connect SETs");
	permits(PG, SELECT_ONLY, "SELECT set_config('bytea_output','hex',false) FROM pg_show_all_settings() WHERE name = 'bytea_output'",
		true, "pgAdmin set_config(bytea_output)");
	permits(PG, SELECT_ONLY, "SET application_name = 'DBeaver 24.1 - Main'", true, "DBeaver application_name");
	permits(PG, SELECT_ONLY, "SET extra_float_digits = 3", true, "JDBC extra_float_digits");
	permits(PG, SELECT_ONLY, "SET search_path = public, \"$user\"", true, "search_path");
	permits(PG, SELECT_ONLY, "SET statement_timeout TO 30000", true, "SET ... TO");
	permits(PG, SELECT_ONLY, "SET SESSION TimeZone = 'UTC'", true, "SET SESSION setting");
	permits(PG, SELECT_ONLY, "SET LOCAL lock_timeout = '5s'", true, "SET LOCAL setting");
	permits(PG, SELECT_ONLY, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", true, "SET TRANSACTION");
	permits(PG, SELECT_ONLY, "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", true, "SESSION CHARACTERISTICS");
	permits(PG, SELECT_ONLY, "RESET search_path", true, "RESET a setting");
	permits(PG, SELECT_ONLY, "DISCARD ALL", true, "DISCARD ALL");
	permits(PG, SELECT_ONLY, "DEALLOCATE ALL", true, "DEALLOCATE ALL (psycopg 3 after ROLLBACK)");
	permits(PG, SELECT_ONLY, "deallocate prepare all;", true, "DEALLOCATE PREPARE ALL");
	permits(PG, SELECT_ONLY, "DEALLOCATE s1", false, "DEALLOCATE <name> stays EXECUTE");
	permits(PG, SELECT_ONLY, "DEALLOCATE prepare", false, "a statement named prepare");
	permits(PG, SELECT_ONLY, "DEALLOCATE ALL; DELETE FROM t", false, "a second statement still counts");
	permits(PG, SELECT_ONLY, "SHOW search_path", true, "SHOW stays SELECT");
	permits(PG, SELECT_ONLY, "SET TIME ZONE 'UTC'", true, "SET TIME ZONE");
	permits(PG, SELECT_ONLY, "SET NAMES 'UTF8'", true, "SET NAMES");

	// --- transactions, as a SELECT-only session ---
	permits(PG, SELECT_ONLY, "BEGIN", true, "BEGIN");
	permits(PG, SELECT_ONLY, "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE", true, "BEGIN TRANSACTION ...");
	permits(PG, SELECT_ONLY, "START TRANSACTION READ ONLY", true, "START TRANSACTION");
	permits(PG, SELECT_ONLY, "BEGIN; SELECT * FROM orders; COMMIT", true, "a read in a transaction");
	permits(PG, SELECT_ONLY, "COMMIT", true, "COMMIT");
	permits(PG, SELECT_ONLY, "END", true, "END");
	permits(PG, SELECT_ONLY, "ROLLBACK", true, "ROLLBACK");
	permits(PG, SELECT_ONLY, "ABORT", true, "ABORT");
	permits(PG, SELECT_ONLY, "SAVEPOINT s1", true, "SAVEPOINT");
	permits(PG, SELECT_ONLY, "ROLLBACK TO SAVEPOINT s1", true, "ROLLBACK TO");
	permits(PG, SELECT_ONLY, "RELEASE SAVEPOINT s1", true, "RELEASE");
	permits(PG, INSERT_ONLY, "BEGIN; INSERT INTO t VALUES (1); COMMIT", true, "an insert in a transaction");

	// --- still refused: housekeeping does not open a way round the grant ---
	permits(PG, SELECT_ONLY, "BEGIN; DELETE FROM orders; COMMIT", false, "a delete in a transaction");
	permits(PG, SELECT_ONLY, "SET ROLE postgres", false, "SET ROLE");
	permits(PG, SELECT_ONLY, "SET LOCAL ROLE app_admin", false, "SET LOCAL ROLE");
	permits(PG, SELECT_ONLY, "SET SESSION ROLE app_admin", false, "SET SESSION ROLE");
	permits(PG, SELECT_ONLY, "SET role = 'app_admin'", false, "SET role = (a setting named role)");
	permits(PG, SELECT_ONLY, "SET role TO app_admin", false, "SET role TO");
	permits(PG, SELECT_ONLY, "SET SESSION AUTHORIZATION app_admin", false, "SESSION AUTHORIZATION");
	permits(PG, SELECT_ONLY, "SET session_authorization = 'app_admin'", false, "session_authorization setting");
	permits(PG, SELECT_ONLY, "select set_config('role', 'app_admin', false)", false, "set_config(role)");
	permits(PG, SELECT_ONLY, "select set_config('ROLE', 'app_admin', false)", false, "set_config(ROLE), any case");
	permits(PG, SELECT_ONLY, "select set_config('session_authorization', 'x', false)", false, "set_config(session_authorization)");
	permits(PG, SELECT_ONLY, "select set_config(name, 'x', false) from params", false, "set_config with a name not written out");
	permits(PG, SELECT_ONLY, "select set_config(E'role', 'x', false)", false, "set_config(E'role')");
	// Only the settings clients send: one that loosens what the session may do is not housekeeping.
	permits(PG, SELECT_ONLY, "SET default_transaction_read_only = off", false, "loosening read-only");
	permits(PG, SELECT_ONLY, "select set_config('default_transaction_read_only','off',false)", false, "the same through set_config");
	permits(PG, SELECT_ONLY, "SET session_replication_role = replica", false, "a setting not on the list");
	permits(PG, SELECT_ONLY, "COMMIT PREPARED 'tx1'", false, "COMMIT PREPARED");
	permits(PG, SELECT_ONLY, "ROLLBACK PREPARED 'tx1'", false, "ROLLBACK PREPARED");
	permits(PG, SELECT_ONLY, "PREPARE TRANSACTION 'tx1'", false, "PREPARE TRANSACTION");
	permits(PG, SELECT_ONLY, "DO $$ BEGIN DELETE FROM orders; END $$", false, "a DO block");
	permits(PG, SELECT_ONLY, "BEGIN ATOMIC DELETE FROM orders; END", false, "BEGIN with something after it");
	permits(PG, SELECT_ONLY, "SET search_path = public; DELETE FROM orders", false, "a delete after a SET");
	permits(PG, SELECT_ONLY, "SELECT pg_terminate_backend(42)", false, "side-effect functions unchanged");

	// --- MySQL Connector/J and DBeaver on connect, as a SELECT-only session ---
	permits(MY, SELECT_ONLY, "SET NAMES utf8mb4", true, "SET NAMES");
	permits(MY, SELECT_ONLY, "SET character_set_results = NULL", true, "character_set_results");
	permits(MY, SELECT_ONLY, "SET autocommit=1", true, "autocommit");
	permits(MY, SELECT_ONLY, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED", true, "SET SESSION TRANSACTION");
	permits(MY, SELECT_ONLY, "SET SESSION sql_mode = 'STRICT_TRANS_TABLES'", true, "SET SESSION var");
	permits(MY, SELECT_ONLY, "SET @@session.wait_timeout = 600", true, "SET @@session.var");
	permits(MY, SELECT_ONLY, "SET @@sql_select_limit = DEFAULT", true, "SET @@var");
	permits(MY, SELECT_ONLY, "SET @a = 1", true, "user variable");
	permits(MY, SELECT_ONLY, "SET @n = (SELECT count(*) FROM orders)", true, "user variable from a read");
	permits(MY, SELECT_ONLY, "USE dbmfa_test", true, "USE");
	permits(MY, SELECT_ONLY, "START TRANSACTION", true, "START TRANSACTION");
	permits(MY, SELECT_ONLY, "BEGIN WORK", true, "BEGIN WORK");
	permits(MY, SELECT_ONLY, "COMMIT WORK AND NO CHAIN", true, "COMMIT ... CHAIN");
	permits(MY, SELECT_ONLY, "SHOW VARIABLES LIKE 'lower_case%'", true, "SHOW stays SELECT");

	// --- MySQL: still refused ---
	permits(MY, SELECT_ONLY, "SET GLOBAL max_connections = 1000", false, "SET GLOBAL");
	permits(MY, SELECT_ONLY, "SET @@global.max_connections = 1000", false, "SET @@global");
	permits(MY, SELECT_ONLY, "SET PERSIST max_connections = 1000", false, "SET PERSIST");
	permits(MY, SELECT_ONLY, "SET PERSIST_ONLY max_connections = 1000", false, "SET PERSIST_ONLY");
	permits(MY, SELECT_ONLY, "SET @@persist.max_connections = 1000", false, "SET @@persist");
	permits(MY, SELECT_ONLY, "SET PASSWORD = 'x'", false, "SET PASSWORD");
	permits(MY, SELECT_ONLY, "SET PASSWORD FOR 'u'@'%' = 'x'", false, "SET PASSWORD FOR");
	permits(MY, SELECT_ONLY, "SET ROLE ALL", false, "SET ROLE");
	permits(MY, SELECT_ONLY, "SET DEFAULT ROLE ALL TO 'u'@'%'", false, "SET DEFAULT ROLE");
	permits(MY, SELECT_ONLY, "SET RESOURCE GROUP rg", false, "SET RESOURCE GROUP");
	permits(MY, SELECT_ONLY, "SET sql_mode = 'x', GLOBAL max_connections = 5", false, "a GLOBAL among several");
	permits(MY, SELECT_ONLY, "SET @a = load_file('/etc/passwd')", false, "a side-effect function in a SET");
	permits(MY, SELECT_ONLY, "SET @a = (SELECT id FROM t FOR UPDATE)", false, "a row lock in a SET");
	permits(MY, INSERT_ONLY, "SET @n = (SELECT count(*) FROM orders)", false, "a read still needs SELECT");
	permits(MY, SELECT_ONLY, "BEGIN NOT ATOMIC DELETE FROM orders; END", false, "a MariaDB compound statement");
	permits(MY, SELECT_ONLY, "XA START 'x'", false, "XA");

	if (failures) {
		std::fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	std::printf("authnull_query_client_test: ok\n");
	return 0;
}
