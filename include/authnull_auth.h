// Which ProxySQL logins go through AuthNull MFA.
//
// Every login on a CLIENT port does -- the port databases are reached through (6133 Postgres,
// 6033 MySQL) -- whatever the username. ProxySQL's own interfaces (admin, stats, sqlite) do not:
// they authenticate against ProxySQL's credentials and carry no AuthNull token.
//
// The Postgres path used to decide this by USERNAME: a login named "admin" kept the password the
// client sent and never called AuthNull, on any port. The intent was the admin interface (6132),
// which shares this login code; the effect was that a database role called "admin", once in
// pgsql_users, reached the database on 6133 with its password alone. The MySQL path already decided
// by session type (MySQL_Session.cpp), which is what this does for both.
//
// session_type and client_session_type are ProxySQL's proxysql_session_type; it is a template
// parameter so the test needs no ProxySQL headers. username is deliberately not consulted.
#ifndef AUTHNULL_AUTH_H
#define AUTHNULL_AUTH_H

#include <string>

template <typename SessionType>
inline bool authnullRequiresMFA(SessionType session_type, SessionType client_session_type,
	const std::string& /* username: never an exemption */) {
	return session_type == client_session_type;
}

// authnullTokenLoginAccepted: whether a MySQL login passes ProxySQL's password check.
//
// The console's MySQL connection string is "-u<user>,<token> -p<token>": the token is the
// credential, and authn-service decides on it in the MFA call that follows. ProxySQL compares the
// client's password with the account's in mysql_users through MySQL's salted hash, so it can
// neither read the token there nor swap in the backend password the way the PostgreSQL path does
// (PgSQL_Protocol.cpp, pass2). The check therefore stands aside for exactly these logins: a client
// session, carrying a token, for a user ProxySQL has an account for -- and not part-way through an
// auth switch, where the final round decides. Everything else keeps the password check.
inline bool authnullTokenLoginAccepted(bool password_ok, bool auth_in_progress, bool client_session,
		bool has_token, bool account_exists) {
	if (password_ok) return true;
	return !auth_in_progress && client_session && has_token && account_exists;
}

#endif // AUTHNULL_AUTH_H
