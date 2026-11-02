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

#endif // AUTHNULL_AUTH_H
