// What AuthNull code may write to syslog about a credential.
//
// The connection token a client puts after the comma in its username ("<role>,<token>") is a bearer
// credential: within its lifetime it opens a session in the console user's name. It was logged in
// full -- at INFO, on every login -- so anyone who could read syslog could replay it. Log a hint
// instead: enough to match a log line to a connection string, not enough to use.
#ifndef AUTHNULL_LOG_H
#define AUTHNULL_LOG_H

#include <string>

inline std::string authnullTokenHint(const std::string& token) {
	if (token.empty()) return "(none)";
	if (token.size() <= 8) return "(short)";
	return token.substr(0, 8) + "...";
}

#endif // AUTHNULL_LOG_H
