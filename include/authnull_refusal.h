#ifndef AUTHNULL_REFUSAL_H
#define AUTHNULL_REFUSAL_H

// What a refused database login tells the client.
//
// authn-service's refusal carries a reason written for the person -- "this database needs an
// approved access request: request access in the AuthNull console", "access to this database is
// blocked by policy". It reached only ProxySQL's log; the client read the bare "Access denied for
// user ...", which says nothing about what to do. The session keeps the reason
// (PgSQL_Session::authnull_refusal, set in PgSQL_Protocol) and the error packet carries it after the
// usual text, which stays as it was for anything that matches on it.
//
// What reaches a client's terminal is text: control characters become spaces, and the reason is
// bounded. test/authnull/authnull_refusal_test.cpp.

#include <cctype>
#include <string>

static const size_t kAuthnullRefusalMax = 300;

inline std::string authnullDeniedMessage(const std::string& base, const std::string& reason) {
	std::string r;
	for (char c : reason) {
		unsigned char u = static_cast<unsigned char>(c);
		r += (u < 0x20 || u == 0x7f) ? ' ' : c;
	}
	size_t a = r.find_first_not_of(' ');
	if (a == std::string::npos) return base;
	size_t b = r.find_last_not_of(' ');
	r = r.substr(a, b - a + 1);
	// collapse the runs the replaced characters leave
	std::string out;
	for (char c : r) {
		if (c == ' ' && !out.empty() && out.back() == ' ') continue;
		out += c;
	}
	if (out.size() > kAuthnullRefusalMax) out = out.substr(0, kAuthnullRefusalMax) + "...";
	return base + ": " + out;
}

#endif // AUTHNULL_REFUSAL_H
