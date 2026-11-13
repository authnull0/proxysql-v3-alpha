#ifndef AUTHNULL_SESSION_ENDS_H
#define AUTHNULL_SESSION_ENDS_H

// PGSQL|MYSQL SET SESSION ENDS <id> <unix seconds>: move the access-grant end of an open session.
//
// A session let in on an access grant ends with it (authnull_session_limits.h, ends_s). When the
// grant is extended (authnull-service docs/DB-ACCESS-REQUESTS.md, "Extending a grant"), the
// database agent sends this from the admin interface for each of the grant's open sessions, so they
// go on to the new end instead of closing at the old one. The engine is named because ProxySQL
// numbers its Postgres and MySQL sessions separately. Only a session that has limits -- it came in
// on a grant -- gets a new end. The admin answers with a row (updated 1 or 0, and why), as
// PGSQL KILL CONNECTION does. test/authnull/authnull_session_ends_test.cpp.

#include <cctype>
#include <cstdint>
#include <cstring>
#include <strings.h>

#include "authnull_session_limits.h"

static const char* const kAuthnullPgsqlSetEnds = "PGSQL SET SESSION ENDS ";
static const char* const kAuthnullMysqlSetEnds = "MYSQL SET SESSION ENDS ";

struct AuthnullSessionEnds {
	bool pgsql = false;
	uint32_t id = 0;
	long long ends_s = 0;
};

namespace authnull_session_ends_detail {
// readNumber reads digits up to a space or the end; false on anything else, nothing, or past max.
inline bool readNumber(const char*& p, unsigned long long max, unsigned long long& out) {
	unsigned long long v = 0;
	const char* start = p;
	for (; *p && *p != ' '; p++) {
		if (!std::isdigit(static_cast<unsigned char>(*p))) return false;
		v = v * 10 + static_cast<unsigned long long>(*p - '0');
		if (v > max) return false;
	}
	if (p == start) return false;
	out = v;
	return true;
}
} // namespace authnull_session_ends_detail

// authnullParseSetSessionEnds reads "PGSQL|MYSQL SET SESSION ENDS <id> <unix>": id 1 to 2^32-1, a
// positive end, one space between, nothing after.
inline bool authnullParseSetSessionEnds(const char* q, AuthnullSessionEnds& out) {
	namespace d = authnull_session_ends_detail;
	if (!q) return false;
	size_t n = strlen(kAuthnullPgsqlSetEnds);
	bool pgsql;
	if (strncasecmp(q, kAuthnullPgsqlSetEnds, n) == 0) pgsql = true;
	else if (strncasecmp(q, kAuthnullMysqlSetEnds, n) == 0) pgsql = false;
	else return false;
	const char* p = q + n;
	unsigned long long id = 0, ends = 0;
	if (!d::readNumber(p, 0xffffffffULL, id) || id == 0 || *p != ' ') return false;
	p++;
	if (!d::readNumber(p, 0x7fffffffffffffffULL, ends) || ends == 0 || *p != '\0') return false;
	out.pgsql = pgsql;
	out.id = static_cast<uint32_t>(id);
	out.ends_s = static_cast<long long>(ends);
	return true;
}

#endif // AUTHNULL_SESSION_ENDS_H
