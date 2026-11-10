#ifndef AUTHNULL_KILL_H
#define AUTHNULL_KILL_H

// PGSQL KILL CONNECTION <id>: end a Postgres client session from the admin interface.
//
// ProxySQL's KILL CONNECTION reaches the MySQL threads only (GloMTH); PgSQL_Threads_Handler::
// kill_session existed with no caller. Postgres and MySQL session ids are counted separately and
// can be the same number, so this is its own command rather than a fallback that could end the
// other protocol's session. The database agent sends it for a kill from the AuthNull console
// (authnull-service docs/DB-LIVE-SESSIONS.md). test/authnull/authnull_kill_test.cpp.

#include <cctype>
#include <cstdint>
#include <cstring>
#include <strings.h>

static const char* const kAuthnullPgsqlKill = "PGSQL KILL CONNECTION ";

// authnullParseKillID reads the id of "PGSQL KILL CONNECTION <id>": digits only, 1 to 2^32-1.
inline bool authnullParseKillID(const char* q, uint32_t& id) {
	size_t n = strlen(kAuthnullPgsqlKill);
	if (!q || strncasecmp(q, kAuthnullPgsqlKill, n) != 0) return false;
	const char* p = q + n;
	if (*p == '\0') return false;
	unsigned long long v = 0;
	for (; *p; p++) {
		if (!std::isdigit(static_cast<unsigned char>(*p))) return false;
		v = v * 10 + static_cast<unsigned long long>(*p - '0');
		if (v > 0xffffffffULL) return false;
	}
	if (v == 0) return false;
	id = static_cast<uint32_t>(v);
	return true;
}

#endif // AUTHNULL_KILL_H
