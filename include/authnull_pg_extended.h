// PostgreSQL's extended query protocol, answered over the simple one.
//
// pgAdmin 4 (psycopg 3), pgjdbc and most drivers send a query with parameters as the extended
// protocol: Parse (the SQL, with $1, $2 ...), Bind (the values), Describe, Execute, then Sync.
// ProxySQL here runs simple queries ('Q') only, and every AuthNull check -- the policy's
// privileges, field masking, session limits, recording -- reads the SQL of one. So the session
// keeps the statements and portals itself and, at Sync, runs the Executes as one simple query
// whose SQL is each statement with every $n replaced by its value as a quoted literal. That SQL
// takes exactly the path a 'Q' does, and the client's answer is rebuilt around the backend's:
// ParseComplete, BindComplete, CloseComplete, ParameterDescription, RowDescription or NoData where
// the client asked for a description, DataRows, CommandComplete, ReadyForQuery.
//
// Values. Text format, and binary for the common built-in types (psycopg 3 sends numbers,
// booleans, dates and UUIDs in binary), read into their text form; other binary parameters, and
// binary results, are refused (0A000). A value becomes
// '...' with ' doubled, which reads the same with standard_conforming_strings on or off and in every
// client encoding (no multibyte character has a ' byte); a value holding a backslash is
// dollar-quoted instead, $an$...$an$, with a tag that cannot end it early, so nothing in it is an
// escape. NULL is NULL. A value of a declared built-in type is cast to it, ('42'::int4), so the
// statement types the way the server would have typed the parameter; an undeclared one stays a
// bare literal, which the server types from context as it would the parameter. A value with a
// zero byte is refused, as the server does.
//
// Finding the parameters. scan() reads the SQL as the server's lexer does -- strings ('', E'',
// U&'', b'', dollar quotes), quoted identifiers, nested comments -- and finds each $n outside them.
// A backslash before a quote inside '...' reads differently with standard_conforming_strings on and
// off, and the proxy does not know which the server uses: a statement whose $n are not the same
// both ways is refused rather than guessed. So is anything not read to its end, a $n run into more
// identifier characters or straight after a number, and more than one statement (the server
// refuses that too).
//
// LIMITS -- each answered with an ErrorResponse, never dropped or guessed:
//  - Describe of a statement or portal that the next Execute in the same Sync does not run: its
//    description would need the statement run.
//  - Execute's row limit is ignored: all rows come back, then CommandComplete (no PortalSuspended).
//  - The Executes of one Sync run as one multi-statement query, one transaction, as the server
//    would; an error in a message before Sync means none of them runs (the server rolls them back),
//    and the error is answered in place of the first. A Flush with an Execute pending runs it then.
//  - The statements live in the proxy, not the server: SQL PREPARE/EXECUTE still reach the server,
//    DEALLOCATE of one of these is answered here, DEALLOCATE ALL and DISCARD ALL forget them all.
//
// test/authnull/authnull_pg_extended_test.cpp.
#ifndef AUTHNULL_PG_EXTENDED_H
#define AUTHNULL_PG_EXTENDED_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace authnull_pgx {

// ---- Wire format

inline void put16(std::string& b, uint16_t v) {
	b += static_cast<char>(v >> 8);
	b += static_cast<char>(v & 0xff);
}

inline void put32(std::string& b, uint32_t v) {
	put16(b, static_cast<uint16_t>(v >> 16));
	put16(b, static_cast<uint16_t>(v & 0xffff));
}

inline std::string message(char type, const std::string& body = std::string()) {
	std::string m(1, type);
	put32(m, static_cast<uint32_t>(body.size() + 4));
	return m + body;
}

inline std::string errorResponse(const std::string& sqlstate, const std::string& text) {
	std::string b;
	b += 'S'; b += "ERROR"; b += '\0';
	b += 'V'; b += "ERROR"; b += '\0';
	b += 'C'; b += sqlstate; b += '\0';
	b += 'M'; b += text; b += '\0';
	b += '\0';
	return message('E', b);
}

// Reader reads a message body. A read past its end fails, and the reader stays failed.
struct Reader {
	const unsigned char* p;
	size_t n;
	size_t i = 0;
	bool ok = true;
	Reader(const unsigned char* p_, size_t n_) : p(p_), n(n_) {}
	bool need(size_t k) {
		if (ok && n - i < k) ok = false;
		return ok;
	}
	std::string cstr() {
		const void* z = ok ? std::memchr(p + i, 0, n - i) : nullptr;
		if (!z) { ok = false; return std::string(); }
		const size_t len = static_cast<const unsigned char*>(z) - (p + i);
		std::string s(reinterpret_cast<const char*>(p + i), len);
		i += len + 1;
		return s;
	}
	char byte() { if (!need(1)) return 0; return static_cast<char>(p[i++]); }
	uint16_t u16() {
		if (!need(2)) return 0;
		const uint16_t v = static_cast<uint16_t>((p[i] << 8) | p[i + 1]);
		i += 2;
		return v;
	}
	uint32_t u32() {
		if (!need(4)) return 0;
		const uint32_t v = (uint32_t(p[i]) << 24) | (uint32_t(p[i + 1]) << 16) | (uint32_t(p[i + 2]) << 8) | uint32_t(p[i + 3]);
		i += 4;
		return v;
	}
	std::string bytes(size_t len) {
		if (!need(len)) return std::string();
		std::string s(reinterpret_cast<const char*>(p + i), len);
		i += len;
		return s;
	}
	bool end() const { return ok && i == n; }
};

// ---- Finding the parameters

inline bool identStart(unsigned char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80; }
inline bool isDigit(unsigned char c) { return c >= '0' && c <= '9'; }
inline bool identCont(unsigned char c) { return identStart(c) || isDigit(c) || c == '$'; }
inline bool isSpace(unsigned char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

struct Param {
	size_t at, len; // the "$n" in the SQL
	int number;
	bool operator==(const Param& o) const { return at == o.at && len == o.len; }
};

struct Scan {
	std::vector<Param> params;
	int maxParam = 0;
	int statements = 0;           // not counting empty ones
	std::string sqlstate, error;  // set: refuse the SQL
};

// scanAs reads sql the way the server's lexer does with standard_conforming_strings scs.
inline Scan scanAs(const std::string& s, bool scs) {
	Scan r;
	const size_t n = s.size();
	size_t i = 0;
	int depth = 0;
	bool content = false;    // the statement being read has a token
	bool afterNumber = false;
	auto fail = [&](const char* state, const std::string& msg) {
		r.sqlstate = state;
		r.error = msg;
		return r;
	};
	// quoted reads up to the closing q (doubled: part of the text); bs: a backslash escapes.
	auto quoted = [&](char q, bool bs) {
		while (i < n) {
			const char c = s[i];
			if (bs && c == '\\') { i += 2; continue; }
			i++;
			if (c == q) {
				if (i < n && s[i] == q) { i++; continue; }
				return true;
			}
		}
		return false;
	};
	while (i < n) {
		const unsigned char c = s[i];
		const bool wasNumber = afterNumber;
		afterNumber = false;
		if (isSpace(c)) { i++; continue; }
		if (c == '-' && i + 1 < n && s[i + 1] == '-') {
			while (i < n && s[i] != '\n' && s[i] != '\r') i++;
			continue;
		}
		if (c == '/' && i + 1 < n && s[i + 1] == '*') {
			int d = 0;
			while (i < n) {
				if (s[i] == '/' && i + 1 < n && s[i + 1] == '*') { d++; i += 2; }
				else if (s[i] == '*' && i + 1 < n && s[i + 1] == '/') { d--; i += 2; if (d == 0) break; }
				else i++;
			}
			if (d != 0) return fail("42601", "unterminated /* comment");
			continue;
		}
		if (c == ';' && depth == 0) {
			if (content) r.statements++;
			content = false;
			i++;
			continue;
		}
		content = true;
		if (c == '\'') {
			i++;
			if (!quoted('\'', !scs)) return fail("42601", "unterminated quoted string");
			continue;
		}
		if (c == '"') {
			i++;
			if (!quoted('"', false)) return fail("42601", "unterminated quoted identifier");
			continue;
		}
		if (c == '$') {
			size_t j = i + 1;
			if (j < n && isDigit(s[j])) {
				long v = 0;
				while (j < n && isDigit(s[j])) {
					if (v <= 65535) v = v * 10 + (s[j] - '0');
					j++;
				}
				if (wasNumber || (j < n && identCont(s[j]))) return fail("42601", "trailing junk after parameter");
				if (v < 1 || v > 65535) return fail("42P02", "there is no parameter $" + s.substr(i + 1, j - i - 1));
				r.params.push_back({i, j - i, static_cast<int>(v)});
				if (v > r.maxParam) r.maxParam = static_cast<int>(v);
				i = j;
				continue;
			}
			if (j < n && identStart(s[j])) {
				while (j < n && (identStart(s[j]) || isDigit(s[j]))) j++;
			}
			if (j < n && s[j] == '$') { // a dollar quote: up to the same tag
				const std::string tag = s.substr(i, j - i + 1);
				const size_t end = s.find(tag, j + 1);
				if (end == std::string::npos) return fail("42601", "unterminated dollar-quoted string");
				i = end + tag.size();
				continue;
			}
			i++;
			continue;
		}
		if (identStart(c)) {
			size_t j = i;
			while (j < n && identCont(s[j])) j++;
			if (j - i == 1 && j < n) { // E'...', B'...', X'...', U&'...', U&"..."
				const char p = s[i];
				if ((p == 'e' || p == 'E') && s[j] == '\'') {
					i = j + 1;
					if (!quoted('\'', true)) return fail("42601", "unterminated quoted string");
					continue;
				}
				if ((p == 'b' || p == 'B' || p == 'x' || p == 'X') && s[j] == '\'') {
					i = j + 1;
					if (!quoted('\'', false)) return fail("42601", "unterminated quoted string");
					continue;
				}
				if ((p == 'u' || p == 'U') && s[j] == '&' && j + 1 < n && (s[j + 1] == '\'' || s[j + 1] == '"')) {
					const char q = s[j + 1];
					i = j + 2;
					if (!quoted(q, false)) return fail("42601", q == '"' ? "unterminated quoted identifier" : "unterminated quoted string");
					continue;
				}
			}
			i = j;
			continue;
		}
		if (isDigit(c) || (c == '.' && i + 1 < n && isDigit(s[i + 1]))) {
			while (i < n && (isDigit(s[i]) || s[i] == '_')) i++;
			if (i < n && s[i] == '.') {
				i++;
				while (i < n && (isDigit(s[i]) || s[i] == '_')) i++;
			}
			if (i < n && (s[i] == 'e' || s[i] == 'E')) {
				size_t j = i + 1;
				if (j < n && (s[j] == '+' || s[j] == '-')) j++;
				if (j < n && isDigit(s[j])) {
					i = j;
					while (i < n && isDigit(s[i])) i++;
				}
			}
			afterNumber = true;
			continue;
		}
		if (c == '(') depth++;
		if (c == ')' && depth > 0) depth--;
		i++;
	}
	if (content) r.statements++;
	return r;
}

// scan reads sql both ways (standard_conforming_strings on and off) and refuses it when the two
// readings find different parameters.
inline Scan scan(const std::string& sql) {
	Scan on = scanAs(sql, true);
	const Scan off = scanAs(sql, false);
	if (on.error.empty() != off.error.empty() || on.params != off.params || on.statements != off.statements) {
		Scan r;
		r.sqlstate = "0A000";
		r.error = "this statement reads differently with standard_conforming_strings on and off (a backslash "
			"before a quote in a '...' string): write the string as E'...' to send it with parameters";
		return r;
	}
	return on;
}

// ---- Values

struct Value {
	bool null = false;
	std::string text;
};

// typeName: the built-in types a parameter can be declared as, by OID (pg_type.dat). Quoted where
// the bare word would carry a length ("char" is char(1), "bit" is bit(1)).
inline const char* typeName(uint32_t oid) {
	switch (oid) {
	case 16: return "bool";
	case 17: return "bytea";
	case 18: return "\"char\"";
	case 19: return "name";
	case 20: return "int8";
	case 21: return "int2";
	case 23: return "int4";
	case 24: return "regproc";
	case 25: return "text";
	case 26: return "oid";
	case 114: return "json";
	case 142: return "xml";
	case 650: return "cidr";
	case 700: return "float4";
	case 701: return "float8";
	case 774: return "macaddr8";
	case 790: return "money";
	case 829: return "macaddr";
	case 869: return "inet";
	case 1042: return "bpchar";
	case 1043: return "varchar";
	case 1082: return "date";
	case 1083: return "time";
	case 1114: return "timestamp";
	case 1184: return "timestamptz";
	case 1186: return "interval";
	case 1266: return "timetz";
	case 1560: return "\"bit\"";
	case 1562: return "varbit";
	case 1700: return "numeric";
	case 2205: return "regclass";
	case 2206: return "regtype";
	case 2950: return "uuid";
	case 3802: return "jsonb";
	case 4089: return "regnamespace";
	case 4096: return "regrole";
	case 199: return "json[]";
	case 1000: return "bool[]";
	case 1001: return "bytea[]";
	case 1002: return "\"char\"[]";
	case 1003: return "name[]";
	case 1005: return "int2[]";
	case 1007: return "int4[]";
	case 1009: return "text[]";
	case 1014: return "bpchar[]";
	case 1015: return "varchar[]";
	case 1016: return "int8[]";
	case 1021: return "float4[]";
	case 1022: return "float8[]";
	case 1028: return "oid[]";
	case 1041: return "inet[]";
	case 1115: return "timestamp[]";
	case 1182: return "date[]";
	case 1183: return "time[]";
	case 1185: return "timestamptz[]";
	case 1187: return "interval[]";
	case 1231: return "numeric[]";
	case 2951: return "uuid[]";
	case 3807: return "jsonb[]";
	default: return nullptr;
	}
}

// fromBinary turns a binary-format parameter of a common built-in type into its text form, which
// is what the SQL carries (psycopg 3 sends numbers, booleans, dates and UUIDs in binary by
// default). False for a type it does not read, or a value of the wrong size.
inline bool fromBinary(uint32_t oid, const std::string& b, std::string& out) {
	const unsigned char* p = reinterpret_cast<const unsigned char*>(b.data());
	auto be = [&](size_t at, size_t n) {
		uint64_t v = 0;
		for (size_t k = 0; k < n; k++) v = (v << 8) | p[at + k];
		return v;
	};
	auto two = [](long v) { return std::string(v < 10 ? "0" : "") + std::to_string(v); };
	auto ymd = [&](long long days) { // days since 2000-01-01 -> YYYY-MM-DD[ BC]
		long long z = days + 10957 + 719468; // to 1970, then the civil-from-days algorithm
		const long long era = (z >= 0 ? z : z - 146096) / 146097;
		const long long doe = z - era * 146097;
		const long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
		const long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
		const long long mp = (5 * doy + 2) / 153;
		const long long d = doy - (153 * mp + 2) / 5 + 1;
		const long long m = mp < 10 ? mp + 3 : mp - 9;
		long long y = yoe + era * 400 + (m <= 2);
		const bool bc = y <= 0;
		if (bc) y = 1 - y;
		std::string ys = std::to_string(y);
		while (ys.size() < 4) ys = "0" + ys;
		return ys + "-" + two(m) + "-" + two(d) + (bc ? " BC" : "");
	};
	auto hms = [&](long long us) { // microseconds of a day -> HH:MM:SS.ffffff
		std::string f = std::to_string(us % 1000000);
		while (f.size() < 6) f = "0" + f;
		return two(us / 3600000000LL) + ":" + two(us / 60000000 % 60) + ":" + two(us / 1000000 % 60) + "." + f;
	};
	switch (oid) {
	case 16: // bool
		if (b.size() != 1) return false;
		out = p[0] ? "t" : "f";
		return true;
	case 21: if (b.size() != 2) return false; out = std::to_string(static_cast<int16_t>(be(0, 2))); return true;
	case 23: if (b.size() != 4) return false; out = std::to_string(static_cast<int32_t>(be(0, 4))); return true;
	case 20: if (b.size() != 8) return false; out = std::to_string(static_cast<int64_t>(be(0, 8))); return true;
	case 26: if (b.size() != 4) return false; out = std::to_string(static_cast<uint32_t>(be(0, 4))); return true;
	case 700:
	case 701: {
		char buf[64];
		double d;
		if (oid == 700 && b.size() == 4) {
			const uint32_t u = static_cast<uint32_t>(be(0, 4));
			float f;
			std::memcpy(&f, &u, 4);
			d = f;
		} else if (oid == 701 && b.size() == 8) {
			const uint64_t u = be(0, 8);
			std::memcpy(&d, &u, 8);
		} else {
			return false;
		}
		if (d != d) out = "NaN";
		else if (d > 1.7976931348623157e308) out = "Infinity";
		else if (d < -1.7976931348623157e308) out = "-Infinity";
		else { std::snprintf(buf, sizeof(buf), oid == 700 ? "%.9g" : "%.17g", d); out = buf; }
		return true;
	}
	case 1700: { // numeric: ndigits, weight, sign, dscale, then base-10000 digits
		if (b.size() < 8) return false;
		const int nd = static_cast<int16_t>(be(0, 2)), weight = static_cast<int16_t>(be(2, 2));
		const uint16_t sign = static_cast<uint16_t>(be(4, 2));
		const int dscale = static_cast<int16_t>(be(6, 2));
		if (nd < 0 || dscale < 0 || b.size() != 8 + 2 * static_cast<size_t>(nd)) return false;
		if (sign == 0xC000) { out = "NaN"; return true; }
		if (sign == 0xD000) { out = "Infinity"; return true; }
		if (sign == 0xF000) { out = "-Infinity"; return true; }
		if (sign != 0 && sign != 0x4000) return false;
		auto digit = [&](int k) { return k >= 0 && k < nd ? static_cast<int>(be(8 + 2 * k, 2)) : 0; };
		std::string s = sign == 0x4000 ? "-" : "";
		if (weight < 0) s += "0";
		for (int k = 0; k <= weight; k++) {
			std::string g = std::to_string(digit(k));
			if (k > 0) while (g.size() < 4) g = "0" + g;
			s += g;
		}
		if (dscale > 0) {
			std::string frac;
			for (int k = weight + 1; static_cast<int>(frac.size()) < dscale; k++) {
				std::string g = std::to_string(digit(k));
				while (g.size() < 4) g = "0" + g;
				frac += g;
			}
			s += "." + frac.substr(0, dscale);
		}
		out = s;
		return true;
	}
	case 1082: { // date: days since 2000-01-01
		if (b.size() != 4) return false;
		const int32_t days = static_cast<int32_t>(be(0, 4));
		out = days == INT32_MAX ? "infinity" : days == INT32_MIN ? "-infinity" : ymd(days);
		return true;
	}
	case 1083: if (b.size() != 8) return false; out = hms(static_cast<int64_t>(be(0, 8))); return true;
	case 1114:
	case 1184: { // microseconds since 2000-01-01 00:00 (UTC for timestamptz)
		if (b.size() != 8) return false;
		const int64_t t = static_cast<int64_t>(be(0, 8));
		if (t == INT64_MAX) { out = "infinity"; return true; }
		if (t == INT64_MIN) { out = "-infinity"; return true; }
		long long days = t / 86400000000LL, us = t % 86400000000LL;
		if (us < 0) { us += 86400000000LL; days--; }
		std::string d = ymd(days), bc;
		if (d.size() > 3 && d.compare(d.size() - 3, 3, " BC") == 0) { bc = " BC"; d.resize(d.size() - 3); }
		out = d + " " + hms(us) + (oid == 1184 ? "+00" : "") + bc;
		return true;
	}
	case 2950: { // uuid
		if (b.size() != 16) return false;
		static const char* hex = "0123456789abcdef";
		out.clear();
		for (size_t k = 0; k < 16; k++) {
			if (k == 4 || k == 6 || k == 8 || k == 10) out += '-';
			out += hex[p[k] >> 4];
			out += hex[p[k] & 15];
		}
		return true;
	}
	case 17: { // bytea: its hex text form
		static const char* hex = "0123456789abcdef";
		out = "\\x";
		for (const unsigned char c : b) { out += hex[c >> 4]; out += hex[c & 15]; }
		return true;
	}
	case 25: case 1043: case 1042: case 19: case 114: // the text is the value
		out = b;
		return true;
	case 3802: // jsonb: a version byte, then the text
		if (b.empty() || p[0] != 1) return false;
		out = b.substr(1);
		return true;
	default:
		break;
	}
	// An array of one of those (psycopg sends a list of numbers so): its text form, {..,..}.
	if (b.size() < 12) return false;
	const uint32_t ndim = static_cast<uint32_t>(be(0, 4)), elem = static_cast<uint32_t>(be(8, 4));
	const char* arrayType = typeName(oid);
	if (!arrayType || std::strstr(arrayType, "[]") == nullptr) return false;
	if (ndim < 1 || ndim > 6 || b.size() < 12 + 8 * static_cast<size_t>(ndim)) return false;
	std::vector<uint32_t> dims;
	for (uint32_t k = 0; k < ndim; k++) {
		dims.push_back(static_cast<uint32_t>(be(12 + 8 * k, 4)));
		if (be(16 + 8 * k, 4) != 1 || dims.back() > b.size()) return false; // lower bounds other than 1: not read
	}
	size_t at = 12 + 8 * static_cast<size_t>(ndim);
	bool ok = true;
	std::function<std::string(uint32_t)> level = [&](uint32_t d) {
		std::string s = "{";
		for (uint32_t k = 0; ok && k < dims[d]; k++) {
			if (k) s += ',';
			if (d + 1 < ndim) { s += level(d + 1); continue; }
			if (b.size() - at < 4) { ok = false; break; }
			const int32_t len = static_cast<int32_t>(be(at, 4));
			at += 4;
			if (len == -1) { s += "NULL"; continue; }
			std::string v;
			if (len < 0 || b.size() - at < static_cast<size_t>(len) || !fromBinary(elem, b.substr(at, len), v)) { ok = false; break; }
			at += len;
			s += '"';
			for (const char c : v) {
				if (c == '"' || c == '\\') s += '\\';
				s += c;
			}
			s += '"';
		}
		return s + "}";
	};
	out = level(0);
	return ok && at == b.size();
}

// literal quotes a text value (see the header).
inline std::string literal(const std::string& v) {
	if (v.find('\\') == std::string::npos) {
		std::string out = "'";
		for (const char c : v) {
			if (c == '\'') out += '\'';
			out += c;
		}
		return out + "'";
	}
	// The first tag in v+tag must be the closing one: v must not hold the tag, nor end in its start.
	std::string tag = "$an$";
	for (int k = 1; (v + tag).find(tag) != v.size(); k++) tag = "$an" + std::to_string(k) + "$";
	return tag + v + tag;
}

inline std::string valueSQL(const Value& v, uint32_t oid) {
	const std::string lit = v.null ? "NULL" : literal(v.text);
	const char* t = typeName(oid);
	return t ? "(" + lit + "::" + t + ")" : lit;
}

// substitute puts the values in place of the statement's $n.
inline std::string substitute(const std::string& sql, const std::vector<Param>& params, const std::vector<Value>& values,
		const std::vector<uint32_t>& types) {
	std::string out;
	size_t at = 0;
	for (const Param& p : params) {
		out.append(sql, at, p.at - at);
		const size_t k = static_cast<size_t>(p.number - 1);
		// A quote right next to it would run into the literal ('a''b' is one string): keep them apart.
		if (!out.empty() && (out.back() == '\'' || out.back() == '"' || out.back() == '$')) out += ' ';
		out += valueSQL(values[k], k < types.size() ? types[k] : 0);
		at = p.at + p.len;
		if (at < sql.size() && (sql[at] == '\'' || sql[at] == '"')) out += ' ';
	}
	out.append(sql, at, std::string::npos);
	return out;
}

// ---- The session's statements, portals and the answer to a Sync

class Extended {
public:
	enum Action {
		Wait,   // nothing to send yet
		Answer, // send takeAnswer(); after a Sync, then ReadyForQuery
		Run     // send takeAnswer(), then run sql() as a simple query: the answer is built around its result
	};
	static constexpr size_t kMaxStatements = 10000;
	static constexpr int kMaxExecutes = 10000;

	// on: one client message of the extended protocol ('P', 'B', 'D', 'E', 'C', 'H', 'S'), its body
	// without the type and length. queued: more client messages are already waiting.
	Action on(char type, const unsigned char* body, size_t len, bool queued) {
		if (type == 'S') return sync();
		if (type == 'H') return flush(queued);
		if (failed_) return Wait; // after an error, everything up to Sync is skipped
		Reader r(body, len);
		switch (type) {
		case 'P': parse(r); break;
		case 'B': bind(r); break;
		case 'D': describe(r); break;
		case 'E': execute(r); break;
		case 'C': close(r); break;
		default: fail("08P01", std::string("unexpected message type '") + type + "'"); break;
		}
		return Wait;
	}

	// takeAnswer: what can be answered now, up to the first answer that needs the backend's result.
	std::string takeAnswer() { return locals(); }

	// sql: for Run, the SQL to run, the Executes' statements with their values in.
	std::string sql() const {
		std::string out;
		for (const Item& it : plan_) {
			if (it.kind != 'X') continue;
			if (!out.empty()) out += "\n;\n";
			out += it.sql;
		}
		return out;
	}

	bool running() const { return running_; }
	bool wantsReady() const { return ready_; }

	// The backend's answer to sql(), message by message (all but DataRow, which passes as it is):
	// each returns what to send in its place.
	std::string onRowDescription(const std::string& T) { return walk(&T); }

	std::string onComplete(const std::string& C) { // CommandComplete or EmptyQueryResponse
		std::string out = walk(nullptr);
		if (pos_ < plan_.size() && plan_[pos_].kind == 'X' && plan_[pos_].result == cur_) {
			out += C;
			pos_++;
		}
		cur_++;
		return out + locals();
	}

	std::string onError(const std::string& E) {
		std::string out = locals() + E;
		pos_ = plan_.size();
		failed_ = true;
		return out;
	}

	std::string onReady(const std::string& Z) {
		std::string out = failed_ ? std::string() : locals();
		if (ready_) {
			out += Z;
			failed_ = false;
		}
		endRun();
		return out;
	}

	// abandon: the run was answered without the backend (refused, or answered by the proxy).
	void abandon() {
		if (!ready_) failed_ = true;
		endRun();
	}

	// deallocate looks at a simple query: DEALLOCATE of one of these statements is answered here
	// (true). DEALLOCATE ALL and DISCARD ALL forget them all and still go to the server.
	bool deallocate(const std::string& q) {
		size_t i = 0;
		auto ws = [&]() { while (i < q.size() && isSpace(q[i])) i++; };
		auto word = [&](const char* w) {
			const size_t k = std::strlen(w);
			if (q.size() - i < k) return false;
			for (size_t j = 0; j < k; j++) {
				if ((q[i + j] | 0x20) != w[j]) return false;
			}
			if (i + k < q.size() && identCont(q[i + k])) return false;
			i += k;
			return true;
		};
		auto rest = [&]() { // nothing more but a ';', blanks, and the query's terminating zero
			ws();
			if (i < q.size() && q[i] == ';') i++;
			ws();
			while (i < q.size() && q[i] == '\0') i++;
			return i == q.size();
		};
		ws();
		if (word("discard")) {
			ws();
			if (word("all") && rest()) statements_.clear();
			return false;
		}
		if (!word("deallocate")) return false;
		ws();
		const size_t afterKeyword = i;
		if (word("prepare")) {
			ws();
			if (i >= q.size() || q[i] == ';' || q[i] == '\0') i = afterKeyword; // "prepare" is the name
		}
		std::string name;
		if (i < q.size() && q[i] == '"') {
			i++;
			while (i < q.size()) {
				if (q[i] == '"') {
					if (i + 1 < q.size() && q[i + 1] == '"') { name += '"'; i += 2; continue; }
					break;
				}
				name += q[i++];
			}
			if (i >= q.size()) return false;
			i++;
		} else {
			const size_t start = i;
			if (word("all")) {
				if (rest()) statements_.clear();
				return false;
			}
			i = start;
			while (i < q.size() && identCont(q[i])) {
				const char c = q[i++];
				name += (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
			}
		}
		if (name.empty() || !rest()) return false;
		return statements_.erase(name) == 1;
	}

private:
	struct Statement {
		std::string sql;
		std::vector<Param> params;
		std::vector<uint32_t> types; // one per parameter; 0: not declared
		bool empty = false;
	};
	struct Portal {
		std::string sql; // the values in
		std::string statement;
		bool empty = false;
	};
	struct Item {
		char kind;          // 'L' an answer as it is, 'D' a Describe, 'X' an Execute
		std::string bytes;  // L: the answer; D: what goes before the row description (a ParameterDescription)
		int result;         // D, X: which of sql()'s results answers it; -1: none yet
		char of;            // D: 'S' a statement, 'P' a portal
		std::string target; // D: the statement or portal described; X: the portal
		std::string sql;    // X
	};

	std::map<std::string, Statement> statements_;
	std::map<std::string, Portal> portals_;
	std::vector<Item> plan_;
	size_t pos_ = 0;      // next plan item to answer
	int nexec_ = 0;       // Executes in the plan
	int cur_ = 0;         // the result arriving
	bool failed_ = false; // an error: skip to Sync
	bool running_ = false;
	bool ready_ = true;   // the run ends with ReadyForQuery (a Sync, not a Flush)

	void local(const std::string& b) { plan_.push_back({'L', b, -1, 0, std::string(), std::string()}); }

	// fail answers an error. Nothing of this Sync runs: the server would roll it back.
	void fail(const char* state, const std::string& text) {
		size_t k = pos_;
		while (k < plan_.size() && plan_[k].kind == 'L') k++;
		plan_.resize(k);
		nexec_ = 0;
		local(errorResponse(state, text));
		failed_ = true;
	}

	std::string locals() {
		std::string out;
		while (pos_ < plan_.size() && plan_[pos_].kind == 'L') out += plan_[pos_++].bytes;
		return out;
	}

	std::string walk(const std::string* T) {
		std::string out;
		for (; pos_ < plan_.size(); pos_++) {
			const Item& it = plan_[pos_];
			if (it.kind == 'L') out += it.bytes;
			else if (it.kind == 'D' && it.result == cur_) out += it.bytes + (T ? *T : message('n'));
			else break;
		}
		return out;
	}

	void endRun() {
		plan_.clear();
		pos_ = 0;
		nexec_ = 0;
		cur_ = 0;
		running_ = false;
	}

	// pending: a Describe that no Execute answers (after the last one).
	bool pendingDescribe() const {
		for (size_t j = plan_.size(); j-- > pos_ && plan_[j].kind != 'X';) {
			if (plan_[j].kind == 'D' && plan_[j].result < 0) return true;
		}
		return false;
	}

	static const char* describeAlone() {
		return "a Describe must be followed by the Execute it describes, before Sync, through this proxy";
	}

	Action sync() {
		if (!failed_ && pendingDescribe()) fail("0A000", describeAlone());
		portals_.clear(); // portals end with the transaction Sync closes
		failed_ = false;
		ready_ = true;
		return start();
	}

	Action flush(bool queued) {
		ready_ = false;
		if (failed_ || nexec_ == 0) return Answer;
		if (queued) return Wait; // its Sync (or more) is right behind it
		if (pendingDescribe()) {
			fail("0A000", describeAlone());
			return Answer;
		}
		ready_ = false;
		return start();
	}

	Action start() {
		if (nexec_ == 0) return Answer;
		running_ = true;
		cur_ = 0;
		return Run;
	}

	void parse(Reader& r) {
		const std::string name = r.cstr(), sql = r.cstr();
		const uint16_t nt = r.u16();
		std::vector<uint32_t> types;
		for (uint16_t k = 0; k < nt && r.ok; k++) types.push_back(r.u32());
		if (!r.end()) return fail("08P01", "invalid Parse message");
		if (!name.empty() && statements_.count(name)) return fail("42P05", "prepared statement \"" + name + "\" already exists");
		if (!name.empty() && statements_.size() >= kMaxStatements) return fail("53400", "too many prepared statements in this session");
		const Scan sc = scan(sql);
		if (!sc.error.empty()) return fail(sc.sqlstate.c_str(), sc.error);
		if (sc.statements > 1) return fail("42601", "cannot insert multiple commands into a prepared statement");
		Statement st;
		st.sql = sql;
		st.params = sc.params;
		st.types = types;
		if (st.types.size() < static_cast<size_t>(sc.maxParam)) st.types.resize(sc.maxParam, 0);
		st.empty = sc.statements == 0;
		statements_[name] = st;
		local(message('1'));
	}

	void bind(Reader& r) {
		const std::string portal = r.cstr(), name = r.cstr();
		const uint16_t nf = r.u16();
		std::vector<uint16_t> formats;
		for (uint16_t k = 0; k < nf && r.ok; k++) formats.push_back(r.u16());
		const uint16_t np = r.u16();
		std::vector<Value> values;
		for (uint16_t k = 0; k < np && r.ok; k++) {
			const int32_t len = static_cast<int32_t>(r.u32());
			Value v;
			if (len == -1) v.null = true;
			else if (len < 0) r.ok = false;
			else v.text = r.bytes(static_cast<size_t>(len));
			values.push_back(v);
		}
		const uint16_t nr = r.u16();
		std::vector<uint16_t> resultFormats;
		for (uint16_t k = 0; k < nr && r.ok; k++) resultFormats.push_back(r.u16());
		if (!r.end()) return fail("08P01", "invalid Bind message");
		const auto it = statements_.find(name);
		if (it == statements_.end()) {
			return fail("26000", name.empty() ? "unnamed prepared statement does not exist" : "prepared statement \"" + name + "\" does not exist");
		}
		if (!portal.empty() && portals_.count(portal)) return fail("42P03", "cursor \"" + portal + "\" already exists");
		const Statement& st = it->second;
		if (np != st.types.size()) {
			return fail("08P01", "bind message supplies " + std::to_string(np) + " parameters, but prepared statement \"" + name +
				"\" requires " + std::to_string(st.types.size()));
		}
		if (nf > 1 && nf != np) return fail("08P01", "bind message has " + std::to_string(nf) + " parameter formats but " + std::to_string(np) + " parameters");
		for (uint16_t k = 0; k < np; k++) {
			const uint16_t f = nf == 0 ? 0 : formats[nf == 1 ? 0 : k];
			if (f > 1) return fail("08P01", "unsupported format code: " + std::to_string(f));
			if (f == 1 && !values[k].null) {
				std::string text;
				if (!fromBinary(st.types[k], values[k].text, text)) {
					return fail("0A000", "binary-format parameters of type " + std::to_string(st.types[k]) +
						" are not supported through this proxy; send them as text");
				}
				values[k].text = text;
			}
			if (values[k].text.find('\0') != std::string::npos) return fail("22021", "invalid byte sequence for encoding \"UTF8\": 0x00");
		}
		for (const uint16_t f : resultFormats) {
			if (f > 1) return fail("08P01", "unsupported format code: " + std::to_string(f));
			if (f == 1) return fail("0A000", "binary-format results are not supported through this proxy; ask for text");
		}
		Portal p;
		p.statement = name;
		p.empty = st.empty;
		if (!st.empty) p.sql = substitute(st.sql, st.params, values, st.types);
		portals_[portal] = p;
		local(message('2'));
	}

	void describe(Reader& r) {
		const char of = r.byte();
		const std::string name = r.cstr();
		if (!r.end() || (of != 'S' && of != 'P')) return fail("08P01", "invalid Describe message");
		if (of == 'S') {
			const auto it = statements_.find(name);
			if (it == statements_.end()) {
				return fail("26000", name.empty() ? "unnamed prepared statement does not exist" : "prepared statement \"" + name + "\" does not exist");
			}
			std::string t;
			put16(t, static_cast<uint16_t>(it->second.types.size()));
			for (const uint32_t oid : it->second.types) put32(t, oid);
			if (it->second.empty) return local(message('t', t) + message('n'));
			plan_.push_back({'D', message('t', t), -1, 'S', name, std::string()});
			return;
		}
		const auto it = portals_.find(name);
		if (it == portals_.end()) return fail("34000", "portal \"" + name + "\" does not exist");
		if (it->second.empty) return local(message('n'));
		plan_.push_back({'D', std::string(), -1, 'P', name, std::string()});
	}

	void execute(Reader& r) {
		const std::string name = r.cstr();
		r.u32(); // the row limit: ignored, every row comes back (see the header)
		if (!r.end()) return fail("08P01", "invalid Execute message");
		const auto it = portals_.find(name);
		if (it == portals_.end()) return fail("34000", "portal \"" + name + "\" does not exist");
		if (it->second.empty) return local(message('I'));
		if (nexec_ >= kMaxExecutes) return fail("54000", "too many Executes before Sync");
		// The Describes since the last Execute are answered with this one's result, if they are of it.
		for (size_t j = plan_.size(); j-- > pos_ && plan_[j].kind != 'X';) {
			Item& d = plan_[j];
			if (d.kind != 'D' || d.result >= 0) continue;
			if (d.of == 'P' ? d.target != name : d.target != it->second.statement) return fail("0A000", describeAlone());
			d.result = nexec_;
		}
		plan_.push_back({'X', std::string(), nexec_++, 0, name, it->second.sql});
	}

	void close(Reader& r) {
		const char of = r.byte();
		const std::string name = r.cstr();
		if (!r.end() || (of != 'S' && of != 'P')) return fail("08P01", "invalid Close message");
		if (of == 'S') statements_.erase(name);
		else portals_.erase(name);
		local(message('3'));
	}
};

} // namespace authnull_pgx

typedef authnull_pgx::Extended AuthnullPgExtended;

#endif // AUTHNULL_PG_EXTENDED_H
